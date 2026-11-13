"""
Make the Shikari walkthrough video from scripts/video/script.yaml: a narrated screen recording with
subtitles and YouTube chapters.

Each scene's narration is spoken by a text-to-speech backend (--tts), the browser plays the scene's
actions across that time, and ffmpeg joins it all up. Run it against a throwaway instance with sample
data, never a real one:

    python scripts/video/make_video.py --base http://127.0.0.1:8010 --out ~/Desktop/Staging/shikari/video

Three backends: kokoro (default, local, free, more natural than piper), piper (local), and google
(Google Cloud Chirp 3: HD — higher quality but a cloud call needing GOOGLE_TTS_API_KEY; ~7k characters a
render sits well inside the free monthly tier). Needs ffmpeg and Playwright's Chromium. Writes
shikari-walkthrough.mp4, its .srt and youtube.txt (a description with chapters).

The work folder (shikari-video-* in the system temp folder) holds the lossless frames, ~18 GB for a
full-length run. It's removed when the run ends, however it ends; --keep-work keeps it for debugging.
"""
import argparse
import base64
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
import wave
from pathlib import Path

import yaml
from PIL import Image, ImageDraw, ImageFont
from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = Path(__file__).with_name("script.yaml")
WORK_PREFIX = "shikari-video-"
W, H = 1920, 1080
# The browser window: a full 1920x1080 CSS viewport so each page sits in frame at desktop width without
# feeling cramped or zoomed in. Captured 1:1 as lossless PNG (see Recorder) — JPEG frames put visible
# grain/mosquito noise around text, PNG does not.
VIEW, SCALE = {"width": 1920, "height": 1080}, 1.0
# A scene fades in from black and out to black unless it's marked `continues` in script.yaml, in which
# case it joins the one before it with no black between — a pause and a scroll down the same page. GAP is
# the quiet tail after a scene's narration (the pause, held on the page or on black); FADE is each dip.
TITLE_SECONDS, END_SECONDS, GAP, FADE, FPS = 4.0, 5.0, 1.6, 0.5, 30
# SEGMENT_PAUSE: the silence between a scene's segments (a blank line in its narration). LEAD: actions
# fire this far ahead of the words they're pinned to, so a scroll has settled by the time it's said.
SEGMENT_PAUSE, LEAD = 0.7, 0.25

# A pulsing outline that follows an element as the page scrolls, over a dimmed page
HIGHLIGHT = r"""
(el) => {
  const SUBTITLE_BAND = 0.22;  // share of the frame the two subtitle lines take up
  if (!document.getElementById('vhl-style')) {
    const st = document.createElement('style'); st.id = 'vhl-style';
    st.textContent = `#vhl { position: fixed; box-sizing: border-box; z-index: 2147483000; pointer-events: none;
      border: 4px solid #C53030; border-radius: 10px; box-shadow: 0 0 0 9999px rgba(10,14,20,.38);
      animation: vhl 1.6s ease-in-out infinite; }
      @keyframes vhl { 0%,100% { outline: 0 solid rgba(197,48,48,.6); outline-offset: 0 } 50% { outline: 10px solid rgba(197,48,48,0); outline-offset: 8px } }`;
    document.head.append(st);
  }
  let box = document.getElementById('vhl');
  if (!box) { box = document.createElement('div'); box.id = 'vhl'; document.body.append(box); }
  // The app sets `html { zoom: .95 }` (common.css). getBoundingClientRect returns post-zoom (visual)
  // coordinates, but #vhl is itself inside that zoom, so every value we assign is scaled by .95 a
  // second time — which drops the frame high and short of its target. Divide the zoom back out.
  // (box-sizing:border-box keeps the 4px border inside the measured size; no `transition` so the box
  // tracks the element exactly each frame instead of trailing a smooth scroll.)
  const z = parseFloat(getComputedStyle(document.documentElement).zoom) || 1;
  // Clear of the fixed nav bar
  const nav = document.querySelector('.global-nav-controls');
  const pinned = nav && ['fixed', 'sticky'].includes(getComputedStyle(nav).position);
  // ...unless the target is in the nav itself (a menu item drops down over the bar's edge)
  const top = pinned && !nav.contains(el) ? nav.getBoundingClientRect().bottom + 6 : 6;
  // The subtitles cover the bottom of the frame: keep what's being discussed above them
  const floor = innerHeight - Math.round(innerHeight * SUBTITLE_BAND);
  el.style.scrollMarginTop = top + 14 + 'px';
  // Centring the margin box centres the target between the nav and the subtitles
  el.style.scrollMarginBottom = innerHeight - floor + 'px';
  // Scroll only when the target isn't already in full view: nudging a visible element to the centre
  // moved the whole page on every highlight (and on Home, resized the hero with it), which read as shake.
  // A target taller than the space goes to the top, and the frame shows its head and first few items.
  // Measured afresh at each check: a section still expanding when it's shown starts short and ends tall
  const tall = r => r.height > (floor - top) * 0.9;
  const misplaced = r => tall(r) ? Math.abs(r.top - (top + 14)) > 24 : r.top < top || r.bottom > floor;
  const settle = r => el.scrollIntoView({ behavior: 'smooth', block: tall(r) ? 'start' : 'center' });
  const rr = el.getBoundingClientRect();
  if (misplaced(rr)) settle(rr);
  // A section collapsing above the target (or the target still rendering) moves it after the scroll
  // has finished, which left a tall one's top cut off: check again as each smooth scroll ends.
  const t0 = performance.now(), checks = [900, 1800, 2700];
  cancelAnimationFrame(window.__vhlRaf);
  const follow = () => {
    const r = el.getBoundingClientRect(), pad = 8, y = Math.max(r.top - pad, top);
    if (checks.length && performance.now() - t0 > checks[0]) {
      checks.shift();
      if (misplaced(r)) settle(r);
    }
    // A fixed control already in the subtitle band (Ask Shikari) can't move up: frame it where it is
    const bottom = Math.min(r.bottom + pad, r.top > floor - 40 ? innerHeight - 6 : floor);
    Object.assign(box.style, { left: (r.left - pad) / z + 'px', top: y / z + 'px',
      width: (r.width + 2 * pad) / z + 'px', height: Math.max(0, bottom - y) / z + 'px' });
    window.__vhlRaf = requestAnimationFrame(follow);
  };
  follow();
}
"""


def spoken(text, say):
    for written in sorted(say, key=len, reverse=True):
        text = re.sub(rf"(?<![\w&]){re.escape(written)}(?![\w&])", say[written], text)
    return text


def _wav_seconds(out):
    with wave.open(str(out)) as w:
        return w.getnframes() / w.getframerate()


def speak_piper(piper, voice, text, out, length_scale=1.0, sentence_silence=0.35, noise_w=0.7, noise_scale=0.5):
    # Confident, un-breathy delivery: a lower noise_scale de-breathes the voice (the "sultry" quality),
    # a lower phoneme-width noise keeps prosody steady rather than wobbly, with a short inter-sentence
    # silence for breathing room. Pair with a clear voice (en_GB-alan-medium) rather than a soft one.
    subprocess.run(
        [piper, "-m", voice, "-f", str(out),
         "--length-scale", str(length_scale),
         "--sentence-silence", str(sentence_silence),
         "--noise-w-scale", str(noise_w),
         "--noise-scale", str(noise_scale)],
        input=text.encode(), check=True, capture_output=True)
    return _wav_seconds(out)


def speak_kokoro(kpython, helper, model, voices, voice, text, out, lang="en-gb", speed=1.0, pause=0.45):
    # Kokoro is noticeably more natural than Piper, still local and free. It runs in its own venv
    # (kokoro_onnx isn't in the project venv), so shell out to scripts/video/kokoro_tts.py. `pause` is
    # the silence spliced between sentences for an unhurried read.
    subprocess.run(
        [kpython, str(helper), str(model), str(voices), voice, lang, str(speed), str(pause), str(out)],
        input=text.encode(), check=True, capture_output=True)
    return _wav_seconds(out)


def speak_google(text, out, voice, api_key, language="en-GB", speaking_rate=0.9, ipa=None):
    # Google Cloud Text-to-Speech (Chirp 3: HD). Opt-in and NOT local: the scene text is sent to Google
    # over the REST API and an API key is required (GOOGLE_TTS_API_KEY, or --google-key). At ~7k
    # characters a render it stays well inside the free monthly tier. LINEAR16 comes back as a WAV with a
    # header, so _wav_seconds reads it straight. Chirp 3: HD takes no SSML, so there's no inter-sentence
    # pause knob — --speed maps to speakingRate for overall pacing. Respellings don't always
    # land with Chirp (it read "shih-car-ee" as "chicory"), so words in the script's `ipa:` map go as
    # customPronunciations instead, which pin the phonemes exactly.
    body = {
        "input": {"text": text},
        "voice": {"languageCode": language, "name": voice},
        "audioConfig": {"audioEncoding": "LINEAR16", "sampleRateHertz": 24000, "speakingRate": speaking_rate},
    }
    if ipa:
        body["input"]["customPronunciations"] = {"pronunciations": [
            {"phrase": w, "phoneticEncoding": "PHONETIC_ENCODING_IPA", "pronunciation": p} for w, p in ipa.items()]}
    req = urllib.request.Request(
        "https://texttospeech.googleapis.com/v1/text:synthesize?key=" + api_key,
        data=json.dumps(body).encode(), headers={"Content-Type": "application/json"})
    # A dropped connection ("No route to host") is retried; an HTTP error is the request's fault, so it isn't
    for attempt in range(4):
        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                payload = json.loads(r.read())
            break
        except urllib.error.HTTPError as e:
            raise SystemExit(f"Google TTS request failed ({e.code}): {e.read().decode(errors='replace')}")
        except (urllib.error.URLError, TimeoutError, ConnectionError) as e:
            if attempt == 3:
                raise SystemExit(f"Google TTS unreachable after 4 attempts: {e}")
            time.sleep(5 * (attempt + 1))
    Path(out).write_bytes(base64.b64decode(payload["audioContent"]))
    return _wav_seconds(out)


def join_segments(parts, out, pause):
    # Each segment spoken on its own, joined with `pause` seconds of silence: the narration keeps the
    # voice's cadence inside a segment, and every segment's start is known exactly, so actions and
    # subtitles can be pinned to it instead of to a guessed fraction of the scene.
    spans, frames, t = [], [], 0.0
    with wave.open(str(parts[0])) as w:
        params = w.getparams()
    gap = b"\0" * (int(pause * params.framerate) * params.sampwidth * params.nchannels)
    for i, part in enumerate(parts):
        with wave.open(str(part)) as w:
            data = w.readframes(w.getnframes())
            d = w.getnframes() / w.getframerate()
        if i:
            frames.append(gap)
            t += pause
        spans.append((t, d))
        frames.append(data)
        t += d
    with wave.open(str(out), "wb") as w:
        w.setparams(params)
        w.writeframes(b"".join(frames))
    return t, spans


CARD_BG = (234, 236, 238)  # light, so the dark-text / two-tone-K lockup reads


def _font(size, bold=True):
    for name in (["Arial Bold.ttf"] if bold else []) + ["Arial.ttf"]:
        try:
            return ImageFont.truetype(f"/System/Library/Fonts/Supplemental/{name}", size)
        except OSError:
            pass
    return ImageFont.load_default()


def _tracked_width(d, text, font, track):
    return sum(d.textlength(c, font=font) for c in text) + track * max(0, len(text) - 1)


def _draw_tracked(d, cx, y, text, font, fill, track):
    # Letter-spaced centred text — PIL has no tracking, so place each glyph by hand.
    x = cx - _tracked_width(d, text, font, track) / 2
    for c in text:
        d.text((x, y), c, font=font, fill=fill)
        x += d.textlength(c, font=font) + track


def card(path, lines, logo):
    # The brand lockup (bateleur, SHIKARI, rule and tagline, the app's own hero without its card) over a
    # light ground, then any extra lines (repo + handle on the end card) centred under the word. The
    # whole stack is vertically centred so title and end sit the same on screen.
    img = Image.new("RGB", (W, H), CARD_BG)
    d = ImageDraw.Draw(img)
    src = Image.open(logo).convert("RGBA")
    # The word's edges and the tagline's foot, written into the PNG by scripts/brand/build_assets.py
    word_l, word_r, tag_foot = (int(v) for v in Image.open(logo).text["word"].split(","))
    # Scale so the visible mark (ignoring the transparent padding) fills the frame bar a margin, centred
    l, u, r, _lo = src.split()[-1].getbbox()
    scale = 1656 / (r - l)
    banner = src.resize((round(src.width * scale), round(src.height * scale)))
    fonts = [(line, _font(size, False), size, colour) for line, size, colour in lines]
    extra = sum(size + 28 for *_, size, _c in fonts) + (40 if lines else 0)
    top = round(u * scale)
    stack = round(tag_foot * scale) - top + extra
    bx = round(W / 2 - (l + r) / 2 * scale)
    by = (H - stack) // 2 - top
    img.paste(banner, (bx, by), banner)
    cx = bx + round((word_l + word_r) / 2 * scale)   # centred under SHIKARI, not the ™
    y = by + round(tag_foot * scale) + 40
    for line, f, size, colour in fonts:
        _draw_tracked(d, cx, y, line, f, colour, 0)
        y += size + 28
    img.save(path)


def srt_time(t):
    ms = int(round(t * 1000))
    return f"{ms // 3600000:02}:{ms // 60000 % 60:02}:{ms // 1000 % 60:02},{ms % 1000:03}"


def chapter_time(t):
    t = int(t)
    return f"{t // 60}:{t % 60:02}" if t < 3600 else f"{t // 3600}:{t // 60 % 60:02}:{t % 60:02}"


class Recorder:
    """Chromium's screencast: full-quality frames as the page changes, each with its time."""

    def __init__(self, page, folder):
        self.cdp = page.context.new_cdp_session(page)
        self.folder, self.frames = folder, []
        self.cdp.on("Page.screencastFrame", self.frame)

    def frame(self, e):
        n = len(self.frames)
        path = self.folder / f"{n:06}.png"
        path.write_bytes(base64.b64decode(e["data"]))
        # Chrome's own time for the frame: frames can reach us late, and timing them on arrival drifts
        self.frames.append((e["metadata"].get("timestamp") or time.time(), path))
        self.cdp.send("Page.screencastFrameAck", {"sessionId": e["sessionId"]})

    def start(self):
        # Lossless PNG frames, captured at the full viewport size — no JPEG grain around text.
        self.cdp.send("Page.startScreencast", {"format": "png", "maxWidth": W, "maxHeight": H, "everyNthFrame": 1})

    def stop(self):
        self.cdp.send("Page.stopScreencast")


def act(page, base, action):
    kind, arg = next(iter(action.items()))
    if kind == "goto":
        # These pages hold a live SSE connection open (role-watch), so 'networkidle' never fires —
        # waiting on it burned the full timeout on every scene, delaying the tab-click and highlights
        # to the end while the narration played over the default tab. Wait for the DOM instead, then a
        # short settle for layout (server-rendered Jinja, so the HTML is all there at domcontentloaded).
        # Park the mouse off the nav first: left over a menu button it holds that menu open on the next page
        page.mouse.move(VIEW["width"] - 20, VIEW["height"] - 20)
        page.goto(base + arg, wait_until="domcontentloaded")
        try:
            page.wait_for_load_state("networkidle", timeout=1500)
        except Exception:
            pass
    elif kind == "click":
        page.locator(arg).first.click(timeout=5000)
    elif kind == "type":
        page.locator(arg[0]).first.click()
        page.locator(arg[0]).first.press_sequentially(arg[1], delay=85)
        # Out of the way, or whatever the filtered results slide under the pointer shows a hover state
        page.mouse.move(VIEW["width"] - 20, VIEW["height"] - 20)
    elif kind == "clear":
        # Empty a field and fire its input event — e.g. a continuing scene clearing the group box so the
        # CVE path (mutually exclusive with it) re-enables before the CVE actions run.
        page.locator(arg).first.fill("")
    elif kind == "show":
        loc = page.locator(arg).first
        if loc.count():
            page.evaluate(HIGHLIGHT, loc.element_handle())
        else:
            print(f"    nothing matches {arg}")
    elif kind == "scroll":
        page.mouse.wheel(0, int(arg))
    elif kind == "key":
        page.keyboard.press(arg)
    elif kind == "guide":
        page.evaluate("id => ShikariGuide.open(id)", arg)
    elif kind == "eval":
        # A page's own function, for what a click can't reach cleanly (e.g. Results' toggleVendor)
        page.evaluate(f"() => {{ {arg} }}")


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--base", default="http://127.0.0.1:8010")
    parser.add_argument("--out", type=Path, default=Path.home() / "Desktop" / "Staging" / "shikari" / "video")
    parser.add_argument("--piper", default=str(Path.home() / ".cache/shikari/piper/venv/bin/piper"))
    parser.add_argument("--voice", default=str(Path.home() / ".cache/shikari/piper/voices/en_GB-alan-medium.onnx"))
    parser.add_argument("--only", nargs="*", help="scene ids to include (a quick draft)")
    parser.add_argument("--length-scale", type=float, default=1.0,
                        help="Piper phoneme length; >1 slows delivery (default 1.0)")
    parser.add_argument("--sentence-silence", type=float, default=0.35,
                        help="seconds of silence after each sentence (default 0.35)")
    parser.add_argument("--noise-w", type=float, default=0.7,
                        help="Piper phoneme-width noise; higher = more prosodic variation (default 0.7)")
    parser.add_argument("--noise-scale", type=float, default=0.5,
                        help="Piper generator noise; lower = less breathy/more confident (default 0.5)")
    parser.add_argument("--tts", choices=["kokoro", "piper", "google"], default="kokoro",
                        help="text-to-speech backend (default kokoro: natural, local, free). google uses "
                             "Google Cloud Chirp 3: HD — higher quality but a cloud call needing an API key")
    kcache = Path.home() / ".cache/shikari/kokoro"
    parser.add_argument("--kokoro-python", default=str(kcache / "venv/bin/python"))
    parser.add_argument("--kokoro-model", default=str(kcache / "kokoro-v1.0.onnx"))
    parser.add_argument("--kokoro-voices", default=str(kcache / "voices-v1.0.bin"))
    parser.add_argument("--kokoro-voice", default="bm_george", help="Kokoro voice id (default bm_george)")
    parser.add_argument("--lang", default="en-gb", help="Kokoro phonemisation language (default en-gb)")
    parser.add_argument("--speed", type=float, default=0.85, help="speaking speed / Google speakingRate (default 0.85: measured but not sluggish)")
    parser.add_argument("--kokoro-pause", type=float, default=0.3, help="silence spliced between sentences, seconds (default 0.3)")
    parser.add_argument("--google-voice", default="en-GB-Chirp3-HD-Charon",
                        help="Google Chirp 3: HD voice (default en-GB-Chirp3-HD-Charon, male British)")
    parser.add_argument("--google-language", default="en-GB", help="Google TTS BCP-47 language code (default en-GB)")
    parser.add_argument("--google-key", default=os.environ.get("GOOGLE_TTS_API_KEY", ""),
                        help="Google Cloud API key (defaults to the GOOGLE_TTS_API_KEY env var)")
    parser.add_argument("--google-key-file", default=os.environ.get("GOOGLE_TTS_KEY_FILE", ""),
                        help="read the Google API key from this file instead (defaults to the GOOGLE_TTS_KEY_FILE env var)")
    parser.add_argument("--keep-work", action="store_true",
                        help="keep the work folder (frames, WAVs, intermediate MP4s) and print its path")
    parser.add_argument("--min-free-gb", type=float, default=30,
                        help="refuse to start with less free space than this where the work folder goes (default 30)")
    args = parser.parse_args()
    if args.tts == "google" and not args.google_key and args.google_key_file:
        args.google_key = Path(args.google_key_file).expanduser().read_text().strip()
    if args.tts == "google" and not args.google_key:
        parser.error("--tts google needs a key: set GOOGLE_TTS_API_KEY, --google-key, or --google-key-file")
    email = os.environ.get("SHIKARI_GUIDE_EMAIL", "admin@shikari.app")
    password = os.environ.get("SHIKARI_GUIDE_PASSWORD", "BigGameHunter")

    spec = yaml.safe_load(SCRIPT.read_text())
    scenes = [s for s in spec["scenes"] if not args.only or s["id"] in args.only]
    out = args.out.expanduser()
    out.mkdir(parents=True, exist_ok=True)
    sweep_stale_work()
    free_gb = shutil.disk_usage(tempfile.gettempdir()).free / 1e9
    if free_gb < args.min_free_gb:
        sys.exit(f"Only {free_gb:.0f} GB free in {tempfile.gettempdir()}: a full-length run needs ~20 GB "
                 f"for its frames. Free some space, or lower --min-free-gb for a short --only run.")
    work = Path(tempfile.mkdtemp(prefix=WORK_PREFIX))
    if args.keep_work:
        print(f"Work folder (kept): {work}")
    # SIGTERM (a killed background run) otherwise skips the finally and leaves the frames behind
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(143))
    try:
        return render(args, spec, scenes, out, work, email, password)
    finally:
        if args.keep_work:
            print(f"Work folder kept: {work}")
        else:
            shutil.rmtree(work, ignore_errors=True)


def sweep_stale_work(max_age=86400):
    """Remove work folders a run left behind (one killed outright) more than max_age seconds ago."""
    for d in Path(tempfile.gettempdir()).glob(f"{WORK_PREFIX}*"):
        try:
            if d.is_dir() and time.time() - d.stat().st_mtime > max_age:
                shutil.rmtree(d, ignore_errors=True)
                print(f"Removed a stale work folder: {d}")
        except OSError:
            pass


def render(args, spec, scenes, out, work, email, password):
    (work / "frames").mkdir()

    kokoro_helper = Path(__file__).with_name("kokoro_tts.py")
    print(f"Narration ({args.tts}):")
    for s in scenes:
        s["text"] = " ".join(s["narration"].split())
        # a blank line in the narration is a segment break: a longer pause than between sentences
        s["segments"] = [" ".join(seg.split()) for seg in s["narration"].split("\n") if seg.strip()]
        s["audio"] = work / f"{s['id']}.wav"
        say = spec.get("say", {})
        if args.tts == "google":
            say = {w: v for w, v in say.items() if w not in spec.get("ipa", {})}
        spoken_text = spoken(s["text"], say)
        if args.tts == "google":
            parts = []
            for j, seg in enumerate(s["segments"]):
                parts.append(work / f"{s['id']}.{j}.wav")
                speak_google(spoken(seg, say), parts[-1], args.google_voice, args.google_key,
                             language=args.google_language, speaking_rate=args.speed, ipa=spec.get("ipa"))
            s["seconds"], s["spans"] = join_segments(parts, s["audio"], SEGMENT_PAUSE)
        elif args.tts == "kokoro":
            s["seconds"] = speak_kokoro(args.kokoro_python, kokoro_helper, args.kokoro_model,
                                        args.kokoro_voices, args.kokoro_voice, spoken_text, s["audio"],
                                        lang=args.lang, speed=args.speed, pause=args.kokoro_pause)
        else:
            s["seconds"] = speak_piper(args.piper, args.voice, spoken_text, s["audio"],
                                       length_scale=args.length_scale, sentence_silence=args.sentence_silence,
                                       noise_w=args.noise_w, noise_scale=args.noise_scale)
        if "spans" not in s:
            # the local voices speak a scene in one go: estimate each segment's span by its length
            total_chars, t = sum(len(x) for x in s["segments"]), 0.0
            s["spans"] = []
            for x in s["segments"]:
                d = s["seconds"] * len(x) / total_chars
                s["spans"].append((t, d))
                t += d
        print(f"  {s['id']:<18} {s['seconds']:5.1f}s")
    # The outro is spoken over the end card, so "It's on GitHub" lands on the card that shows the link
    outro = " ".join(spec.get("outro", "").split())
    if outro:
        outro_audio = work / "outro.wav"
        if args.tts == "google":
            outro_seconds = speak_google(spoken(outro, say), outro_audio, args.google_voice, args.google_key,
                                         language=args.google_language, speaking_rate=args.speed,
                                         ipa=spec.get("ipa"))
        elif args.tts == "kokoro":
            outro_seconds = speak_kokoro(args.kokoro_python, kokoro_helper, args.kokoro_model,
                                         args.kokoro_voices, args.kokoro_voice, spoken(outro, say), outro_audio,
                                         lang=args.lang, speed=args.speed, pause=args.kokoro_pause)
        else:
            outro_seconds = speak_piper(args.piper, args.voice, spoken(outro, say), outro_audio,
                                        length_scale=args.length_scale, sentence_silence=args.sentence_silence,
                                        noise_w=args.noise_w, noise_scale=args.noise_scale)
        print(f"  {'outro':<18} {outro_seconds:5.1f}s")

    print("Recording:")
    with sync_playwright() as pw:
        browser = pw.chromium.launch()
        page = browser.new_page(viewport=VIEW, device_scale_factor=SCALE, color_scheme="light")
        page.goto(f"{args.base}/login")
        page.fill('input[name="email"]', email)
        page.fill('input[name="password"]', password)
        page.locator('button[type="submit"]').first.click()
        page.wait_for_load_state("networkidle")
        act(page, args.base, {"goto": "/"})
        rec = Recorder(page, work / "frames")
        rec.start()
        page.wait_for_timeout(500)
        t0 = time.time()
        for s in scenes:
            actions = list(s.get("actions", []))
            # A scene's opening page loads before its clock starts: a heavy page (Results) otherwise left
            # the previous scene on screen under the new narration. The load lands in the fade to black.
            if actions and "goto" in actions[0] and "at" not in actions[0] and "seg" not in actions[0]:
                try:
                    act(page, args.base, actions.pop(0))
                except Exception as e:
                    print(f"    {s['id']}: goto failed: {str(e).splitlines()[0]}")
                page.wait_for_timeout(300)
            s["start"] = time.time() - t0
            # `seg: n` pins an action to the start of the scene's nth segment (a blank line in the
            # narration), and `at` then places it within that segment (0..1). `at` alone is a fraction of
            # the whole scene; with neither, actions spread evenly. Order is kept: pins only retime.
            slot = s["seconds"] / max(1, len(actions))
            for i, a in enumerate(actions):
                at, seg = a.get("at"), a.get("seg")
                if seg is not None:
                    seg_start, seg_len = s["spans"][min(int(seg), len(s["spans"]) - 1)]
                    off = seg_start + (float(at) if at is not None else 0.0) * seg_len - LEAD
                elif at is not None:
                    off = max(0.0, min(1.0, float(at))) * s["seconds"] - LEAD
                else:
                    off = i * slot
                wait = t0 + s["start"] + max(0.0, off) - time.time()
                if wait > 0:
                    page.wait_for_timeout(wait * 1000)
                try:
                    act(page, args.base, {k: v for k, v in a.items() if k not in ("at", "seg")})
                except Exception as e:
                    print(f"    {s['id']}: {a} failed: {str(e).splitlines()[0]}")
            end = t0 + s["start"] + s["seconds"] + GAP
            # Keep the page moving so the screencast keeps sending frames to the end of the scene
            while time.time() < end:
                page.wait_for_timeout(min(250, max(1, (end - time.time()) * 1000)))
            s["end"] = time.time() - t0
            print(f"  {s['id']:<18} at {s['start']:6.1f}s")
        total = time.time() - t0
        rec.stop()
        browser.close()

    # Chrome sends a frame whenever the page changes; ffmpeg wants a steady 30 a second, each the latest
    # frame drawn by then
    frames = sorted((ts - t0, p) for ts, p in rec.frames)
    seq = work / "seq"
    seq.mkdir()
    k = 0
    for n in range(int(total * FPS)):
        while k + 1 < len(frames) and frames[k + 1][0] <= n / FPS:
            k += 1
        (seq / f"{n:06}.png").symlink_to(frames[k][1])

    logo = ROOT / "static" / "images" / "shikari" / "shikari-lockup.png"
    card(work / "title.png", [], logo)
    card(work / "end.png", [("github.com/cmdaltr/shikari", 55, (60, 68, 80)),
                            ("@cmdaltr", 41, (120, 128, 140))], logo)

    print("Encoding:")
    main_mp4 = work / "main.mp4"
    scale_pad = f"scale={W}:{H}:force_original_aspect_ratio=decrease,pad={W}:{H}:(ow-iw)/2:(oh-ih)/2"
    # Each scene is encoded as its own clip that fades in from black and out to black — one fade pair
    # per clip, which (unlike a chain of fades on one stream) actually dips to black at each join.
    # Concatenating them reproduces the full timeline, so the narration track still lines up. A scene
    # is now a self-contained section: reorder or drop scenes in script.yaml and every join stays clean.
    # Keep each scene's clip as its own file under <out>/scenes, named by order and scene id, so the
    # per-scene segments survive the render (the joined walkthrough is built from these). Cleared at the
    # start of each run so the directory always mirrors the scenes this render produced.
    scenes_dir = out / "scenes"
    scenes_dir.mkdir(exist_ok=True)
    for stale in scenes_dir.glob("scene_*.mp4"):
        stale.unlink()
    clips, concat_list = [], work / "clips.txt"
    # A clip runs from its scene's start to its end; the time between scenes (the next page loading
    # off the clock) is cut, and each scene's place in the video, `pos`, is the clips before it.
    pos = 0.0
    for i, s in enumerate(scenes):
        first = int(round(s["start"] * FPS))
        count = max(1, int(round(s["end"] * FPS)) - first)
        dur = count / FPS
        s["pos"] = pos
        pos += dur
        clip = scenes_dir / f"scene_{i:02}_{s['id']}.mp4"
        clips.append(clip)
        # Fade only at the edges of a same-page group: a scene marked `continues` joins the one before it
        # with no black between (a pause and a scroll, not a cut), so consecutive beats on one page read
        # as a single shot. A group fades in on its first scene and out on its last; scenes inside it get
        # neither fade and simply concatenate.
        starts_group = not s.get("continues")
        ends_group = i + 1 >= len(scenes) or not scenes[i + 1].get("continues")
        parts = [scale_pad]
        if starts_group:
            parts.append(f"fade=t=in:st=0:d={FADE}:color=black")
        if ends_group:
            parts.append(f"fade=t=out:st={max(0, dur - FADE):.3f}:d={FADE}:color=black")
        vf = ",".join(parts)
        subprocess.run(["ffmpeg", "-y", "-loglevel", "error", "-framerate", str(FPS),
                        "-start_number", str(first), "-i", str(seq / "%06d.png"), "-frames:v", str(count),
                        "-vf", vf, "-c:v", "libx264", "-preset", "slow", "-crf", "18", "-pix_fmt", "yuv420p",
                        str(clip)], check=True)
    # The clips are the last readers of the frames: drop them now rather than carry ~18 GB to the end
    if not args.keep_work:
        shutil.rmtree(seq, ignore_errors=True)
        shutil.rmtree(work / "frames", ignore_errors=True)
    concat_list.write_text("".join(f"file '{c}'\n" for c in clips))
    subprocess.run(["ffmpeg", "-y", "-loglevel", "error", "-f", "concat", "-safe", "0", "-i", str(concat_list),
                    "-c", "copy", str(main_mp4)], check=True)

    # Narration placed where each scene started, after the title card
    inputs, filters = [], []
    for i, s in enumerate(scenes):
        inputs += ["-i", str(s["audio"])]
        ms = int((TITLE_SECONDS + s["pos"]) * 1000)
        filters.append(f"[{i}:a]adelay={ms}|{ms},aresample=48000[a{i}]")
    end_seconds = END_SECONDS
    n_audio = len(scenes)
    if outro:
        inputs += ["-i", str(outro_audio)]
        ms = int((TITLE_SECONDS + pos + 0.8) * 1000)
        filters.append(f"[{n_audio}:a]adelay={ms}|{ms},aresample=48000[a{n_audio}]")
        n_audio += 1
        end_seconds = max(END_SECONDS, 0.8 + outro_seconds + 2.0)
    mix = "".join(f"[a{i}]" for i in range(n_audio))
    length = TITLE_SECONDS + pos + end_seconds
    filters.append(f"{mix}amix=inputs={n_audio}:normalize=0,apad,atrim=0:{length:.3f},loudnorm=I=-16:TP=-1.5[a]")
    narration = work / "narration.m4a"
    subprocess.run(["ffmpeg", "-y", "-loglevel", "error", *inputs, "-filter_complex", ";".join(filters),
                    "-map", "[a]", "-c:a", "aac", "-b:a", "192k", str(narration)], check=True)

    final = out / "shikari-walkthrough.mp4"
    subprocess.run(["ffmpeg", "-y", "-loglevel", "error",
                    "-loop", "1", "-t", str(TITLE_SECONDS), "-i", str(work / "title.png"),
                    "-i", str(main_mp4),
                    "-loop", "1", "-t", str(end_seconds), "-i", str(work / "end.png"),
                    "-i", str(narration),
                    "-filter_complex",
                    f"[0:v]fps=30,format=yuv420p,fade=t=out:st={TITLE_SECONDS - 0.5}:d=0.5[t];"
                    f"[1:v]fps=30,format=yuv420p[m];"
                    f"[2:v]fps=30,format=yuv420p,fade=t=in:st=0:d=0.5[e];"
                    "[t][m][e]concat=n=3:v=1:a=0[v]",
                    "-map", "[v]", "-map", "3:a", "-c:v", "libx264", "-preset", "slow", "-crf", "18",
                    "-c:a", "copy", "-movflags", "+faststart", "-shortest", str(final)], check=True)

    # Subtitles: at most two lines a cue (~42 chars a line), broken at sentence then word boundaries so
    # a long sentence becomes a run of short cues rather than a four-line wall, each timed by its share of
    # the scene's narration.
    def caption_cues(text, max_line=42):
        chunks = []
        for sentence in re.split(r"(?<=[.!?])\s+", text.strip()):
            line, lines = "", []
            for word in sentence.split():
                if line and len(line) + 1 + len(word) > max_line:
                    lines.append(line)
                    line = word
                else:
                    line = f"{line} {word}".strip()
                if len(lines) == 2:
                    chunks.append(lines)
                    lines = []
            if line:
                lines.append(line)
            if lines:
                chunks.append(lines)
        return ["\n".join(c) for c in chunks]

    def timed(text, start, seconds):
        chunks = caption_cues(text)
        weights = [len(c) for c in chunks]
        t = start
        for chunk, wgt in zip(chunks, weights):
            d = seconds * wgt / sum(weights)
            cues.append((t, t + d, chunk))
            t += d

    # Each segment's cues share out that segment's own time, so subtitles keep pace with the voice
    cues = []
    for s in scenes:
        for seg, (a, d) in zip(s["segments"], s["spans"]):
            timed(seg, TITLE_SECONDS + s["pos"] + a, d)
    if outro:
        timed(outro, TITLE_SECONDS + pos + 0.8, outro_seconds)
    (out / "shikari-walkthrough.srt").write_text("".join(
        f"{i}\n{srt_time(a)} --> {srt_time(b)}\n{text}\n\n" for i, (a, b, text) in enumerate(cues, 1)))

    chapters = [("0:00", "Introduction")] + [(chapter_time(TITLE_SECONDS + s["pos"]), s.get("chapter", s["id"])) for s in scenes[1:]]
    (out / "youtube.txt").write_text(
        "Shikari turns a threat group, a CVE, a threat report or a company's domain into detections for "
        "Google SecOps, Defender XDR, Splunk and Elastic, and shows you the coverage gaps you didn't "
        "know you had. Every detection is mapped to MITRE ATT&CK and tied back to its evidence. "
        "This walkthrough covers every page: what it's for, who uses it, and when it helps most.\n\n"
        "https://github.com/cmdaltr/shikari\n\nChapters\n" + "".join(f"{t} {name}\n" for t, name in chapters) +
        ("\nNarrated with Google Chirp 3: HD text-to-speech.\n" if args.tts == "google"
         else "\nNarrated with a local text-to-speech voice.\n"))
    print(f"Wrote {final} ({length / 60:.1f} min), its .srt and youtube.txt")
    print(f"Per-scene clips: {scenes_dir} ({len(clips)} clips)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
