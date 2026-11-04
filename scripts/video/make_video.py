"""
Make the Shikari walkthrough video from scripts/video/script.yaml: a narrated screen recording with
subtitles and YouTube chapters.

Each scene's narration is spoken by Piper (a local neural voice: no account, no API, nothing leaves the
machine), the browser plays the scene's actions across that time, and ffmpeg joins it all up. Run it
against a throwaway instance with sample data, never a real one:

    python scripts/video/make_video.py --base http://127.0.0.1:8010 --out ~/Movies/Shikari

Needs ffmpeg, Playwright's Chromium, and Piper with a voice (--piper, --voice); a voice is an .onnx
file from https://huggingface.co/rhasspy/piper-voices. Writes shikari-walkthrough.mp4, its .srt and
youtube.txt (a description with chapters).
"""
import argparse
import base64
import os
import re
import subprocess
import sys
import tempfile
import time
import wave
from pathlib import Path

import yaml
from PIL import Image, ImageDraw, ImageFont
from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = Path(__file__).with_name("script.yaml")
W, H = 1920, 1080
# The browser window: a full 1920x1080 CSS viewport so each page sits in frame at desktop width without
# feeling cramped or zoomed in. Captured 1:1 as lossless PNG (see Recorder) — JPEG frames put visible
# grain/mosquito noise around text, PNG does not.
VIEW, SCALE = {"width": 1920, "height": 1080}, 1.0
# Each scene fades in from black and out to black, so a scene is a self-contained section: add,
# remove or reorder scenes in script.yaml and every join stays clean. GAP is the quiet tail after
# a scene's narration, long enough to hold black between sections; FADE is each dip's length.
TITLE_SECONDS, END_SECONDS, GAP, FADE, FPS = 4.0, 5.0, 1.2, 0.5, 30

# A pulsing outline that follows an element as the page scrolls, over a dimmed page
HIGHLIGHT = r"""
(el) => {
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
  const top = pinned ? nav.getBoundingClientRect().bottom + 6 : 6;
  el.style.scrollMarginTop = top + 14 + 'px';
  el.scrollIntoView({ behavior: 'smooth', block: el.getBoundingClientRect().height > (innerHeight - top) * 0.82 ? 'start' : 'center' });
  cancelAnimationFrame(window.__vhlRaf);
  const follow = () => {
    const r = el.getBoundingClientRect(), pad = 8, y = Math.max(r.top - pad, top);
    const bottom = Math.min(r.bottom + pad, innerHeight - 6);
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


TAGLINE = "Automated Multi-vendor Threat Hunting and Detection Suite"
CARD_BG = (234, 236, 238)  # light, so the black-text / gold-A lockup reads
# The lockup is [bateleur]  SHIKARI; the tagline and footer sit under the SHIKARI wordmark only, sized
# to fit its width and anchored to its baseline. Measured from the asset's alpha (eagle ends ~0.30):
# wordmark runs x 0.31..0.92 of the image width, and its bottom (baseline) is y 0.63 of the height.
WORDMARK_L, WORDMARK_R, WORDMARK_BOTTOM = 0.314, 0.920, 0.631


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
    # The brand lockup (bateleur + SHIKARI, black text / gold A) over a light ground, the tagline
    # tracked out beneath it, then any extra lines (repo + handle on the end card). The whole stack is
    # vertically centred so title and end sit the same on screen.
    img = Image.new("RGB", (W, H), CARD_BG)
    d = ImageDraw.Draw(img)
    # Scale the lockup so its *visible* content (the mark, ignoring the transparent padding around it)
    # fills the frame width bar a small margin, and centre that content — the widest a 3:1 mark goes
    # without running the eagle off the left or the final letter off the right.
    src = Image.open(logo).convert("RGBA")
    l, _u, r, _lo = src.split()[-1].getbbox()
    target_cw = 1656  # visible mark width, centred in the frame
    scale = target_cw / (r - l)
    banner = src.resize((round(src.width * scale), round(src.height * scale)))
    bw, bh = banner.size
    bx = round(W / 2 - ((l + r) / 2 / src.width) * bw)  # centre the visible content, not the padding
    by = (H - bh) // 2
    wm_l, wm_r = bx + WORDMARK_L * bw, bx + WORDMARK_R * bw
    cx = int((wm_l + wm_r) / 2)   # centre under the SHIKARI wordmark
    avail = (wm_r - wm_l) * 0.99  # roughly the wordmark's width; the footer fits within it
    tag = TAGLINE.upper()

    def fit(s, size, bold, cap=avail):
        f = _font(size, bold)
        while size > 10 and _tracked_width(d, s, f, 2 if bold else 0) > cap:
            size -= 1
            f = _font(size, bold)
        return f, size

    img.paste(banner, (bx, by), banner)
    # Tagline just beneath the wordmark baseline, almost underlining SHIKARI. Pinned to a point size
    # (near the wordmark's own width) rather than auto-fit, and only shrunk if it would hit the frame.
    tag_font, tag_size = fit(tag, 29.2, True, W - 80)
    y = by + WORDMARK_BOTTOM * bh + 20
    _draw_tracked(d, cx, y, tag, tag_font, (96, 104, 117), 2)
    y += tag_size + 40
    for line, size, colour in lines:
        f, s = fit(line, size, False)
        _draw_tracked(d, cx, y, line, f, colour, 0)
        y += s + 28
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
        page.goto(base + arg, wait_until="domcontentloaded")
        try:
            page.wait_for_load_state("networkidle", timeout=1500)
        except Exception:
            pass
        page.evaluate("() => { document.querySelectorAll('#ask-shikari-btn').forEach(e => e.remove()); }")
    elif kind == "click":
        page.locator(arg).first.click(timeout=5000)
    elif kind == "type":
        page.locator(arg[0]).first.click()
        page.locator(arg[0]).first.press_sequentially(arg[1], delay=85)
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


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--base", default="http://127.0.0.1:8010")
    parser.add_argument("--out", type=Path, default=Path.home() / "Movies" / "Shikari")
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
    parser.add_argument("--tts", choices=["kokoro", "piper"], default="kokoro",
                        help="text-to-speech backend (default kokoro: more natural, local)")
    kcache = Path.home() / ".cache/shikari/kokoro"
    parser.add_argument("--kokoro-python", default=str(kcache / "venv/bin/python"))
    parser.add_argument("--kokoro-model", default=str(kcache / "kokoro-v1.0.onnx"))
    parser.add_argument("--kokoro-voices", default=str(kcache / "voices-v1.0.bin"))
    parser.add_argument("--kokoro-voice", default="bm_george", help="Kokoro voice id (default bm_george)")
    parser.add_argument("--lang", default="en-gb", help="Kokoro phonemisation language (default en-gb)")
    parser.add_argument("--speed", type=float, default=0.9, help="Kokoro speaking speed (default 0.9: measured but not sluggish)")
    parser.add_argument("--kokoro-pause", type=float, default=0.3, help="silence spliced between sentences, seconds (default 0.3)")
    args = parser.parse_args()
    email = os.environ.get("SHIKARI_GUIDE_EMAIL", "admin@shikari.app")
    password = os.environ.get("SHIKARI_GUIDE_PASSWORD", "BigGameHunter")

    spec = yaml.safe_load(SCRIPT.read_text())
    scenes = [s for s in spec["scenes"] if not args.only or s["id"] in args.only]
    out = args.out.expanduser()
    out.mkdir(parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix="shikari-video-"))
    (work / "frames").mkdir()

    kokoro_helper = Path(__file__).with_name("kokoro_tts.py")
    print(f"Narration ({args.tts}):")
    for s in scenes:
        s["text"] = " ".join(s["narration"].split())
        s["audio"] = work / f"{s['id']}.wav"
        spoken_text = spoken(s["text"], spec.get("say", {}))
        if args.tts == "kokoro":
            s["seconds"] = speak_kokoro(args.kokoro_python, kokoro_helper, args.kokoro_model,
                                        args.kokoro_voices, args.kokoro_voice, spoken_text, s["audio"],
                                        lang=args.lang, speed=args.speed, pause=args.kokoro_pause)
        else:
            s["seconds"] = speak_piper(args.piper, args.voice, spoken_text, s["audio"],
                                       length_scale=args.length_scale, sentence_silence=args.sentence_silence,
                                       noise_w=args.noise_w, noise_scale=args.noise_scale)
        print(f"  {s['id']:<18} {s['seconds']:5.1f}s")

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
            s["start"] = time.time() - t0
            actions = s.get("actions", [])
            # Each action fires at `at` (a 0..1 fraction of the scene) when given, so a highlight lands
            # on the beat the narration describes it; otherwise it keeps the old even split across the
            # scene. Authored order is preserved — `at` only retimes, it doesn't reorder.
            slot = s["seconds"] / max(1, len(actions))
            for i, a in enumerate(actions):
                at = a.get("at")
                off = max(0.0, min(1.0, float(at))) * s["seconds"] if at is not None else i * slot
                wait = t0 + s["start"] + off - time.time()
                if wait > 0:
                    page.wait_for_timeout(wait * 1000)
                try:
                    act(page, args.base, {k: v for k, v in a.items() if k != "at"})
                except Exception as e:
                    print(f"    {s['id']}: {a} failed: {str(e).splitlines()[0]}")
            end = t0 + s["start"] + s["seconds"] + GAP
            # Keep the page moving so the screencast keeps sending frames to the end of the scene
            while time.time() < end:
                page.wait_for_timeout(min(250, max(1, (end - time.time()) * 1000)))
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
    clips, concat_list = [], work / "clips.txt"
    for i, s in enumerate(scenes):
        nxt_start = scenes[i + 1]["start"] if i + 1 < len(scenes) else total
        first = int(round(s["start"] * FPS))
        count = max(1, int(round(nxt_start * FPS)) - first)
        dur = count / FPS
        clip = work / f"clip_{i:03}.mp4"
        clips.append(clip)
        vf = f"{scale_pad},fade=t=in:st=0:d={FADE}:color=black,fade=t=out:st={max(0, dur - FADE):.3f}:d={FADE}:color=black"
        subprocess.run(["ffmpeg", "-y", "-loglevel", "error", "-framerate", str(FPS),
                        "-start_number", str(first), "-i", str(seq / "%06d.png"), "-frames:v", str(count),
                        "-vf", vf, "-c:v", "libx264", "-preset", "slow", "-crf", "18", "-pix_fmt", "yuv420p",
                        str(clip)], check=True)
    concat_list.write_text("".join(f"file '{c}'\n" for c in clips))
    subprocess.run(["ffmpeg", "-y", "-loglevel", "error", "-f", "concat", "-safe", "0", "-i", str(concat_list),
                    "-c", "copy", str(main_mp4)], check=True)

    # Narration placed where each scene started, after the title card
    inputs, filters = [], []
    for i, s in enumerate(scenes):
        inputs += ["-i", str(s["audio"])]
        ms = int((TITLE_SECONDS + s["start"]) * 1000)
        filters.append(f"[{i}:a]adelay={ms}|{ms},aresample=48000[a{i}]")
    mix = "".join(f"[a{i}]" for i in range(len(scenes)))
    length = TITLE_SECONDS + total + END_SECONDS
    filters.append(f"{mix}amix=inputs={len(scenes)}:normalize=0,apad,atrim=0:{length:.3f},loudnorm=I=-16:TP=-1.5[a]")
    narration = work / "narration.m4a"
    subprocess.run(["ffmpeg", "-y", "-loglevel", "error", *inputs, "-filter_complex", ";".join(filters),
                    "-map", "[a]", "-c:a", "aac", "-b:a", "192k", str(narration)], check=True)

    final = out / "shikari-walkthrough.mp4"
    subprocess.run(["ffmpeg", "-y", "-loglevel", "error",
                    "-loop", "1", "-t", str(TITLE_SECONDS), "-i", str(work / "title.png"),
                    "-i", str(main_mp4),
                    "-loop", "1", "-t", str(END_SECONDS), "-i", str(work / "end.png"),
                    "-i", str(narration),
                    "-filter_complex",
                    f"[0:v]fps=30,format=yuv420p,fade=t=out:st={TITLE_SECONDS - 0.5}:d=0.5[t];"
                    f"[1:v]fps=30,format=yuv420p[m];"
                    f"[2:v]fps=30,format=yuv420p,fade=t=in:st=0:d=0.5[e];"
                    "[t][m][e]concat=n=3:v=1:a=0[v]",
                    "-map", "[v]", "-map", "3:a", "-c:v", "libx264", "-preset", "slow", "-crf", "18",
                    "-c:a", "copy", "-movflags", "+faststart", "-shortest", str(final)], check=True)

    # Subtitles: each scene's sentences, timed by their share of its narration
    cues = []
    for s in scenes:
        sentences = re.split(r"(?<=[.!?])\s+", s["text"])
        weights = [len(x) for x in sentences]
        t = TITLE_SECONDS + s["start"]
        for sentence, wgt in zip(sentences, weights):
            d = s["seconds"] * wgt / sum(weights)
            cues.append((t, t + d, sentence))
            t += d
    (out / "shikari-walkthrough.srt").write_text("".join(
        f"{i}\n{srt_time(a)} --> {srt_time(b)}\n{text}\n\n" for i, (a, b, text) in enumerate(cues, 1)))

    chapters = [("0:00", "Introduction")] + [(chapter_time(TITLE_SECONDS + s["start"]), s.get("chapter", s["id"])) for s in scenes[1:]]
    (out / "youtube.txt").write_text(
        "Shikari turns MITRE ATT&CK into detections for Google SecOps, Defender XDR, Splunk and Elastic. "
        "This walkthrough covers every page: what it's for, who uses it, and when it helps most.\n\n"
        "https://github.com/cmdaltr/shikari\n\nChapters\n" + "".join(f"{t} {name}\n" for t, name in chapters) +
        "\nNarrated with a local text-to-speech voice.\n")
    print(f"Wrote {final} ({length / 60:.1f} min), its .srt and youtube.txt")
    return 0


if __name__ == "__main__":
    sys.exit(main())
