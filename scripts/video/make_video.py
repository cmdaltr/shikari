"""
Make the Archer walkthrough video from scripts/video/script.yaml: a narrated screen recording with
subtitles and YouTube chapters.

Each scene's narration is spoken by Piper (a local neural voice: no account, no API, nothing leaves the
machine), the browser plays the scene's actions across that time, and ffmpeg joins it all up. Run it
against a throwaway instance with sample data, never a real one:

    python scripts/video/make_video.py --base http://127.0.0.1:8010 --out ~/Movies/Archer

Needs ffmpeg, Playwright's Chromium, and Piper with a voice (--piper, --voice); a voice is an .onnx
file from https://huggingface.co/rhasspy/piper-voices. Writes archer-walkthrough.mp4, its .srt and
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
# The browser window: 1280x720 drawn at 1.5x, so the frames are 1080p with text large enough to read
VIEW, SCALE = {"width": 1280, "height": 720}, 1.5
TITLE_SECONDS, END_SECONDS, GAP, FPS = 4.0, 5.0, 0.7, 30

# A pulsing outline that follows an element as the page scrolls, over a dimmed page
HIGHLIGHT = r"""
(el) => {
  if (!document.getElementById('vhl-style')) {
    const st = document.createElement('style'); st.id = 'vhl-style';
    st.textContent = `#vhl { position: fixed; z-index: 2147483000; pointer-events: none; border: 4px solid #C53030;
      border-radius: 10px; box-shadow: 0 0 0 9999px rgba(10,14,20,.38); transition: all .45s ease; animation: vhl 1.6s ease-in-out infinite; }
      @keyframes vhl { 0%,100% { outline: 0 solid rgba(197,48,48,.6); outline-offset: 0 } 50% { outline: 10px solid rgba(197,48,48,0); outline-offset: 8px } }`;
    document.head.append(st);
  }
  let box = document.getElementById('vhl');
  if (!box) { box = document.createElement('div'); box.id = 'vhl'; document.body.append(box); }
  // Clear of the fixed nav bar
  const nav = document.querySelector('.global-nav-controls');
  const pinned = nav && ['fixed', 'sticky'].includes(getComputedStyle(nav).position);
  const top = pinned ? nav.getBoundingClientRect().bottom + 6 : 6;
  el.style.scrollMarginTop = top + 14 + 'px';
  el.scrollIntoView({ behavior: 'smooth', block: el.getBoundingClientRect().height > (innerHeight - top) * 0.8 ? 'start' : 'center' });
  cancelAnimationFrame(window.__vhlRaf);
  const follow = () => {
    const r = el.getBoundingClientRect(), pad = 8, y = Math.max(r.top - pad, top);
    Object.assign(box.style, { left: r.left - pad + 'px', top: y + 'px', width: r.width + 2 * pad + 'px',
      height: Math.max(0, Math.min(r.bottom + pad, innerHeight - 6) - y) + 'px' });
    window.__vhlRaf = requestAnimationFrame(follow);
  };
  follow();
}
"""


def spoken(text, say):
    for written in sorted(say, key=len, reverse=True):
        text = re.sub(rf"(?<![\w&]){re.escape(written)}(?![\w&])", say[written], text)
    return text


def speak(piper, voice, text, out):
    subprocess.run([piper, "-m", voice, "-f", str(out)], input=text.encode(), check=True, capture_output=True)
    with wave.open(str(out)) as w:
        return w.getnframes() / w.getframerate()


def card(path, lines, logo):
    img = Image.new("RGB", (W, H), (13, 17, 23))
    d = ImageDraw.Draw(img)
    banner = Image.open(logo).convert("RGBA")
    banner = banner.resize((int(banner.width * 300 / banner.height), 300))
    img.paste(banner, ((W - banner.width) // 2, 250), banner)
    y = 620
    for text, size, colour in lines:
        try:
            font = ImageFont.truetype("/System/Library/Fonts/Supplemental/Arial.ttf", size)
        except OSError:
            font = ImageFont.load_default()
        w = d.textlength(text, font=font)
        d.text(((W - w) / 2, y), text, font=font, fill=colour)
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
        path = self.folder / f"{n:06}.jpg"
        path.write_bytes(base64.b64decode(e["data"]))
        # Chrome's own time for the frame: frames can reach us late, and timing them on arrival drifts
        self.frames.append((e["metadata"].get("timestamp") or time.time(), path))
        self.cdp.send("Page.screencastFrameAck", {"sessionId": e["sessionId"]})

    def start(self):
        self.cdp.send("Page.startScreencast", {"format": "jpeg", "quality": 92, "maxWidth": W, "maxHeight": H, "everyNthFrame": 1})

    def stop(self):
        self.cdp.send("Page.stopScreencast")


def act(page, base, action):
    kind, arg = next(iter(action.items()))
    if kind == "goto":
        page.goto(base + arg)
        try:
            page.wait_for_load_state("networkidle", timeout=15000)
        except Exception:
            pass
        page.evaluate("() => { document.querySelectorAll('#ask-archer-btn').forEach(e => e.remove()); }")
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
        page.evaluate("id => ArcherGuide.open(id)", arg)


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--base", default="http://127.0.0.1:8010")
    parser.add_argument("--out", type=Path, default=Path.home() / "Movies" / "Archer")
    parser.add_argument("--piper", default=str(Path.home() / ".cache/archer/piper/venv/bin/piper"))
    parser.add_argument("--voice", default=str(Path.home() / ".cache/archer/piper/voices/en_GB-cori-high.onnx"))
    parser.add_argument("--only", nargs="*", help="scene ids to include (a quick draft)")
    args = parser.parse_args()
    email = os.environ.get("ARCHER_GUIDE_EMAIL", "admin@archer.app")
    password = os.environ.get("ARCHER_GUIDE_PASSWORD", "£missary_0f_the_G0rg0nite$")

    spec = yaml.safe_load(SCRIPT.read_text())
    scenes = [s for s in spec["scenes"] if not args.only or s["id"] in args.only]
    out = args.out.expanduser()
    out.mkdir(parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix="archer-video-"))
    (work / "frames").mkdir()

    print("Narration:")
    for s in scenes:
        s["text"] = " ".join(s["narration"].split())
        s["audio"] = work / f"{s['id']}.wav"
        s["seconds"] = speak(args.piper, args.voice, spoken(s["text"], spec.get("say", {})), s["audio"])
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
            slot = s["seconds"] / max(1, len(actions))
            for i, a in enumerate(actions):
                wait = t0 + s["start"] + i * slot - time.time()
                if wait > 0:
                    page.wait_for_timeout(wait * 1000)
                try:
                    act(page, args.base, a)
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
        (seq / f"{n:06}.jpg").symlink_to(frames[k][1])

    logo = ROOT / "static" / "images" / "archer_banner.png"
    card(work / "title.png", [("Threat hunting and detection engineering, walked through", 54, (240, 240, 240)),
                              ("Every page, who it's for, and when it helps", 38, (170, 176, 186))], logo)
    card(work / "end.png", [("github.com/cmdaltr/archer", 54, (240, 240, 240)),
                            ("@cmdaltr", 38, (170, 176, 186))], logo)

    print("Encoding:")
    main_mp4 = work / "main.mp4"
    subprocess.run(["ffmpeg", "-y", "-loglevel", "error", "-framerate", str(FPS), "-i", str(seq / "%06d.jpg"),
                    "-vf", f"scale={W}:{H}:force_original_aspect_ratio=decrease,pad={W}:{H}:(ow-iw)/2:(oh-ih)/2",
                    "-c:v", "libx264", "-preset", "slow", "-crf", "18", "-pix_fmt", "yuv420p", str(main_mp4)], check=True)

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

    final = out / "archer-walkthrough.mp4"
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
    (out / "archer-walkthrough.srt").write_text("".join(
        f"{i}\n{srt_time(a)} --> {srt_time(b)}\n{text}\n\n" for i, (a, b, text) in enumerate(cues, 1)))

    chapters = [("0:00", "Introduction")] + [(chapter_time(TITLE_SECONDS + s["start"]), s.get("chapter", s["id"])) for s in scenes[1:]]
    (out / "youtube.txt").write_text(
        "Archer turns MITRE ATT&CK into detections for Google SecOps, Defender XDR, Splunk and Elastic. "
        "This walkthrough covers every page: what it's for, who uses it, and when it helps most.\n\n"
        "https://github.com/cmdaltr/archer\n\nChapters\n" + "".join(f"{t} {name}\n" for t, name in chapters) +
        "\nNarrated with Piper, a local text-to-speech voice.\n")
    print(f"Wrote {final} ({length / 60:.1f} min), its .srt and youtube.txt")
    return 0


if __name__ == "__main__":
    sys.exit(main())
