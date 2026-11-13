# The Guide Pictures and the Walkthrough Video

Both are made by driving a browser through a running Shikari, so they show the real pages and need remaking when the pages change. Make them from a throwaway instance, never your own: the pictures are committed, and the video is published.

## A Throwaway Instance

An empty home with Shikari's reference data, its own database (the default admin), one real hunt saved to the Library, and the sample company:

```bash
H=/tmp/shikari-guide && mkdir -p $H/shikari/data/cache
git ls-files data | while read f; do mkdir -p "$H/$(dirname "$f")"; cp "$f" "$H/$f"; done
cp shikari/data/cache/enterprise-attack.json* $H/shikari/data/cache/
cp data/mitre_procedures.csv data/mitre_procedures.meta.json $H/data/ && touch $H/data/mitre_procedures.csv
(cd $H && SHIKARI_HOME=$H PYTHONPATH=$OLDPWD $OLDPWD/.venv/bin/python -m shikari.cli.test_data populate)
(cd $H && SHIKARI_HOME=$H $OLDPWD/.venv/bin/python -m uvicorn shikari.app:app --app-dir $OLDPWD --port 8010)
```

Then log in at `http://127.0.0.1:8010` as the default admin, hunt APT29 (answer No to AI), tick the Validation checklist and **Save to Library**.

For the video, two more things so those pages show real data:

- **Coverage:** copy your reference queries in (`cp -R bespoke/llm_references $H/bespoke/`) and restart the server. The page only shows counts, technique IDs and platforms, never the queries' index names.
- **Detections as code:** export SampleSpider from Detections as code, change one of its queries in `$H/data/groups/` (as a regenerate would), and export it again, so History has two commits to compare.

## The Guide's Pictures

`scripts/guide/pages.yaml` holds each page's sections and what the guide says about them; `scripts/guide/capture.py` photographs each page and finds where each section is:

```bash
.venv/bin/python scripts/guide/capture.py --base http://127.0.0.1:8010            # every page
.venv/bin/python scripts/guide/capture.py --only results library                   # just these
```

It writes `static/guide/img/*.jpg` and `static/guide/guide.json`, and writes nothing if any selector matches nothing, so a changed page can't leave a highlight in the wrong place. The tips are `static/guide/tips.json`, edited by hand.

## The Video

`scripts/video/script.yaml` is the narration and what happens on screen, scene by scene, with each scene's YouTube chapter title. `scripts/video/make_video.py` speaks each scene (default: [Kokoro](https://github.com/hexgrad/kokoro), a local neural voice), plays the scene's actions in a browser over that time, and joins it all with ffmpeg.

Each scene is its own section: it fades in from black and out to black, so you add a new feature by adding a scene to `script.yaml` (its own `id`, `chapter`, `narration` and `actions`), drop one, or reorder them, and every join stays clean. A scene begins on its own page (`goto: <path>`) so it doesn't depend on the scene before it.

```bash
.venv/bin/python scripts/video/make_video.py --base http://127.0.0.1:8010 --out ~/Desktop/Staging/shikari/video
```

It writes `shikari-walkthrough.mp4` (1080p), `shikari-walkthrough.srt` (upload it to YouTube as the subtitles) and `youtube.txt` (a description with chapter times). `--only intro hunt` makes a quick draft of some scenes. The `say` list at the top of the script is how the voice pronounces what the subtitles spell (ATT&CK as "Attack", SIEM as "sim"); for the Google voice, words in the `ipa` list are pinned by their phonemes instead (Chirp read the respelling "shih-car-ee" as "chicory"). A blank line in a scene's narration starts a new segment, spoken after a short pause; `seg: n` pins an action to segment n, and the `outro` is spoken over the end card.

### Voices

Three `--tts` backends, all behind the same timing and subtitle logic:

- `--tts kokoro` (default) — local, free, no account. `--kokoro-voice` takes any of the 54 Kokoro voice ids; the British ones are `bm_george` (default), `bm_daniel`, `bm_fable`, `bm_lewis`, `bf_emma`, `bf_alice`, `bf_isabella`, `bf_lily`. `--speed` sets the pace.
- `--tts piper` — local, free. `--piper` and `--voice` point at the Piper binary and an `.onnx` voice from [piper-voices](https://huggingface.co/rhasspy/piper-voices).
- `--tts google` — Google Cloud Chirp 3: HD, the highest quality but a cloud call: it sends the narration to Google and needs an API key (`GOOGLE_TTS_API_KEY`, `--google-key`, or `--google-key-file`). At ~7k characters a render it stays inside the free monthly tier, with commercial use permitted. `--google-voice` defaults to `en-GB-Chirp3-HD-Charon`; `--speed` maps to the speaking rate. Kokoro stays the committed default so the repo always builds a video with no account.

```bash
GOOGLE_TTS_API_KEY=... .venv/bin/python scripts/video/make_video.py \
  --base http://127.0.0.1:8010 --out ~/Desktop/Staging/shikari/video \
  --tts google --google-voice en-GB-Chirp3-HD-Charon
```
