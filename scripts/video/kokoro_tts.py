"""Synthesise one scene's narration with Kokoro (local, more natural than Piper).

make_video.py shells out to this under Kokoro's own venv (it has kokoro_onnx + soundfile, which the
project venv does not). Reads the text on stdin, writes a WAV to the path given.

Kokoro's own sentence_pause argument is a no-op in this version, so for an unhurried read with room to
breathe we synthesise each sentence separately and splice a fixed silence between them.

    kokoro-venv/bin/python kokoro_tts.py MODEL VOICES VOICE LANG SPEED PAUSE OUT.wav  <<< "text"
"""
import re
import sys

import numpy as np
import soundfile as sf
from kokoro_onnx import Kokoro

model, voices, voice, lang, speed, pause, out = sys.argv[1:8]
speed, pause = float(speed), float(pause)
text = sys.stdin.read().strip()

kokoro = Kokoro(model, voices)
sentences = [s for s in re.split(r"(?<=[.!?])\s+", text) if s.strip()]

chunks, sr = [], 24000
for i, sentence in enumerate(sentences):
    audio, sr = kokoro.create(sentence, voice=voice, speed=speed, lang=lang)
    chunks.append(audio)
    if pause > 0 and i < len(sentences) - 1:
        chunks.append(np.zeros(int(pause * sr), dtype=audio.dtype))

sf.write(out, np.concatenate(chunks) if chunks else np.zeros(1, dtype="float32"), sr)
