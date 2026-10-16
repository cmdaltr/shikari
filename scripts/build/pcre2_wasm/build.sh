#!/usr/bin/env bash
# Builds static/vendor/pcre2/ (pcre2.js + pcre2.wasm) for the Regex page from the official
# PCRE2 release, checked against the SHA-256 GitHub publishes for it.
#
#   source /path/to/emsdk/emsdk_env.sh     # Emscripten (https://emscripten.org)
#   scripts/build/pcre2_wasm/build.sh
set -euo pipefail

VERSION=10.49
SHA256=929f0b20e62879252a15886b06c89f1edef61a363cbd5826fb041080a5e557ae
URL="https://github.com/PCRE2Project/pcre2/releases/download/pcre2-${VERSION}/pcre2-${VERSION}.tar.gz"

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../../.." && pwd)"
OUT="$ROOT/static/vendor/pcre2"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

command -v emcc >/dev/null || { echo "emcc not found: source emsdk_env.sh first" >&2; exit 1; }

curl -fsSL "$URL" -o "$WORK/pcre2.tar.gz"
echo "$SHA256  $WORK/pcre2.tar.gz" | shasum -a 256 -c -
tar xzf "$WORK/pcre2.tar.gz" -C "$WORK"
SRC="$WORK/pcre2-${VERSION}"

# 8-bit library only, no JIT (WebAssembly can't generate code), Unicode on
emcmake cmake -S "$SRC" -B "$WORK/build" -DCMAKE_BUILD_TYPE=Release \
  -DPCRE2_BUILD_PCRE2_8=ON -DPCRE2_BUILD_PCRE2_16=OFF -DPCRE2_BUILD_PCRE2_32=OFF \
  -DPCRE2_SUPPORT_JIT=OFF -DPCRE2_SUPPORT_UNICODE=ON -DPCRE2_BUILD_PCRE2GREP=OFF \
  -DPCRE2_BUILD_TESTS=OFF -DBUILD_SHARED_LIBS=OFF >/dev/null
cmake --build "$WORK/build" --target pcre2-8-static -j 4 >/dev/null

mkdir -p "$OUT"
emcc -O2 "$HERE/glue.c" -I "$WORK/build/interface" -I "$WORK/build" "$WORK/build/libpcre2-8.a" \
  -o "$OUT/pcre2.js" \
  -sMODULARIZE=1 -sEXPORT_NAME=createPcre2 -sENVIRONMENT=worker -sALLOW_MEMORY_GROWTH=1 \
  -sEXPORTED_FUNCTIONS=_malloc,_free -sEXPORTED_RUNTIME_METHODS=cwrap,HEAPU8 -sFILESYSTEM=0
cp "$SRC/LICENCE.md" "$OUT/LICENCE.md" 2>/dev/null || cp "$SRC/LICENCE" "$OUT/LICENCE"
echo "PCRE2 ${VERSION}: $(ls -l "$OUT" | awk 'NR>1 {print $9, $5}' | tr '\n' ' ')"
