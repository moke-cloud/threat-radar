#!/usr/bin/env bash
# Start a local llama-server for Japanese translation (used by the daily
# workflow). Everything is pinned and checksum-verified: a mismatch aborts
# before anything is executed. The collector only talks to 127.0.0.1.
set -euo pipefail

LLAMA_TAG="b11740"
LLAMA_SHA256="6f67fd0a9aaeaad376b7cf4bf02a633dd7793cbe0f02cce2d773d4be724dce5a"
MODEL_REPO="unsloth/Qwen3-4B-Instruct-2507-GGUF"
MODEL_REV="a06e946bb6b655725eafa393f4a9745d460374c9"
MODEL_FILE="Qwen3-4B-Instruct-2507-Q4_K_M.gguf"
MODEL_SHA256="3605803b982cb64aead44f6c1b2ae36e3acdb41d8e46c8a94c6533bc4c67e597"

LLM_DIR="${LLM_DIR:-$HOME/llm}"
PORT="${LLM_PORT:-8080}"
mkdir -p "$LLM_DIR"
cd "$LLM_DIR"

fetch() { # url dest sha256
  if [ -f "$2" ] && echo "$3  $2" | sha256sum -c --quiet - 2>/dev/null; then
    return 0
  fi
  curl -fsSL --retry 3 -o "$2.part" "$1"
  echo "$3  $2.part" | sha256sum -c --quiet -
  mv "$2.part" "$2"
}

fetch "https://github.com/ggml-org/llama.cpp/releases/download/${LLAMA_TAG}/llama-${LLAMA_TAG}-bin-ubuntu-x64.tar.gz" \
  "llama-${LLAMA_TAG}.tar.gz" "$LLAMA_SHA256"
fetch "https://huggingface.co/${MODEL_REPO}/resolve/${MODEL_REV}/${MODEL_FILE}" "$MODEL_FILE" "$MODEL_SHA256"

rm -rf "llama-${LLAMA_TAG}"
tar xzf "llama-${LLAMA_TAG}.tar.gz"
BIN="$LLM_DIR/llama-${LLAMA_TAG}"

LD_LIBRARY_PATH="$BIN" nohup "$BIN/llama-server" \
  -m "$LLM_DIR/$MODEL_FILE" -t "$(nproc)" -c 8192 -np 1 \
  --host 127.0.0.1 --port "$PORT" > "$LLM_DIR/server.log" 2>&1 &

for _ in $(seq 1 90); do
  if curl -fs "http://127.0.0.1:${PORT}/health" | grep -q ok; then
    echo "llama-server ready on 127.0.0.1:${PORT} ($(nproc) threads)"
    exit 0
  fi
  sleep 2
done
echo "llama-server did not become ready" >&2
tail -n 30 "$LLM_DIR/server.log" >&2 || true
exit 1
