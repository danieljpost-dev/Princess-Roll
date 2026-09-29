#!/usr/bin/env bash
# Serve docs/ exactly as GitHub Pages would. Python's http.server is used
# because it resolves .wasm to application/wasm, which WebAssembly's streaming
# loader requires.
set -euo pipefail
cd "$(dirname "$0")"

PORT="${1:-8080}"
BIND="${2:-127.0.0.1}"

if [ ! -d docs ]; then
  echo "docs/ does not exist yet. Run ./build.sh first." >&2
  exit 1
fi

echo "Princess-Roll on http://${BIND}:${PORT}"
echo
echo "Open two tabs to test the pair: one enters Daddy's code, the other"
echo "Princess's. Pass the invite and reply codes between them by hand."
echo
echo "To reach it from another device on your network:  ./serve.sh ${PORT} 0.0.0.0"
echo

exec python3 -m http.server "$PORT" --bind "$BIND" --directory docs
