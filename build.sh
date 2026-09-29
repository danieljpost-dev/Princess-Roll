#!/usr/bin/env bash
# Build the page into docs/. No test code: the `tests` feature stays off.
set -euo pipefail
cd "$(dirname "$0")"

OUT=docs
CRATE=princess_roll
WASM="target/wasm32-unknown-unknown/release/${CRATE}.wasm"

echo "==> compiling to wasm32 (release, default features)"
cargo build --release --lib --target wasm32-unknown-unknown

echo "==> generating bindings"
rm -rf "$OUT"
mkdir -p "$OUT"
wasm-bindgen --target web --no-typescript --out-dir "$OUT" "$WASM"

echo "==> assembling site"
cp web/index.html web/style.css "$OUT"/
cp web/CNAME "$OUT"/
# Stops GitHub Pages running the output through Jekyll, which would drop files
# whose names begin with an underscore.
touch "$OUT/.nojekyll"

if [ -f web/pairing.bin ]; then
  cp web/pairing.bin "$OUT"/
else
  echo
  echo "!! web/pairing.bin is missing, so the page cannot unlock."
  echo "!! Run: cargo run --bin setup"
  echo
fi

echo
echo "built $OUT/ ($(du -sh "$OUT" | cut -f1))"
ls -lh "$OUT" | tail -n +2 | awk '{printf "   %-28s %s\n", $9, $5}'
echo
echo "serve it with ./serve.sh"
