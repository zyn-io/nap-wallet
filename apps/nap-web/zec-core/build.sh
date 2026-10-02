#!/bin/sh
# Builds the Zcash wallet core into ../src/zec-pkg for the page to import.
# Needs the wasm32 target, wasm-bindgen-cli 0.2.128 and a clang that targets
# wasm32 (Apple's does not; Homebrew's llvm does) for the C in secp256k1/ring.
set -e
cd "$(dirname "$0")"
LLVM=${LLVM:-$(brew --prefix llvm 2>/dev/null)/bin}
export CC_wasm32_unknown_unknown="$LLVM/clang" AR_wasm32_unknown_unknown="$LLVM/llvm-ar"
cargo build --release --target wasm32-unknown-unknown
wasm-bindgen --target web --out-dir ../src/zec-pkg --no-typescript \
  target/wasm32-unknown-unknown/release/nap_zec.wasm
ls -l ../src/zec-pkg
