#!/bin/sh
# Builds the pool core into ../src/pool-pkg for the page to import. Pure Rust:
# no C toolchain needed (unlike zec-core). Needs the wasm32 target and
# wasm-bindgen-cli 0.2.128.
set -e
cd "$(dirname "$0")"
cargo build --release --target wasm32-unknown-unknown
wasm-bindgen --target web --out-dir ../src/pool-pkg --no-typescript \
  target/wasm32-unknown-unknown/release/nap_pool.wasm
ls -l ../src/pool-pkg
