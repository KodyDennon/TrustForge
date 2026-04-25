#!/usr/bin/env bash
# Build TrustForge core as wasm bundles for web, node, and bundler targets.
#
# Requires:
#   - rustup target add wasm32-unknown-unknown
#   - cargo install wasm-pack
set -euo pipefail
cd "$(dirname "$0")"
wasm-pack build --release --target web --out-dir dist/web
wasm-pack build --release --target nodejs --out-dir dist/node
wasm-pack build --release --target bundler --out-dir dist/bundler
echo "Built wasm bundles in dist/"
