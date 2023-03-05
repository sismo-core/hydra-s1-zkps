#!/bin/bash -e

cd "$(git rev-parse --show-toplevel)"

mkdir -p package/lib
cp "./package/src/prover/hydra-s1.zkey" "./package/lib/cjs"
cp "./package/src/prover/hydra-s1.wasm" "./package/lib/cjs"
cp "./package/src/verifier/hydra-s1-verification-key.json" "./package/lib/cjs"
cp "./package/src/verifier/hydra-s1-verification-key.json" "./package/lib/esm"