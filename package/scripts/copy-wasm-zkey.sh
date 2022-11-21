#!/bin/bash -e

cd "$(git rev-parse --show-toplevel)"

# Uncomment next lines to update Trusted setup
# cp "./artifacts/circuits/hydra-s1_js/hydra-s1.wasm" "./package/src/prover"
# cp "./artifacts/circuits/hydra-s1.zkey" "./package/src/prover"