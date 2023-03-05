// Highly inspired from tornado cash https://github.com/tornadocash/tornado-core/tree/master/circuits
pragma circom 2.0.0;

include "../../node_modules/circomlib/circuits/poseidon.circom";
include "../../node_modules/circomlib/circuits/bitify.circom";
include "../../node_modules/circomlib/circuits/comparators.circom";

// if s == 0 returns [in[0], in[1]]
// if s == 1 returns [in[1], in[0]]
template PositionSwitcher() {
    signal input in[2];
    signal input s;
    signal output out[2];

    s * (1 - s) === 0;
    out[0] <== (in[1] - in[0])*s + in[0];
    out[1] <== (in[0] - in[1])*s + in[1];
}


// Verifies that merkle path is correct for a given merkle root and leaf
// pathIndices input is an array of 0/1 selectors telling whether given 
// pathElement is on the left or right side of merkle path
template VerifyMerklePath(levels) {
    signal input leaf;
    signal input root;
    signal input enabled;
    signal input pathElements[levels];
    signal input pathIndices[levels];

    component selectors[levels];
    component hashers[levels];

    signal computedPath[levels];

    for (var i = 0; i < levels; i++) {
        selectors[i] = PositionSwitcher();
        selectors[i].in[0] <== i == 0 ? leaf : computedPath[i - 1];
        selectors[i].in[1] <== pathElements[i];
        selectors[i].s <== pathIndices[i];

        hashers[i] = Poseidon(2);
        hashers[i].inputs[0] <== selectors[i].out[0];
        hashers[i].inputs[1] <== selectors[i].out[1];
        computedPath[i] <== hashers[i].out;
    }

    (root - computedPath[levels - 1])*enabled === 0;
}
