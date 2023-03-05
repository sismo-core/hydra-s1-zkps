pragma circom 2.0.0;

include "../../node_modules/circomlib/circuits/eddsaposeidon.circom";
include "../../node_modules/circomlib/circuits/poseidon.circom";


// This template verify a Hydra Delegated Proof Of Ownership
// For more informations about Delegated Proof Of Ownership
// See the Commitment Mapper https://commitment-mapper.docs.sismo.io 
template VerifyHydraCommitment() {
  signal input address; 
  signal input accountSecret;
  signal input vaultSecret;
  signal input enabled;

  signal input commitmentMapperPubKey[2];
  signal input commitmentReceipt[3];

  // Verify that the user has the right commitment accountSecret
  // This is a Proof Of Commitment Ownership
  component commitment = Poseidon(2);
  commitment.inputs[0] <== vaultSecret;
  commitment.inputs[1] <== accountSecret;

  // Re-create the commitment mapping between the address and 
  // the commitment
  component message = Poseidon(2);
  message.inputs[0] <== address;
  message.inputs[1] <== commitment.out;

  // Verify the Hydra commitment receipt
  // of the given commitmentMapperPubKey
  component eddsa = EdDSAPoseidonVerifier();
  eddsa.enabled <== enabled;
  eddsa.Ax <== commitmentMapperPubKey[0];
  eddsa.Ay <== commitmentMapperPubKey[1];
  eddsa.R8x <== commitmentReceipt[0];
  eddsa.R8y <== commitmentReceipt[1];
  eddsa.S <== commitmentReceipt[2];
  eddsa.M <== message.out;
}