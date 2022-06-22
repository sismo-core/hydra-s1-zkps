pragma circom 2.0.0;

include "../node_modules/circomlib/circuits/comparators.circom";
include "../node_modules/circomlib/circuits/poseidon.circom";
include "../node_modules/circomlib/circuits/bitify.circom";
include "../node_modules/circomlib/circuits/mux1.circom";
include "../node_modules/circomlib/circuits/babyjub.circom";

include "./common/verify-merkle-path.circom";
include "./common/verify-hydra-commitment.circom";

// This is the circuit for the Hydra S1 Proving Scheme
// please read this doc to understand the underlying concepts
// https://hydra-s1.docs.sismo.io
template hydraS1(registryTreeHeight, accountsTreeHeight) {
  // Private inputs
  signal input sourceIdentifier;
  signal input sourceSecret;
  signal input sourceCommitmentReceipt[3];
  signal input destinationSecret; 
  signal input destinationCommitmentReceipt[3];
  signal input accountMerklePathElements[accountsTreeHeight];
  signal input accountMerklePathIndices[accountsTreeHeight];
  signal input accountsTreeRoot;
  signal input registryMerklePathElements[registryTreeHeight];
  signal input registryMerklePathIndices[registryTreeHeight];
  signal input sourceValue;

  // Public inputs
  signal input destinationIdentifier;
  signal input chainId;
  signal input commitmentMapperPubKey[2];
  signal input registryTreeRoot;
  signal input ticketIdentifier;
  signal input userTicket;
  signal input claimedValue;
  signal input accountsTreeValue;
  signal input isStrict;

  // Verify the source account went through the Hydra Delegated Proof of Ownership
  // That means the user own the source address
  component sourceCommitmentVerification = VerifyHydraCommitment();
  sourceCommitmentVerification.address <== sourceIdentifier;
  sourceCommitmentVerification.secret <== sourceSecret; 
  sourceCommitmentVerification.commitmentMapperPubKey[0] <== commitmentMapperPubKey[0];
  sourceCommitmentVerification.commitmentMapperPubKey[1] <== commitmentMapperPubKey[1];
  sourceCommitmentVerification.commitmentReceipt[0] <== sourceCommitmentReceipt[0];
  sourceCommitmentVerification.commitmentReceipt[1] <== sourceCommitmentReceipt[1];
  sourceCommitmentVerification.commitmentReceipt[2] <== sourceCommitmentReceipt[2];

  // Verify the destination account went through the Hydra Delegated Proof of Ownership
  // That means the user own the destination address
  component destinationCommitmentVerification = VerifyHydraCommitment();
  destinationCommitmentVerification.address <== destinationIdentifier;
  destinationCommitmentVerification.secret <== destinationSecret; 
  destinationCommitmentVerification.commitmentMapperPubKey[0] <== commitmentMapperPubKey[0];
  destinationCommitmentVerification.commitmentMapperPubKey[1] <== commitmentMapperPubKey[1];
  destinationCommitmentVerification.commitmentReceipt[0] <== destinationCommitmentReceipt[0];
  destinationCommitmentVerification.commitmentReceipt[1] <== destinationCommitmentReceipt[1];
  destinationCommitmentVerification.commitmentReceipt[2] <== destinationCommitmentReceipt[2];


  // Verification that the source account is part of an accounts tree
  // Recreating the leaf which is the hash of an account identifier and an account value
  component accountLeafConstructor = Poseidon(2);
  accountLeafConstructor.inputs[0] <== sourceIdentifier;
  accountLeafConstructor.inputs[1] <== sourceValue;

  // This tree is an Accounts Merkle Tree which is constituted by accounts
  // https://accounts-registry-tree.docs.sismo.io
  // leaf = Hash(accountIdentifier, accountValue) 
  // verify the merkle path
  component accountsTreesPathVerifier = VerifyMerklePath(accountsTreeHeight);
  accountsTreesPathVerifier.leaf <== accountLeafConstructor.out;  
  accountsTreesPathVerifier.root <== accountsTreeRoot;
  for (var i = 0; i < accountsTreeHeight; i++) {
    accountsTreesPathVerifier.pathElements[i] <== accountMerklePathElements[i];
    accountsTreesPathVerifier.pathIndices[i] <== accountMerklePathIndices[i];
  }

  // Verification that the accounts tree is part of a registry tree
  // Recreating the leaf
  component registryLeafConstructor = Poseidon(2);
  registryLeafConstructor.inputs[0] <== accountsTreeRoot;
  registryLeafConstructor.inputs[1] <== accountsTreeValue; 

  // https://accounts-registry-tree.docs.sismo.io
  // leaf = Hash(accountsTreeRoot, accountsTreeValue)
  // verify the merkle path
  component registryTreePathVerifier = VerifyMerklePath(registryTreeHeight);
  registryTreePathVerifier.leaf <== registryLeafConstructor.out; 
  registryTreePathVerifier.root <== registryTreeRoot;
  for (var i = 0; i < registryTreeHeight; i++) {
    registryTreePathVerifier.pathElements[i] <== registryMerklePathElements[i];
    registryTreePathVerifier.pathIndices[i] <== registryMerklePathIndices[i];
  }

  // Verify claimed value validity
  // 0 <= claimedValue <= sourceValue
  component leq = LessEqThan(252);
  leq.in[0] <== claimedValue;
  leq.in[1] <== sourceValue;
  leq.out === 1;
  // If isStrict == 1 then claimedValue == sourceValue
  0 === (isStrict-1)*isStrict;
  sourceValue === sourceValue+((claimedValue-sourceValue)*isStrict);

  // Verify the userTicket is valid
  // compute the sourceSecretHash using the hash of the sourceSecret
  signal sourceSecretHash; 
  component sourceSecretHasher = Poseidon(2);
  sourceSecretHasher.inputs[0] <== sourceSecret;
  sourceSecretHasher.inputs[1] <== 1;  
  sourceSecretHash <== sourceSecretHasher.out; 

  // Verify the userTicket is valid
  // by hashing the sourceSecretHash and ticketIdentifier
  // and verifying the result is equals
  component userTicketHasher = Poseidon(2);
  userTicketHasher.inputs[0] <== sourceSecretHash;
  userTicketHasher.inputs[1] <== ticketIdentifier;
  userTicketHasher.out === userTicket;

  // Square serve to avoid removing by the compilator optimizer
  signal chainIdSquare;
  chainIdSquare <== chainId * chainId;
}

component main {public [commitmentMapperPubKey, registryTreeRoot, ticketIdentifier, userTicket, destinationIdentifier, claimedValue, chainId, accountsTreeValue, isStrict]} = hydraS1(20,20);
