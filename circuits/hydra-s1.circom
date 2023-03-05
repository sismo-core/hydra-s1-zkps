pragma circom 2.1.2;

include "../node_modules/circomlib/circuits/compconstant.circom";
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
  signal input vaultSecret;
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
  signal input requestIdentifier;
  signal input proofIdentifier;
  signal input statementValue;
  signal input accountsTreeValue; // accounts tree 0 => on check pas le group 
  signal input statementComparator; // 1 => strict, 0 => not strict, 
  signal input vaultIdentifier;
  signal input vaultNamespace;

  // Verify the source account went through the Hydra Delegated Proof of Ownership
  // That means the user own the source address
  component sourceCommitmentVerification = VerifyHydraCommitment();
  sourceCommitmentVerification.address <== sourceIdentifier;
  sourceCommitmentVerification.vaultSecret <== vaultSecret; 
  sourceCommitmentVerification.accountSecret <== sourceSecret; 
  sourceCommitmentVerification.enabled <== 1; 
  sourceCommitmentVerification.commitmentMapperPubKey[0] <== commitmentMapperPubKey[0];
  sourceCommitmentVerification.commitmentMapperPubKey[1] <== commitmentMapperPubKey[1];
  sourceCommitmentVerification.commitmentReceipt[0] <== sourceCommitmentReceipt[0];
  sourceCommitmentVerification.commitmentReceipt[1] <== sourceCommitmentReceipt[1];
  sourceCommitmentVerification.commitmentReceipt[2] <== sourceCommitmentReceipt[2];


  // Verify the destination only if the destinationIdentifier is not 0
  component destinationIdentifierIsZero = IsZero();
  destinationIdentifierIsZero.in <== accountsTreeValue;

  // Verify the destination account went through the Hydra Delegated Proof of Ownership
  // That means the user own the destination address
  component destinationCommitmentVerification = VerifyHydraCommitment();
  destinationCommitmentVerification.address <== destinationIdentifier;
  destinationCommitmentVerification.vaultSecret <== vaultSecret; 
  destinationCommitmentVerification.accountSecret <== destinationSecret; 
  destinationCommitmentVerification.enabled <== (1 - destinationIdentifierIsZero.out); 
  destinationCommitmentVerification.commitmentMapperPubKey[0] <== commitmentMapperPubKey[0];
  destinationCommitmentVerification.commitmentMapperPubKey[1] <== commitmentMapperPubKey[1];
  destinationCommitmentVerification.commitmentReceipt[0] <== destinationCommitmentReceipt[0];
  destinationCommitmentVerification.commitmentReceipt[1] <== destinationCommitmentReceipt[1];
  destinationCommitmentVerification.commitmentReceipt[2] <== destinationCommitmentReceipt[2];


  // Merkle path verification enabled
  // if accountsTreeValue is 0 then we don't verify the merkle path
  component accountsTreeValueIsZero = IsZero();
  accountsTreeValueIsZero.in <== accountsTreeValue;

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
  accountsTreesPathVerifier.enabled <== (1 - accountsTreeValueIsZero.out);
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
  registryTreePathVerifier.enabled <== (1 - accountsTreeValueIsZero.out);
  for (var i = 0; i < registryTreeHeight; i++) {
    registryTreePathVerifier.pathElements[i] <== registryMerklePathElements[i];
    registryTreePathVerifier.pathIndices[i] <== registryMerklePathIndices[i];
  }

  // Verify claimed value validity
  // Prevent overflow of comparator range
  component sourceInRange = Num2Bits(252);
  sourceInRange.in <== sourceValue;
  component claimedInRange = Num2Bits(252);
  claimedInRange.in <== statementValue;
  // 0 <= statementValue <= sourceValue
  component leq = LessEqThan(252);
  leq.in[0] <== statementValue;
  leq.in[1] <== sourceValue;
  leq.out === 1;
  // If statementComparator == 1 then statementValue == sourceValue
  0 === (statementComparator-1)*statementComparator;
  sourceValue === sourceValue+((statementValue-sourceValue)*statementComparator);

  // Verify the proofIdentifier is valid
  // compute the sourceSecretHash using the hash of the sourceSecret
  signal sourceSecretHash; 
  component sourceSecretHasher = Poseidon(2);
  sourceSecretHasher.inputs[0] <== sourceSecret;
  sourceSecretHasher.inputs[1] <== 1;  
  sourceSecretHash <== sourceSecretHasher.out; 


  // Verify if the requestIdentifier is 0 then we don't verify the proofIdentifier
  component requestIdentifierIsZero = IsZero();
  requestIdentifierIsZero.in <== requestIdentifier;

  // Verify the proofIdentifier is valid
  // by hashing the sourceSecretHash and requestIdentifier
  // and verifying the result is equals
  component proofIdentifierHasher = Poseidon(2);
  proofIdentifierHasher.inputs[0] <== sourceSecretHash;
  proofIdentifierHasher.inputs[1] <== requestIdentifier;
  // Check the proofIdentifier is valid only if requestIdentifier is not 0
  (proofIdentifierHasher.out - proofIdentifier) * (1-requestIdentifierIsZero.out) === 0;

  // Compute the vaultIdentifier
  component vaultIdentifierHasher = Poseidon(2);
  vaultIdentifierHasher.inputs[0] <== vaultSecret;
  vaultIdentifierHasher.inputs[1] <== vaultNamespace;
  vaultIdentifierHasher.out === vaultIdentifier;

  // Square serve to avoid removing by the compilator optimizer
  signal chainIdSquare;
  chainIdSquare <== chainId * chainId;
}

component main {public [commitmentMapperPubKey, registryTreeRoot, vaultNamespace, vaultIdentifier, requestIdentifier, proofIdentifier, destinationIdentifier, statementValue, chainId, accountsTreeValue, statementComparator]} = hydraS1(20,20);