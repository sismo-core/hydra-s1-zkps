export type PrivateInputs = {
  sourceIdentifier: BigInt;
  sourceSecret: BigInt;
  vaultSecret: BigInt;
  sourceCommitmentReceipt: BigInt[];
  destinationSecret: BigInt;
  destinationCommitmentReceipt: BigInt[];
  accountMerklePathElements: BigInt[];
  accountMerklePathIndices: number[];
  accountsTreeRoot: BigInt;
  registryMerklePathElements: BigInt[];
  registryMerklePathIndices: number[];
  sourceValue: BigInt;
};

export type PublicInputs = {
  vaultIdentifier: BigInt;
  vaultNamespace: BigInt;
  commitmentMapperPubKey: BigInt[];
  registryTreeRoot: BigInt;
  requestIdentifier: BigInt;
  proofIdentifier: BigInt;
  destinationIdentifier: BigInt;
  statementValue: BigInt;
  chainId: BigInt;
  accountsTreeValue: BigInt;
  statementComparator: BigInt;
  sourceVerificationEnabled: BigInt;
  destinationVerificationEnabled: BigInt;
  randomBeacon: BigInt;
};

export type Inputs = {
  privateInputs: PrivateInputs;
  publicInputs: PublicInputs;
};
