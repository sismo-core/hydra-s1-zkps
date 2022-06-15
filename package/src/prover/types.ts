export type PrivateInputs = {
  sourceIdentifier: BigInt;
  sourceSecret: BigInt;
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
  isStrict: 1 | 0;
  commitmentMapperPubKey: BigInt[];
  registryTreeRoot: BigInt;
  ticketIdentifier: BigInt;
  userTicket: BigInt;
  destinationIdentifier: BigInt;
  chainId: BigInt;
  accountsTreeValue: BigInt;
  claimedValue: BigInt;
};

export type Inputs = {
  privateInputs: PrivateInputs;
  publicInputs: PublicInputs;
};
