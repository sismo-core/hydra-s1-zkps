import hre from "hardhat";
import { BigNumber } from "ethers";
import { describe } from "mocha";
import { HydraS1Verifier } from "../package/src/verifier";
import { expect } from "chai";
import { ACCOUNTS_TREE_HEIGHT, HydraS1Account, KVMerkleTree, MerkleTreeData, buildPoseidon, SnarkProof, REGISTRY_TREE_HEIGHT, HydraS1Prover } from "../package/src";
import { CommitmentMapperTester, getOwnershipMsg } from "@sismo-core/commitment-mapper-tester-js";

describe("Hydra S1 Verifier", () => {
  let commitmentMapperTester: CommitmentMapperTester; 
  let accounts: HydraS1Account[];
  let ticketIdentifier: BigNumber;
  let proof: SnarkProof;
  let registryTree: KVMerkleTree;
  let accountsTree: KVMerkleTree;
  let merkleTreeData: MerkleTreeData;

  before(async () => {
    // init poseidon hash function and elliptic curve setup
    const poseidon = await buildPoseidon();
    // generate an commitmentMapper that make the link between an ethereum account and a eddsa account.
    commitmentMapperTester = await CommitmentMapperTester.generate();

    const signers = await hre.ethers.getSigners();

    accounts = [];

    for(let i = 0; i < 10; i++) {
        const address = (await signers[i].getAddress()).toLowerCase();
        const signature =  await signers[i].signMessage(getOwnershipMsg(address));  
        const secret = BigNumber.from(i);
        const commitment = poseidon([secret]).toHexString();
        const { commitmentReceipt } = await commitmentMapperTester.commit(address, signature, commitment);
        accounts.push({
          identifier: address,
          secret,
          commitmentReceipt
        })
    }

    ticketIdentifier = BigNumber.from(123);

    merkleTreeData = {
      [BigNumber.from(accounts[0].identifier).toHexString()]: 1,
      [BigNumber.from(accounts[1].identifier).toHexString()]: 2,
      [BigNumber.from(accounts[2].identifier).toHexString()]: 3,
      [BigNumber.from(accounts[3].identifier).toHexString()]: 4
    };
    accountsTree = new KVMerkleTree(merkleTreeData, poseidon, ACCOUNTS_TREE_HEIGHT);

    registryTree = new KVMerkleTree({
      [accountsTree.getRoot().toHexString()]: 1
    }, poseidon, REGISTRY_TREE_HEIGHT);
  })

  it("Should be able to generate the proof using the prover package", async () => {
    const prover = new HydraS1Prover(
      registryTree,
      await commitmentMapperTester.getPubKey()
    ); 

    const source = accounts[0];
    const destination = accounts[4];
    const claimedValue = BigNumber.from(merkleTreeData[BigNumber.from(source.identifier).toHexString()]);

    proof = await prover.generateSnarkProof({
      source,
      destination,
      claimedValue,
      chainId: parseInt(await hre.getChainId()),
      accountsTree: accountsTree,
      ticketIdentifier,
      isStrict: Boolean(registryTree.getValue(accountsTree.getRoot().toHexString()).toNumber())
    });
  })

  it("Should be able to verify the proof using the verifier", async () => {
    const isValidOffChain = await HydraS1Verifier.verifyProof(proof.a, proof.b, proof.c, proof.input);
    expect(isValidOffChain).to.equals(true);
  });

  it("Should change a public input and expect the verifier to revert", async () => {
    const invalidInput = proof.input;
    invalidInput[3] = BigNumber.from(123) // override signal corresponding to registryTreeRoot 
    const isValidOffChain = await HydraS1Verifier.verifyProof(proof.a, proof.b, proof.c, invalidInput);
    expect(isValidOffChain).to.equals(false);
  });
});
  