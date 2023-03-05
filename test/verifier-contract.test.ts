import hre from "hardhat";
import { BigNumber } from "ethers";
import { describe } from "mocha";
import { HydraS1Verifier, HydraS1Verifier__factory } from "../types";
import { expect } from "chai";
import {
  ACCOUNTS_TREE_HEIGHT,
  KVMerkleTree,
  MerkleTreeData,
  buildPoseidon,
  HydraS1Account,
  SnarkProof,
  REGISTRY_TREE_HEIGHT,
  HydraS1Prover,
} from "../package/src";
import {
  CommitmentMapperTester,
  getOwnershipMsg,
} from "@sismo-core/commitment-mapper-tester-js";

describe("Hydra S1 Verifier contract", () => {
  let commitmentMapperTester: CommitmentMapperTester;
  let accounts: HydraS1Account[];
  let requestIdentifier: BigNumber;
  let hydraS1VerifierContract: HydraS1Verifier;
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

    for (let i = 0; i < 10; i++) {
      const address = (await signers[i].getAddress()).toLowerCase();
      const signature = await signers[i].signMessage(getOwnershipMsg(address));
      const secret = BigNumber.from(i);
      const commitment = poseidon([secret]).toHexString();
      const { commitmentReceipt } = await commitmentMapperTester.commit(
        address,
        signature,
        commitment
      );
      accounts.push({
        identifier: address,
        secret,
        commitmentReceipt,
      });
    }

    requestIdentifier = BigNumber.from(123);

    merkleTreeData = {
      [BigNumber.from(accounts[0].identifier).toHexString()]: 1,
      [BigNumber.from(accounts[1].identifier).toHexString()]: 2,
      [BigNumber.from(accounts[2].identifier).toHexString()]: 3,
      [BigNumber.from(accounts[3].identifier).toHexString()]: 4,
    };
    accountsTree = new KVMerkleTree(
      merkleTreeData,
      poseidon,
      ACCOUNTS_TREE_HEIGHT
    );

    registryTree = new KVMerkleTree(
      {
        [accountsTree.getRoot().toHexString()]: 1,
      },
      poseidon,
      REGISTRY_TREE_HEIGHT
    );

    //deploy contracts

    const deployer = signers[0];
    const deployed = await hre.deployments.deploy("HydraS1Verifier", {
      contract: "HydraS1Verifier",
      from: deployer.address,
      args: [],
      skipIfAlreadyDeployed: false,
    });
    hydraS1VerifierContract = HydraS1Verifier__factory.connect(
      deployed.address,
      deployer
    );
  });

  it("Should be able to generate the proof using the prover package", async () => {
    const prover = new HydraS1Prover(
      registryTree,
      await commitmentMapperTester.getPubKey()
    );

    const source = accounts[0];
    const destination = accounts[4];
    const statementValue = BigNumber.from(
      merkleTreeData[BigNumber.from(source.identifier).toHexString()]
    );

    proof = await prover.generateSnarkProof({
      source,
      destination,
      statementValue,
      chainId: parseInt(await hre.getChainId()),
      accountsTree: accountsTree,
      requestIdentifier,
      statementComparator: Boolean(
        registryTree.getValue(accountsTree.getRoot().toHexString()).toNumber()
      ),
    });
  });

  it("Should be able to verify the proof using the verifier", async () => {
    const isValidContract = await hydraS1VerifierContract.verifyProof(
      proof.a,
      proof.b,
      proof.c,
      proof.input
    );
    expect(isValidContract).to.equals(true);
  });

  it("Should change a public input and expect the verifier to revert", async () => {
    const invalidInput = proof.input;
    invalidInput[3] = BigNumber.from(123); // override signal corresponding to registryTreeRoot
    const isValidContract = await hydraS1VerifierContract.verifyProof(
      proof.a,
      proof.b,
      proof.c,
      invalidInput
    );
    expect(isValidContract).to.equals(false);
  });
});
