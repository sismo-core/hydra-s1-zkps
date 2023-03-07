import {
  DestinationInput,
  SourceInput,
  VaultInput,
} from "./../package/src/prover/hydra-s1-prover";
import {
  CommitmentMapperTester,
  getOwnershipMsg,
} from "@sismo-core/commitment-mapper-tester-js";
import { expect } from "chai";
import { BigNumber } from "ethers";
import hre, { ethers } from "hardhat";
import { describe } from "mocha";
import {
  ACCOUNTS_TREE_HEIGHT,
  buildPoseidon,
  HydraS1Account,
  HydraS1Prover,
  KVMerkleTree,
  MerkleTreeData,
  Poseidon,
  REGISTRY_TREE_HEIGHT,
  SnarkProof,
} from "../package/src";

describe("Hydra S1 Prover", () => {
  let commitmentMapperTester: CommitmentMapperTester;
  let accounts: HydraS1Account[];
  let requestIdentifier: BigNumber;
  let registryTree: KVMerkleTree;
  let poseidon: Poseidon;
  let accountsTree1: KVMerkleTree;
  let merkleTreeData1: MerkleTreeData;
  let accountsTree2: KVMerkleTree;
  let prover: HydraS1Prover;
  let chainId: number;
  let source: SourceInput;
  let destination: DestinationInput;
  let sourceValue: BigNumber;
  let snarkProof: SnarkProof;
  let statementComparator: 0 | 1;
  let vault: VaultInput;

  before(async () => {
    poseidon = await buildPoseidon();
    commitmentMapperTester = await CommitmentMapperTester.generate();

    const vaultSecret = BigNumber.from("0x123456");
    const vaultNamespace = BigNumber.from(123);
    vault = {
      secret: vaultSecret,
      namespace: vaultNamespace,
    };

    const signers = await hre.ethers.getSigners();

    accounts = [];

    for (let i = 0; i < 20; i++) {
      const address = (await signers[i].getAddress()).toLowerCase();
      const signature = await signers[i].signMessage(getOwnershipMsg(address));
      const secret = BigNumber.from(i);
      const commitment = poseidon([vaultSecret, secret]).toHexString();
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

    merkleTreeData1 = {
      [BigNumber.from(accounts[0].identifier).toHexString()]: 4,
      [BigNumber.from(accounts[1].identifier).toHexString()]: 5,
      [BigNumber.from(accounts[2].identifier).toHexString()]: 6,
      [BigNumber.from(accounts[3].identifier).toHexString()]: 7,
      [ethers.utils.hexZeroPad(
        BigNumber.from(accounts[19].identifier).toHexString(),
        20
      )]: 7,
    };

    accountsTree1 = new KVMerkleTree(
      merkleTreeData1,
      poseidon,
      ACCOUNTS_TREE_HEIGHT
    );

    registryTree = new KVMerkleTree(
      {
        [accountsTree1.getRoot().toHexString()]: 1,
      },
      poseidon,
      REGISTRY_TREE_HEIGHT
    );

    prover = new HydraS1Prover(await commitmentMapperTester.getPubKey());

    chainId = parseInt(await hre.getChainId());

    source = {
      ...accounts[0],
      verificationEnabled: true,
    };
    destination = {
      ...accounts[4],
      verificationEnabled: true,
      chainId: chainId,
    };

    sourceValue = BigNumber.from(
      merkleTreeData1[BigNumber.from(source.identifier).toHexString()]
    );

    statementComparator = registryTree
      .getValue(accountsTree1.getRoot().toHexString())
      .toNumber() as 0 | 1;
  });

  it("Should generate a snark proof with correct inputs", async () => {
    snarkProof = await prover.generateSnarkProof({
      vault,
      source,
      destination,
      statement: {
        value: sourceValue,
        comparator: 0,
        accountsTree: accountsTree1,
        registryTree,
      },
      requestIdentifier,
    });

    expect(snarkProof.input).to.deep.equal([
      "454499773101623097675665140164886290476978118997",
      "31337",
      "3268380547641047729088085784617708493474401130426516096643943726492544573596",
      "15390691699624678165709040191639591743681460873292995904381058558679154201615",
      "2239886174460707204370256878761962330187476314139148528390622981963521260926",
      "123",
      "8075686738959054507695243166556461654566805841122075512669335921145764546801",
      "4",
      "1",
      "0",
      "20422825120840285657511723889661237099631272576795262869762539754512105357233",
      "123",
      "1",
      "1",
      "0",
    ]);

    const account19Value =
      merkleTreeData1[
        ethers.utils.hexZeroPad(
          BigNumber.from(accounts[19].identifier).toHexString(),
          20
        )
      ];
    const secondSnarkProof = await prover.generateSnarkProof({
      vault,
      source: {
        ...accounts[19],
        verificationEnabled: true,
      },
      destination,
      statement: {
        value: account19Value,
        comparator: 1,
        accountsTree: accountsTree1,
        registryTree,
      },
      requestIdentifier,
    });

    expect(secondSnarkProof.input).to.deep.equal([
      "454499773101623097675665140164886290476978118997",
      "31337",
      "3268380547641047729088085784617708493474401130426516096643943726492544573596",
      "15390691699624678165709040191639591743681460873292995904381058558679154201615",
      "2239886174460707204370256878761962330187476314139148528390622981963521260926",
      "123",
      "15308508994751661638002446427622257142997575318999224286421872638048029013084",
      "7",
      "1",
      "1",
      "20422825120840285657511723889661237099631272576795262869762539754512105357233",
      "123",
      "1",
      "1",
      "0",
    ]);
  });

  it("Should export the proof in Bytes", async () => {
    expect(snarkProof.toBytes().substring(514)).to.equal(
      "0000000000000000000000004f9c798553d207536b79e886b54f169264a7a1550000000000000000000000000000000000000000000000000000000000007a690739d67c4d0c90837361c2fe595d11dfecc2847dc41e1ef0da8201c0b16aa09c2206d2a327e39f643e508f5a08e922990cceba9610c15f9a94ef30d6dd54940f04f3bb0bc061e4c1df1767a6bb2e314f9e3f05bb44f19e468eac50a54580fd7e000000000000000000000000000000000000000000000000000000000000007b11daad3d3b51d9cb5b3fe940a00f3e4da0f9bafff28d088f3f202dbd412a88f10000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000002d26e8cd86be758573f24bea0fe037b793a9f1bbf6aadb54360a0542aabc3fb1000000000000000000000000000000000000000000000000000000000000007b000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000"
    );
  });

  it("Snark proof of vault identifier for a specific vault namespace", async () => {
    await prover.generateSnarkProof({
      vault,
    });
  });

  it("Snark proof of vault identifier for a specific vault namespace with source verification", async () => {
    await prover.generateSnarkProof({
      vault,
      source,
    });
  });

  it("Snark proof of vault identifier for a specific vault namespace with an unverified destination", async () => {
    await prover.generateSnarkProof({
      vault,
      source,
      destination: {
        identifier: destination.identifier,
        verificationEnabled: false,
        chainId,
      },
    });
  });

  it("Snark proof of simple value in a merkleTree with simple proofIdentifier without destination verification", async () => {
    snarkProof = await prover.generateSnarkProof({
      vault,
      source,
      destination: {
        identifier: destination.identifier,
        verificationEnabled: false,
        chainId,
      },
      statement: {
        value: sourceValue,
        comparator: 0,
        accountsTree: accountsTree1,
        registryTree,
      },
      requestIdentifier,
    });
  });

  it("Should throw with Invalid Accounts Merkle tree height", async () => {
    accountsTree2 = new KVMerkleTree(merkleTreeData1, poseidon);

    const registryTree2 = new KVMerkleTree(
      {
        [accountsTree2.getRoot().toHexString()]: 1,
      },
      poseidon,
      REGISTRY_TREE_HEIGHT
    );

    const prover2 = new HydraS1Prover(await commitmentMapperTester.getPubKey());

    try {
      await prover2.generateSnarkProof({
        vault,
        source,
        destination,
        statement: {
          accountsTree: accountsTree2,
          registryTree: registryTree2,
          value: sourceValue,
          comparator: 0,
        },
        requestIdentifier,
      });
    } catch (e: any) {
      expect(e.message).to.equal("Invalid Accounts tree height");
    }
  });

  it("Should throw with invalid Registry tree height", async () => {
    const registryTree3 = new KVMerkleTree(
      {
        [accountsTree1.getRoot().toHexString()]: 1,
      },
      poseidon
    );

    const prover3 = new HydraS1Prover(await commitmentMapperTester.getPubKey());

    try {
      await prover3.generateSnarkProof({
        vault,
        source,
        destination,
        statement: {
          value: sourceValue,
          registryTree: registryTree3,
          accountsTree: accountsTree1,
          comparator: 0,
        },
        requestIdentifier,
      });
    } catch (e: any) {
      expect(e.message).to.equal("Invalid Registry tree height");
    }
  });

  it("Should throw with invalid source secret", async () => {
    try {
      await prover.generateSnarkProof({
        vault,
        source: {
          ...source,
          secret: BigNumber.from(3),
        },
        destination,
        statement: {
          value: sourceValue,
          comparator: 0,
          accountsTree: accountsTree1,
          registryTree,
        },
        requestIdentifier,
      });
    } catch (e: any) {
      expect(e.message).to.equal("Invalid source commitment receipt");
    }
  });

  it("Should throw with invalid source commitment receipt", async () => {
    try {
      await prover.generateSnarkProof({
        vault,
        source: {
          ...source,
          commitmentReceipt: [
            BigNumber.from(1),
            BigNumber.from(2),
            BigNumber.from(3),
          ],
        },
        destination,
        statement: {
          value: sourceValue,
          comparator: 0,
          accountsTree: accountsTree1,
          registryTree,
        },
        requestIdentifier,
      });
    } catch (e: any) {
      expect(e.message).to.equal("Invalid source commitment receipt");
    }
  });

  it("Should throw with invalid destination secret", async () => {
    try {
      await prover.generateSnarkProof({
        vault,
        source,
        destination: {
          ...destination,
          secret: BigNumber.from(3),
        },
        statement: {
          value: sourceValue,
          comparator: 0,
          accountsTree: accountsTree1,
          registryTree,
        },
        requestIdentifier,
      });
    } catch (e: any) {
      expect(e.message).to.equal("Invalid destination commitment receipt");
    }
  });

  it("Should throw with invalid destination commitment receipt", async () => {
    try {
      await prover.generateSnarkProof({
        vault,
        source,
        destination: {
          ...destination,
          commitmentReceipt: [
            BigNumber.from(1),
            BigNumber.from(2),
            BigNumber.from(3),
          ],
        },
        statement: {
          value: sourceValue,
          comparator: 0,
          accountsTree: accountsTree1,
          registryTree,
        },
        requestIdentifier,
      });
    } catch (e: any) {
      expect(e.message).to.equal("Invalid destination commitment receipt");
    }
  });

  it("Should throw when sending statementValue > sourceValue", async () => {
    try {
      await prover.generateSnarkProof({
        vault,
        source,
        destination,
        statement: {
          value: BigNumber.from(10),
          comparator: 0,
          accountsTree: accountsTree1,
          registryTree,
        },
        requestIdentifier,
      });
    } catch (e: any) {
      expect(e.message).to.equal(
        `Statement value 10 can't be superior to Source value`
      );
    }
  });

  it("Should throw when sending statementValue is not equal to sourceValue and statementComparator == 1 (EQ)", async () => {
    try {
      await prover.generateSnarkProof({
        vault,
        source,
        destination,
        statement: {
          value: BigNumber.from(3),
          comparator: 1,
          accountsTree: accountsTree1,
          registryTree,
        },
        requestIdentifier,
      });
    } catch (e: any) {
      expect(e.message).to.equal(
        `Statement value 3 must be equal with Source value when statementComparator == 1`
      );
    }
  });

  it("Should throw when sending statementValue negative", async () => {
    try {
      await prover.generateSnarkProof({
        vault,
        source,
        destination,
        statement: {
          value: BigNumber.from(-3),
          comparator: 0,
          accountsTree: accountsTree1,
          registryTree,
        },
        requestIdentifier,
      });
    } catch (e: any) {
      expect(e.message).to.equal(`Statement value -3 can't be negative`);
    }
  });

  it("Should throw when sending Accounts tree which is not in the Registry tree", async () => {
    const merkleTreeData = {
      [BigNumber.from(accounts[4].identifier).toHexString()]: 4,
      [BigNumber.from(accounts[5].identifier).toHexString()]: 5,
      [BigNumber.from(accounts[6].identifier).toHexString()]: 6,
      [BigNumber.from(accounts[7].identifier).toHexString()]: 7,
    };
    const accountsTree = new KVMerkleTree(
      merkleTreeData,
      poseidon,
      ACCOUNTS_TREE_HEIGHT
    );

    try {
      await prover.generateSnarkProof({
        vault,
        source,
        destination,
        statement: {
          value: BigNumber.from(4),
          accountsTree: accountsTree,
          registryTree,
          comparator: 0,
        },
        requestIdentifier,
      });
    } catch (e: any) {
      expect(e.message).to.equal(
        "Accounts tree root not found in the Registry tree"
      );
    }
  });

  it("Should throw when sending a source which is not in the accountsTree", async () => {
    const newSource = accounts[0];
    try {
      await prover.generateSnarkProof({
        vault,
        source: {
          ...newSource,
          verificationEnabled: true,
        },
        destination,
        statement: {
          value: BigNumber.from(4),
          comparator: 0,
          accountsTree: accountsTree1,
          registryTree,
        },
        requestIdentifier,
      });
    } catch (e: any) {
      expect(e.message).to.equal(
        `Could not find the source ${BigNumber.from(
          newSource.identifier
        ).toHexString()} in the Accounts tree`
      );
    }
  });
});
