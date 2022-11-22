import { BigNumber } from "ethers";
import hre from "hardhat";
import path from "path";
import { describe } from "mocha";
import { buildPoseidon, Poseidon, HydraS1Account, KVMerkleTree, MerkleTreeData, ACCOUNTS_TREE_HEIGHT, PrivateInputs, PublicInputs, REGISTRY_TREE_HEIGHT, HydraS1Prover } from "../package/src";
import { circuitShouldFail } from "./utils/circuit-should-fail";
import { CommitmentMapperTester, getOwnershipMsg } from "@sismo-core/commitment-mapper-tester-js";
import { wasm, WasmTester } from "circom_tester";


describe("Hydra S1 Circuits", () => {
  let commitmentMapperTester: CommitmentMapperTester; 
  let accounts: HydraS1Account[];
  let circuitTester: WasmTester;
  let externalNullifier: BigNumber;
  let registryTree: KVMerkleTree;
  let poseidon: Poseidon;
  let inputs: PublicInputs & PrivateInputs;
  let accountsTree1: KVMerkleTree;
  let merkleTreeData1: MerkleTreeData;
  let accountsTree2: KVMerkleTree;
  let merkleTreeData2: MerkleTreeData;
  let prover: HydraS1Prover;
  let host: number;
  let source: HydraS1Account;
  let destination: HydraS1Account;
  let sourceValue: BigNumber;

  before(async () => {
    poseidon = await buildPoseidon();
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
    circuitTester = await wasm(path.join(__dirname, "../circuits", "hydra-s1.circom"));
    externalNullifier = BigNumber.from(123);

    merkleTreeData1 = {
      [BigNumber.from(accounts[0].identifier).toHexString()]: 4,
      [BigNumber.from(accounts[1].identifier).toHexString()]: 5,
      [BigNumber.from(accounts[2].identifier).toHexString()]: 6,
      [BigNumber.from(accounts[3].identifier).toHexString()]: 7
    };
    accountsTree1 = new KVMerkleTree(merkleTreeData1, poseidon, ACCOUNTS_TREE_HEIGHT);

    merkleTreeData2 = {
      [BigNumber.from(accounts[4].identifier).toHexString()]: 4,
      [BigNumber.from(accounts[5].identifier).toHexString()]: 2,
      [BigNumber.from(accounts[6].identifier).toHexString()]: 5,
      [BigNumber.from(accounts[7].identifier).toHexString()]: 1
    };
    accountsTree2 = new KVMerkleTree(merkleTreeData2, poseidon, ACCOUNTS_TREE_HEIGHT);

    registryTree = new KVMerkleTree({
      [accountsTree1.getRoot().toHexString()]: 1,
      [accountsTree2.getRoot().toHexString()]: 0,
    }, poseidon, REGISTRY_TREE_HEIGHT);

    prover = new HydraS1Prover(
      registryTree,
      await commitmentMapperTester.getPubKey()
    ); 

    host = parseInt(await hre.getChainId());

    source = accounts[0];
    destination = accounts[4];

    sourceValue = BigNumber.from(merkleTreeData1[BigNumber.from(source.identifier).toHexString()]);
  })
  
  describe("Generating proof", async () => {
    it("Snark proof of simple value in a merkleTree with simple nullifier", async () => {
      const { privateInputs, publicInputs } = await prover.generateInputs({
        source,
        destination,
        claimedValue: sourceValue,
        chainId: host,
        accountsTree: accountsTree1,
        externalNullifier,
        isStrict: Boolean(registryTree.getValue(accountsTree1.getRoot().toHexString()).toNumber())
      });
      
      inputs = { ...privateInputs, ...publicInputs };

      const w = await circuitTester.calculateWitness(inputs, true);
      await circuitTester.checkConstraints(w);
    });
  })


    describe("Verifying accountsTree and registryTree are good", async () => {

      it("Should throw when using an Accounts tree with wrong height", async () => {
        const accountsTree3 = new KVMerkleTree(merkleTreeData1, poseidon);
  
        const registryTree3 = new KVMerkleTree({
          [accountsTree3.getRoot().toHexString()]: 1,
        }, poseidon, REGISTRY_TREE_HEIGHT);
  
        const prover2 = new HydraS1Prover(
          registryTree3,
          await commitmentMapperTester.getPubKey()
        ); 
        
        const { privateInputs, publicInputs } = await prover2.generateInputs({
          source,
          destination,
          claimedValue: BigNumber.from(1),
          chainId: host,
          accountsTree: accountsTree3,
          externalNullifier,
          isStrict: true
        });
        
        const inputs3 = { ...privateInputs, ...publicInputs };
  
        await circuitShouldFail(circuitTester, {
          ...inputs3,
        }, "Not enough values for input signal accountMerklePathElements");
      });

      it("Should throw when using an Registry Merkle tree with wrong height", async () => {
        const registryTree3 = new KVMerkleTree({
          [accountsTree1.getRoot().toHexString()]: 1,
          [accountsTree2.getRoot().toHexString()]: 0
        }, poseidon);
  
        const prover2 = new HydraS1Prover(
          registryTree3,
          await commitmentMapperTester.getPubKey()
        ); 
        
        const { privateInputs, publicInputs } = await prover2.generateInputs({
          source,
          destination,
          claimedValue: BigNumber.from(1),
          chainId: host,
          accountsTree: accountsTree1,
          externalNullifier,
          isStrict: true
        });
        
        const inputs3 = { ...privateInputs, ...publicInputs };
  
        await circuitShouldFail(circuitTester, {
          ...inputs3,
        }, "Not enough values for input signal registryMerklePathElements");
      });
    });

    describe("Verifying source address constraints are good", async () => {
      it("Should throw with wrong source address", async () => {
        await circuitShouldFail(circuitTester, {
          ...inputs,
          ...{ sourceIdentifier: BigNumber.from(accounts[1].identifier).toBigInt() }
        }, "Error: Assert Failed.\nError in template ForceEqualIfEnabled");
      })

      it("Should throw with wrong sourceSecret", async () => {
        await circuitShouldFail(circuitTester, {
          ...inputs,
          ...{ sourceSecret: BigNumber.from(123).toBigInt() }
        }, "Error: Assert Failed.\nError in template ForceEqualIfEnabled");
      })

      it("Should throw with wrong sourceCommitmentReceipt", async () => {
        await circuitShouldFail(circuitTester, {
          ...inputs,
          ...{ sourceCommitmentReceipt: [BigNumber.from(1).toBigInt(),BigNumber.from(2).toBigInt(),BigNumber.from(3).toBigInt()] }
        }, "Error: Assert Failed.\nError in template ForceEqualIfEnabled");
      })
    });

    describe("Verifying destination address constraints are good", async () => {

      it("Should throw with wrong destination address", async () => {
        await circuitShouldFail(circuitTester, {
          ...inputs,
          ...{ destinationIdentifier: BigNumber.from(accounts[5].identifier).toBigInt() }
        }, "Error: Assert Failed.\nError in template ForceEqualIfEnabled");
      })

      it("Should throw with wrong destinationSecret", async () => {
        await circuitShouldFail(circuitTester, {
          ...inputs,
          ...{ destinationSecret: BigNumber.from(123).toBigInt() }
        }, "Error: Assert Failed.\nError in template ForceEqualIfEnabled");
      })

      it("Should throw with wrong destinationCommitmentReceipt", async () => {
        await circuitShouldFail(circuitTester, {
          ...inputs,
          ...{ destinationCommitmentReceipt: [BigNumber.from(1).toBigInt(),BigNumber.from(2).toBigInt(),BigNumber.from(3).toBigInt()] }
        }, "Error: Assert Failed.\nError in template ForceEqualIfEnabled");
      })

      it("Should throw with wrong commitmentMapperPubKey", async () => {
        await circuitShouldFail(circuitTester, {
          ...inputs,
          ...{ commitmentMapperPubKey: [BigNumber.from(1).toBigInt(),BigNumber.from(2).toBigInt()] }
        }, "Error: Assert Failed.\nError in template ForceEqualIfEnabled");
      })
    });

    describe("Verify externalDataMerkleTree constraint against the globalSismoTree", async () => {

      it("Should verify the global sismo tree root constraint", async () => {
        await circuitShouldFail(circuitTester, {
          ...inputs,
          ...{
            registryTreeRoot: registryTree.getRoot().add(1).toBigInt(),
          }
        }, "Error: Assert Failed.\nError in template ForceEqualIfEnabled");
      })

      it("Should verify the accountsTreeRoot constraint along the global sismo merkle tree", async () => {
        await circuitShouldFail(circuitTester, {
          ...inputs,
          ...{
            registryMerklePathElements: inputs.registryMerklePathElements.slice().reverse(),
          }
        }, "Error: Assert Failed.\nError in template ForceEqualIfEnabled");
      })
    });

    describe("Verify data merkle tree constraint is good", async () => {
      it("Should throw when having a bad data merkle tree root or a bad data merkle tree height", async () => {
        await circuitShouldFail(circuitTester, {
          ...inputs,
          ...{ accountsTreeRoot: BigNumber.from(123).toBigInt() } // changing only the merkle Root
        }, "Error: Assert Failed.\nError in template ForceEqualIfEnabled");
      });

      it("Should throw when using a bad Merkle path", async () => {
        const wrongAccountMerklePathElements = [...inputs.accountMerklePathElements];
        wrongAccountMerklePathElements[2] = BigNumber.from(345).toBigInt();
        await circuitShouldFail(circuitTester, {
          ...inputs,
          ...{ accountMerklePathElements:  wrongAccountMerklePathElements}
        }, "Error: Assert Failed.\nError in template ForceEqualIfEnabled");
        const wrongAccountMerklePathIndices = [...inputs.accountMerklePathIndices];
        wrongAccountMerklePathIndices[0] = 1;
        wrongAccountMerklePathIndices[1] = 0;
        await circuitShouldFail(circuitTester, {
          ...inputs,
          ...{ accountMerklePathIndices: wrongAccountMerklePathIndices }
        }, "Error: Assert Failed.\nError in template ForceEqualIfEnabled");
      });

      it("Should throw when using a good Merkle path but for an other source address than the specified one", async () => {
        const externalDataMerklePathSource2 = accountsTree1.getMerklePathFromKey(BigNumber.from(accounts[2].identifier).toHexString());

        await circuitShouldFail(circuitTester, {
          ...inputs,
          accountMerklePathElements: externalDataMerklePathSource2.elements.map(el => el.toBigInt()),
          accountMerklePathIndices: externalDataMerklePathSource2.indices
        }, "Error: Assert Failed.\nError in template ForceEqualIfEnabled");
      });
    });

    describe("Verify the value selected by the user", async () => {

      it("Should throw when using isStrict < 0", async () => {
        await circuitShouldFail(circuitTester, {   
            ...inputs,
            ...{ 
              isStrict: -5 as any // Must force any to bypass typescript error
            } 
        }, "Error: Assert Failed.\nError in template ForceEqualIfEnabled");
      });

      it("Should throw when using isStrict > 1", async () => {
        await circuitShouldFail(circuitTester, {   
            ...inputs,
            ...{ 
              isStrict: 2 as any // Must force any to bypass typescript error
            } 
        }, "Error: Assert Failed.\nError in template ForceEqualIfEnabled");
      });

      it("Should throw when using a value superior of the Merkle tree value for isStrict == 1", async () => {
        await circuitShouldFail(circuitTester, {
          ...inputs,
          ...{ claimedValue: BigNumber.from(5).toBigInt() } // the good one is value: 4
        }, "Error: Assert Failed.\nError in template ForceEqualIfEnabled");
      });

      it("Should throw when using a value superior of the Merkle tree value for isStrict == 0", async () => {
        await circuitShouldFail(circuitTester, {
          ...inputs,
          ...{ 
            claimedValue: BigNumber.from(5).toBigInt(),
            isStrict: 0
          } // the good one is value: 4
        }, "Error: Assert Failed.\nError in template ForceEqualIfEnabled");
      });

      it("Should throw when using negative value for isStrict == 1", async () => {
        await circuitShouldFail(circuitTester, {
          ...inputs,
          ...{ claimedValue: BigNumber.from(-5).toBigInt() } // the good one is value: 4
        }, "Error: Assert Failed.\nError in template ForceEqualIfEnabled");
      });

      it("Should throw when using negative value for isStrict == 0", async () => {
        await circuitShouldFail(circuitTester, {
          ...inputs,
          ...{ 
            claimedValue: BigNumber.from(-5).toBigInt() ,
            isStrict: 0
          } // the good one is value: 4
        }, "Error: Assert Failed.\nError in template ForceEqualIfEnabled");
      });
      
      it("Should throw when using a value inferior of the Merkle tree value for isStrict == 1", async () => {
        await circuitShouldFail(circuitTester, {
          ...inputs,
          ...{ claimedValue: BigNumber.from(3).toBigInt() } // the good one is value: 4
        }, "Error: Assert Failed.\nError in template ForceEqualIfEnabled");
      });

      it("Should generate a Snark proof when using a value inferior of the Merkle tree value for isStrict == 0", async () => {
        const w = await circuitTester.calculateWitness({
          ...inputs,
          ...{ 
            claimedValue: BigNumber.from(3),
            isStrict: 0
          } // the good one is value: 4
        }, true);
        await circuitTester.checkConstraints(w);
      });
    });

    describe("Verify nullifier validity", async () => {
      it("Should throw when the externalNullifier does not corresponds to the nullifier ", async () => {
        await circuitShouldFail(circuitTester, {
          ...inputs,
          ...{ externalNullifier: BigNumber.from(456).toBigInt() }  // good one is 123
        }, "Error: Assert Failed.\nError in template ForceEqualIfEnabled");
      });

      it("Should throw when the nullifier does not corresponds to the externalNullifier and sourceNullifier", async () => {
        await circuitShouldFail(circuitTester, {
          ...inputs,
          ...{ nullifier: BigNumber.from(789).toBigInt() }
        }, "Error: Assert Failed.\nError in template ForceEqualIfEnabled");
      });
    });
})
