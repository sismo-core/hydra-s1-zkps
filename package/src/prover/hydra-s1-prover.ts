import { buildPoseidon, EddsaPublicKey, SNARK_FIELD } from "@sismo-core/crypto";
import { KVMerkleTree, MerklePath } from "@sismo-core/kv-merkle-tree";
import { BigNumber, BigNumberish, ethers } from "ethers";
import { groth16 } from "snarkjs";
import {
  ACCOUNTS_TREE_HEIGHT,
  PrivateInputs,
  PublicInputs,
  REGISTRY_TREE_HEIGHT,
} from ".";
import { wasmPath, zkeyPath } from "./files";
import { SnarkProof } from "./snark-proof";
import { Inputs } from "./types";
import { verifyCommitment } from "./utils/verify-commitment";

export type CircuitPath = { wasmPath: string; zkeyPath: string } | null;

export type HydraS1Account = {
  identifier: BigNumberish;
  secret: BigNumberish;
  commitmentReceipt: [BigNumberish, BigNumberish, BigNumberish];
};

export type VaultInput = {
  secret: BigNumberish;
  namespace: BigNumberish;
  identifier: BigNumberish;
};

export type StatementInput = {
  value?: BigNumberish;
  // A comparator of 0 means the accounts value in the tree can be more than the value in the statement
  // A comparator of 1 means the accounts value in the tree must be equal to the value in the statement
  comparator?: number;
  registryTree: KVMerkleTree;
  accountsTree: KVMerkleTree;
};

export type DestinationInput = HydraS1Account & { chainId: BigNumberish };

export type UserParams = {
  vault: VaultInput;
  source: HydraS1Account;
  destination?: DestinationInput;
  statement?: StatementInput;
  requestIdentifier?: BigNumberish;
};

export class HydraS1Prover {
  private commitmentMapperPubKey: EddsaPublicKey;
  private esmOverrideCircuitPath: CircuitPath;

  constructor(
    commitmentMapperPubKey: EddsaPublicKey,
    esmOverrideCircuitPath: CircuitPath = null
  ) {
    this.commitmentMapperPubKey = commitmentMapperPubKey;
    this.esmOverrideCircuitPath = esmOverrideCircuitPath;
  }

  public async generateInputs({
    vault,
    source,
    destination,
    statement,
    requestIdentifier,
  }: UserParams): Promise<Inputs> {
    const vaultSecret = BigNumber.from(vault.secret);
    const vaultNamespace = BigNumber.from(vault.namespace);
    const vaultIdentifier = BigNumber.from(vault.identifier);
    source.identifier = BigNumber.from(source.identifier);
    source.secret = BigNumber.from(source.secret);
    const destinationIdentifier = destination
      ? BigNumber.from(destination.identifier)
      : BigNumber.from(0);
    const destinationSecret = destination
      ? BigNumber.from(destination.secret)
      : BigNumber.from(0);
    const destinationCommitmentReceipt = destination
      ? destination.commitmentReceipt
      : [0, 0, 0];

    const statementValue = BigNumber.from(
      statement && statement.value ? statement.value : 0
    );
    requestIdentifier = BigNumber.from(requestIdentifier ?? 0);
    const chainId =
      destination !== undefined
        ? BigNumber.from(destination.chainId)
        : BigNumber.from(0);

    const zeroPaddedSourceIdentifier = ethers.utils.hexZeroPad(
      source.identifier.toHexString(),
      20
    );

    const poseidon = await buildPoseidon();
    const emptyMerklePath = {
      elements: new Array(ACCOUNTS_TREE_HEIGHT).fill(BigNumber.from(0)),
      indices: new Array(ACCOUNTS_TREE_HEIGHT).fill(0),
    };

    const accountsTree = statement ? statement.accountsTree : undefined;
    const registryTree = statement ? statement.registryTree : undefined;

    if (accountsTree !== undefined && registryTree === undefined) {
      throw new Error("accountsTree and registryTree must be defined together");
    }

    const accountMerklePath =
      accountsTree !== undefined
        ? accountsTree.getMerklePathFromKey(zeroPaddedSourceIdentifier)
        : emptyMerklePath;
    const sourceValue =
      accountsTree !== undefined
        ? accountsTree.getValue(zeroPaddedSourceIdentifier)
        : BigNumber.from(0);

    const registryMerklePath: MerklePath =
      accountsTree !== undefined
        ? registryTree!.getMerklePathFromKey(
            accountsTree.getRoot().toHexString()
          )
        : emptyMerklePath;
    const accountsTreeValue =
      accountsTree !== undefined
        ? registryTree!.getValue(accountsTree.getRoot().toHexString())
        : BigNumber.from(0);

    const accountsTreeRoot =
      accountsTree !== undefined
        ? accountsTree.getRoot().toBigInt()
        : BigInt(0);

    const registryTreeRoot =
      registryTree !== undefined
        ? registryTree.getRoot().toBigInt()
        : BigInt(0);

    const sourceSecretHash = poseidon([source.secret, 1]);
    const proofIdentifier = !requestIdentifier.eq(0)
      ? poseidon([sourceSecretHash, requestIdentifier])
      : BigNumber.from(0);

    const mapArrayToBigInt = (arr: BigNumberish[]) =>
      arr.map((el) => BigNumber.from(el).toBigInt());

    const privateInputs: PrivateInputs = {
      vaultSecret: vaultSecret.toBigInt(),
      sourceIdentifier: source.identifier.toBigInt(),
      sourceSecret: source.secret.toBigInt(),
      sourceCommitmentReceipt: source.commitmentReceipt.map((el) =>
        BigNumber.from(el).toBigInt()
      ),
      destinationSecret: destinationSecret.toBigInt(),
      destinationCommitmentReceipt: destinationCommitmentReceipt.map((el) =>
        BigNumber.from(el).toBigInt()
      ),
      accountsTreeRoot: accountsTreeRoot,
      accountMerklePathElements: mapArrayToBigInt(accountMerklePath.elements),
      accountMerklePathIndices: accountMerklePath.indices,
      registryMerklePathElements: mapArrayToBigInt(registryMerklePath.elements),
      registryMerklePathIndices: registryMerklePath.indices,
      sourceValue: sourceValue.toBigInt(),
    };

    const publicInputs: PublicInputs = {
      vaultNamespace: vaultNamespace.toBigInt(),
      vaultIdentifier: vaultIdentifier.toBigInt(),
      destinationIdentifier: destinationIdentifier.toBigInt(),
      chainId: chainId ? chainId.toBigInt() : BigInt(0),
      commitmentMapperPubKey: this.commitmentMapperPubKey.map((el) =>
        el.toBigInt()
      ),
      registryTreeRoot: registryTreeRoot,
      requestIdentifier: requestIdentifier.toBigInt(),
      proofIdentifier: proofIdentifier.toBigInt(),
      statementValue: statementValue.toBigInt(),
      accountsTreeValue: accountsTreeValue.toBigInt(),
      statementComparator: statement && statement.comparator ? 1 : 0,
    };

    return {
      privateInputs,
      publicInputs,
    };
  }

  public async userParamsValidation({
    vault,
    source,
    destination,
    statement,
    requestIdentifier,
  }: UserParams) {
    source.identifier = BigNumber.from(source.identifier);
    source.secret = BigNumber.from(source.secret);
    vault.secret = BigNumber.from(vault.secret);
    vault.namespace = BigNumber.from(vault.namespace);
    vault.identifier = BigNumber.from(vault.identifier);
    const destinationIdentifier = destination
      ? BigNumber.from(destination.identifier)
      : BigNumber.from(0);
    const destinationSecret = destination
      ? BigNumber.from(destination.secret)
      : BigNumber.from(0);
    const destinationCommitmentReceipt: [
      BigNumberish,
      BigNumberish,
      BigNumberish
    ] = destination
      ? destination.commitmentReceipt
      : [BigNumber.from(0), BigNumber.from(0), BigNumber.from(0)];

    const statementValue = BigNumber.from(statement ? statement.value : 0);
    const statementComparator = BigNumber.from(
      statement ? statement.comparator : 0
    );
    requestIdentifier = BigNumber.from(requestIdentifier);

    const zeroPaddedSourceIdentifier = ethers.utils.hexZeroPad(
      source.identifier.toHexString(),
      20
    );

    const accountsTree = statement ? statement.accountsTree : undefined;
    if (statement && accountsTree) {
      const registryTree = statement.registryTree;
      if (!registryTree) {
        throw new Error(
          "Registry tree should be defined when the accountsTree is defined"
        );
      }
      try {
        registryTree.getValue(accountsTree.getRoot().toHexString());
      } catch (e) {
        throw new Error("Accounts tree root not found in the Registry tree");
      }

      const registryHeight = registryTree.getHeight();
      if (registryHeight != REGISTRY_TREE_HEIGHT)
        throw new Error("Invalid Registry tree height");

      const accountHeight = accountsTree.getHeight();
      if (accountHeight != ACCOUNTS_TREE_HEIGHT)
        throw new Error("Invalid Accounts tree height");

      let sourceValue;
      try {
        sourceValue = accountsTree.getValue(zeroPaddedSourceIdentifier);
      } catch (e) {
        throw new Error(
          `Could not find the source ${zeroPaddedSourceIdentifier} in the Accounts tree`
        );
      }

      if (statementValue.gt(sourceValue)) {
        throw new Error(
          `Statement value ${statementValue.toHexString()} can't be superior to Source value`
        );
      }

      if (statementValue.lt(0)) {
        throw new Error(
          `Statement value ${statementValue.toHexString()} can't be negative`
        );
      }

      if (statementComparator.eq(1) && !statementValue.eq(sourceValue)) {
        throw new Error(
          `Statement value ${statementValue.toHexString()} must be equal with Source value when statementComparator == 1`
        );
      }
    }

    const isSourceCommitmentValid = await verifyCommitment(
      source.identifier,
      vault.secret,
      source.secret,
      source.commitmentReceipt,
      this.commitmentMapperPubKey
    );
    if (!isSourceCommitmentValid)
      throw new Error("Invalid source commitment receipt");

    const isDestinationCommitmentValid = await verifyCommitment(
      destinationIdentifier,
      vault.secret,
      destinationSecret,
      destinationCommitmentReceipt,
      this.commitmentMapperPubKey
    );
    if (!isDestinationCommitmentValid)
      throw new Error("Invalid destination commitment receipt");

    const SnarkField = BigNumber.from(SNARK_FIELD);
    if (requestIdentifier.gt(SnarkField)) {
      throw new Error(
        "RequestIdentifier overflow the snark field, please use request Identifier inside the snark field"
      );
    }
    if (source.identifier.gt(SnarkField)) {
      throw new Error(
        "Source identifier overflow the snark field, please use source identifier inside the snark field"
      );
    }
    if (source.secret.gt(SnarkField)) {
      throw new Error(
        "Source secret overflow the snark field, please use source secret inside the snark field"
      );
    }
    if (destinationIdentifier.gt(SnarkField)) {
      throw new Error(
        "Destination overflow the snark field, please use destination inside the snark field"
      );
    }
    if (destinationSecret.gt(SnarkField)) {
      throw new Error(
        "Destination secret overflow the snark field, please use destination secret inside the snark field"
      );
    }
    if (vault.namespace.gt(SnarkField)) {
      throw new Error(
        "Vault namespace overflow the snark field, please use vault namespace inside the snark field"
      );
    }
    if (vault.identifier.gt(SnarkField)) {
      throw new Error(
        "Vault identifier overflow the snark field, please use vault identifier inside the snark field"
      );
    }
    if (vault.secret.gt(SnarkField)) {
      throw new Error(
        "Vault secret overflow the snark field, please use vault secret inside the snark field"
      );
    }
    if (statementValue.gt(SnarkField)) {
      throw new Error(
        "Statement value overflow the snark field, please use statement value inside the snark field"
      );
    }
  }

  public async generateSnarkProof({
    vault,
    source,
    destination,
    statement,
    requestIdentifier,
  }: UserParams): Promise<SnarkProof> {
    await this.userParamsValidation({
      vault,
      source,
      destination,
      statement,
      requestIdentifier,
    });

    const { privateInputs, publicInputs } = await this.generateInputs({
      vault,
      source,
      destination,
      statement,
      requestIdentifier,
    });

    let files;
    if (process.env.MODULE_FORMAT == "esm" && this.esmOverrideCircuitPath) {
      files = this.esmOverrideCircuitPath;
    } else {
      files = {
        zkeyPath,
        wasmPath,
      };
    }

    const { proof, publicSignals } = await groth16.fullProve(
      { ...privateInputs, ...publicInputs },
      files.wasmPath,
      files.zkeyPath
    );

    return new SnarkProof(publicSignals, proof);
  }
}
