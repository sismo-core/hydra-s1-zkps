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
};

export type StatementInput = {
  value?: BigNumberish;
  // A comparator of 0 means the accounts value in the tree can be more than the value in the statement
  // A comparator of 1 means the accounts value in the tree must be equal to the value in the statement
  comparator?: number;
  registryTree: KVMerkleTree;
  accountsTree: KVMerkleTree;
};

export type SourceInput = HydraS1Account & { verificationEnabled: boolean };
export type DestinationInput = Partial<HydraS1Account> & {
  verificationEnabled: boolean;
};

export type UserParams = {
  vault: VaultInput;
  source?: SourceInput;
  destination?: DestinationInput;
  statement?: StatementInput;
  requestIdentifier?: BigNumberish;
  extraData?: BigNumberish;
};

export type formattedUserParams = {
  vaultSecret: BigInt;
  vaultNamespace: BigInt;
  vaultIdentifier: BigInt;
  sourceIdentifier: BigInt;
  sourceSecret: BigInt;
  sourceCommitmentReceipt: BigInt[];
  destinationIdentifier: BigInt;
  destinationSecret: BigInt;
  destinationCommitmentReceipt: BigInt[];
  statementValue: BigInt;
  requestIdentifier: BigInt;
  proofIdentifier: BigInt;
  statementComparator: BigInt;
  sourceVerificationEnabled: BigInt;
  destinationVerificationEnabled: BigInt;
  extraData: BigInt;
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

  public async format({
    vault,
    source,
    destination,
    statement,
    requestIdentifier: requestIdentifierInput,
    extraData: extraDataInput,
  }: UserParams): Promise<formattedUserParams> {
    const poseidon = await buildPoseidon();
    const vaultSecret = BigNumber.from(vault.secret).toBigInt();
    const vaultNamespace = BigNumber.from(vault.namespace).toBigInt();
    const vaultIdentifier = poseidon([vaultSecret, vaultNamespace]).toBigInt();
    const sourceIdentifier = BigNumber.from(source?.identifier ?? 0).toBigInt();
    const sourceSecret = BigNumber.from(source?.secret ?? 0).toBigInt();
    const mapArrayToBigInt = (arr: BigNumberish[]) =>
      arr.map((el) => BigNumber.from(el).toBigInt());
    const sourceCommitmentReceipt = source?.commitmentReceipt
      ? mapArrayToBigInt(source?.commitmentReceipt)
      : [BigInt(0), BigInt(0), BigInt(0)];
    const destinationIdentifier = BigNumber.from(
      destination?.identifier ?? 0
    ).toBigInt();
    const destinationSecret = BigNumber.from(
      destination?.secret ?? 0
    ).toBigInt();
    const destinationCommitmentReceipt = destination?.commitmentReceipt
      ? mapArrayToBigInt(destination?.commitmentReceipt)
      : [BigInt(0), BigInt(0), BigInt(0)];
    const sourceSecretHash = poseidon([sourceSecret, 1]);
    const requestIdentifier = BigNumber.from(
      requestIdentifierInput ?? 0
    ).toBigInt();
    const proofIdentifier =
      requestIdentifier !== BigInt(0)
        ? poseidon([sourceSecretHash, requestIdentifier]).toBigInt()
        : BigInt(0);

    const statementValue = BigNumber.from(statement?.value ?? 0).toBigInt();
    // requestIdentifier = BigNumber.from(requestIdentifier ?? 0);

    const statementComparator =
      statement?.comparator === 1 ? BigInt(1) : BigInt(0);

    const sourceVerificationEnabled =
      source?.verificationEnabled === true ? BigInt(1) : BigInt(0);
    const destinationVerificationEnabled =
      destination?.verificationEnabled === true ? BigInt(1) : BigInt(0);

    const extraData = BigNumber.from(extraDataInput ?? 0).toBigInt();

    return {
      vaultSecret,
      vaultNamespace,
      vaultIdentifier,
      sourceIdentifier,
      sourceSecret,
      sourceCommitmentReceipt,
      destinationIdentifier,
      destinationSecret,
      destinationCommitmentReceipt,
      requestIdentifier,
      statementValue,
      proofIdentifier,
      statementComparator,
      sourceVerificationEnabled,
      destinationVerificationEnabled,
      extraData: extraData,
    };
  }

  public async generateInputs({
    vault,
    source,
    destination,
    statement,
    requestIdentifier: requestIdentifierParam,
    extraData: extraDataInput,
  }: UserParams): Promise<Inputs> {
    const {
      vaultSecret,
      vaultNamespace,
      vaultIdentifier,
      sourceIdentifier,
      sourceSecret,
      sourceCommitmentReceipt,
      destinationIdentifier,
      destinationSecret,
      destinationCommitmentReceipt,
      requestIdentifier,
      statementValue,
      proofIdentifier,
      statementComparator,
      sourceVerificationEnabled,
      destinationVerificationEnabled,
      extraData: extraData,
    } = await this.format({
      vault,
      source,
      destination,
      statement,
      requestIdentifier: requestIdentifierParam,
      extraData: extraDataInput,
    });

    const accountsTree = statement?.accountsTree;
    const registryTree = statement?.registryTree;

    if (accountsTree !== undefined && registryTree === undefined) {
      throw new Error("accountsTree and registryTree must be defined together");
    }

    const emptyMerklePath = {
      elements: new Array(ACCOUNTS_TREE_HEIGHT).fill(BigNumber.from(0)),
      indices: new Array(ACCOUNTS_TREE_HEIGHT).fill(0),
    };

    const mapArrayToBigInt = (arr: BigNumberish[]) =>
      arr.map((el) => BigNumber.from(el).toBigInt());

    const zeroPaddedSourceIdentifier = ethers.utils.hexZeroPad(
      ethers.utils.hexlify(BigNumber.from(sourceIdentifier)),
      20
    );
    const accountMerklePath = accountsTree
      ? accountsTree.getMerklePathFromKey(zeroPaddedSourceIdentifier)
      : emptyMerklePath;
    const sourceValue = accountsTree
      ? accountsTree.getValue(zeroPaddedSourceIdentifier).toBigInt()
      : BigInt(0);

    const registryMerklePath: MerklePath = accountsTree
      ? registryTree!.getMerklePathFromKey(accountsTree.getRoot().toHexString())
      : emptyMerklePath;
    const accountsTreeValue = accountsTree
      ? registryTree!.getValue(accountsTree.getRoot().toHexString()).toBigInt()
      : BigInt(0);

    const accountsTreeRoot = accountsTree
      ? accountsTree.getRoot().toBigInt()
      : BigInt(0);

    const registryTreeRoot = registryTree
      ? registryTree.getRoot().toBigInt()
      : BigInt(0);

    const privateInputs: PrivateInputs = {
      vaultSecret,
      sourceIdentifier,
      sourceSecret,
      sourceCommitmentReceipt,
      destinationSecret,
      destinationCommitmentReceipt,
      accountsTreeRoot,
      accountMerklePathElements: mapArrayToBigInt(accountMerklePath.elements),
      accountMerklePathIndices: accountMerklePath.indices,
      registryMerklePathElements: mapArrayToBigInt(registryMerklePath.elements),
      registryMerklePathIndices: registryMerklePath.indices,
      sourceValue,
    };

    const publicInputs: PublicInputs = {
      vaultNamespace,
      vaultIdentifier,
      destinationIdentifier,
      commitmentMapperPubKey: mapArrayToBigInt(this.commitmentMapperPubKey),
      registryTreeRoot: registryTreeRoot,
      requestIdentifier: requestIdentifier,
      proofIdentifier: proofIdentifier,
      statementValue: statementValue,
      accountsTreeValue: accountsTreeValue,
      statementComparator,
      sourceVerificationEnabled,
      destinationVerificationEnabled,
      extraData,
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
    requestIdentifier: requestIdentifierParam,
  }: UserParams) {
    const {
      vaultSecret,
      vaultIdentifier,
      sourceIdentifier,
      sourceSecret,
      sourceCommitmentReceipt,
      destinationIdentifier,
      destinationSecret,
      destinationCommitmentReceipt,
      statementValue,
      proofIdentifier,
      statementComparator,
      sourceVerificationEnabled,
      destinationVerificationEnabled,
    } = await this.format({
      vault,
      source,
      destination,
      statement,
      requestIdentifier: requestIdentifierParam,
    });

    const accountsTree = statement?.accountsTree;
    if (accountsTree) {
      const registryTree = statement?.registryTree;
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
      const zeroPaddedSourceIdentifier = ethers.utils.hexZeroPad(
        ethers.utils.hexlify(BigNumber.from(sourceIdentifier)),
        20
      );
      try {
        sourceValue = accountsTree
          .getValue(zeroPaddedSourceIdentifier)
          .toBigInt();
      } catch (e) {
        throw new Error(
          `Could not find the source ${zeroPaddedSourceIdentifier} in the Accounts tree`
        );
      }

      if (statementValue > BigInt(sourceValue)) {
        throw new Error(
          `Statement value ${statementValue} can't be superior to Source value`
        );
      }

      if (statementValue < BigInt(0)) {
        throw new Error(`Statement value ${statementValue} can't be negative`);
      }

      if (statementComparator === BigInt(1) && statementValue !== sourceValue) {
        throw new Error(
          `Statement value ${statementValue} must be equal with Source value when statementComparator == 1`
        );
      }
    }

    if (sourceVerificationEnabled) {
      const isSourceCommitmentValid = await verifyCommitment(
        sourceIdentifier,
        vaultSecret,
        sourceSecret,
        sourceCommitmentReceipt,
        this.commitmentMapperPubKey
      );
      if (!isSourceCommitmentValid)
        throw new Error("Invalid source commitment receipt");
    }

    if (destinationVerificationEnabled) {
      const isDestinationCommitmentValid = await verifyCommitment(
        destinationIdentifier,
        vaultSecret,
        destinationSecret,
        destinationCommitmentReceipt,
        this.commitmentMapperPubKey
      );
      if (!isDestinationCommitmentValid)
        throw new Error("Invalid destination commitment receipt");
    }

    const SnarkField = SNARK_FIELD.toBigInt();
    if (proofIdentifier > SnarkField) {
      throw new Error(
        "ProodIdentifier overflow the snark field, please use request Identifier inside the snark field"
      );
    }
    if (vaultIdentifier > SnarkField) {
      throw new Error(
        "Source identifier overflow the snark field, please use source identifier inside the snark field"
      );
    }
  }

  public async generateSnarkProof({
    vault,
    source,
    destination,
    statement,
    requestIdentifier,
    extraData,
  }: UserParams): Promise<SnarkProof> {
    await this.userParamsValidation({
      vault,
      source,
      destination,
      statement,
      requestIdentifier,
      extraData,
    });

    const { privateInputs, publicInputs } = await this.generateInputs({
      vault,
      source,
      destination,
      statement,
      requestIdentifier,
      extraData,
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
