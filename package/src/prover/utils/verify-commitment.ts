import { buildPoseidon, EddsaAccount } from "@sismo-core/crypto";
import { BigNumber, BigNumberish } from "ethers";

export const verifyCommitment = async (
  address: BigInt,
  vaultSecret: BigInt,
  accountSecret: BigInt,
  commitmentReceipt: BigInt[],
  commitmentMapperPubKey: [BigNumber, BigNumber]
) => {
  const poseidon = await buildPoseidon();
  const commitment = poseidon([vaultSecret, accountSecret]);
  const message = poseidon([address, commitment]);
  const mapArrayToBigNumber = (arr: BigInt[]) =>
    arr.map((el) => BigNumber.from(el));

  return EddsaAccount.verify(
    message,
    mapArrayToBigNumber(commitmentReceipt) as [
      BigNumberish,
      BigNumberish,
      BigNumberish
    ],
    commitmentMapperPubKey
  );
};
