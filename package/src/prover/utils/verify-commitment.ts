import { buildPoseidon, EddsaAccount } from "@sismo-core/crypto";
import { BigNumberish } from "ethers";

export const verifyCommitment = async (
  address: BigNumberish,
  vaultSecret: BigNumberish,
  accountSecret: BigNumberish,
  commitmentReceipt: [BigNumberish, BigNumberish, BigNumberish],
  commitmentMapperPubKey: [BigNumberish, BigNumberish]
) => {
  const poseidon = await buildPoseidon();
  const commitment = poseidon([vaultSecret, accountSecret]);
  const message = poseidon([address, commitment]);
  return EddsaAccount.verify(
    message,
    commitmentReceipt,
    commitmentMapperPubKey
  );
};
