import { BigNumber, ethers } from "ethers";

type ProofGroth16 = {
  pi_a: [BigNumber, BigNumber];
  pi_b: [[BigNumber, BigNumber], [BigNumber, BigNumber]];
  pi_c: [BigNumber, BigNumber];
};

export class SnarkProof {
  public input: BigNumber[];
  public a: [BigNumber, BigNumber];
  public b: [[BigNumber, BigNumber], [BigNumber, BigNumber]];
  public c: [BigNumber, BigNumber];

  constructor(input: BigNumber[], proof: ProofGroth16) {
    this.input = input;

    this.a = [proof.pi_a[0], proof.pi_a[1]];
    this.b = [
      [proof.pi_b[0][1], proof.pi_b[0][0]],
      [proof.pi_b[1][1], proof.pi_b[1][0]],
    ];
    this.c = [proof.pi_c[0], proof.pi_c[1]];
  }

  public toBytes() {
    return ethers.utils.defaultAbiCoder.encode(
      ["uint256[2]", "uint256[2][2]", "uint256[2]", "uint256[14]"],
      [this.a, this.b, this.c, this.input]
    );
  }
}
