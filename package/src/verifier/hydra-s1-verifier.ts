import { BigNumber } from "ethers";
import { groth16 } from "snarkjs";
import vKey from "./hydra-s1-verification-key.json";

export class HydraS1Verifier {
  public static async verifyProof(
    a: BigNumber[],
    b: BigNumber[][],
    c: BigNumber[],
    input: BigNumber[]
  ): Promise<boolean> {
    const snarkProof = {
      pi_a: [...a, "1"],
      pi_b: [
        [b[0][1], b[0][0]],
        [b[1][1], b[1][0]],
        ["1", "0"],
      ],
      pi_c: [...c, "1"],
    };

    return await groth16.verify(vKey, input, snarkProof);
  }
}
