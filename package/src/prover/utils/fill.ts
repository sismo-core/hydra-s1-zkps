import { BigNumber } from "ethers";

export const fillArrayUntil = function <ArrayType>(
  array: ArrayType[],
  size: number,
  value: BigNumber | string = BigNumber.from(0)
) {
  return [...array, ...new Array(size - array.length).fill(value)];
};
