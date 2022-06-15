import { zkeyPath as zkeyPathEsm, wasmPath as wasmPathEsm } from "./files-esm";
import { zkeyPath as zkeyPathCjs, wasmPath as wasmPathCjs } from "./files-cjs";

export const zkeyPath =
  process.env.MODULE_FORMAT == "esm" ? zkeyPathEsm : zkeyPathCjs;
export const wasmPath =
  process.env.MODULE_FORMAT == "esm" ? wasmPathEsm : wasmPathCjs;
