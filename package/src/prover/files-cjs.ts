export const wasmPath =
  process.env.MODULE_FORMAT != "esm" ? require.resolve("./hydra-s1.wasm") : null;
export const zkeyPath =
  process.env.MODULE_FORMAT != "esm" ? require.resolve("./hydra-s1.zkey") : null;
