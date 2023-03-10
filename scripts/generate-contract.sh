
#!/bin/bash -e

# Uncomment next lines to update Trusted setup
# cd "$(git rev-parse --show-toplevel)"

# npx snarkjs zkey export solidityverifier artifacts/circuits/$1.zkey package/contracts/HydraS1Verifier.sol
# sed -i.bak "s/contract Verifier/contract HydraS1Verifier/g" package/contracts/HydraS1Verifier.sol
# sed -i.bak "s/pragma solidity ^0.6.11;/pragma solidity ^0.8.0;/g" package/contracts/HydraS1Verifier.sol
# rm -f "./package/contracts/HydraS1Verifier.sol.bak"