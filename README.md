<br />
<div align="center">
  <img src="https://static.sismo.io/readme/top-main.png" alt="Logo" width="150" height="150" style="borderRadius: 20px">

  <h3 align="center">
    Hydra-S1 ZKPS
  </h3>

  <p align="center">
    Hydra-S1 Zero-Knowledge Proving Scheme
  </p>

  <p align="center">
    Made by <a href="https://www.docs.sismo.io/" target="_blank">Sismo</a>
  </p>
  
  <p align="center">
    <a href="https://discord.gg/sismo" target="_blank">
        <img src="https://img.shields.io/badge/Discord-7289DA?style=for-the-badge&logo=discord&logoColor=white"/>
    </a>
    <a href="https://twitter.com/sismo_eth" target="_blank">
        <img src="https://img.shields.io/badge/Twitter-1DA1F2?style=for-the-badge&logo=twitter&logoColor=white"/>
    </a>
  </p>
  <a href="https://www.sismo.io/" target="_blank"></a>
</div>


Hydra-S1 is a Zero-Knowledge Proving Scheme used by [Hydra S1 attesters](https://github.com/sismo-core/sismo-protocol/tree/main/contracts/attesters/hydra-s1) of the Sismo Protocol.

Hydra-S1 generates ZK Proofs from a merkle tree storing groups of accounts with values (e.g group of ENS DAO voters where the account value is the number of votes). 

Hydra-S1 enables users to prove from these groups: 
- Ownerships: They own two accounts, a source account and a destination account. (via Hydra Delegate Proof of Ownership)
- Account inclusion: Their source account is part of a group (e.g group ENS DAO voters)
- Account value: Their source account holds a specific value (e.g number of votes in the group of ENS DAO voters) 
- Nullifier Generation: They computed a proofIdentifier from an requestIdentifier. The proofIdentifier is deterministically generated from their source account and the requestIdentifier. It can be stored by proof verifiers to only accept one ZK Proof per account per requestIdentifier.
  
Please make sure to read our documentation:
-  [Hydra-S1 general documentation](https://hydra-s1.docs.sismo.io)
-  [Registry Tree](https://registry-tree.docs.sismo.io) The custom merkle tree which stores the groups of accounts.
- [Hydra Proof of Ownership](https://hydra.docs.sismo.io) via the [Commitment Mapper](https://commitment-mapper.docs.sismo.io)

## Circuits and Package

Hydra-S1 Proving Scheme was developed using [circom](https://github.com/iden3/circom) and [snarkjs](https://github.com/iden3/snarkjs). This repo contains the circuits.

It outputs an off-chain prover and verifiers (both on-chain and off-chain).

Theses implementations of prover and verifiers are in the [@sismo-core/hydra-s1](./package) npm package.

```sh
$ yarn add @sismo-core/hydra-s1
```

## Installation

- Install [Circom2](https://docs.circom.io/getting-started/installation/) (rust version)
- Build

```sh
$ yarn build
```

## Test

```sh
$ yarn test 
$ test:circuits
$ test:verifier-js
$ test:verifier-contract
$ test:prover-js
```

## License

Distributed under the MIT License.

## Contribute

Please, feel free to open issues, PRs or simply provide feedback!

## Contact

Prefer [Discord](https://discord.gg/sismo) or [Twitter](https://twitter.com/sismo_eth)

<br/>
<img src="https://static.sismo.io/readme/bottom-main.png" alt="bottom" width="100%" >