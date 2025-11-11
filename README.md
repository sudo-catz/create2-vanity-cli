# Sample Hardhat 3 Beta Project (`node:test` and `viem`)

This project showcases a Hardhat 3 Beta project using the native Node.js test runner (`node:test`) and the `viem` library for Ethereum interactions.

To learn more about the Hardhat 3 Beta, please visit the [Getting Started guide](https://hardhat.org/docs/getting-started#getting-started-with-hardhat-3). To share your feedback, join our [Hardhat 3 Beta](https://hardhat.org/hardhat3-beta-telegram-group) Telegram group or [open an issue](https://github.com/NomicFoundation/hardhat/issues/new) in our GitHub issue tracker.

## Project Overview

This example project includes:

- A simple Hardhat configuration file.
- Foundry-compatible Solidity unit tests.
- TypeScript integration tests using [`node:test`](nodejs.org/api/test.html), the new Node.js native test runner, and [`viem`](https://viem.sh/).
- Examples demonstrating how to connect to different types of networks, including locally simulating OP mainnet.

## Usage

### Running Tests

To run all the tests in the project, execute the following command:

```shell
npx hardhat test
```

You can also selectively run the Solidity or `node:test` tests:

```shell
npx hardhat test solidity
npx hardhat test nodejs
```

### Make a deployment to Sepolia

This project includes an example Ignition module to deploy the contract. You can deploy this module to a locally simulated chain or to Sepolia.

To run the deployment to a local chain:

```shell
npx hardhat ignition deploy ignition/modules/Counter.ts
```

To run the deployment to Sepolia, you need an account with funds to send the transaction. The provided Hardhat configuration includes a Configuration Variable called `SEPOLIA_PRIVATE_KEY`, which you can use to set the private key of the account you want to use.

You can set the `SEPOLIA_PRIVATE_KEY` variable using the `hardhat-keystore` plugin or by setting it as an environment variable.

To set the `SEPOLIA_PRIVATE_KEY` config variable using `hardhat-keystore`:

```shell
npx hardhat keystore set SEPOLIA_PRIVATE_KEY
```

After setting the variable, you can run the deployment with the Sepolia network:

```shell
npx hardhat ignition deploy --network sepolia ignition/modules/Counter.ts
```

## Deterministic / Vanity Deployments (CREATE2)

The repo now includes a minimal CREATE2 factory (`contracts/Create2Factory.sol`) and a helper script for finding vanity salts (`scripts/create2-vanity.ts`). Typical flow:

1. Deploy `Create2Factory` once per chain (any account can own it). The factory exposes `deploy(bytes32 salt, bytes bytecode)` for CREATE2 deployments and `computeAddress` for dry-runs.
2. Generate or brute-force a salt using the helper script. Example: find a `SimpleStorage` address ending in `beef` for a given factory:

   ```shell
   npm exec tsx scripts/create2-vanity.ts \
     -- --factory 0xYourFactoryAddress \
        --artifact artifacts/contracts/SimpleStorage.sol/SimpleStorage.json \
        --suffix beef \
        --attempts 250000
   ```

   The script shows the salt, target address, and init-code hash when it finds a match. You can also pass `--salt 0x...` to compute a single address without brute force.
3. Use that salt with the factory’s `deploy` function (on every chain you care about) to guarantee the same contract address, regardless of the deployer’s nonce history.

This approach lets you pre-fund addresses safely and keep SimpleStorage (or any other contract) aligned across Ethereum, Base, etc., while optionally choosing vanity prefixes/suffixes.

### Faster Rust Vanity Finder

For large searches (e.g., `cafe…beef`) use the Rust CLI in `tools/create2-vanity-rs/`:

```shell
(cd tools/create2-vanity-rs && cargo run --release -- \
  --factory 0xYourFactoryAddress \
  --artifact ../../artifacts/contracts/SimpleStorage.sol/SimpleStorage.json \
  --prefix cafe \
  --suffix beef \
  --checksum-match \
  --attempts 50000000)
```

Add `--salt 0x...` to compute a single address without brute-forcing. Set `--checksum-match` if you want the prefix/suffix constraints applied to the EIP-55 checksum form (case-sensitive). Build once with `cargo build --release` and reuse the binary for repeated searches.

> Full CLI docs live at `tools/create2-vanity-rs/README.md`.

### Automated CREATE2 “stack” deploy (factory + target)

`scripts/create2-stack.ts` automates both layers of determinism:

1. It deploys `Create2Factory` itself via CREATE2 using the canonical Singleton Factory (`0x4e59…56C`). This keeps the factory address identical across chains (as long as you reuse the same salt + bytecode).
2. It then calls the freshly deployed factory to CREATE2 your actual contract (defaults to `SimpleStorage` but any artifact works).

Example (Base Sepolia):

```shell
CREATE2_FACTORY_SALT=0x.... \
CREATE2_SALT=0x.... \
CREATE2_DEPLOYER_PRIVATE_KEY=0x... \
CREATE2_RPC_URL=https://base-sepolia.example \
npm exec tsx scripts/create2-stack.ts -- --chain basesepolia --mode both
```

CLI overrides exist for every input:

- `--mode factory|contract|both` (default `both`)
- `--factory-salt` / `--contract-salt` (32-byte hex, shared across chains)
- `--factory-address` (use when you only need the contract deploy step)
- `--factory-artifact` / `--artifact` for non-default bytecode
- `--rpc`, `--pk`, `--chain`

When run in `contract`-only mode you can skip salts and provide `--factory-address` (or `CREATE2_FACTORY_ADDRESS`). The script prints the predicted addresses before broadcasting, checks if code already exists, and waits for receipts so you can immediately reuse the salts on other networks.
