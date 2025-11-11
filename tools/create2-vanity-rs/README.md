# EVM Smart Contract Vanity Address Generator

This Rust helper brute‑forces CREATE2 salts so you can land contracts (via `Create2Factory`) at vanity addresses. It consumes the existing Hardhat artifacts in this repo, so you can point it at any compiled contract without rewriting init code by hand.

## Features

- Reads the factory address + artifact bytecode, then hashes like a real CREATE2 deploy would.
- Brute‑forces salts with multi‑threaded Rayon workers (defaults to CPU core count).
- Optional checksum matching for case‑sensitive vanity constraints.
- Single‑shot mode (`--salt`) to predict the resulting address without brute force.

## Building

```bash
cd tools/create2-vanity-rs
cargo build --release
```

The binary will be at `target/release/create2-vanity`. You can also use `cargo run --release -- …` while iterating.

## Usage

```bash
cargo run --release -- \
  --factory 0xYourFactory \
  --artifact ../../artifacts/contracts/SimpleStorage.sol/SimpleStorage.json \
  --prefix cafe \
  --suffix f00d \
  --checksum-match
```

Key flags (mirrors `--help` output):

- `--factory <addr>` – the deployed `Create2Factory` address (20‑byte hex).
- `--artifact <path>` – Hardhat artifact JSON; default points to `SimpleStorage`.
- `--salt <hex>` – deterministic mode; prints the resulting address and exits.
- `--prefix <hex>` / `--suffix <hex>` – lowercase hex constraints unless checksum mode is enabled.
- `--checksum-match` – apply prefix/suffix to the EIP‑55 checksum form (case sensitive). Slower but nicer for mixed case vanity.
- `--attempts <n>` – optional cap (defaults to unlimited).
- `--threads <n>` – override Rayon worker count (defaults to available cores).

If you specify neither `--prefix` nor `--suffix`, you must pass `--salt`.

## Performance tips

- Each constrained nibble multiplies difficulty by 16; checksum mode effectively doubles that again per nibble. Plan runtimes accordingly (`bee…cafe` ≈ 1/16⁷, `cafe…babe` ≈ 1/16⁸, etc.).
- The CLI logs every 10k attempts per worker to show progress. For extremely long hunts you can redirect stdout to a file to avoid scrollback spam.
- To resume or partition work, run multiple instances with different RNG seeds (set `RUSTFLAGS="--cfg rand_chacha"` or patch the source to use deterministic seeds); CREATE2 salts need only be unique, they don’t depend on search order.

## Example: predict an address for a known salt

```bash
cargo run --release -- \
  --factory 0x3528225F82292570B366eB4da9727c3E1c9DfBdb \
  --artifact ../../artifacts/contracts/SimpleStorage.sol/SimpleStorage.json \
  --salt 0xc261bc78b72af4a03d00448cc9230d0a861eef6a85ab9a0ef33e0432b868a524
```

Output includes the deterministic CREATE2 child address and its checksum form so you can verify deployments before broadcasting.

## Tweaking

See `src/main.rs` for the brute‑force loop. Ideas if you want to squeeze more throughput before publishing:

- Swap `StdRng` for `SmallRng` or a counter‑based generator per thread.
- Precompute the packed `0xff || factory || salt || initHash` prefix so each iteration copies fewer bytes.
- Split status logging onto a single thread to avoid `println!` contention.

Pull requests welcome if you add tricks like distributed search or file‑based checkpoints.
