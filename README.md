# FHE-DKSAP for Rust

[![CI](https://github.com/Envoy-VC/fhe-dksap/actions/workflows/ci.yml/badge.svg)](https://github.com/Envoy-VC/fhe-dksap/actions/workflows/ci.yml)
[![Coverage](https://github.com/Envoy-VC/fhe-dksap/actions/workflows/coverage.yml/badge.svg)](https://github.com/Envoy-VC/fhe-dksap/actions/workflows/coverage.yml)
[![docs.rs](https://img.shields.io/docsrs/fhe_dksap)](https://docs.rs/fhe_dksap)
[![Crates.io](https://img.shields.io/crates/v/fhe_dksap)](https://crates.io/crates/fhe_dksap)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

An experimental Rust implementation of the [FHE-DKSAP proposal](https://ethresear.ch/t/fhe-dksap-fully-homomorphic-encryption-based-dual-key-stealth-address-protocol/16213): Ethereum-compatible stealth-address recovery using additive fully homomorphic encryption.

> Security status: the implementation has received an internal code audit and extensive automated testing, but neither this crate nor the underlying protocol has been independently audited or standardized. Do not protect production funds with it without an external cryptographic review. Read [SECURITY.md](SECURITY.md) and the [audit report](docs/AUDIT.md).

## What it implements

The receiver creates a reusable secp256k1 spending key `sk₂` and a TFHE key set. For each payment, the sender creates a fresh ephemeral key `sk₁`:

```text
PK_z = PK₁ + PK₂
sk_z = (sk₁ + sk₂) mod n
PK_z = sk_z · G
```

The sender publishes the Ethereum address derived from `PK_z` and `Enc(sk₁)`. The receiver publishes or stores `Enc(sk₂)`. An evaluator holding only the public TFHE server key computes `Enc(sk_z)`; the receiver's secret TFHE client key is required to decrypt it.

This crate provides:

- correct secp256k1 point addition and Ethereum Keccak-256 address derivation;
- overflow-safe homomorphic scalar addition modulo the secp256k1 order;
- separate encryption, public evaluation, and secret decryption APIs;
- TFHE key-tag checks to catch accidental cross-key ciphertext mixing;
- deterministic APIs for hardware wallets and test vectors;
- real TFHE end-to-end tests, Criterion benchmarks, strict lints, and 100% line-coverage enforcement.

## Important boundaries

- This is not EIP-5564 compatible. It implements the linked research proposal, not the standardized EIP-5564 scheme.
- It is not end-to-end post-quantum secure. TFHE is lattice based, but funds are still controlled by a secp256k1 key and Ethereum currently verifies secp256k1 signatures.
- The crate supplies cryptographic primitives, not an anonymity network, on-chain announcement contract, wallet scanner, transaction signer, or authenticated serialization format.
- TFHE tags are mutable misuse-detection metadata, not authentication. Authenticate public keys, evaluation keys, and ciphertexts at the application layer.
- A fresh sender ephemeral key is mandatory for every payment. Receiver key reuse follows the proposal but increases the impact of receiver-key compromise.

## Requirements

- Rust 1.91.1 or newer
- substantial memory and CPU for production TFHE parameters

TFHE key generation and 256-bit evaluation are intentionally expensive. Generate the receiver key set once and reuse it according to your threat model. Debug builds are especially slow; use `--release` for the example and benchmarks.

## Installation

```toml
[dependencies]
fhe_dksap = "0.2"
secp256k1 = "0.31"
tfhe = { version = "1.6", default-features = false, features = ["integer"] }
```

The optional `avx512` feature enables TFHE-rs's AVX-512 backend. Only enable it when the deployment CPU supports the required instructions.

## End-to-end usage

```rust
use fhe_dksap::{
    encrypt_secret_key, ethereum_address, generate_ethereum_key_pair,
    generate_fhe_key_pair, generate_stealth_address, recover_secret_key,
};
use secp256k1::Secp256k1;
use tfhe::ConfigBuilder;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let secp = Secp256k1::new();

    // Receiver setup. Keep the spending secret and TFHE client key secret.
    let receiver = generate_ethereum_key_pair(&secp);
    let fhe_keys = generate_fhe_key_pair(ConfigBuilder::default().build());
    let encrypted_receiver =
        encrypt_secret_key(receiver.secret_key(), fhe_keys.public_key());

    // Sender creates one announcement using only receiver public material.
    let announcement = generate_stealth_address(
        &secp,
        receiver.public_key(),
        fhe_keys.public_key(),
    )?;

    // Receiver convenience path: evaluate and decrypt locally.
    let recovered = recover_secret_key(
        &secp,
        &fhe_keys,
        &encrypted_receiver,
        announcement.encrypted_ephemeral_secret(),
    )?;

    assert_eq!(announcement.address(), ethereum_address(recovered.public_key()));
    Ok(())
}
```

Run the complete example with production TFHE defaults:

```bash
cargo run --release --example user_flow
```

## Outsourced evaluation

The evaluator needs the receiver's public server key and the two ciphertexts, but not the TFHE client key:

```rust,ignore
let encrypted_stealth = evaluate_encrypted_stealth_secret(
    receiver_server_key,
    encrypted_receiver_secret,
    encrypted_ephemeral_secret,
)?;

// Only the receiver performs this step.
let spending_key = decrypt_stealth_secret(
    &secp,
    receiver_client_key,
    &encrypted_stealth,
)?;
```

Applications still need an authenticated transport and a way to associate announcements with the correct receiver key set.

## Development

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --all-features
cargo deny check
```

Tests use TFHE-rs-style non-secure functional parameters so CI can execute real homomorphic operations in seconds. They validate behavior, not the security strength of a deployment configuration.

### Coverage

Install the coverage runner once:

```bash
rustup component add llvm-tools-preview
cargo install cargo-llvm-cov --locked
```

Generate the same report enforced in CI:

```bash
cargo llvm-cov --locked --lib --tests --html \
  --output-dir target/llvm-cov --fail-under-lines 100
open target/llvm-cov/html/index.html
```

### Benchmarks

Fast public-operation benchmarks:

```bash
cargo bench --bench protocol
```

Production-parameter TFHE benchmarks are opt-in because key generation can require minutes and gigabytes of memory:

```bash
FHEDKSAP_BENCH_FHE=1 cargo bench --bench protocol
```

## Dependency policy

Direct dependencies are pinned to current stable releases compatible with the crate's MSRV. `cargo deny` rejects vulnerabilities, yanked crates, unknown registries, and unapproved licenses. TFHE-rs 1.6.3 transitively uses two unmaintained crates (`bincode 1.3.3` and `paste 1.0.15`); those advisories are narrowly documented in `deny.toml` because no downstream-safe replacement exists.

## License

MIT. See [LICENSE](LICENSE).
