# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow semantic versioning.

## [0.2.0] - 2026-07-18

### Added

- Public TFHE encryption-key support and explicit client/server/public accessors.
- Separate homomorphic evaluation and receiver-only decryption APIs.
- Deterministic stealth-address generation for external randomness and test vectors.
- Ethereum address value type with redacted secret-bearing debug output.
- TFHE key-tag mismatch detection.
- End-to-end tests with 100% region, function, and line coverage.
- Criterion benchmarks, CI, coverage enforcement, dependency policy, threat model, and internal audit report.

### Changed

- Upgraded to Rust 2024, TFHE-rs 1.6.3, SHA-3 0.12.0, and current stable supporting crates.
- Scoped TFHE server-key context rather than leaving thread-local state installed.
- Public announcements no longer retain the sender's ephemeral secret key.
- Corrected documentation that previously described the entire construction as post-quantum secure.

### Fixed

- Receiver TFHE client keys are no longer exposed to senders as if they were public keys.
- Point-at-infinity and zero-scalar boundary cases now return explicit errors.
- Cross-key ciphertext mistakes are rejected before evaluation/decryption.
- Vulnerable `crossbeam-epoch` and yanked `keccak` lockfile versions were updated.

## [0.1.0] - 2025-07-05

- Initial research implementation.

[0.2.0]: https://github.com/Envoy-VC/fhe-dksap/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/Envoy-VC/fhe-dksap/releases/tag/v0.1.0
