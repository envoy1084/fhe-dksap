# Internal implementation audit

Date: 2026-07-18  
Scope: Rust crate source, tests, examples, dependency graph, documentation, and release tooling  
Reference: [FHE-DKSAP Ethereum Research post](https://ethresear.ch/t/fhe-dksap-fully-homomorphic-encryption-based-dual-key-stealth-address-protocol/16213)

This is an internal engineering review, not an independent security audit or a formal proof of the research protocol.

## Protocol conformance

The implementation now enforces the proposal's core algebra:

```text
PK_z = PK₁ + PK₂
sk_z = (sk₁ + sk₂) mod n
PK_z = sk_z · G
```

Ethereum addresses are the final 20 bytes of Keccak-256 over the uncompressed public key without its `0x04` prefix. The homomorphic branch avoids a 256-bit overflow by comparing `sk₂ >= n - sk₁` before choosing subtraction or addition.

## Fixed findings

### Critical: TFHE client key exposed as an encryption key

The original published API accepted `ClientKey` where a sender-facing public key was required. A TFHE client key is the secret decryption key, so a conforming sender could not use the protocol without receiving receiver secret material. The API now derives and accepts `tfhe::PublicKey`; client, server, and public roles are separate and private inside `FheKeyPair`.

### High: FHE key roles were mislabeled

The original `FheKeyPair.public_key` contained a secret client key and `secret_key` contained a public evaluation server key. The corrected accessors are `client_key()`, `server_key()`, and `public_key()`, and debug output redacts key bodies.

### High: evaluation could not actually be outsourced

The original recovery function combined public evaluation and secret decryption and left a TFHE server key installed in thread-local state. Evaluation is now exposed independently through `evaluate_encrypted_stealth_secret`, while `decrypt_stealth_secret` requires the client key. Evaluation context is scoped and cleared by TFHE-rs after normal completion.

### Medium: no cross-key misuse detection

Ciphertexts encrypted for different receivers could be passed together. Generated client, server, public, and ciphertext objects now inherit a random TFHE tag, and evaluation/decryption reject tag mismatches. Tags are not cryptographic authentication and the limitation is documented.

### Medium: sender secret retained in a public announcement

`StealthAddress` previously contained the complete ephemeral `EthereumKeyPair`, making accidental logging and retention of the sender scalar likely. It now contains only the destination address and encrypted ephemeral scalar. A deterministic constructor accepts a borrowed scalar without storing or returning it.

### Medium: invalid curve boundary results were not handled or tested

Public keys can cancel to the point at infinity, and scalar addition can reduce to zero. Both cases are now explicit errors with deterministic regression tests.

### Medium: no test or benchmark coverage

The original crate had zero tests. The suite now covers known Ethereum vectors, scalar/point equivalence, both modular branches, invalid scalars, key-tag mismatches, debug redaction, random and deterministic generation, and the real TFHE evaluation/decryption flow. Criterion covers public curve/address operations and opt-in production-parameter TFHE operations.

### Medium: vulnerable/yanked transitive lockfile versions

`crossbeam-epoch` was updated from 0.9.18 to 0.9.20 to resolve RUSTSEC-2026-0204. `keccak` was updated from yanked 0.1.5 to 0.1.6. Automated dependency policy now rejects vulnerabilities and yanked crates.

### Low: security claims exceeded the construction

Prior documentation called the whole protocol quantum resistant and claimed key-leakage elimination. The spending key remains secp256k1, long-lived receiver secrets remain compromise targets, and FHE alone does not provide network anonymity or ciphertext authenticity. The README and threat model now state these boundaries.

## Verification gates

- `cargo fmt --all -- --check`
- `cargo clippy --all-targets --all-features -- -D warnings`
- `cargo test --all-targets`
- rustdoc with warnings denied
- `cargo llvm-cov` with 100% line coverage required
- `cargo deny check`
- `cargo publish --dry-run`

## Residual risk and recommendation

The code is substantially safer and better specified than the original implementation, but production readiness cannot be established by repository hardening alone. Before real asset use, obtain an independent review of the protocol, TFHE parameter choice, wire formats, key lifecycle, announcement discovery, transaction signing, denial-of-service limits, and deployment environment.
