# Security policy and threat model

## Status

FHE-DKSAP and this implementation are experimental. The code has been internally reviewed and tested, but there has been no independent cryptographic audit. A passing test suite is not evidence that a new cryptographic protocol is safe for production funds.

Report suspected vulnerabilities through a private GitHub security advisory for this repository. Do not open a public issue until a disclosure plan has been agreed.

## Intended guarantees

Under the security assumptions of TFHE-rs and secp256k1, and with authenticated inputs:

- a sender can derive a destination public key without learning the receiver's spending scalar;
- a public evaluator can add encrypted receiver and sender scalars without decrypting them;
- only the holder of the matching TFHE client key can decrypt the evaluated scalar;
- the recovered scalar corresponds to the announced combined public key;
- accidental use of ciphertexts from different TFHE key sets is rejected through tags.

## Explicit non-guarantees

- Post-quantum spending security: Ethereum spending remains based on secp256k1.
- Sender, receiver, amount, timing, or network-layer anonymity.
- Compatibility with EIP-5564 wallets or announcement contracts.
- Ciphertext authenticity, chosen-ciphertext security at the application boundary, or denial-of-service resistance against untrusted serialized inputs.
- Secure key storage, transaction signing, blockchain scanning, or transport.
- Cryptographic binding of TFHE tags. Tags are mutable metadata and only prevent accidental misuse.

## Key handling

- `EthereumKeyPair::secret_key` and `FheKeyPair::client_key` are secrets. Keep them out of logs, crash dumps, swap, telemetry, and backups that are not equivalently protected.
- `FheKeyPair::public_key` is an encryption key and may be shared with senders.
- `FheKeyPair::server_key` is an evaluation key and may be shared with evaluators. It can be very large.
- Generate a fresh sender ephemeral scalar for every announcement. Reuse links failures and can invalidate protocol assumptions.
- Authenticate all public keys and ciphertexts outside this crate. Never treat a matching TFHE tag as proof of origin.
- Prefer TFHE-rs safe/versioned serialization with strict size limits and parameter-conformance checks when building a wire format. This crate deliberately does not define one.

## Parameter selection

`ConfigBuilder::default()` uses TFHE-rs defaults, but deployments must review parameter security, failure probability, platform support, memory use, and performance for their own environment. The parameters embedded in `tests/protocol.rs` are deliberately insecure and must never be copied into production code.

## Residual implementation risks

- The high-level TFHE API uses thread-local evaluation-key context. The crate scopes this with `with_server_key_as_context`; callers should still isolate panics around untrusted workloads.
- Receiver key reuse creates a high-value long-lived decryption key and increases compromise impact.
- The research post is not a complete formal specification or security proof. Protocol-level attacks may exist even when this implementation matches its algebra.
- TFHE-rs 1.6.3 transitively depends on the unmaintained `bincode 1.3.3` and `paste 1.0.15` crates. The crate does not expose bincode as a wire format, and dependency checks track new advisories.
