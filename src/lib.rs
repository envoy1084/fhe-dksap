//! FHE-DKSAP primitives for Ethereum-compatible stealth addresses.
//!
//! This crate implements the construction described in the Ethereum Research
//! FHE-DKSAP post: a sender adds an ephemeral secp256k1 public key to a
//! receiver's spending public key, while encrypting the matching ephemeral
//! scalar under the receiver's TFHE public key. An evaluator can homomorphically
//! add the encrypted scalars modulo the secp256k1 group order, and only the
//! receiver can decrypt the resulting spending key.
//!
//! # Important limitations
//!
//! This is an experimental protocol, not a standardized or independently
//! audited construction. FHE protects the scalar-recovery computation, but the
//! resulting Ethereum spending key still uses secp256k1 and is therefore not
//! post-quantum secure. See the repository's `SECURITY.md` for the threat model.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use core::fmt;

use secp256k1::{PublicKey as Secp256k1PublicKey, Secp256k1, SecretKey, rand};
use tfhe::{
    ClientKey, Config, FheUint256, PublicKey as FhePublicKey, ServerKey, generate_keys,
    prelude::{FheDecrypt, FheEncrypt, FheOrd, IfThenElse, Tagged},
    with_server_key_as_context,
};

mod utils;

pub use utils::SECP256K1_ORDER_BYTES;

/// Errors returned by FHE-DKSAP protocol operations.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// The two secp256k1 points add to the point at infinity.
    #[error("the spending and ephemeral public keys cancel to the point at infinity")]
    PointAtInfinity,

    /// Ciphertexts and keys do not belong to the same TFHE key set.
    #[error("TFHE key tag mismatch; ciphertexts and keys must use one receiver key set")]
    FheKeyMismatch,

    /// Homomorphic reduction produced zero, which is not a valid secp256k1 secret.
    #[error("the recovered scalar is zero and cannot be a secp256k1 secret key")]
    ZeroScalar,

    /// The recovered bytes were not a valid secp256k1 scalar.
    #[error("the recovered scalar is not a valid secp256k1 secret key: {0}")]
    InvalidScalar(String),
}

/// Result type used by this crate.
pub type Result<T> = core::result::Result<T, Error>;

/// A secp256k1 secret/public key pair.
#[derive(Clone)]
pub struct EthereumKeyPair {
    secret_key: SecretKey,
    public_key: Secp256k1PublicKey,
}

impl EthereumKeyPair {
    /// Constructs a key pair from an existing secret key.
    #[must_use]
    pub fn from_secret_key<C: secp256k1::Signing>(
        secp: &Secp256k1<C>,
        secret_key: SecretKey,
    ) -> Self {
        let public_key = secret_key.public_key(secp);
        Self {
            secret_key,
            public_key,
        }
    }

    /// Returns the secret key.
    #[must_use]
    pub const fn secret_key(&self) -> &SecretKey {
        &self.secret_key
    }

    /// Returns the public key.
    #[must_use]
    pub const fn public_key(&self) -> &Secp256k1PublicKey {
        &self.public_key
    }
}

impl fmt::Debug for EthereumKeyPair {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EthereumKeyPair")
            .field("secret_key", &"<redacted>")
            .field("public_key", &self.public_key)
            .finish()
    }
}

/// The receiver's TFHE client, server, and public keys.
///
/// The client key is secret. The public key is safe to give to senders and the
/// server key is safe to give to evaluators, although both public artifacts can
/// be large. The generated TFHE tag is an accidental-misuse guard; it is not an
/// authentication mechanism and must not replace authenticated transport.
pub struct FheKeyPair {
    client_key: ClientKey,
    server_key: ServerKey,
    public_key: FhePublicKey,
}

impl FheKeyPair {
    /// Returns the secret TFHE client key used for decryption.
    #[must_use]
    pub const fn client_key(&self) -> &ClientKey {
        &self.client_key
    }

    /// Returns the public TFHE evaluation key.
    #[must_use]
    pub const fn server_key(&self) -> &ServerKey {
        &self.server_key
    }

    /// Returns the TFHE encryption key that can be shared with senders.
    #[must_use]
    pub const fn public_key(&self) -> &FhePublicKey {
        &self.public_key
    }
}

impl fmt::Debug for FheKeyPair {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FheKeyPair")
            .field("client_key", &"<redacted>")
            .field("server_key", &"<evaluation key>")
            .field("public_key", &"<encryption key>")
            .finish()
    }
}

/// A 20-byte Ethereum address.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct EthereumAddress([u8; 20]);

impl EthereumAddress {
    /// Constructs an address from its exact 20-byte representation.
    #[must_use]
    pub const fn new(bytes: [u8; 20]) -> Self {
        Self(bytes)
    }

    /// Returns the raw 20 address bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 20] {
        &self.0
    }
}

impl fmt::Display for EthereumAddress {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "0x{}", hex::encode(self.0))
    }
}

impl fmt::Debug for EthereumAddress {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, formatter)
    }
}

/// The public announcement a sender publishes for one payment.
///
/// It intentionally does not expose or retain the sender's ephemeral secret.
pub struct StealthAddress {
    address: EthereumAddress,
    encrypted_ephemeral_secret: FheUint256,
}

impl StealthAddress {
    /// Returns the destination Ethereum address.
    #[must_use]
    pub const fn address(&self) -> EthereumAddress {
        self.address
    }

    /// Returns the encrypted sender scalar to publish with the announcement.
    #[must_use]
    pub const fn encrypted_ephemeral_secret(&self) -> &FheUint256 {
        &self.encrypted_ephemeral_secret
    }

    /// Consumes the announcement and returns its public parts.
    #[must_use]
    pub fn into_parts(self) -> (EthereumAddress, FheUint256) {
        (self.address, self.encrypted_ephemeral_secret)
    }
}

impl fmt::Debug for StealthAddress {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StealthAddress")
            .field("address", &self.address)
            .field("encrypted_ephemeral_secret", &"<ciphertext>")
            .finish()
    }
}

/// Generates a cryptographically random secp256k1 key pair.
#[must_use]
pub fn generate_ethereum_key_pair<C: secp256k1::Signing>(secp: &Secp256k1<C>) -> EthereumKeyPair {
    let (secret_key, public_key) = secp.generate_keypair(&mut rand::rng());
    EthereumKeyPair {
        secret_key,
        public_key,
    }
}

/// Generates one tagged TFHE client/server/public key set.
///
/// Key generation is expensive and the receiver is expected to reuse this key
/// set. Use security parameters appropriate for the deployment.
#[must_use]
pub fn generate_fhe_key_pair(config: Config) -> FheKeyPair {
    let (mut client_key, mut server_key) = generate_keys(config);

    let tag = rand::random::<u128>();
    client_key.tag_mut().set_u128(tag);
    server_key.tag_mut().set_u128(tag);

    let public_key = FhePublicKey::new(&client_key);
    FheKeyPair {
        client_key,
        server_key,
        public_key,
    }
}

/// Encrypts a secp256k1 secret key for the receiver.
#[must_use]
pub fn encrypt_secret_key(secret_key: &SecretKey, public_key: &FhePublicKey) -> FheUint256 {
    FheUint256::encrypt(
        utils::bytes_be_to_u256(secret_key.secret_bytes()),
        public_key,
    )
}

/// Adds two secp256k1 public keys.
///
/// # Errors
///
/// Returns [`Error::PointAtInfinity`] when the points cancel each other.
pub fn combine_public_keys(
    first: &Secp256k1PublicKey,
    second: &Secp256k1PublicKey,
) -> Result<Secp256k1PublicKey> {
    first.combine(second).map_err(|_| Error::PointAtInfinity)
}

/// Creates a fresh one-time stealth-address announcement.
///
/// # Errors
///
/// Returns [`Error::PointAtInfinity`] in the negligible event that the two
/// public keys cancel. Callers may retry with a new ephemeral key.
pub fn generate_stealth_address<C: secp256k1::Signing>(
    secp: &Secp256k1<C>,
    receiver_spending_public_key: &Secp256k1PublicKey,
    receiver_fhe_public_key: &FhePublicKey,
) -> Result<StealthAddress> {
    let ephemeral = generate_ethereum_key_pair(secp);
    generate_stealth_address_with_secret(
        secp,
        receiver_spending_public_key,
        receiver_fhe_public_key,
        ephemeral.secret_key(),
    )
}

/// Creates a stealth-address announcement from a caller-supplied ephemeral key.
///
/// This is useful for deterministic tests, hardware wallets, and applications
/// that manage randomness outside this crate. Never reuse an ephemeral secret.
///
/// # Errors
///
/// Returns [`Error::PointAtInfinity`] when the public keys cancel.
pub fn generate_stealth_address_with_secret<C: secp256k1::Signing>(
    secp: &Secp256k1<C>,
    receiver_spending_public_key: &Secp256k1PublicKey,
    receiver_fhe_public_key: &FhePublicKey,
    ephemeral_secret: &SecretKey,
) -> Result<StealthAddress> {
    let ephemeral_public_key = ephemeral_secret.public_key(secp);
    let combined = combine_public_keys(&ephemeral_public_key, receiver_spending_public_key)?;

    Ok(StealthAddress {
        address: ethereum_address(&combined),
        encrypted_ephemeral_secret: encrypt_secret_key(ephemeral_secret, receiver_fhe_public_key),
    })
}

/// Homomorphically computes `(receiver + ephemeral) mod n`.
///
/// This step requires only the public TFHE server key, so it can be outsourced.
/// The branch avoids overflowing the 256-bit ciphertext when the mathematical
/// sum is greater than or equal to the secp256k1 order `n`.
///
/// # Errors
///
/// Returns [`Error::FheKeyMismatch`] when either ciphertext's TFHE tag differs
/// from the evaluation key tag.
pub fn evaluate_encrypted_stealth_secret(
    server_key: &ServerKey,
    encrypted_receiver_secret: &FheUint256,
    encrypted_ephemeral_secret: &FheUint256,
) -> Result<FheUint256> {
    ensure_same_fhe_key(server_key, encrypted_receiver_secret)?;
    ensure_same_fhe_key(server_key, encrypted_ephemeral_secret)?;

    Ok(with_server_key_as_context(server_key.clone(), || {
        let threshold = utils::secp256k1_order() - encrypted_ephemeral_secret;
        encrypted_receiver_secret.ge(&threshold).if_then_else(
            &(encrypted_receiver_secret - &threshold),
            &(encrypted_ephemeral_secret + encrypted_receiver_secret),
        )
    }))
}

/// Decrypts an evaluated ciphertext into the stealth-address spending key.
///
/// # Errors
///
/// Returns [`Error::FheKeyMismatch`] for the wrong client key,
/// [`Error::ZeroScalar`] for the point-at-infinity result, or
/// [`Error::InvalidScalar`] for any other invalid scalar.
pub fn decrypt_stealth_secret<C: secp256k1::Signing>(
    secp: &Secp256k1<C>,
    client_key: &ClientKey,
    encrypted_stealth_secret: &FheUint256,
) -> Result<EthereumKeyPair> {
    ensure_same_fhe_key(client_key, encrypted_stealth_secret)?;

    let scalar = encrypted_stealth_secret.decrypt(client_key);
    let bytes = utils::u256_to_bytes_be(scalar);
    if bytes == [0; 32] {
        return Err(Error::ZeroScalar);
    }

    let secret_key = SecretKey::from_byte_array(bytes)
        .map_err(|error| Error::InvalidScalar(error.to_string()))?;
    Ok(EthereumKeyPair::from_secret_key(secp, secret_key))
}

/// Evaluates and decrypts a stealth-address spending key in one call.
///
/// Use [`evaluate_encrypted_stealth_secret`] and [`decrypt_stealth_secret`]
/// separately when evaluation is outsourced.
///
/// # Errors
///
/// Returns the errors documented by the two underlying operations.
pub fn recover_secret_key<C: secp256k1::Signing>(
    secp: &Secp256k1<C>,
    fhe_key_pair: &FheKeyPair,
    encrypted_receiver_secret: &FheUint256,
    encrypted_ephemeral_secret: &FheUint256,
) -> Result<EthereumKeyPair> {
    let evaluated = evaluate_encrypted_stealth_secret(
        fhe_key_pair.server_key(),
        encrypted_receiver_secret,
        encrypted_ephemeral_secret,
    )?;
    decrypt_stealth_secret(secp, fhe_key_pair.client_key(), &evaluated)
}

/// Converts an uncompressed secp256k1 public key to an Ethereum address.
#[must_use]
pub fn ethereum_address(public_key: &Secp256k1PublicKey) -> EthereumAddress {
    EthereumAddress::new(utils::ethereum_address_bytes(public_key))
}

fn ensure_same_fhe_key<K: Tagged>(key: &K, ciphertext: &FheUint256) -> Result<()> {
    if key.tag().is_empty() || key.tag() != ciphertext.tag() {
        return Err(Error::FheKeyMismatch);
    }
    Ok(())
}
