use std::sync::OnceLock;

use fhe_dksap::{
    Error, EthereumAddress, EthereumKeyPair, FheKeyPair, SECP256K1_ORDER_BYTES,
    combine_public_keys, decrypt_stealth_secret, encrypt_secret_key, ethereum_address,
    evaluate_encrypted_stealth_secret, generate_ethereum_key_pair, generate_fhe_key_pair,
    generate_stealth_address, generate_stealth_address_with_secret, recover_secret_key,
};
use secp256k1::{Secp256k1, SecretKey};
use tfhe::{
    ConfigBuilder, FheUint256,
    integer::U256,
    prelude::{FheEncrypt, Tagged},
    shortint::{
        CarryModulus, CiphertextModulus, ClassicPBSParameters, EncryptionKeyChoice, MaxNoiseLevel,
        MessageModulus,
        parameters::{
            DecompositionBaseLog, DecompositionLevelCount, DynamicDistribution, GlweDimension,
            LweDimension, ModulusSwitchType, PolynomialSize, StandardDev,
        },
    },
};

// Equivalent to TFHE-rs's cfg(tarpaulin)-only coverage parameter. This is real
// TFHE evaluation but deliberately not cryptographically secure.
const FUNCTIONAL_TEST_PARAMETERS: ClassicPBSParameters = ClassicPBSParameters {
    lwe_dimension: LweDimension(1),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(256),
    lwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        0.000_007_069_849_454_709_4,
    )),
    glwe_noise_distribution: DynamicDistribution::new_gaussian_from_std_dev(StandardDev(
        0.000_000_000_000_000_294_036_015_354_325_33,
    )),
    pbs_base_log: DecompositionBaseLog(23),
    pbs_level: DecompositionLevelCount(1),
    ks_level: DecompositionLevelCount(5),
    ks_base_log: DecompositionBaseLog(3),
    message_modulus: MessageModulus(4),
    carry_modulus: CarryModulus(4),
    max_noise_level: MaxNoiseLevel::new(5),
    log2_p_fail: -40.0,
    ciphertext_modulus: CiphertextModulus::new_native(),
    encryption_key_choice: EncryptionKeyChoice::Big,
    modulus_switch_noise_reduction_params: ModulusSwitchType::Standard,
};

fn secret(value: u8) -> SecretKey {
    let mut bytes = [0; 32];
    bytes[31] = value;
    SecretKey::from_byte_array(bytes).expect("small nonzero scalar is valid")
}

fn fhe_keys() -> &'static FheKeyPair {
    static KEYS: OnceLock<FheKeyPair> = OnceLock::new();
    // TFHE-rs exposes these deliberately insecure parameters for fast functional
    // coverage. Production callers must use security-reviewed parameters.
    KEYS.get_or_init(|| {
        generate_fhe_key_pair(
            ConfigBuilder::with_custom_parameters(FUNCTIONAL_TEST_PARAMETERS).build(),
        )
    })
}

#[test]
fn ethereum_address_matches_known_vector() {
    let secp = Secp256k1::new();
    let pair = EthereumKeyPair::from_secret_key(&secp, secret(1));
    let address = ethereum_address(pair.public_key());

    assert_eq!(
        address.to_string(),
        "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf"
    );
    assert_eq!(format!("{address:?}"), address.to_string());
    assert_eq!(EthereumAddress::new(*address.as_bytes()), address);
    assert!(format!("{pair:?}").contains("<redacted>"));
    assert_eq!(pair.secret_key(), &secret(1));
}

#[test]
fn public_key_addition_matches_scalar_addition_and_rejects_infinity() {
    let secp = Secp256k1::new();
    let one = secret(1);
    let two = secret(2);
    let three = secret(3);

    assert_eq!(
        combine_public_keys(&one.public_key(&secp), &two.public_key(&secp)).unwrap(),
        three.public_key(&secp)
    );

    let mut inverse_bytes = SECP256K1_ORDER_BYTES;
    inverse_bytes[31] -= 1;
    let inverse = SecretKey::from_byte_array(inverse_bytes).unwrap();
    assert_eq!(
        combine_public_keys(&one.public_key(&secp), &inverse.public_key(&secp)),
        Err(Error::PointAtInfinity)
    );
}

#[test]
fn generated_key_pairs_are_well_formed() {
    let secp = Secp256k1::new();
    let pair = generate_ethereum_key_pair(&secp);
    assert_eq!(pair.secret_key().public_key(&secp), *pair.public_key());

    let keys = fhe_keys();
    assert!(!keys.client_key().tag().is_empty());
    assert_eq!(keys.client_key().tag(), keys.server_key().tag());
    assert_eq!(keys.client_key().tag(), keys.public_key().tag());
    let debug = format!("{keys:?}");
    assert!(debug.contains("<redacted>"));
    assert!(debug.contains("<evaluation key>"));
    assert!(debug.contains("<encryption key>"));
}

#[test]
fn full_fhe_protocol_recovers_the_announced_address() {
    let secp = Secp256k1::new();
    let keys = fhe_keys();
    let receiver = EthereumKeyPair::from_secret_key(&secp, secret(1));
    let ephemeral = secret(2);
    let encrypted_receiver = encrypt_secret_key(receiver.secret_key(), keys.public_key());

    let announcement = generate_stealth_address_with_secret(
        &secp,
        receiver.public_key(),
        keys.public_key(),
        &ephemeral,
    )
    .unwrap();
    assert_eq!(
        announcement.address(),
        ethereum_address(&secret(3).public_key(&secp))
    );
    assert!(format!("{announcement:?}").contains("<ciphertext>"));

    let evaluated = evaluate_encrypted_stealth_secret(
        keys.server_key(),
        &encrypted_receiver,
        announcement.encrypted_ephemeral_secret(),
    )
    .unwrap();
    let recovered = decrypt_stealth_secret(&secp, keys.client_key(), &evaluated).unwrap();
    assert_eq!(recovered.secret_key(), &secret(3));
    assert_eq!(
        ethereum_address(recovered.public_key()),
        announcement.address()
    );

    let recovered_convenience = recover_secret_key(
        &secp,
        keys,
        &encrypted_receiver,
        announcement.encrypted_ephemeral_secret(),
    )
    .unwrap();
    assert_eq!(recovered_convenience.secret_key(), &secret(3));

    let random_announcement =
        generate_stealth_address(&secp, receiver.public_key(), keys.public_key()).unwrap();
    assert_ne!(random_announcement.address(), announcement.address());

    let parts_announcement = generate_stealth_address_with_secret(
        &secp,
        receiver.public_key(),
        keys.public_key(),
        &secret(4),
    )
    .unwrap();
    let (address, ciphertext) = parts_announcement.into_parts();
    assert_eq!(address, ethereum_address(&secret(5).public_key(&secp)));
    assert_eq!(ciphertext.tag(), keys.public_key().tag());
}

#[test]
fn fhe_key_mismatches_are_rejected_before_evaluation_or_decryption() {
    let secp = Secp256k1::new();
    let keys = fhe_keys();
    let encrypted = encrypt_secret_key(&secret(1), keys.public_key());
    let mut wrong_tag = encrypted.clone();
    wrong_tag.tag_mut().set_data(b"not-this-key");

    assert!(matches!(
        evaluate_encrypted_stealth_secret(keys.server_key(), &encrypted, &wrong_tag),
        Err(Error::FheKeyMismatch)
    ));
    assert!(matches!(
        decrypt_stealth_secret(&secp, keys.client_key(), &wrong_tag),
        Err(Error::FheKeyMismatch)
    ));

    let mut empty_tag = encrypted.clone();
    empty_tag.tag_mut().set_data(&[]);
    assert!(matches!(
        evaluate_encrypted_stealth_secret(keys.server_key(), &empty_tag, &encrypted),
        Err(Error::FheKeyMismatch)
    ));
}

#[test]
fn invalid_recovered_scalars_are_reported() {
    let secp = Secp256k1::new();
    let keys = fhe_keys();

    let mut inverse_bytes = SECP256K1_ORDER_BYTES;
    inverse_bytes[31] -= 1;
    let inverse = SecretKey::from_byte_array(inverse_bytes).unwrap();
    let encrypted_inverse = encrypt_secret_key(&inverse, keys.public_key());
    let encrypted_one = encrypt_secret_key(&secret(1), keys.public_key());
    let encrypted_zero =
        evaluate_encrypted_stealth_secret(keys.server_key(), &encrypted_inverse, &encrypted_one)
            .unwrap();
    assert!(matches!(
        decrypt_stealth_secret(&secp, keys.client_key(), &encrypted_zero),
        Err(Error::ZeroScalar)
    ));

    let invalid = FheUint256::encrypt(U256::from((u128::MAX, u128::MAX)), keys.public_key());
    assert!(matches!(
        decrypt_stealth_secret(&secp, keys.client_key(), &invalid),
        Err(Error::InvalidScalar(_))
    ));
}

#[test]
fn deterministic_generation_rejects_the_point_at_infinity() {
    let secp = Secp256k1::new();
    let keys = fhe_keys();
    let receiver = secret(1);
    let mut inverse_bytes = SECP256K1_ORDER_BYTES;
    inverse_bytes[31] -= 1;
    let inverse = SecretKey::from_byte_array(inverse_bytes).unwrap();

    assert!(matches!(
        generate_stealth_address_with_secret(
            &secp,
            &receiver.public_key(&secp),
            keys.public_key(),
            &inverse,
        ),
        Err(Error::PointAtInfinity)
    ));
}

#[test]
fn errors_have_actionable_messages() {
    assert_eq!(
        Error::PointAtInfinity.to_string(),
        "the spending and ephemeral public keys cancel to the point at infinity"
    );
    assert!(
        Error::FheKeyMismatch
            .to_string()
            .contains("key tag mismatch")
    );
    assert!(Error::ZeroScalar.to_string().contains("zero"));
    assert!(
        Error::InvalidScalar("bad scalar".into())
            .to_string()
            .contains("bad scalar")
    );
}
