use std::error::Error;
use std::time::Instant;

use fhe_dksap::{
    encrypt_secret_key, ethereum_address, generate_ethereum_key_pair, generate_fhe_key_pair,
    generate_stealth_address, recover_secret_key,
};
use secp256k1::Secp256k1;
use tfhe::ConfigBuilder;

fn main() -> Result<(), Box<dyn Error>> {
    let started = Instant::now();
    let secp = Secp256k1::new();

    let receiver = generate_ethereum_key_pair(&secp);
    let fhe_keys = generate_fhe_key_pair(ConfigBuilder::default().build());
    let encrypted_receiver = encrypt_secret_key(receiver.secret_key(), fhe_keys.public_key());

    let announcement =
        generate_stealth_address(&secp, receiver.public_key(), fhe_keys.public_key())?;
    println!("stealth address: {}", announcement.address());

    let recovered = recover_secret_key(
        &secp,
        &fhe_keys,
        &encrypted_receiver,
        announcement.encrypted_ephemeral_secret(),
    )?;
    let recovered_address = ethereum_address(recovered.public_key());

    assert_eq!(announcement.address(), recovered_address);
    println!("verified encrypted recovery in {:?}", started.elapsed());
    Ok(())
}
