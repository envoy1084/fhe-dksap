use std::hint::black_box;
use std::time::Duration;

use criterion::{Criterion, criterion_group, criterion_main};
use fhe_dksap::{
    combine_public_keys, encrypt_secret_key, ethereum_address, evaluate_encrypted_stealth_secret,
    generate_fhe_key_pair,
};
use secp256k1::{Secp256k1, SecretKey};
use tfhe::ConfigBuilder;

fn public_operations(criterion: &mut Criterion) {
    let secp = Secp256k1::new();
    let first = SecretKey::from_byte_array([1; 32])
        .expect("benchmark scalar is valid")
        .public_key(&secp);
    let second = SecretKey::from_byte_array([2; 32])
        .expect("benchmark scalar is valid")
        .public_key(&secp);

    criterion.bench_function("combine secp256k1 public keys", |bencher| {
        bencher.iter(|| combine_public_keys(black_box(&first), black_box(&second)))
    });
    criterion.bench_function("derive Ethereum address", |bencher| {
        bencher.iter(|| ethereum_address(black_box(&first)))
    });
}

fn fhe_operations(criterion: &mut Criterion) {
    // Secure TFHE key generation is intentionally opt-in because it is both
    // memory- and time-intensive. This also keeps `cargo test --all-targets`
    // useful as a fast smoke check of the benchmark binary.
    if std::env::var("FHEDKSAP_BENCH_FHE").as_deref() != Ok("1") {
        return;
    }

    let keys = generate_fhe_key_pair(ConfigBuilder::default().build());
    let receiver = SecretKey::from_byte_array([1; 32]).expect("benchmark scalar is valid");
    let ephemeral = SecretKey::from_byte_array([2; 32]).expect("benchmark scalar is valid");
    let encrypted_receiver = encrypt_secret_key(&receiver, keys.public_key());
    let encrypted_ephemeral = encrypt_secret_key(&ephemeral, keys.public_key());

    let mut group = criterion.benchmark_group("TFHE protocol operations");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(20));
    group.bench_function("encrypt secp256k1 scalar", |bencher| {
        bencher.iter(|| encrypt_secret_key(black_box(&ephemeral), keys.public_key()))
    });
    group.bench_function("evaluate encrypted scalar addition", |bencher| {
        bencher.iter(|| {
            evaluate_encrypted_stealth_secret(
                keys.server_key(),
                black_box(&encrypted_receiver),
                black_box(&encrypted_ephemeral),
            )
        })
    });
    group.finish();
}

criterion_group!(benches, public_operations, fhe_operations);
criterion_main!(benches);
