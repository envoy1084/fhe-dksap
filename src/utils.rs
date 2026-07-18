use secp256k1::PublicKey;
use sha3::{Digest, Keccak256};
use tfhe::integer::U256;

/// Big-endian secp256k1 group order.
pub const SECP256K1_ORDER_BYTES: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
    0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
];

pub(crate) fn bytes_be_to_u256(bytes: [u8; 32]) -> U256 {
    let high = u128::from_be_bytes(bytes[..16].try_into().expect("slice length is fixed"));
    let low = u128::from_be_bytes(bytes[16..].try_into().expect("slice length is fixed"));
    U256::from((low, high))
}

pub(crate) fn u256_to_bytes_be(value: U256) -> [u8; 32] {
    let (low, high) = value.to_low_high_u128();
    let mut bytes = [0; 32];
    bytes[..16].copy_from_slice(&high.to_be_bytes());
    bytes[16..].copy_from_slice(&low.to_be_bytes());
    bytes
}

pub(crate) fn ethereum_address_bytes(public_key: &PublicKey) -> [u8; 20] {
    let serialized = public_key.serialize_uncompressed();
    let hash = Keccak256::digest(&serialized[1..]);
    hash[12..]
        .try_into()
        .expect("Keccak-256 output is 32 bytes")
}

pub(crate) fn secp256k1_order() -> U256 {
    bytes_be_to_u256(SECP256K1_ORDER_BYTES)
}

#[cfg(test)]
mod tests {
    use super::{bytes_be_to_u256, u256_to_bytes_be};

    #[test]
    fn u256_big_endian_round_trips_boundaries() {
        for bytes in [[0; 32], [0xff; 32], [0x5a; 32]] {
            assert_eq!(u256_to_bytes_be(bytes_be_to_u256(bytes)), bytes);
        }
    }
}
