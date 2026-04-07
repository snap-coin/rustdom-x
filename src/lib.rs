#[macro_use]
extern crate log;

pub mod byte_string;
pub mod common;
pub mod hash;
pub mod m128;
pub mod memory;
pub mod program;
pub mod superscalar;
pub mod vm;

pub use crate::memory::VmMemory;
pub use crate::vm::new_vm;

#[cfg(test)]
mod tests {
    use crate::memory::VmMemory;
    use crate::vm::new_vm;
    use blake2b_simd::Hash;
    use std::sync::Arc;

    #[test]
    fn test_hashing() {
        let cache = Arc::new(VmMemory::full(b"test key 000"));
        let mut vm = new_vm(cache);

        for i in 0..10usize {
            let _hash = vm.calculate_hash(&vec![10u8; i * 1000]);
        }
    }

    #[test]
    fn test_hashing_is_stateless() {
        let cache = Arc::new(VmMemory::full(b"test key 000"));
        let mut vm = new_vm(cache);

        for i in 1..10usize {
            let hash_i_1 = vm.calculate_hash(&vec![i as u8; i * 1000]);
            let hash_10i_1 = vm.calculate_hash(&vec![(10 * i) as u8; i * 1000]);
            let hash_i_2 = vm.calculate_hash(&vec![i as u8; i * 1000]);
            let hash_10i_2 = vm.calculate_hash(&vec![(10 * i) as u8; i * 1000]);

            assert_eq!(hash_i_1.as_bytes(), hash_i_2.as_bytes());
            assert_eq!(hash_10i_1.as_bytes(), hash_10i_2.as_bytes());
            assert_ne!(hash_i_1.as_bytes(), hash_10i_1.as_bytes());
        }
    }

    #[test]
    fn test_hash_empty_input() {
        let cache = Arc::new(VmMemory::full(b"test key 000"));
        let mut vm = new_vm(cache);

        let hash_1 = vm.calculate_hash(&[]);
        let hash_2 = vm.calculate_hash(&[]);

        assert_eq!(hash_1, hash_2);
        // Note: Not an official test vector.
        assert_eq!(
            hash_1.to_hex().to_string(),
            "7bfae546a780892da6142b5b1316ac1d97c091ef529e66ab49a37867a984f0f5"
        );
    }

    #[test]
    fn test_hash_str_with_confirmation() {
        // Source: https://github.com/tevador/RandomX/blob/e0db3c4a8de36d77f50c12f7099bc37401cab88c/src/tests/tests.cpp#L1179-L1181
        let cache = Arc::new(VmMemory::full(b"test key 000"));
        let mut vm = new_vm(cache);

        let hash: Hash = vm.calculate_hash(b"This is a test");

        assert_eq!(
            hash.to_hex().to_string(),
            // v1 hash
            "639183aae1bf4c9a35884cb46b09cad9175f04efd7684e7262a0ac1c2f0b4e3f"
        );
    }

    #[test]
    fn test_hash_hex_with_confirmation() {
        // Source: https://github.com/tevador/RandomX/blob/e0db3c4a8de36d77f50c12f7099bc37401cab88c/src/tests/tests.cpp#L998
        let cache = Arc::new(VmMemory::full(b"test key 001"));
        let mut vm = new_vm(cache);

        // 0b0b98bea7e805e0010a2126d287a2a0cc833d312cb786385a7c2f9de69d25537f584a9bc9977b00000000666fd8753bf61a8631f12984e3fd44f4014eca629276817b56f32e9b68bd82f416
        let input = [
            0x0b, 0x0b, 0x98, 0xbe, 0xa7, 0xe8, 0x05, 0xe0, 0x01, 0x0a, 0x21, 0x26, 0xd2, 0x87,
            0xa2, 0xa0, 0xcc, 0x83, 0x3d, 0x31, 0x2c, 0xb7, 0x86, 0x38, 0x5a, 0x7c, 0x2f, 0x9d,
            0xe6, 0x9d, 0x25, 0x53, 0x7f, 0x58, 0x4a, 0x9b, 0xc9, 0x97, 0x7b, 0x00, 0x00, 0x00,
            0x00, 0x66, 0x6f, 0xd8, 0x75, 0x3b, 0xf6, 0x1a, 0x86, 0x31, 0xf1, 0x29, 0x84, 0xe3,
            0xfd, 0x44, 0xf4, 0x01, 0x4e, 0xca, 0x62, 0x92, 0x76, 0x81, 0x7b, 0x56, 0xf3, 0x2e,
            0x9b, 0x68, 0xbd, 0x82, 0xf4, 0x16,
        ];
        assert_eq!(input.len(), 76);
        let hash: Hash = vm.calculate_hash(&input);

        // RandomX v1 (pre-2026): c56414121acda1713c2f2a819d8ae38aed7c80c35c2a769298d34f03833cd5f1
        // RandomX v2 (Monero post-2026): c8e92c5f7c1946fecf06bc382b92e3111da38ee3e6a5ad90704e1a9d8aaf6e76
        assert_eq!(
            hash.to_hex().to_string(),
            "c56414121acda1713c2f2a819d8ae38aed7c80c35c2a769298d34f03833cd5f1"
        );
    }
}
