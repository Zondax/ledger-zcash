use aes::Aes256;
use aes::block_cipher_trait::generic_array::GenericArray;
use aes::block_cipher_trait::BlockCipher;
use crate::bolos;

extern "C" {
    fn c_aes256_encryptblock(k: *const u8, a: *const u8, out: *mut u8);
}

/// Encrypts a block using AES-256.
/// This function uses a C function for encryption in non-test environments.
#[cfg(not(test))]
pub fn aes256_encrypt_block(k: &[u8], a: &[u8]) -> [u8; 16] {
    let mut out = [0u8; 16];
    unsafe {
        c_aes256_encryptblock(k.as_ptr(), a.as_ptr(), out.as_mut_ptr());
    }
    out
}

/// Encrypts a block using AES-256.
/// This function uses the Rust `aes` crate for encryption in test environments.
#[cfg(test)]
pub fn aes256_encrypt_block(k: &[u8], a: &[u8]) -> [u8; 16] {
    let cipher: Aes256 = Aes256::new(GenericArray::from_slice(k));

    let mut b = GenericArray::clone_from_slice(a);
    cipher.encrypt_block(&mut b);

    let out: [u8; 16] = b.as_slice().try_into().expect("err");
    out
}
