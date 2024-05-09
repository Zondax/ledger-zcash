use aes::cipher::generic_array::typenum::{U16, U32, U8};
use aes::cipher::generic_array::GenericArray;
use aes::cipher::BlockEncrypt;
use aes::cipher::NewBlockCipher;
use aes::cipher::{BlockCipher, BlockCipherKey};
use aes::Aes256;

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

pub struct AesBOLOS {
    key: [u8; 32],
}

impl AesBOLOS {
    pub fn new(k: &[u8; 32]) -> AesBOLOS {
        AesBOLOS { key: *k }
    }
}

impl BlockCipher for AesBOLOS {
    type BlockSize = U16;
    type ParBlocks = U8;
}

impl NewBlockCipher for AesBOLOS {
    type KeySize = U32;

    #[inline(never)]
    fn new(key: &BlockCipherKey<Self>) -> Self {
        let v: [u8; 32] = key.as_slice().try_into().expect("Wrong length");
        AesBOLOS { key: v }
    }
}
impl BlockEncrypt for AesBOLOS {
    #[inline(never)]
    fn encrypt_block(&self, block: &mut GenericArray<u8, Self::BlockSize>) {
        let x: [u8; 16] = block.as_slice().try_into().expect("err");
        let y = aes256_encrypt_block(&self.key, &x);

        block.copy_from_slice(&y);
    }
}
