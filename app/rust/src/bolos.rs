//! Rust interfaces to Ledger SDK APIs.

use cstr_core::CStr;
use rand::{CryptoRng, RngCore};

#[cfg(test)]
use blake2b_simd::{Hash as Blake2bHash, Params as Blake2bParams};

use blake2s_simd::{blake2s, Hash as Blake2sHash, Params as Blake2sParams};
use core::convert::TryInto;

use aes::{
    block_cipher_trait::{
        generic_array::typenum::{U16, U32, U8},
        generic_array::GenericArray,
        BlockCipher,
    },
    Aes256,
};

extern "C" {
    fn cx_rng(buffer: *mut u8, len: u32);
    fn c_zcash_blake2b_expand_seed(
        input_a: *const u8,
        input_a_len: u32,
        input_b: *const u8,
        input_b_len: u32,
        out: *mut u8,
    );
    fn c_aes256_encryptblock(k: *const u8, a: *const u8, out: *mut u8);
    fn c_zcash_blake2b_expand_vec_two(
        input_a: *const u8,
        input_a_len: u32,
        input_b: *const u8,
        input_b_len: u32,
        input_c: *const u8,
        input_c_len: u32,
        out: *mut u8,
    );

    // FIXME: We should probably consider exposing context + update to minimize so many arguments + stack usage
    fn c_zcash_blake2b_expand_vec_four(
        input_a: *const u8,
        input_a_len: u32,
        input_b: *const u8,
        input_b_len: u32,
        input_c: *const u8,
        input_c_len: u32,
        input_d: *const u8,
        input_d_len: u32,
        input_e: *const u8,
        input_e_len: u32,
        out: *mut u8,
    );
    fn c_zcash_blake2b_zip32master(a: *const u8, a_len: u32, out: *mut u8);

    fn zemu_log_stack(buffer: *const u8);
    fn check_app_canary();
    fn zcash_blake2b_expand_seed(a: *const u8, a_len: u32, b: *const u8, b_len: u32, out: *mut u8);
    fn zcash_blake2b_kdf_sapling(a: *const u8, a_len: u32, out: *mut u8);
    fn zcash_blake2b_prf_ock(a: *const u8, a_len: u32, out: *mut u8);
}
#[cfg(not(test))]
pub fn c_zemu_log_stack(s: &[u8]) {
    unsafe { zemu_log_stack(s.as_ptr()) }
}
#[cfg(test)]
pub fn c_zemu_log_stack(s: &[u8]) {}

pub fn c_check_app_canary() {
    unsafe { check_app_canary() }
}

#[cfg(not(test))]
pub fn blake2b_expand_seed(a: &[u8], b: &[u8]) -> [u8; 64] {
    let mut hash = [0; 64];
    unsafe {
        c_zcash_blake2b_expand_seed(
            a.as_ptr(),
            a.len() as u32,
            b.as_ptr(),
            b.len() as u32,
            hash.as_mut_ptr(),
        );
    }
    hash
}

#[cfg(not(test))]
pub fn blake2b_expand_vec_two(a: &[u8], b: &[u8], c: &[u8]) -> [u8; 64] {
    let mut hash = [0; 64];
    unsafe {
        c_zcash_blake2b_expand_vec_two(
            a.as_ptr(),
            a.len() as u32,
            b.as_ptr(),
            b.len() as u32,
            c.as_ptr(),
            c.len() as u32,
            hash.as_mut_ptr(),
        );
    }
    hash
}

#[cfg(not(test))]
pub fn blake2b_expand_vec_four(a: &[u8], b: &[u8], c: &[u8], d: &[u8], e: &[u8]) -> [u8; 64] {
    let mut hash = [0; 64];
    unsafe {
        c_zcash_blake2b_expand_vec_four(
            a.as_ptr(),
            a.len() as u32,
            b.as_ptr(),
            b.len() as u32,
            c.as_ptr(),
            c.len() as u32,
            d.as_ptr(),
            d.len() as u32,
            e.as_ptr(),
            e.len() as u32,
            hash.as_mut_ptr(),
        );
    }
    hash
}

#[cfg(not(test))]
pub fn aes256_encryptblock(k: &[u8], a: &[u8]) -> [u8; 16] {
    let mut out = [0u8; 16];
    unsafe {
        c_aes256_encryptblock(k.as_ptr(), a.as_ptr(), out.as_mut_ptr());
    }
    out
}

#[cfg(not(test))]
pub fn blake2b_kdf_sapling(a: &[u8]) -> [u8; 32] {
    let mut hash = [0; 32];
    unsafe {
        zcash_blake2b_kdf_sapling(a.as_ptr(), a.len() as u32, hash.as_mut_ptr());
    }
    hash
}

#[cfg(test)]
pub fn aes256_encryptblock(k: &[u8], a: &[u8]) -> [u8; 16] {
    let cipher: Aes256 = Aes256::new(GenericArray::from_slice(k));
    //cipher.encrypt_block(block);

    let mut b = GenericArray::clone_from_slice(a);
    cipher.encrypt_block(&mut b);

    let out: [u8; 16] = b.as_slice().try_into().expect("err");
    out
}

#[cfg(test)]
pub fn blake2b_kdf_sapling(a: &[u8]) -> [u8; 32] {
    pub const KDF_SAPLING_PERSONALIZATION: &[u8; 16] = b"Zcash_SaplingKDF";

    let h = Blake2bParams::new()
        .hash_length(32)
        .personal(KDF_SAPLING_PERSONALIZATION)
        .hash(a);

    let result: [u8; 32] = h.as_bytes().try_into().expect("wrong length");
    result
}

#[cfg(test)]
pub fn blake2b_prf_ock(a: &[u8]) -> [u8; 32] {
    pub const PRF_OCK_PERSONALIZATION: &[u8; 16] = b"Zcash_Derive_ock";

    let h = Blake2bParams::new()
        .hash_length(32)
        .personal(PRF_OCK_PERSONALIZATION)
        .hash(a);

    let result: [u8; 32] = h.as_bytes().try_into().expect("wrong length");
    result
}

#[cfg(not(test))]
pub fn blake2b_prf_ock(a: &[u8]) -> [u8; 32] {
    let mut hash = [0; 32];
    unsafe {
        zcash_blake2b_prf_ock(a.as_ptr(), a.len() as u32, hash.as_mut_ptr());
    }
    hash
}

#[cfg(test)]
pub fn blake2b_expand_seed(a: &[u8], b: &[u8]) -> [u8; 64] {
    pub const PRF_EXPAND_PERSONALIZATION: &[u8; 16] = b"Zcash_ExpandSeed";

    let h = Blake2bParams::new()
        .hash_length(64)
        .personal(PRF_EXPAND_PERSONALIZATION)
        .to_state()
        .update(a)
        .update(b)
        .finalize();

    let result: [u8; 64] = *h.as_array();
    result
}

// FIXME: Can we send this to the SDK?
#[inline(never)]
pub fn blake2s_diversification(tag: &[u8]) -> [u8; 32] {
    pub const KEY_DIVERSIFICATION_PERSONALIZATION: &[u8; 8] = b"Zcash_gd";
    pub const GH_FIRST_BLOCK: &[u8; 64] =
        b"096b36a5804bfacef1691e173c366a47ff5ba84a44f26ddd7e8d9f79d5b42df0";

    let h = Blake2sParams::new()
        .hash_length(32)
        .personal(KEY_DIVERSIFICATION_PERSONALIZATION)
        .to_state()
        .update(GH_FIRST_BLOCK)
        .update(tag)
        .finalize();

    let result: [u8; 32] = *h.as_array();
    result
}

#[cfg(test)]
pub fn blake2b_expand_vec_two(sk: &[u8], a: &[u8], b: &[u8]) -> [u8; 64] {
    pub const PRF_EXPAND_PERSONALIZATION: &[u8; 16] = b"Zcash_ExpandSeed";
    let mut h = Blake2bParams::new()
        .hash_length(64)
        .personal(PRF_EXPAND_PERSONALIZATION)
        .to_state();
    h.update(sk);
    h.update(a);
    h.update(b);
    let mut hash = [0u8; 64];
    hash.copy_from_slice(&h.finalize().as_bytes());
    hash
}

#[cfg(test)]
pub fn blake2b_zip32master(seed: &[u8]) -> [u8; 64] {
    pub const ZIP32_SAPLING_MASTER_PERSONALIZATION: &[u8; 16] = b"ZcashIP32Sapling";
    let h = Blake2bParams::new()
        .hash_length(64)
        .personal(ZIP32_SAPLING_MASTER_PERSONALIZATION)
        .hash(seed);

    let mut hash = [0u8; 64];
    hash.copy_from_slice(&h.as_bytes());
    hash
}

#[cfg(not(test))]
pub fn blake2b_zip32master(seed: &[u8]) -> [u8; 64] {
    let mut out = [0u8; 64];
    unsafe {
        c_zcash_blake2b_zip32master(seed.as_ptr(), seed.len() as u32, out.as_mut_ptr());
    }
    out
}

#[cfg(test)]
pub fn blake2b_expand_vec_four(a: &[u8], b: &[u8], c: &[u8], d: &[u8], e: &[u8]) -> [u8; 64] {
    pub const PRF_EXPAND_PERSONALIZATION: &[u8; 16] = b"Zcash_ExpandSeed";
    let mut h = Blake2bParams::new()
        .hash_length(64)
        .personal(PRF_EXPAND_PERSONALIZATION)
        .to_state();
    h.update(a);
    h.update(b);
    h.update(c);
    h.update(d);
    h.update(e);
    let mut hash = [0u8; 64];
    hash.copy_from_slice(&h.finalize().as_bytes());
    hash
}

pub struct Trng;

impl RngCore for Trng {
    fn next_u32(&mut self) -> u32 {
        let mut out = [0; 4];
        self.fill_bytes(&mut out);
        u32::from_le_bytes(out)
    }

    fn next_u64(&mut self) -> u64 {
        let mut out = [0; 8];
        self.fill_bytes(&mut out);
        u64::from_le_bytes(out)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        unsafe {
            cx_rng(dest.as_mut_ptr(), dest.len() as u32);
        }
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
        Ok(self.fill_bytes(dest))
    }
}

impl CryptoRng for Trng {}
