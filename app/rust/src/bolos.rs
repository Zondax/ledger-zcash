//! Rust interfaces to Ledger SDK APIs.

use cstr_core::CStr;
use rand::{CryptoRng, RngCore};

#[cfg(test)]
use blake2b_simd::{Hash as Blake2bHash, Params as Blake2bParams};

use blake2s_simd::{blake2s, Hash as Blake2sHash, Params as Blake2sParams};
use core::convert::TryInto;

#[cfg(test)]
#[cfg(target_arch = "x86_64")]
use getrandom::getrandom;

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

    fn c_blake2b32_withpersonal(person: *const u8, input: *const u8, input_len: u32, out: *mut u8);
    fn c_blake2b64_withpersonal(person: *const u8, input: *const u8, input_len: u32, out: *mut u8);

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
    fn c_zcash_blake2b_redjubjub(a: *const u8, a_len: u32, b: *const u8, b_len: u32, out: *mut u8);
}

#[cfg(test)]
pub fn blake2b32_with_personalization(person: &[u8; 16], data: &[u8]) -> [u8; 32] {
    let h = Blake2bParams::new()
        .hash_length(32)
        .personal(person)
        .hash(data);
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&h.as_bytes());
    hash
}

#[cfg(not(test))]
pub fn blake2b32_with_personalization(person: &[u8; 16], data: &[u8]) -> [u8; 32] {
    let mut hash = [0; 32];
    unsafe {
        c_blake2b32_withpersonal(
            person.as_ptr(),
            data.as_ptr(),
            data.len() as u32,
            hash.as_mut_ptr(),
        );
    }
    hash
}

#[cfg(test)]
pub fn blake2b64_with_personalization(person: &[u8; 16], data: &[u8]) -> [u8; 64] {
    let h = Blake2bParams::new()
        .hash_length(64)
        .personal(person)
        .hash(data);
    let mut hash = [0u8; 64];
    hash.copy_from_slice(&h.as_bytes());
    hash
}

#[cfg(not(test))]
pub fn blake2b64_with_personalization(person: &[u8; 16], data: &[u8]) -> [u8; 64] {
    let mut hash = [0; 64];
    unsafe {
        c_blake2b64_withpersonal(
            person.as_ptr(),
            data.as_ptr(),
            data.len() as u32,
            hash.as_mut_ptr(),
        );
    }
    hash
}

#[cfg(test)]
pub fn blake2b_redjubjub(a: &[u8], b: &[u8]) -> [u8; 64] {
    pub const REDJUBJUB_PERSONALIZATION: &[u8; 16] = b"Zcash_RedJubjubH";

    let h = Blake2bParams::new()
        .hash_length(64)
        .personal(REDJUBJUB_PERSONALIZATION)
        .to_state()
        .update(a)
        .update(b)
        .finalize();

    let result: [u8; 64] = *h.as_array();
    result
}

#[cfg(not(test))]
pub fn blake2b_redjubjub(a: &[u8], b: &[u8]) -> [u8; 64] {
    let mut hash = [0; 64];
    unsafe {
        c_zcash_blake2b_redjubjub(
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
pub fn c_zemu_log_stack(s: &[u8]) {
    unsafe { zemu_log_stack(s.as_ptr()) }
}
#[cfg(test)]
pub fn c_zemu_log_stack(_s: &[u8]) {}

#[cfg(not(test))]
pub fn c_check_app_canary() {
    unsafe { check_app_canary() }
}

#[cfg(test)]
pub fn c_check_app_canary() {}

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
pub fn blake2b_expand_vec_two(in_a: &[u8], in_b: &[u8], in_c: &[u8]) -> [u8; 64] {
    let mut hash = [0; 64];
    unsafe {
        c_zcash_blake2b_expand_vec_two(
            in_a.as_ptr(),
            in_a.len() as u32,
            in_b.as_ptr(),
            in_b.len() as u32,
            in_c.as_ptr(),
            in_c.len() as u32,
            hash.as_mut_ptr(),
        );
    }
    hash
}

#[cfg(not(test))]
pub fn blake2b_expand_vec_four(
    in_a: &[u8],
    in_b: &[u8],
    in_c: &[u8],
    in_d: &[u8],
    in_e: &[u8],
) -> [u8; 64] {
    let mut hash = [0; 64];
    unsafe {
        c_zcash_blake2b_expand_vec_four(
            in_a.as_ptr(),
            in_a.len() as u32,
            in_b.as_ptr(),
            in_b.len() as u32,
            in_c.as_ptr(),
            in_c.len() as u32,
            in_d.as_ptr(),
            in_d.len() as u32,
            in_e.as_ptr(),
            in_e.len() as u32,
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
pub fn blake2b_expand_vec_four(
    in_a: &[u8],
    in_b: &[u8],
    in_c: &[u8],
    in_d: &[u8],
    in_e: &[u8],
) -> [u8; 64] {
    pub const PRF_EXPAND_PERSONALIZATION: &[u8; 16] = b"Zcash_ExpandSeed";
    let mut blake2b_state = Blake2bParams::new()
        .hash_length(64)
        .personal(PRF_EXPAND_PERSONALIZATION)
        .to_state();
    blake2b_state.update(in_a);
    blake2b_state.update(in_b);
    blake2b_state.update(in_c);
    blake2b_state.update(in_d);
    blake2b_state.update(in_e);
    let mut hash = [0u8; 64];
    hash.copy_from_slice(&blake2b_state.finalize().as_bytes());
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

    #[cfg(not(target_arch = "x86_64"))]
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        unsafe {
            cx_rng(dest.as_mut_ptr(), dest.len() as u32);
        }
    }

    #[cfg(target_arch = "x86_64")]
    #[cfg(test)]
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        getrandom(dest);
    }

    #[cfg(target_arch = "x86_64")]
    #[cfg(not(test))]
    fn fill_bytes(&mut self, _dest: &mut [u8]) {}

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl CryptoRng for Trng {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_randomness() {
        let mut buf = [0u8; 64];
        Trng.fill_bytes(&mut buf);
        assert_ne!(buf[..], [0u8; 64][..]);
    }
}
