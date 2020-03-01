//! Rust interfaces to Ledger SDK APIs.

use rand::{CryptoRng, RngCore};

#[cfg(test)]
use blake2b_simd::{Hash as Blake2bHash, Params as Blake2bParams};

use blake2s_simd::{Hash as Blake2sHash, Params as Blake2sParams, blake2s};

extern "C" {
    fn cx_rng(buffer: *mut u8, len: u32);
    fn zcash_blake2b_expand_seed(a: *const u8, a_len: u32, b: *const u8, b_len: u32, out: *mut u8);
}

#[cfg(not(test))]
pub fn blake2b_expand_seed(a: &[u8], b: &[u8]) -> [u8; 64] {
    let mut hash = [0; 64];
    unsafe {
        zcash_blake2b_expand_seed(a.as_ptr(), a.len() as u32,
                                  b.as_ptr(), b.len() as u32,
                                  hash.as_mut_ptr());
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
    pub const GH_FIRST_BLOCK: &[u8; 64] = b"096b36a5804bfacef1691e173c366a47ff5ba84a44f26ddd7e8d9f79d5b42df0";

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
