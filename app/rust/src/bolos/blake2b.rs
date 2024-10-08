use crate::bolos;
use crate::personalization::{
    KEY_DIVERSIFICATION_PERSONALIZATION, PRF_EXPAND_PERSONALIZATION, REDJUBJUB_PERSONALIZATION,
};
use blake2b_simd::Params as Blake2bParams;
use blake2s_simd::Params as Blake2sParams;

extern "C" {
    fn c_zcash_blake2b_expand_seed(
        input_a: *const u8,
        input_a_len: u32,
        input_b: *const u8,
        input_b_len: u32,
        out: *mut u8,
    );
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
    hash.copy_from_slice(h.as_bytes());
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
    hash.copy_from_slice(h.as_bytes());
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
pub fn blake2b_expand_v4(
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

#[cfg(test)]
pub fn blake2b_expand_seed(a: &[u8], b: &[u8]) -> [u8; 64] {
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

#[inline(never)]
pub fn blake2s_diversification(tag: &[u8]) -> [u8; 32] {
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
    let mut h = Blake2bParams::new()
        .hash_length(64)
        .personal(PRF_EXPAND_PERSONALIZATION)
        .to_state();
    h.update(sk);
    h.update(a);
    h.update(b);
    let mut hash = [0u8; 64];
    hash.copy_from_slice(h.finalize().as_bytes());
    hash
}

#[cfg(test)]
pub fn blake2b_expand_v4(
    in_a: &[u8],
    in_b: &[u8],
    in_c: &[u8],
    in_d: &[u8],
    in_e: &[u8],
) -> [u8; 64] {
    let mut blake2b_state = Blake2bParams::new()
        .hash_length(64)
        .personal(PRF_EXPAND_PERSONALIZATION)
        .to_state();
    crate::bolos::heartbeat();

    blake2b_state.update(in_a);
    crate::bolos::heartbeat();

    blake2b_state.update(in_b);
    crate::bolos::heartbeat();

    blake2b_state.update(in_c);
    crate::bolos::heartbeat();

    blake2b_state.update(in_d);
    crate::bolos::heartbeat();

    blake2b_state.update(in_e);
    crate::bolos::heartbeat();

    let mut hash = [0u8; 64];
    hash.copy_from_slice(blake2b_state.finalize().as_bytes());
    hash
}
