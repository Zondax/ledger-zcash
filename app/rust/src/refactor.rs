use crate::bolos::blake2b::blake2b32_with_personalization;
use crate::personalization::{PRF_OCK_PERSONALIZATION, PRF_SESSION_PERSONALIZATION};

#[no_mangle]
pub extern "C" fn blake2b_prf(input_ptr: *const [u8; 128], out_ptr: *mut [u8; 32]) {
    // todo: move directly to C. No need to get into rust
    let input = unsafe { &*input_ptr }; //ovk, cv, cmu, epk
    let hash = blake2b32_with_personalization(PRF_OCK_PERSONALIZATION, input);
    let output = unsafe { &mut *out_ptr }; //ovk, cv, cmu, epk
    output.copy_from_slice(&hash);
}

#[inline(never)]
pub fn prf_sessionkey(data: &[u8]) -> [u8; 32] {
    crate::bolos::heartbeat();
    blake2b32_with_personalization(PRF_SESSION_PERSONALIZATION, &data)
}

// pub fn generate_esk() -> [u8; 32] {
//     let mut buffer = [0u8; 64];
//     Trng.fill_bytes(&mut buffer);
//     let esk = Fr::from_bytes_wide(&buffer);
//     esk.to_bytes()
// }

//epk
// pub fn derive_public(esk: &[u8; 32], g_d: &[u8; 32]) -> [u8; 32] {
//     let p = AffinePoint::from_bytes(*g_d).unwrap();
//     let q = p.to_niels().multiply_bits(esk);
//     let t = AffinePoint::from(q);
//     t.to_bytes()
// }

// pub fn prf_ock(ovk: &[u8; 32], cv: &[u8; 32], cmu: &[u8; 32], epk: &[u8; 32]) -> [u8; 32] {
//     let mut ock_input = [0u8; 128];
//     ock_input[0..32].copy_from_slice(ovk);
//     ock_input[32..64].copy_from_slice(cv);
//     ock_input[64..96].copy_from_slice(cmu);
//     ock_input[96..128].copy_from_slice(epk);
//     crate::bolos::heartbeat();
//     blake2b32_with_personalization(PRF_OCK_PERSONALIZATION, &ock_input)
// }

// #[no_mangle]
// pub extern "C" fn pubkey_gen(scalar_ptr: *const [u8; 32], output_ptr: *mut [u8; 32]) {
//     let scalar = unsafe { &*scalar_ptr };
//     let output = unsafe { &mut *output_ptr };
//     let v = constants::SESSION_KEY_BASE.multiply_bits(scalar);
//     output.copy_from_slice(&extended_to_bytes(&v));
// }

// #[no_mangle]
// pub extern "C" fn sessionkey_agree(
//     scalar_ptr: *const [u8; 32],
//     point_ptr: *const [u8; 32],
//     output_ptr: *mut [u8; 32],
// ) {
//     let scalar = unsafe { &*scalar_ptr }; //ovk, cv, cmu, epk
//     let point = unsafe { &*point_ptr };
//
//     let epk = sapling_ka_agree(scalar, point);
//     let sessionkey = prf_sessionkey(&epk);
//
//     let output = unsafe { &mut *output_ptr }; //ovk, cv, cmu, epk
//     output[0..32].copy_from_slice(&sessionkey);
// }
// pub fn verify_bindingsig_keys(rcmsum: &[u8; 32], valuecommitsum: &[u8; 32]) -> bool {
//     let v = bytes_to_extended(*valuecommitsum);
//     let r = VALUE_COMMITMENT_RANDOM_BASE.multiply_bits(rcmsum);
//     v == r
// }
