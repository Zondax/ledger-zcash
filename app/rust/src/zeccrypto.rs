use blake2s_simd::{blake2s, Hash as Blake2sHash, Params as Blake2sParams};
use core::convert::TryInto;
use core::mem;
use group::{Group, GroupEncoding};
use jubjub::{AffineNielsPoint, AffinePoint, ExtendedPoint, Fq, Fr, SubgroupPoint};
use rand::RngCore;

use crate::bolos::{c_zemu_log_stack, Trng};
use crate::commitments::bytes_to_extended;
use crate::constants;
use crate::zip32::*;
use crate::{bolos, pedersen::extended_to_bytes, zip32};

#[inline(never)]
pub fn rseed_generate_rcm(rseed: &[u8; 32]) -> Fr {
    let bytes = zip32::prf_expand(rseed, &[0x04]);
    jubjub::Fr::from_bytes_wide(&bytes)
}

#[inline(never)]
pub fn rseed_generate_esk(rseed: &[u8; 32]) -> Fr {
    let bytes = zip32::prf_expand(rseed, &[0x05]);
    jubjub::Fr::from_bytes_wide(&bytes)
}

pub fn generate_esk() -> [u8; 32] {
    let mut buffer = [0u8; 64];
    Trng.fill_bytes(&mut buffer);
    //Trng.fill_bytes(&mut buffer); //fill with random bytes
    let esk = Fr::from_bytes_wide(&buffer);
    esk.to_bytes()
}

//epk
pub fn derive_public(esk: &[u8; 32], g_d: &[u8; 32]) -> [u8; 32] {
    let p = AffinePoint::from_bytes(*g_d).unwrap();
    let q = p.to_niels().multiply_bits(esk);
    let t = AffinePoint::from(q);
    t.to_bytes()
}

#[inline(never)]
pub fn sapling_ka_agree(esk: &[u8; 32], pk_d: &[u8; 32]) -> [u8; 32] {
    let mut y = bytes_to_extended(*pk_d);
    mul_by_cof(&mut y);
    niels_multbits(&mut y, esk);
    extended_to_bytes(&y)
}

pub fn kdf_sapling(dhsecret: &[u8; 32], epk: &[u8; 32]) -> [u8; 32] {
    let mut input = [0u8; 64];
    (&mut input[..32]).copy_from_slice(dhsecret);
    (&mut input[32..]).copy_from_slice(epk);
    pub const KDF_SAPLING_PERSONALIZATION: &[u8; 16] = b"Zcash_SaplingKDF";
    bolos::blake2b32_with_personalization(KDF_SAPLING_PERSONALIZATION, &input)
}

pub fn prf_ock(ovk: &[u8; 32], cv: &[u8; 32], cmu: &[u8; 32], epk: &[u8; 32]) -> [u8; 32] {
    let mut ock_input = [0u8; 128];
    ock_input[0..32].copy_from_slice(ovk);
    ock_input[32..64].copy_from_slice(cv);
    ock_input[64..96].copy_from_slice(cmu);
    ock_input[96..128].copy_from_slice(epk);
    pub const PRF_OCK_PERSONALIZATION: &[u8; 16] = b"Zcash_Derive_ock";
    bolos::blake2b32_with_personalization(PRF_OCK_PERSONALIZATION, &ock_input)
}

#[inline(never)]
pub fn prf_sessionkey(data: &[u8]) -> [u8; 32] {
    pub const PRF_SESSION_PERSONALIZATION: &[u8; 16] = b"Zcash_SessionKey";
    bolos::blake2b32_with_personalization(PRF_SESSION_PERSONALIZATION, &data)
}

#[no_mangle]
pub extern "C" fn pubkey_gen(scalar_ptr: *const [u8; 32], output_ptr: *mut [u8; 32]) {
    let scalar = unsafe { &*scalar_ptr };
    let output = unsafe { &mut *output_ptr };
    let v = constants::SESSION_KEY_BASE.multiply_bits(scalar);
    output.copy_from_slice(&extended_to_bytes(&v));
}

#[no_mangle]
pub extern "C" fn rseed_get_rcm(rseed_ptr: *const [u8; 32], output_ptr: *mut [u8; 32]) {
    let rseed = unsafe { &*rseed_ptr };
    let output = unsafe { &mut *output_ptr };
    let p = rseed_generate_rcm(rseed);
    output.copy_from_slice(&p.to_bytes());
}

#[no_mangle]
pub fn rseed_get_esk(rseed_ptr: *const [u8; 32], output_ptr: *mut [u8; 32]) {
    let rseed = unsafe { &*rseed_ptr };
    let output = unsafe { &mut *output_ptr };
    let p = rseed_generate_esk(rseed);
    output.copy_from_slice(&p.to_bytes());
}

#[no_mangle]
pub extern "C" fn sessionkey_agree(
    scalar_ptr: *const [u8; 32],
    point_ptr: *const [u8; 32],
    output_ptr: *mut [u8; 32],
) {
    let scalar = unsafe { &*scalar_ptr }; //ovk, cv, cmu, epk
    let point = unsafe { &*point_ptr };

    let epk = sapling_ka_agree(scalar, point);
    let sessionkey = prf_sessionkey(&epk);

    let output = unsafe { &mut *output_ptr }; //ovk, cv, cmu, epk
    output[0..32].copy_from_slice(&sessionkey);
}
