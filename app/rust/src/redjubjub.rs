use jubjub::{AffinePoint, ExtendedPoint, Fr};
use rand::RngCore;

use crate::bolos::blake2b::blake2b_redjubjub;
use crate::bolos::c_zemu_log_stack;
use crate::bolos::jubjub::scalarmult_spending_base;
use crate::bolos::rng::Trng;
use crate::constants::*;
use crate::cryptoops::bytes_to_extended;

#[inline(never)]
pub fn jubjub_sk_to_pk(sk: &[u8; 32]) -> [u8; 32] {
    let mut point = [0u8; 32];
    scalarmult_spending_base(&mut point, &sk[..]);
    point
}

#[inline(never)]
pub fn sk_to_pk(sk_ptr: *const [u8; 32], pk_ptr: *mut [u8; 32]) {
    let sk = unsafe { &*sk_ptr };
    let pk = unsafe { &mut *pk_ptr };
    let pubkey = jubjub_sk_to_pk(sk);
    pk.copy_from_slice(&pubkey);
}

#[no_mangle]
pub extern "C" fn rsk_to_rk(rsk_ptr: *const [u8; 32], rk_ptr: *mut [u8; 32]) {
    sk_to_pk(rsk_ptr, rk_ptr)
}

//////////////////////////
/////////////////////////.

#[inline(never)]
pub fn h_star(a: &[u8], b: &[u8]) -> Fr {
    Fr::from_bytes_wide(&blake2b_redjubjub(a, b))
}

#[inline(never)]
pub fn sign_generate_r(msg: &[u8]) -> Fr {
    let mut t = [0u8; 80];
    Trng.fill_bytes(&mut t);
    h_star(&t, msg)
}

#[inline(never)]
pub fn sign_compute_rbar(r: &[u8; 32]) -> [u8; 32] {
    let r_g = SPENDING_KEY_BASE.multiply_bits(r);
    AffinePoint::from(r_g).to_bytes()
}

#[inline(never)]
pub fn sign_compute_sbar(msg: &[u8], r: &Fr, rbar: &[u8], sfr: &Fr) -> [u8; 32] {
    let s = r + h_star(&rbar, msg) * sfr;
    s.to_bytes()
}

#[inline(never)]
pub fn sign_complete(msg: &[u8], sk: &Fr) -> [u8; 64] {
    crate::bolos::heartbeat();
    let r = sign_generate_r(&msg);

    crate::bolos::heartbeat();
    let rbar = sign_compute_rbar(&r.to_bytes());

    crate::bolos::heartbeat();
    let sbar = sign_compute_sbar(msg, &r, &rbar, sk);
    let mut sig = [0u8; 64];
    sig[..32].copy_from_slice(&rbar);
    sig[32..].copy_from_slice(&sbar);
    crate::bolos::heartbeat();
    sig
}

#[no_mangle]
pub extern "C" fn sign_redjubjub(
    key_ptr: *const [u8; 32],
    msg_ptr: *const [u8; 64],
    out_ptr: *mut [u8; 64],
) {
    c_zemu_log_stack(b"sign_redjubjub\x00".as_ref());
    let key = unsafe { *key_ptr };
    let msg = unsafe { *msg_ptr };
    let output = unsafe { &mut *out_ptr };
    let sk = Fr::from_bytes(&key).unwrap();
    output.copy_from_slice(&sign_complete(&msg, &sk));
}

///////////////////////////
///////////////////////////

#[inline(never)]
pub fn random_scalar() -> Fr {
    let mut t = [0u8; 64];
    Trng.fill_bytes(&mut t);
    Fr::from_bytes_wide(&t)
}

#[no_mangle]
pub extern "C" fn random_fr(alpha_ptr: *mut [u8; 32]) {
    let alpha = unsafe { &mut *alpha_ptr };
    let fr = random_scalar();
    alpha.copy_from_slice(&fr.to_bytes());
}

///////////////////////////
///////////////////////////

#[inline(never)]
pub fn randomized_secret(
    sk_ptr: *const [u8; 32],
    alpha_ptr: *const [u8; 32],
    output_ptr: *mut [u8; 32],
) {
    let alpha = unsafe { &*alpha_ptr };
    let sk = unsafe { &*sk_ptr };
    let output = unsafe { &mut *output_ptr };
    let mut skfr = Fr::from_bytes(&sk).unwrap();
    let alphafr = Fr::from_bytes(&alpha).unwrap();
    skfr += alphafr;
    output.copy_from_slice(&skfr.to_bytes());
}

#[no_mangle]
pub extern "C" fn get_rk(
    ask_ptr: *const [u8; 32],
    alpha_ptr: *const [u8; 32],
    rk_ptr: *mut [u8; 32],
) {
    let alpha = unsafe { &*alpha_ptr };
    let ask = unsafe { &*ask_ptr };
    let rk = unsafe { &mut *rk_ptr };
    let mut rsk = [0u8; 32];
    randomized_secret(ask, alpha, &mut rsk);
    sk_to_pk(&rsk, rk);
}

// #[no_mangle]
// pub extern "C" fn randomize_pk(alpha_ptr: *const [u8; 32], pk_ptr: *mut [u8; 32]) {
//     let alpha = unsafe { *alpha_ptr };
//     let pk = unsafe { &mut *pk_ptr };
//     let mut pubkey = bytes_to_extended(*pk);
//     jubjub_randomized_pk(&mut pubkey, alpha);
//     pk.copy_from_slice(&extended_to_bytes(&pubkey));
// }

#[cfg(test)]
mod tests {
    use super::*;

    pub fn jubjub_randomized_pk(pk: &mut ExtendedPoint, alpha: [u8; 32]) {
        let rndpk = jubjub_sk_to_pk(&alpha);
        *pk += bytes_to_extended(rndpk);
    }

    pub fn jubjub_randomized_sk(sk: &Fr, alpha: &Fr) -> Fr {
        sk + alpha
    }

    #[test]
    pub fn test_jubjub_nonrandom() {
        let sk = [
            0x32, 0x16, 0xae, 0x47, 0xe9, 0xf5, 0x3e, 0x8a, 0x52, 0x79, 0x6f, 0x24, 0xb6, 0x24,
            0x60, 0x77, 0x6b, 0xd5, 0xf2, 0x05, 0xa7, 0x8e, 0x15, 0x95, 0xbc, 0x8e, 0xfe, 0xdc,
            0x51, 0x9d, 0x36, 0x0b,
        ];
        let skfr = Fr::from_bytes(&sk).unwrap();
        let b = jubjub_sk_to_pk(&sk);
        assert_eq!(
            b,
            [
                0xdf, 0x74, 0xbf, 0x04, 0x79, 0x61, 0xcc, 0x5c, 0xda, 0xc8, 0x28, 0x90, 0xc7, 0x6e,
                0xc6, 0x75, 0xbd, 0x4e, 0x89, 0xea, 0xd2, 0x80, 0xc9, 0x52, 0xd7, 0xc3, 0x3e, 0xea,
                0xf2, 0xb5, 0xa6, 0x6b
            ]
        );

        let msg = [
            0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08,
            0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08,
            0x08, 0x08, 0x08, 0x08,
        ];

        let randomr = [
            0xb9, 0x9d, 0xae, 0x64, 0xe1, 0x7f, 0x2a, 0x20, 0x53, 0x0b, 0x94, 0xb0, 0x6d, 0x96,
            0xcc, 0x0a, 0x91, 0x34, 0x6e, 0x47, 0xab, 0x80, 0xb9, 0xf1, 0x70, 0xf1, 0x42, 0xfa,
            0xcb, 0xf2, 0x48, 0x04,
        ];
        let rbar = sign_compute_rbar(&randomr);
        let rbartest = [
            0x24, 0x93, 0x2c, 0x1f, 0xaa, 0x01, 0x63, 0xca, 0x9a, 0x7f, 0xcd, 0xe4, 0x76, 0x11,
            0x29, 0xd2, 0xe5, 0xe9, 0x9c, 0xf5, 0xef, 0xa2, 0x5d, 0x27, 0x04, 0x58, 0x8e, 0x1c,
            0x75, 0x67, 0x7b, 0x5e,
        ];

        assert_eq!(rbar, rbartest);

        let rfr = Fr::from_bytes(&randomr).unwrap();
        let sbar = sign_compute_sbar(&msg, &rfr, &rbar, &skfr);

        let sbartest = [
            0xeb, 0xe4, 0x55, 0x04, 0x8d, 0x7c, 0xe1, 0xb0, 0xd2, 0x01, 0x27, 0x53, 0xf7, 0x1b,
            0x27, 0x25, 0x01, 0x2e, 0xe1, 0x85, 0x49, 0x28, 0x73, 0x18, 0xf9, 0xcd, 0x73, 0xf0,
            0x7f, 0x0f, 0xb5, 0x02,
        ];

        assert_eq!(sbar, sbartest);
    }

    #[test]
    pub fn test_jubjub_random() {
        let sk = [
            0x85, 0x83, 0x6f, 0x98, 0x32, 0xb2, 0x8d, 0xe7, 0xc6, 0x36, 0x13, 0xe2, 0xa6, 0xed,
            0x36, 0xfb, 0x1a, 0xb4, 0x4f, 0xb0, 0xc1, 0x3f, 0xa8, 0x79, 0x8c, 0xd9, 0xcd, 0x30,
            0x30, 0xd4, 0x55, 0x03,
        ];

        let alpha = [
            0xa2, 0xe8, 0xb9, 0xe1, 0x6d, 0x6f, 0xf3, 0xca, 0x6c, 0x53, 0xd4, 0xe8, 0x8a, 0xbb,
            0xb9, 0x9b, 0xe7, 0xaf, 0x7e, 0x36, 0x59, 0x63, 0x1f, 0x1e, 0xae, 0x1e, 0xff, 0x23,
            0x87, 0x4d, 0x8e, 0x0c,
        ];

        let skfr = Fr::from_bytes(&sk).unwrap();
        let alphafr = Fr::from_bytes(&alpha).unwrap();

        let rsk = jubjub_randomized_sk(&skfr, &alphafr);

        assert_eq!(
            rsk.to_bytes(),
            [
                0x70, 0x3f, 0x32, 0xa3, 0x41, 0x13, 0xea, 0xe1, 0xb0, 0x79, 0x1f, 0xfe, 0x9d, 0x88,
                0x88, 0xf0, 0x01, 0x29, 0x9a, 0xe5, 0x19, 0x68, 0x60, 0x91, 0x91, 0x48, 0x99, 0xef,
                0xcc, 0x6c, 0x66, 0x01
            ]
        );

        let mut pk = bytes_to_extended(jubjub_sk_to_pk(&sk));

        jubjub_randomized_pk(&mut pk, alpha);

        let msg = [
            0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09,
            0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09,
            0x09, 0x09, 0x09, 0x09,
        ];

        let randomr = [
            0x00, 0x38, 0x7c, 0x61, 0x7a, 0x1a, 0xfc, 0x19, 0xce, 0x4f, 0x57, 0x1f, 0x0a, 0xd8,
            0x92, 0xf5, 0x1b, 0x2c, 0xe6, 0x09, 0x05, 0xae, 0xa7, 0x8e, 0xcf, 0xbf, 0x59, 0xae,
            0x8d, 0x4f, 0x50, 0x0c,
        ];
        let rbar = sign_compute_rbar(&randomr);
        let rbartest = [
            0xeb, 0x7a, 0x06, 0x5d, 0x75, 0xf8, 0x45, 0xdc, 0x09, 0x41, 0xb7, 0x09, 0xc0, 0xb1,
            0x49, 0xea, 0xfd, 0x80, 0x5e, 0xa5, 0x8f, 0x38, 0x0b, 0x92, 0xb9, 0xd3, 0x10, 0x8a,
            0x56, 0x1b, 0xda, 0x17,
        ];

        assert_eq!(rbar, rbartest);

        let rfr = Fr::from_bytes(&randomr).unwrap();
        let sbar = sign_compute_sbar(&msg, &rfr, &rbar, &rsk);

        let sbartest = [
            0x85, 0xdf, 0x8f, 0x10, 0x1e, 0x0e, 0x14, 0x0f, 0xca, 0xee, 0x99, 0xb7, 0xdb, 0xb7,
            0xdf, 0xbf, 0x7e, 0x61, 0xf3, 0xa1, 0x2f, 0x46, 0x09, 0x50, 0x69, 0xe0, 0x6e, 0x88,
            0x96, 0xa9, 0xe4, 0x04,
        ];

        assert_eq!(sbar, sbartest);
    }
}
