#![no_std]
#![no_builtins]
#![allow(dead_code, unused_imports)]

mod bolos;
mod constants;

extern crate core;

use jubjub::{AffineNielsPoint, AffinePoint, ExtendedPoint, Fq, Fr};

use blake2s_simd::{blake2s, Hash as Blake2sHash, Params as Blake2sParams};

fn debug(_msg: &str) {}

use crate::bolos::{c_check_app_canary, c_zemu_log_stack};
use core::convert::TryInto;
use core::mem;
#[cfg(not(test))]
use core::panic::PanicInfo;

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}

#[inline(always)]
pub fn prf_expand(sk: &[u8], t: &[u8]) -> [u8; 64] {
    bolos::blake2b_expand_seed(sk, t)
}

fn sapling_derive_dummy_ask(sk_in: &[u8]) -> [u8; 32] {
    let t = prf_expand(&sk_in, &[0x00]);
    let ask = Fr::from_bytes_wide(&t);
    ask.to_bytes()
}

fn sapling_derive_dummy_nsk(sk_in: &[u8]) -> [u8; 32] {
    let t = prf_expand(&sk_in, &[0x01]);
    let nsk = Fr::from_bytes_wide(&t);
    nsk.to_bytes()
}

fn sapling_ask_to_ak(ask: &[u8; 32]) -> [u8; 32] {
    let ak = constants::SPENDING_KEY_BASE.multiply_bits(&ask);
    AffinePoint::from(ak).to_bytes()
}

fn sapling_nsk_to_nk(nsk: &[u8; 32]) -> [u8; 32] {
    let nk = constants::PROVING_KEY_BASE.multiply_bits(&nsk);
    AffinePoint::from(nk).to_bytes()
}

fn aknk_to_ivk(ak: &[u8; 32], nk: &[u8; 32]) -> [u8; 32] {
    pub const CRH_IVK_PERSONALIZATION: &[u8; 8] = b"Zcashivk"; //move to constants

    // blake2s CRH_IVK_PERSONALIZATION || ak || nk
    let h = Blake2sParams::new()
        .hash_length(32)
        .personal(CRH_IVK_PERSONALIZATION)
        .to_state()
        .update(ak)
        .update(nk)
        .finalize();

    let mut x: [u8; 32] = *h.as_array();
    x[31] &= 0b0000_0111; //check this
    x
}

#[inline(never)]
fn diversifier_group_hash_check(hash: &[u8; 32]) -> bool {
    let u = AffinePoint::from_bytes(*hash);
    if u.is_some().unwrap_u8() == 1 {
        let v = u.unwrap();
        let q = v.mul_by_cofactor();
        let i = ExtendedPoint::identity();
        return q != i;
    }

    false
}

#[inline(never)]
fn diversifier_group_hash_light(tag: &[u8]) -> bool {
    c_zemu_log_stack(b"diversifier_group_hash_light\x00");
    c_check_app_canary();

    let x = bolos::blake2s_diversification(tag);

    //    diversifier_group_hash_check(&x)

    c_check_app_canary();
    c_zemu_log_stack(b"AffinePoint::from_bytes \x00");
    let u = AffinePoint::from_bytes(x);
    c_check_app_canary();
    c_zemu_log_stack(b"AffinePoint::from_bytes DONE \x00");

    if u.is_some().unwrap_u8() == 1 {
        let v = u.unwrap();
        let q = v.mul_by_cofactor();
        let i = ExtendedPoint::identity();
        return q != i;
    }

    false
}

#[inline(never)]
fn default_diversifier(sk: &[u8; 32]) -> [u8; 11] {
    //fixme: replace blake2b with aes
    let mut c: [u8; 2] = [0x03, 0x0];

    c_zemu_log_stack(b"default_diversifier\x00");
    c_check_app_canary();

    // blake2b sk || 0x03 || c
    loop {
        let x = prf_expand(sk, &c);
        if diversifier_group_hash_light(&x[0..11]) {
            let mut result = [0u8; 11];
            result.copy_from_slice(&x[..11]);
            return result;
        }
        c[1] += 1;
        c_check_app_canary();
        c_zemu_log_stack(b"LOOP \x00");
    }
}

#[inline(never)]
fn pkd_group_hash(d: &[u8; 11]) -> [u8; 32] {
    let h = bolos::blake2s_diversification(d);

    let v = AffinePoint::from_bytes(h).unwrap();
    let q = v.mul_by_cofactor();
    let t = AffinePoint::from(q);
    t.to_bytes()
}

#[inline(never)]
fn default_pkd(ivk: &[u8; 32], d: &[u8; 11]) -> [u8; 32] {
    let h = bolos::blake2s_diversification(d);

    let v = AffinePoint::from_bytes(h).unwrap();
    let y = v.mul_by_cofactor();

    // FIXME: We should avoid asserts in ledger code
    //assert_eq!(x.is_some().unwrap_u8(), 1);

    let v = y.to_niels().multiply_bits(ivk);
    let t = AffinePoint::from(v);
    t.to_bytes()
}

#[no_mangle]
pub extern "C" fn get_ak(sk_ptr: *mut u8, ak_ptr: *mut u8) {
    let sk: &[u8; 32] = unsafe { mem::transmute::<*const u8, &[u8; 32]>(sk_ptr) };
    let ak: &mut [u8; 32] = unsafe { mem::transmute::<*const u8, &mut [u8; 32]>(ak_ptr) };

    c_zemu_log_stack(b"get_ak\x00");

    let ask = sapling_derive_dummy_ask(sk);
    let tmp_ak = sapling_ask_to_ak(&ask);
    ak.copy_from_slice(&tmp_ak)
}

#[no_mangle]
pub extern "C" fn get_nk(sk_ptr: *mut u8, nk_ptr: *mut u8) {
    let sk: &[u8; 32] = unsafe { mem::transmute::<*const u8, &[u8; 32]>(sk_ptr) };
    let nk: &mut [u8; 32] = unsafe { mem::transmute::<*const u8, &mut [u8; 32]>(nk_ptr) };

    c_zemu_log_stack(b"get_nk\x00");

    let nsk = sapling_derive_dummy_nsk(sk);
    let tmp_nk = sapling_nsk_to_nk(&nsk);
    nk.copy_from_slice(&tmp_nk)
}

#[no_mangle]
pub extern "C" fn get_ivk(ak_ptr: *mut u8, nk_ptr: *mut u8, ivk_ptr: *mut u8) {
    let ak: &[u8; 32] = unsafe { mem::transmute::<*const u8, &[u8; 32]>(ak_ptr) };
    let nk: &[u8; 32] = unsafe { mem::transmute::<*const u8, &[u8; 32]>(nk_ptr) };
    let ivk: &mut [u8; 32] = unsafe { mem::transmute::<*const u8, &mut [u8; 32]>(ivk_ptr) };

    c_zemu_log_stack(b"get_ivk\x00");

    let tmp_ivk = aknk_to_ivk(&ak, &nk);
    ivk.copy_from_slice(&tmp_ivk)
}

#[no_mangle]
pub extern "C" fn get_diversifier(sk_ptr: *mut u8, diversifier_ptr: *mut u8) {
    let sk: &[u8; 32] = unsafe { mem::transmute::<*const u8, &[u8; 32]>(sk_ptr) };
    let diversifier: &mut [u8; 11] =
        unsafe { mem::transmute::<*const u8, &mut [u8; 11]>(diversifier_ptr) };

    c_zemu_log_stack(b"get_diversifier\x00");
    let d = default_diversifier(sk);
    diversifier.copy_from_slice(&d)
}

#[no_mangle]
pub extern "C" fn get_pkd(ivk_ptr: *mut u8, diversifier_ptr: *mut u8, pkd_ptr: *mut u8) {
    let ivk: &[u8; 32] = unsafe { mem::transmute::<*const u8, &[u8; 32]>(ivk_ptr) };
    let diversifier: &[u8; 11] = unsafe { mem::transmute::<*const u8, &[u8; 11]>(diversifier_ptr) };
    let pkd: &mut [u8; 32] = unsafe { mem::transmute::<*const u8, &mut [u8; 32]>(pkd_ptr) };

    let tmp_pkd = default_pkd(&ivk, &diversifier);
    pkd.copy_from_slice(&tmp_pkd)
}

//fixme
//fixme: we need to add a prefix to exported functions.. as there are no namespaces in C :(
//get seed from the ledger
#[no_mangle]
pub extern "C" fn get_address(sk_ptr: *mut u8, ivk_ptr: *mut u8, address_ptr: *mut u8) {
    let sk: &[u8; 32] = unsafe { mem::transmute::<*const u8, &[u8; 32]>(sk_ptr) };
    let ivk: &[u8; 32] = unsafe { mem::transmute::<*const u8, &[u8; 32]>(ivk_ptr) };
    let address: &mut [u8; 43] = unsafe { mem::transmute::<*const u8, &mut [u8; 43]>(address_ptr) };

    let div = default_diversifier(sk);
    let pkd = default_pkd(&ivk, &div);

    address[..11].copy_from_slice(&div);
    address[11..].copy_from_slice(&pkd);
}

#[cfg(test)]
mod tests {
    use crate::*;

    #[test]
    fn test_div() {
        let nk = [
            0xf7, 0xcf, 0x9e, 0x77, 0xf2, 0xe5, 0x86, 0x83, 0x38, 0x3c, 0x15, 0x19, 0xac, 0x7b,
            0x06, 0x2d, 0x30, 0x04, 0x0e, 0x27, 0xa7, 0x25, 0xfb, 0x88, 0xfb, 0x19, 0xa9, 0x78,
            0xbd, 0x3f, 0xd6, 0xba,
        ];
        let ak = [
            0xf3, 0x44, 0xec, 0x38, 0x0f, 0xe1, 0x27, 0x3e, 0x30, 0x98, 0xc2, 0x58, 0x8c, 0x5d,
            0x3a, 0x79, 0x1f, 0xd7, 0xba, 0x95, 0x80, 0x32, 0x76, 0x07, 0x77, 0xfd, 0x0e, 0xfa,
            0x8e, 0xf1, 0x16, 0x20,
        ];

        let ivk: [u8; 32] = aknk_to_ivk(&ak, &nk);
        let default_d = [
            0xf1, 0x9d, 0x9b, 0x79, 0x7e, 0x39, 0xf3, 0x37, 0x44, 0x58, 0x39,
        ];

        let result = pkd_group_hash(&default_d);
        let x = super::AffinePoint::from_bytes(result);
        if x.is_some().unwrap_u8() == 1 {
            let y = super::ExtendedPoint::from(x.unwrap());
            let v = y.to_niels().multiply_bits(&ivk);
            let t = super::AffinePoint::from(v);
            let pk_d = t.to_bytes();
            assert_eq!(
                pk_d,
                [
                    0xdb, 0x4c, 0xd2, 0xb0, 0xaa, 0xc4, 0xf7, 0xeb, 0x8c, 0xa1, 0x31, 0xf1, 0x65,
                    0x67, 0xc4, 0x45, 0xa9, 0x55, 0x51, 0x26, 0xd3, 0xc2, 0x9f, 0x14, 0xe3, 0xd7,
                    0x76, 0xe8, 0x41, 0xae, 0x74, 0x15
                ]
            );
        }
    }

    #[test]
    fn test_default_diversifier() {
        let seed = [0u8; 32];
        let default_d = default_diversifier(&seed);
        assert_eq!(
            default_d,
            [0xf1, 0x9d, 0x9b, 0x79, 0x7e, 0x39, 0xf3, 0x37, 0x44, 0x58, 0x39]
        );
    }

    #[test]
    fn test_defaultpkd() {
        let seed = [0u8; 32];
        let default_d = default_diversifier(&seed);

        let nk = [
            0xf7, 0xcf, 0x9e, 0x77, 0xf2, 0xe5, 0x86, 0x83, 0x38, 0x3c, 0x15, 0x19, 0xac, 0x7b,
            0x06, 0x2d, 0x30, 0x04, 0x0e, 0x27, 0xa7, 0x25, 0xfb, 0x88, 0xfb, 0x19, 0xa9, 0x78,
            0xbd, 0x3f, 0xd6, 0xba,
        ];
        let ak = [
            0xf3, 0x44, 0xec, 0x38, 0x0f, 0xe1, 0x27, 0x3e, 0x30, 0x98, 0xc2, 0x58, 0x8c, 0x5d,
            0x3a, 0x79, 0x1f, 0xd7, 0xba, 0x95, 0x80, 0x32, 0x76, 0x07, 0x77, 0xfd, 0x0e, 0xfa,
            0x8e, 0xf1, 0x16, 0x20,
        ];

        let ivk: [u8; 32] = aknk_to_ivk(&ak, &nk);

        let pkd = default_pkd(&ivk, &default_d);
        assert_eq!(
            pkd,
            [
                0xdb, 0x4c, 0xd2, 0xb0, 0xaa, 0xc4, 0xf7, 0xeb, 0x8c, 0xa1, 0x31, 0xf1, 0x65, 0x67,
                0xc4, 0x45, 0xa9, 0x55, 0x51, 0x26, 0xd3, 0xc2, 0x9f, 0x14, 0xe3, 0xd7, 0x76, 0xe8,
                0x41, 0xae, 0x74, 0x15
            ]
        );
    }

    #[test]
    fn test_grouphash_default() {
        let default_d = [
            0xf1, 0x9d, 0x9b, 0x79, 0x7e, 0x39, 0xf3, 0x37, 0x44, 0x58, 0x39,
        ];

        let result = pkd_group_hash(&default_d);
        let x = super::AffinePoint::from_bytes(result);
        assert_eq!(x.is_some().unwrap_u8(), 1);
        assert_eq!(
            result,
            [
                0x3a, 0x71, 0xe3, 0x48, 0x16, 0x9e, 0x0c, 0xed, 0xbc, 0x4f, 0x36, 0x33, 0xa2, 0x60,
                0xd0, 0xe7, 0x85, 0xea, 0x8f, 0x89, 0x27, 0xce, 0x45, 0x01, 0xce, 0xf3, 0x21, 0x6e,
                0xd0, 0x75, 0xce, 0xa2
            ]
        );
    }

    #[test]
    fn test_ak() {
        let seed = [0u8; 32];
        let ask: [u8; 32] = sapling_derive_dummy_ask(&seed);
        assert_eq!(
            ask,
            [
                0x85, 0x48, 0xa1, 0x4a, 0x47, 0x3e, 0xa5, 0x47, 0xaa, 0x23, 0x78, 0x40, 0x20, 0x44,
                0xf8, 0x18, 0xcf, 0x19, 0x11, 0xcf, 0x5d, 0xd2, 0x05, 0x4f, 0x67, 0x83, 0x45, 0xf0,
                0x0d, 0x0e, 0x88, 0x06
            ]
        );
        let ak: [u8; 32] = sapling_ask_to_ak(&ask);
        assert_eq!(
            ak,
            [
                0xf3, 0x44, 0xec, 0x38, 0x0f, 0xe1, 0x27, 0x3e, 0x30, 0x98, 0xc2, 0x58, 0x8c, 0x5d,
                0x3a, 0x79, 0x1f, 0xd7, 0xba, 0x95, 0x80, 0x32, 0x76, 0x07, 0x77, 0xfd, 0x0e, 0xfa,
                0x8e, 0xf1, 0x16, 0x20
            ]
        );
    }

    #[test]
    fn test_nk() {
        let seed = [0u8; 32];

        let nsk: [u8; 32] = sapling_derive_dummy_nsk(&seed);
        assert_eq!(
            nsk,
            [
                0x30, 0x11, 0x4e, 0xa0, 0xdd, 0x0b, 0xb6, 0x1c, 0xf0, 0xea, 0xea, 0xb6, 0xec, 0x33,
                0x31, 0xf5, 0x81, 0xb0, 0x42, 0x5e, 0x27, 0x33, 0x85, 0x01, 0x26, 0x2d, 0x7e, 0xac,
                0x74, 0x5e, 0x6e, 0x05
            ]
        );

        let nk: [u8; 32] = sapling_nsk_to_nk(&nsk);
        assert_eq!(
            nk,
            [
                0xf7, 0xcf, 0x9e, 0x77, 0xf2, 0xe5, 0x86, 0x83, 0x38, 0x3c, 0x15, 0x19, 0xac, 0x7b,
                0x06, 0x2d, 0x30, 0x04, 0x0e, 0x27, 0xa7, 0x25, 0xfb, 0x88, 0xfb, 0x19, 0xa9, 0x78,
                0xbd, 0x3f, 0xd6, 0xba
            ]
        );
    }

    #[test]
    fn test_ivk() {
        let nk = [
            0xf7, 0xcf, 0x9e, 0x77, 0xf2, 0xe5, 0x86, 0x83, 0x38, 0x3c, 0x15, 0x19, 0xac, 0x7b,
            0x06, 0x2d, 0x30, 0x04, 0x0e, 0x27, 0xa7, 0x25, 0xfb, 0x88, 0xfb, 0x19, 0xa9, 0x78,
            0xbd, 0x3f, 0xd6, 0xba,
        ];
        let ak = [
            0xf3, 0x44, 0xec, 0x38, 0x0f, 0xe1, 0x27, 0x3e, 0x30, 0x98, 0xc2, 0x58, 0x8c, 0x5d,
            0x3a, 0x79, 0x1f, 0xd7, 0xba, 0x95, 0x80, 0x32, 0x76, 0x07, 0x77, 0xfd, 0x0e, 0xfa,
            0x8e, 0xf1, 0x16, 0x20,
        ];

        let ivk: [u8; 32] = aknk_to_ivk(&ak, &nk);
        assert_eq!(
            ivk,
            [
                0xb7, 0x0b, 0x7c, 0xd0, 0xed, 0x03, 0xcb, 0xdf, 0xd7, 0xad, 0xa9, 0x50, 0x2e, 0xe2,
                0x45, 0xb1, 0x3e, 0x56, 0x9d, 0x54, 0xa5, 0x71, 0x9d, 0x2d, 0xaa, 0x0f, 0x5f, 0x14,
                0x51, 0x47, 0x92, 0x04
            ]
        );
    }
}
