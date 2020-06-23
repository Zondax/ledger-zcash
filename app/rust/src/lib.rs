#![no_std]
#![no_builtins]
#![allow(dead_code, unused_imports)]

extern crate core;

mod bolos;
mod constants;
mod parser;
mod zeccrypto;
mod zxformat;
mod zip32;

use jubjub::{AffineNielsPoint, AffinePoint, ExtendedPoint, Fq, Fr};
pub use parser::{_getItem, _getNumItems, _parser_init, _read, _validate};
pub use zxformat::{fpi64_to_str, fpu64_to_str};
use blake2s_simd::{blake2s, Hash as Blake2sHash, Params as Blake2sParams};

fn debug(_msg: &str) {}

use core::convert::TryInto;
use core::mem;
#[cfg(not(test))]
use core::panic::PanicInfo;
#[cfg(test)]
extern crate hex;

use core::mem;

use crate::bolos::{c_check_app_canary, c_zemu_log_stack};
use core::convert::TryInto;

#[cfg(not(test))]
use core::panic::PanicInfo;

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}

#[no_mangle]
pub extern "C" fn ask_to_ak(ask_ptr: *const u8, ak_ptr: *mut u8) {
    let ask: &[u8; 32] = unsafe { mem::transmute(ask_ptr) };
    let ak: &mut [u8; 32] = unsafe { mem::transmute(ak_ptr) };
    let tmp_ak = zip32::sapling_ask_to_ak(&ask);
    ak.copy_from_slice(&tmp_ak)
}

#[no_mangle]
pub extern "C" fn nsk_to_nk(nsk_ptr: *const u8, nk_ptr: *mut u8) {
    let nsk: &[u8; 32] = unsafe { mem::transmute(nsk_ptr) };
    let nk: &mut [u8; 32] = unsafe { mem::transmute(nk_ptr) };
    let tmp_nk = zip32::sapling_nsk_to_nk(&nsk);
    nk.copy_from_slice(&tmp_nk)
}


#[no_mangle]
pub extern "C" fn get_ak(sk_ptr: *const u8, ak_ptr: *mut u8) {
    let sk: &[u8; 32] = unsafe { mem::transmute(sk_ptr) };
    let ak: &mut [u8; 32] = unsafe { mem::transmute(ak_ptr) };
    let ask = zip32::sapling_derive_dummy_ask(sk);
    let tmp_ak = zip32::sapling_ask_to_ak(&ask);
    ak.copy_from_slice(&tmp_ak)
}

#[no_mangle]
pub extern "C" fn get_nk(sk_ptr: *const u8, nk_ptr: *mut u8) {
    let sk: &[u8; 32] = unsafe { mem::transmute(sk_ptr) };
    let nk: &mut [u8; 32] = unsafe { mem::transmute(nk_ptr) };
    let nsk = zip32::sapling_derive_dummy_nsk(sk);
    let tmp_nk = zip32::sapling_nsk_to_nk(&nsk);
    nk.copy_from_slice(&tmp_nk)
}

#[no_mangle]
pub extern "C" fn get_ivk(ak_ptr: *const u8, nk_ptr: *mut u8, ivk_ptr: *mut u8) {
    let ak: &[u8; 32] = unsafe { mem::transmute(ak_ptr) };
    let nk: &[u8; 32] = unsafe { mem::transmute(nk_ptr) };
    let ivk: &mut [u8; 32] = unsafe { mem::transmute(ivk_ptr) };

    let tmp_ivk = zip32::aknk_to_ivk(&ak, &nk);
    ivk.copy_from_slice(&tmp_ivk)
}

#[no_mangle]
pub extern "C" fn zip32_master(seed_ptr: *const u8, sk_ptr: *mut u8, dk_ptr: *mut u8) {
    let seed: &[u8; 32] = unsafe { mem::transmute(seed_ptr) };
    let sk: &mut [u8; 32] = unsafe { mem::transmute(sk_ptr) };
    let dk: &mut [u8; 32] = unsafe { mem::transmute(dk_ptr) };

    let k = zip32::derive_zip32_master(seed);
    sk.copy_from_slice(&k[0..32]);
    dk.copy_from_slice(&k[32..64])
}

//fixme
#[no_mangle]
pub extern "C" fn zip32_child(seed_ptr: *const u8, dk_ptr: *mut u8,ask_ptr: *mut u8,nsk_ptr: *mut u8) {
    let seed: &[u8; 32] = unsafe { mem::transmute(seed_ptr) };
    let dk: &mut [u8; 32] = unsafe { mem::transmute(dk_ptr) };
    let ask: &mut [u8; 32] = unsafe { mem::transmute(ask_ptr) };
    let nsk: &mut [u8; 32] = unsafe { mem::transmute(nsk_ptr) };
    let p: u32 = 0x80000001;
    let k = zip32::derive_zip32_child_fromseedandpath(seed, &[p]);//todo: fix me
    dk.copy_from_slice(&k[0..32]);
    ask.copy_from_slice(&k[32..64]);
    nsk.copy_from_slice(&k[64..96]);
}

#[no_mangle]
pub extern "C" fn get_diversifier_list(sk_ptr: *const u8, diversifier_list_ptr: *mut u8) {
    let sk: &[u8; 32] = unsafe { mem::transmute(sk_ptr) };
    let diversifier: &mut [u8; 44] = unsafe { mem::transmute(diversifier_list_ptr) };
    let d = zip32::ff1aes_list(sk);
    diversifier.copy_from_slice(&d)
}

#[no_mangle]
pub extern "C" fn get_diversifier_fromlist(div_ptr: *mut u8,diversifier_list_ptr: *const u8) {
    let diversifier_list: &mut [u8; 44] = unsafe { mem::transmute(diversifier_list_ptr) };
    let div: &mut [u8; 11] = unsafe { mem::transmute(div_ptr) };

    let d = zip32::default_diversifier_fromlist(diversifier_list);
    div.copy_from_slice(&d)
}

#[no_mangle]
pub extern "C" fn get_pkd(ivk_ptr: *mut u8, diversifier_ptr: *mut u8, pkd_ptr: *mut u8) {
    let ivk: &[u8; 32] = unsafe { mem::transmute(ivk_ptr) };
    let diversifier: &[u8; 11] = unsafe { mem::transmute(diversifier_ptr) };
    let pkd: &mut [u8; 32] = unsafe { mem::transmute(pkd_ptr) };

    let tmp_pkd = zip32::default_pkd(&ivk, &diversifier);
    pkd.copy_from_slice(&tmp_pkd)
}

#[cfg(test)]
mod tests {
    use crate::*;
    use crate::zip32::*;
    use core::convert::TryInto;


    #[test]
    fn test_zip32_master() {
        let seed = [
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 30, 31,
        ];

        let dk: [u8; 32] = [
            0x77, 0xc1, 0x7c, 0xb7, 0x5b, 0x77, 0x96, 0xaf, 0xb3, 0x9f, 0x0f, 0x3e, 0x91, 0xc9,
            0x24, 0x60, 0x7d, 0xa5, 0x6f, 0xa9, 0xa2, 0x0e, 0x28, 0x35, 0x09, 0xbc, 0x8a, 0x3e,
            0xf9, 0x96, 0xa1, 0x72,
        ];
        let keys = derive_zip32_master(&seed);
        assert_eq!(keys[0..32], dk);
    }

    #[test]
    fn test_zip32_childaddress() {
        let seed = [0u8;32];

        let dk_test: [u8; 32] = [
            0xcb, 0xf6, 0xca, 0x4d, 0x57, 0x0f, 0xaf, 0x7e, 0xb0, 0xad, 0xcd, 0xab, 0xbf, 0xef,
            0x36, 0x1b, 0x62, 0x95, 0x4b, 0x08, 0x10, 0x25, 0x18, 0x2f, 0x50, 0x16, 0x1d, 0x40,
            0x4f, 0x21, 0x45, 0x47
        ];
        let p: u32 = 0x80000001;
        let keys = derive_zip32_child_fromseedandpath(&seed,&[p]);

        let mut dk = [0u8; 32];
        dk.copy_from_slice(&keys[0..32]);

        let mut ask = [0u8;32];
        ask.copy_from_slice(&keys[32..64]);

        let mut nsk = [0u8;32];
        nsk.copy_from_slice(&keys[64..96]);

        //fixme: add ecc operations
        let ask_test: [u8;32] = [0x66, 0x5e, 0xd6, 0xf7, 0xb7, 0x93, 0xaf, 0xa1, 0x82, 0x21, 0xe1, 0x57, 0xba, 0xd5, 0x43, 0x3c, 0x54, 0x23, 0xf4, 0xfe, 0xc9, 0x46, 0xe0, 0x8e, 0xd6, 0x30, 0xa0, 0xc6, 0x0a, 0x1f, 0xac, 0x02];

        assert_eq!(ask,ask_test);

        let mut nk: [u8; 32] = sapling_nsk_to_nk(&nsk);
        let mut ak: [u8; 32] = sapling_ask_to_ak(&ask);

        let ivk_test: [u8;32] = [
            0x2c, 0x57, 0xfb, 0x12, 0x8c, 0x35, 0xa4, 0x4d, 0x2d, 0x5b, 0xf2, 0xfd, 0x21, 0xdc, 0x3b, 0x44, 0x11, 0x4c, 0x36, 0x6c, 0x9c, 0x49, 0x60, 0xc4, 0x91, 0x66, 0x17, 0x38, 0x3e, 0x89, 0xfd, 0x00
        ];
        let ivk = aknk_to_ivk(&ak, &nk);

        assert_eq!(ivk,ivk_test);

        let list = ff1aes_list(&dk);
        let default_d = default_diversifier_fromlist(&list);

        let pk_d = default_pkd(&ivk, &default_d);

        assert_eq!(default_d, [0x10, 0xaa, 0x8e, 0xe1, 0xe1, 0x91, 0x48, 0xe7, 0x49, 0x7d, 0x3c]);
        assert_eq!(pk_d, [0xb3, 0xbe, 0x9e, 0xb3, 0xe7, 0xa9, 0x61, 0x17, 0x95, 0x17, 0xae, 0x28, 0xab, 0x19, 0xb4, 0x84, 0xae, 0x17, 0x2f, 0x1f, 0x33, 0xd1, 0x16, 0x33, 0xe9, 0xec, 0x05, 0xee, 0xa1, 0xe8, 0xa9, 0xd6]);

    }

    #[test]
    fn test_zip32_childaddress_ledgerkey() {
        let s = hex::decode("b08e3d98da431cef4566a13c1bb348b982f7d8e743b43bb62557ba51994b1257").expect("error");
        let seed: [u8;32] = s.as_slice().try_into().expect("er");
        let p: u32 = 0x80000001;
        let keys = derive_zip32_child_fromseedandpath(&seed,&[p]);

        let mut dk = [0u8; 32];
        dk.copy_from_slice(&keys[0..32]);

        let mut ask = [0u8;32];
        ask.copy_from_slice(&keys[32..64]);

        let mut nsk = [0u8;32];
        nsk.copy_from_slice(&keys[64..96]);

        let mut nk: [u8; 32] = sapling_nsk_to_nk(&nsk);
        let mut ak: [u8; 32] = sapling_ask_to_ak(&ask);

        let ivk = aknk_to_ivk(&ak, &nk);

        let list = ff1aes_list(&dk);
        let default_d = default_diversifier_fromlist(&list);

        let pk_d = default_pkd(&ivk, &default_d);

        assert_eq!(default_d, [250, 115, 180, 200, 239, 11, 123, 73, 187, 60, 148]);
        assert_eq!(pk_d, [191, 46, 29, 241, 178, 127, 191, 115, 187, 149, 153, 207, 116, 119, 20, 209, 250, 139, 59, 242, 251, 143, 230, 0, 172, 160, 16, 248, 117, 182, 234, 83]);

    }

    #[test]
    fn test_zip32_master_address_ledgerkey() {
        let s = hex::decode("b08e3d98da431cef4566a13c1bb348b982f7d8e743b43bb62557ba51994b1257").expect("error");
        let seed: [u8;32] = s.as_slice().try_into().expect("er");

        let keys = derive_zip32_master(&seed);

        let mut dk = [0u8; 32];
        dk.copy_from_slice(&keys[0..32]);

        let mut ask = [0u8;32];
        ask.copy_from_slice(&keys[32..64]);

        let mut nsk = [0u8;32];
        nsk.copy_from_slice(&keys[64..96]);

        let nk: [u8; 32] = sapling_nsk_to_nk(&nsk);
        let ak: [u8; 32] = sapling_ask_to_ak(&ask);

        let ivk = aknk_to_ivk(&ak, &nk);

        let list = ff1aes_list(&dk);
        let default_d = default_diversifier_fromlist(&list);

        let pk_d = default_pkd(&ivk, &default_d);

        assert_eq!(default_d, [249, 61, 207, 226, 4, 114, 83, 238, 188, 23, 212]);
        assert_eq!(pk_d, [220, 53, 23, 146, 73, 107, 157, 1, 78, 98, 108, 59, 201, 41, 230, 211, 47, 80, 127, 184, 11, 102, 79, 92, 174, 151, 211, 123, 247, 66, 219, 169]);

    }

    #[test]
    fn test_zip32_master_address_allzero() {
        let seed = [0u8; 32];


        let keys = derive_zip32_master(&seed);


        let mut dk = [0u8; 32];
        dk.copy_from_slice(&keys[0..32]);

        let mut ask = [0u8;32];
        ask.copy_from_slice(&keys[32..64]);

        let mut nsk = [0u8;32];
        nsk.copy_from_slice(&keys[64..96]);

        let nk: [u8; 32] = sapling_nsk_to_nk(&nsk);
        let ak: [u8; 32] = sapling_ask_to_ak(&ask);

        let ivk = aknk_to_ivk(&ak, &nk);

        let list = ff1aes_list(&dk);
        let default_d = default_diversifier_fromlist(&list);

        let pk_d = default_pkd(&ivk, &default_d);

        assert_eq!(default_d, [0x3b, 0xf6, 0xfa, 0x1f, 0x83, 0xbf, 0x45, 0x63, 0xc8, 0xa7,
            0x13]);
        assert_eq!(pk_d, [0x04, 0x54, 0xc0, 0x14, 0x13, 0x5e, 0xc6, 0x95, 0xa1, 0x86,
            0x0f, 0x8d, 0x65, 0xb3, 0x73, 0x54, 0x6b, 0x62, 0x3f, 0x38, 0x8a, 0xbb, 0xec, 0xd0, 0xc8, 0xb2, 0x11, 0x1a, 0xbd, 0xec, 0x30, 0x1d]);

    }

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
    fn test_default_diversifier_fromlist() {
        let seed = [0u8; 32];
        let list = ff1aes_list(&seed);
        let default_d = default_diversifier_fromlist(&list);
        assert_eq!(
            default_d,
            [0xdc, 0xe7, 0x7e, 0xbc, 0xec, 0x0a, 0x26, 0xaf, 0xd6, 0x99, 0x8c]
        );
    }


    #[test]
    fn test_grouphash_default() {
        let default_d = [
            0xf1, 0x9d, 0x9b, 0x79, 0x7e, 0x39, 0xf3, 0x37, 0x44, 0x58, 0x39,
        ];

        let result = zip32::pkd_group_hash(&default_d);
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
