use core::convert::TryInto;
use core::mem;

use crate::constants;
use crate::{bolos, zip32};

use crate::bolos::c_zemu_log_stack;
use blake2s_simd::{blake2s, Hash as Blake2sHash, Params as Blake2sParams};
use jubjub::{AffineNielsPoint, AffinePoint, ExtendedPoint, Fq, Fr};

const COMPACT_NOTE_SIZE: usize = 1 /* version */ + 11 /*diversifier*/ + 8 /*value*/ + 32 /*rcv*/;

const NOTE_PLAINTEXT_SIZE: usize = COMPACT_NOTE_SIZE + 512;
const OUT_PLAINTEXT_SIZE: usize = 32 /*pk_d*/ + 32 /* esk */;

const ENC_CIPHERTEXT_SIZE: usize = NOTE_PLAINTEXT_SIZE + 16;
const OUT_CIPHERTEXT_SIZE: usize = OUT_PLAINTEXT_SIZE + 16;

pub fn generate_esk(buffer: [u8; 64]) -> [u8; 32] {
    //Rng.fill_bytes(&mut buffer); fill with random bytes
    let esk = Fr::from_bytes_wide(&buffer);
    esk.to_bytes()
}

pub fn derive_public(esk: [u8; 32], g_d: [u8; 32]) -> [u8; 32] {
    let p = AffinePoint::from_bytes(g_d).unwrap();
    let q = p.to_niels().multiply_bits(&esk);
    let t = AffinePoint::from(q);
    t.to_bytes()
}

pub fn sapling_ka_agree(esk: [u8; 32], pk_d: [u8; 32]) -> [u8; 32] {
    let p = AffinePoint::from_bytes(pk_d).unwrap();
    let q = p.mul_by_cofactor();
    let v = q.to_niels().multiply_bits(&esk);
    let t = AffinePoint::from(v);
    t.to_bytes()
}

fn kdf_sapling(dhsecret: [u8; 32], epk: [u8; 32]) -> [u8; 32] {
    let mut input = [0u8; 64];
    (&mut input[..32]).copy_from_slice(&dhsecret);
    (&mut input[32..]).copy_from_slice(&epk);
    bolos::blake2b_kdf_sapling(&input)
}

fn prf_ock(ovk: [u8; 32], cv: [u8; 32], cmu: [u8; 32], epk: [u8; 32]) -> [u8; 32] {
    let mut ock_input = [0u8; 128];
    ock_input[0..32].copy_from_slice(&ovk); //Todo: compute this from secret key
    ock_input[32..64].copy_from_slice(&cv);
    ock_input[64..96].copy_from_slice(&cmu);
    ock_input[96..128].copy_from_slice(&epk);

    bolos::blake2b_prf_ock(&ock_input)
}

#[cfg(test)]
mod tests {
    use crate::pedersen::*;
    use crate::zeccrypto::*;
    use crate::zip32::*;
    use crate::*;
    use core::convert::TryInto;

    #[test]
    fn test_bitstreamer() {
        let a: [u8; 2] = [254, 0];
        let mut b = Bitstreamer {
            input_bytes: &a,
            byte_index: 0,
            bitsize: 9,
            bit_index: 0,
            curr: a[0] as u32,
            shift: 5,
            carry: 0,
        };
        assert_eq!(b.next(), Some(7 as u8));
        assert_eq!(b.next(), Some(7 as u8));
        assert_eq!(b.next(), Some(4 as u8));
        assert_eq!(b.next(), None);
    }

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
        let seed = [0u8; 32];

        let p: u32 = 0x80000001;
        let keys = derive_zip32_child_fromseedandpath(&seed, &[p]);

        let mut dk = [0u8; 32];
        dk.copy_from_slice(&keys[0..32]);

        let mut ask = [0u8; 32];
        ask.copy_from_slice(&keys[32..64]);

        let mut nsk = [0u8; 32];
        nsk.copy_from_slice(&keys[64..96]);

        //fixme: add ecc operations
        let ask_test: [u8; 32] = [
            0x66, 0x5e, 0xd6, 0xf7, 0xb7, 0x93, 0xaf, 0xa1, 0x82, 0x21, 0xe1, 0x57, 0xba, 0xd5,
            0x43, 0x3c, 0x54, 0x23, 0xf4, 0xfe, 0xc9, 0x46, 0xe0, 0x8e, 0xd6, 0x30, 0xa0, 0xc6,
            0x0a, 0x1f, 0xac, 0x02,
        ];

        assert_eq!(ask, ask_test);

        let nk: [u8; 32] = sapling_nsk_to_nk(&nsk);
        let ak: [u8; 32] = sapling_ask_to_ak(&ask);

        let ivk_test: [u8; 32] = [
            0x2c, 0x57, 0xfb, 0x12, 0x8c, 0x35, 0xa4, 0x4d, 0x2d, 0x5b, 0xf2, 0xfd, 0x21, 0xdc,
            0x3b, 0x44, 0x11, 0x4c, 0x36, 0x6c, 0x9c, 0x49, 0x60, 0xc4, 0x91, 0x66, 0x17, 0x38,
            0x3e, 0x89, 0xfd, 0x00,
        ];
        let ivk = aknk_to_ivk(&ak, &nk);

        assert_eq!(ivk, ivk_test);

        let list = ff1aes_list(&dk);
        let default_d = default_diversifier_fromlist(&list);

        let pk_d = default_pkd(&ivk, &default_d);

        assert_eq!(
            default_d,
            [0x10, 0xaa, 0x8e, 0xe1, 0xe1, 0x91, 0x48, 0xe7, 0x49, 0x7d, 0x3c]
        );
        assert_eq!(
            pk_d,
            [
                0xb3, 0xbe, 0x9e, 0xb3, 0xe7, 0xa9, 0x61, 0x17, 0x95, 0x17, 0xae, 0x28, 0xab, 0x19,
                0xb4, 0x84, 0xae, 0x17, 0x2f, 0x1f, 0x33, 0xd1, 0x16, 0x33, 0xe9, 0xec, 0x05, 0xee,
                0xa1, 0xe8, 0xa9, 0xd6
            ]
        );
    }

    #[test]
    fn test_zip32_childaddress_ledgerkey() {
        let s = hex::decode("b08e3d98da431cef4566a13c1bb348b982f7d8e743b43bb62557ba51994b1257")
            .expect("error");
        let seed: [u8; 32] = s.as_slice().try_into().expect("er");
        let p: u32 = 0x80000001;
        let keys = derive_zip32_child_fromseedandpath(&seed, &[p]);

        let mut dk = [0u8; 32];
        dk.copy_from_slice(&keys[0..32]);

        let mut ask = [0u8; 32];
        ask.copy_from_slice(&keys[32..64]);

        let mut nsk = [0u8; 32];
        nsk.copy_from_slice(&keys[64..96]);

        let nk: [u8; 32] = sapling_nsk_to_nk(&nsk);
        let ak: [u8; 32] = sapling_ask_to_ak(&ask);

        let ivk = aknk_to_ivk(&ak, &nk);

        let list = ff1aes_list(&dk);
        let default_d = default_diversifier_fromlist(&list);

        let pk_d = default_pkd(&ivk, &default_d);

        assert_eq!(
            default_d,
            [250, 115, 180, 200, 239, 11, 123, 73, 187, 60, 148]
        );
        assert_eq!(
            pk_d,
            [
                191, 46, 29, 241, 178, 127, 191, 115, 187, 149, 153, 207, 116, 119, 20, 209, 250,
                139, 59, 242, 251, 143, 230, 0, 172, 160, 16, 248, 117, 182, 234, 83
            ]
        );
    }

    #[test]
    fn test_zip32_master_address_ledgerkey() {
        let s = hex::decode("b08e3d98da431cef4566a13c1bb348b982f7d8e743b43bb62557ba51994b1257")
            .expect("error");
        let seed: [u8; 32] = s.as_slice().try_into().expect("er");

        let keys = derive_zip32_master(&seed);

        let mut dk = [0u8; 32];
        dk.copy_from_slice(&keys[0..32]);

        let mut ask = [0u8; 32];
        ask.copy_from_slice(&keys[32..64]);

        let mut nsk = [0u8; 32];
        nsk.copy_from_slice(&keys[64..96]);

        let nk: [u8; 32] = sapling_nsk_to_nk(&nsk);
        let ak: [u8; 32] = sapling_ask_to_ak(&ask);

        let ivk = aknk_to_ivk(&ak, &nk);

        let list = ff1aes_list(&dk);
        let default_d = default_diversifier_fromlist(&list);

        let pk_d = default_pkd(&ivk, &default_d);

        assert_eq!(
            default_d,
            [249, 61, 207, 226, 4, 114, 83, 238, 188, 23, 212]
        );
        assert_eq!(
            pk_d,
            [
                220, 53, 23, 146, 73, 107, 157, 1, 78, 98, 108, 59, 201, 41, 230, 211, 47, 80, 127,
                184, 11, 102, 79, 92, 174, 151, 211, 123, 247, 66, 219, 169
            ]
        );
    }

    #[test]
    fn test_zip32_master_address_allzero() {
        let seed = [0u8; 32];

        let keys = derive_zip32_master(&seed);

        let mut dk = [0u8; 32];
        dk.copy_from_slice(&keys[0..32]);

        let mut ask = [0u8; 32];
        ask.copy_from_slice(&keys[32..64]);

        let mut nsk = [0u8; 32];
        nsk.copy_from_slice(&keys[64..96]);

        let nk: [u8; 32] = sapling_nsk_to_nk(&nsk);
        let ak: [u8; 32] = sapling_ask_to_ak(&ask);

        let ivk = aknk_to_ivk(&ak, &nk);

        let list = ff1aes_list(&dk);
        let default_d = default_diversifier_fromlist(&list);

        let pk_d = default_pkd(&ivk, &default_d);

        assert_eq!(
            default_d,
            [0x3b, 0xf6, 0xfa, 0x1f, 0x83, 0xbf, 0x45, 0x63, 0xc8, 0xa7, 0x13]
        );
        assert_eq!(
            pk_d,
            [
                0x04, 0x54, 0xc0, 0x14, 0x13, 0x5e, 0xc6, 0x95, 0xa1, 0x86, 0x0f, 0x8d, 0x65, 0xb3,
                0x73, 0x54, 0x6b, 0x62, 0x3f, 0x38, 0x8a, 0xbb, 0xec, 0xd0, 0xc8, 0xb2, 0x11, 0x1a,
                0xbd, 0xec, 0x30, 0x1d
            ]
        );
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

    #[test]
    fn test_key_small() {
        let m: [u8; 1] = [0xb0; 1];
        assert_eq!(
            pedersen_hash(&m, 3),
            [
                115, 27, 180, 151, 186, 120, 30, 98, 134, 221, 162, 136, 54, 82, 230, 141, 30, 114,
                188, 151, 176, 20, 4, 182, 255, 43, 30, 173, 67, 98, 64, 22
            ]
        );
    }

    #[test]
    fn test_pedersen_ledger() {
        let m: [u8; 32] = [0xb0; 32];
        let mut output = [0u8; 32];
        do_pedersen_hash(m.as_ptr(), output.as_mut_ptr());
        assert_eq!(
            output,
            [
                115, 27, 180, 151, 186, 120, 30, 98, 134, 221, 162, 136, 54, 82, 230, 141, 30, 114,
                188, 151, 176, 20, 4, 182, 255, 43, 30, 173, 67, 98, 64, 22
            ]
        );
    }

    #[test]
    fn test_pedersen_onechunk() {
        let input_bits: [u8; 189] = [
            1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 1, 1, 1, 1, 0, 1, 1, 1, 0, 0, 0, 1, 1, 1, 0, 0, 0,
            0, 1, 0, 0, 0, 0, 1, 0, 0, 1, 1, 1, 0, 1, 0, 1, 1, 0, 1, 0, 0, 0, 1, 1, 0, 1, 0, 0, 0,
            0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 1, 0, 1, 1, 1, 1, 1, 0, 1, 1, 1, 0, 1, 0, 1,
            1, 1, 0, 0, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 1, 1, 1, 0, 0, 0, 0, 1, 1, 1, 0, 1, 1,
            0, 0, 1, 1, 0, 0, 1, 0, 1, 0, 0, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 1, 0, 1,
            1, 1, 0, 1, 0, 0, 1, 1, 1, 1, 1, 0, 0, 1, 0, 1, 0, 1, 0, 0, 1, 1, 0, 1, 0, 0, 0, 1, 0,
            1, 0, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 0, 0,
        ];
        let m = [
            254, 15, 113, 194, 19, 173, 26, 16, 40, 190, 235, 147, 77, 195, 179, 41, 127, 194, 233,
            242, 166, 138, 85, 64,
        ];

        let h = pedersen_hash(&m, input_bits.len() as u32);
        assert_eq!(
            h,
            [
                0xdd, 0xf5, 0x21, 0xad, 0xc3, 0xa5, 0x97, 0xf5, 0xcf, 0x72, 0x29, 0xff, 0x02, 0xcf,
                0xed, 0x7e, 0x94, 0x9f, 0x01, 0xb6, 0x1d, 0xf3, 0xe1, 0xdc, 0xdf, 0xf5, 0x20, 0x76,
                0x31, 0x10, 0xa5, 0x2d
            ]
        );
    }

    #[test]
    fn test_pedersen_big1() {
        let input_bits: [u8; 190] = [
            1, 1, 1, 1, 1, 1, 1, 0, 1, 0, 0, 0, 1, 1, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0,
            0, 1, 1, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 0, 0, 0, 0, 1, 1, 1, 0, 0, 0, 1, 1, 1, 0, 1, 1,
            0, 0, 1, 1, 1, 1, 1, 0, 0, 1, 0, 1, 0, 1, 0, 0, 0, 0, 1, 0, 1, 1, 0, 1, 1, 0, 0, 1, 1,
            1, 1, 1, 0, 1, 0, 0, 0, 1, 0, 1, 0, 1, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1,
            1, 0, 0, 1, 0, 1, 1, 0, 0, 0, 0, 1, 1, 0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1,
            0, 1, 1, 0, 1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 0, 1, 1, 0, 0, 0, 1, 1, 0, 0, 1, 1, 1, 1, 0,
            0, 0, 0, 1, 0, 1, 1, 1, 1, 1, 0, 0, 0, 0, 1, 1,
        ];
        let m = [
            254, 141, 17, 3, 7, 195, 142, 207, 149, 11, 103, 209, 80, 192, 57, 97, 146, 64, 183,
            222, 198, 120, 95, 12,
        ];
        let h = pedersen_hash(&m, input_bits.len() as u32);
        assert_eq!(
            h,
            [
                0x40, 0x0c, 0xf2, 0x1e, 0xeb, 0x6f, 0x8e, 0x59, 0x4a, 0x0e, 0xcd, 0x2b, 0x7f, 0x7a,
                0x68, 0x46, 0x34, 0xd9, 0x6e, 0xdf, 0x51, 0xfb, 0x3d, 0x19, 0x2d, 0x99, 0x40, 0xe6,
                0xc7, 0x47, 0x12, 0x60
            ]
        );
    }

    #[test]
    fn test_pedersen_big2() {
        let inp2: [u8; 756] = [
            1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0,
            1, 0, 1, 1, 1, 1, 0, 1, 0, 1, 1, 0, 0, 1, 1, 1, 0, 0, 0, 0, 1, 1, 0, 0, 1, 0, 0, 1, 1,
            1, 0, 0, 1, 0, 0, 1, 1, 1, 0, 1, 1, 1, 0, 1, 1, 0, 1, 0, 0, 0, 0, 0, 1, 1, 1, 0, 1, 1,
            1, 1, 1, 0, 0, 1, 1, 1, 1, 1, 1, 0, 0, 0, 1, 1, 0, 1, 1, 0, 0, 1, 0, 1, 0, 1, 1, 1, 0,
            1, 0, 0, 0, 0, 0, 1, 0, 0, 1, 1, 1, 0, 0, 0, 1, 0, 1, 1, 1, 0, 0, 0, 1, 1, 0, 1, 1, 1,
            0, 0, 0, 0, 0, 1, 1, 0, 1, 0, 0, 0, 0, 0, 1, 1, 1, 1, 0, 1, 0, 1, 1, 0, 0, 0, 1, 0, 0,
            0, 0, 1, 1, 0, 1, 0, 1, 0, 1, 1, 1, 1, 1, 0, 0, 0, 1, 0, 1, 0, 1, 1, 1, 0, 0, 1, 0, 0,
            1, 1, 0, 0, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 1, 1, 0, 0, 1, 0, 0, 1, 1, 1, 1, 0, 1, 1, 1,
            1, 0, 0, 1, 1, 1, 0, 0, 0, 1, 0, 1, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 1, 1,
            0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 1, 1, 0, 1, 1, 0, 0, 0, 1, 0, 0, 0, 1, 1, 0, 1, 1, 0,
            0, 1, 0, 0, 0, 0, 1, 0, 1, 0, 0, 1, 0, 1, 0, 0, 1, 0, 1, 0, 1, 1, 0, 1, 1, 0, 0, 1, 0,
            1, 1, 1, 1, 1, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 1, 1, 1,
            1, 0, 0, 1, 0, 1, 1, 1, 1, 0, 1, 0, 1, 1, 1, 0, 1, 1, 0, 1, 0, 1, 1, 1, 1, 0, 1, 0, 0,
            1, 1, 0, 0, 0, 1, 0, 0, 1, 1, 0, 1, 1, 1, 0, 0, 0, 0, 0, 1, 1, 1, 0, 0, 1, 0, 1, 0, 1,
            0, 0, 0, 1, 0, 0, 1, 1, 1, 0, 1, 1, 1, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1,
            0, 1, 1, 0, 1, 0, 1, 0, 1, 0, 1, 1, 0, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 1, 0, 0, 1, 0, 0,
            0, 1, 0, 0, 0, 1, 1, 1, 1, 1, 0, 1, 0, 0, 0, 0, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1, 1, 0, 1,
            1, 1, 1, 0, 1, 0, 0, 0, 0, 1, 0, 1, 0, 0, 1, 0, 0, 0, 1, 1, 0, 0, 1, 0, 0, 0, 1, 1, 0,
            0, 1, 0, 0, 1, 1, 0, 1, 0, 1, 0, 0, 0, 1, 0, 1, 1, 0, 1, 0, 0, 0, 1, 1, 1, 0, 1, 0, 0,
            1, 1, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 1, 1, 0, 1, 1, 0, 1, 0, 1, 0, 0, 0,
            1, 0, 1, 0, 1, 0, 1, 1, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1,
            0, 1, 0, 1, 1, 0, 1, 1, 1, 1, 0, 1, 0, 1, 0, 0, 1, 1, 1, 1, 0, 0, 0, 1, 0, 1, 1, 1, 1,
            1, 1, 0, 1, 0, 1, 0, 0, 1, 1, 1, 1, 1, 1, 0, 1, 0, 1, 1, 1, 1, 0, 1, 1, 0, 1, 0, 1, 0,
            1, 0, 0, 1, 0, 0, 0, 1, 0, 1, 0, 1, 1, 0, 0, 0, 1, 1, 1, 1, 1, 0, 1, 0, 1, 0, 0, 1, 0,
            0, 0, 1, 0, 1, 1, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0, 1, 0, 0, 1, 0, 0, 0, 1, 1, 0, 1,
            0, 1, 1, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1,
            1, 1,
        ];
        let m2 = [
            255, 36, 160, 101, 235, 56, 100, 228, 238, 208, 119, 207, 198, 202, 232, 39, 23, 27,
            131, 65, 235, 16, 213, 241, 92, 152, 205, 100, 247, 156, 81, 34, 24, 5, 216, 141, 144,
            165, 43, 101, 240, 136, 5, 121, 122, 237, 122, 98, 110, 14, 84, 78, 249, 4, 45, 86, 50,
            228, 71, 208, 239, 239, 66, 145, 145, 147, 81, 104, 233, 145, 2, 218, 138, 184, 136,
            89, 173, 234, 120, 191, 83, 245, 237, 82, 43, 31, 82, 45, 4, 164, 107, 205, 32, 64,
            112,
        ];
        let h2 = pedersen_hash(&m2, inp2.len() as u32);
        assert_eq!(
            h2,
            [
                0x27, 0xae, 0xf2, 0xe8, 0xeb, 0xed, 0xad, 0x19, 0x39, 0x37, 0x9f, 0x4f, 0x44, 0x7e,
                0xfb, 0xd9, 0x25, 0x5a, 0x87, 0x4c, 0x70, 0x08, 0x81, 0x6a, 0x80, 0xd8, 0xf2, 0xb1,
                0xec, 0x92, 0x41, 0x31
            ]
        );
    }
    #[test]
    fn test_pedersen_big3() {
        let inp3: [u8; 945] = [
            0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0,
            0, 1, 0, 1, 1, 1, 1, 0, 1, 0, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 1, 0, 1, 1, 1, 0, 0, 0, 0,
            0, 1, 0, 1, 1, 1, 1, 1, 1, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 0, 0, 1, 1, 0, 0, 0,
            1, 1, 0, 1, 1, 0, 1, 0, 1, 0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 1, 0, 1, 0, 0, 1, 0, 0, 1, 0,
            0, 1, 1, 0, 1, 0, 1, 0, 0, 0, 1, 1, 1, 1, 1, 0, 1, 0, 1, 0, 0, 0, 0, 1, 1, 0, 1, 1, 0,
            1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 1, 0, 1, 0, 1, 1, 0, 1, 0, 0, 0, 1, 1, 0, 1, 1, 1, 1,
            1, 0, 0, 1, 1, 1, 0, 0, 1, 1, 0, 1, 1, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 1, 1,
            1, 1, 1, 0, 1, 0, 1, 0, 0, 1, 0, 0, 1, 1, 0, 0, 0, 1, 1, 1, 0, 0, 1, 0, 1, 1, 1, 1, 0,
            0, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1, 0, 0, 1, 0, 0, 0, 0, 1, 0, 1, 1, 0, 1, 1, 0, 1, 1,
            0, 0, 1, 1, 0, 0, 0, 0, 1, 1, 1, 1, 1, 0, 1, 0, 0, 1, 1, 0, 1, 1, 1, 1, 1, 0, 0, 0, 1,
            0, 0, 1, 1, 0, 0, 0, 0, 0, 1, 1, 1, 0, 1, 1, 1, 0, 1, 1, 1, 0, 1, 1, 0, 0, 1, 0, 0, 1,
            0, 1, 1, 0, 0, 1, 0, 0, 0, 1, 1, 1, 0, 1, 1, 0, 1, 0, 1, 0, 0, 0, 1, 1, 0, 1, 1, 0, 1,
            0, 1, 1, 1, 0, 0, 0, 0, 0, 1, 1, 0, 0, 1, 1, 0, 1, 1, 0, 1, 0, 1, 1, 1, 0, 1, 0, 1, 0,
            0, 1, 0, 0, 1, 0, 0, 1, 1, 1, 0, 0, 0, 0, 0, 1, 1, 1, 1, 0, 1, 0, 1, 1, 1, 0, 1, 1, 1,
            1, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0,
            0, 1, 0, 0, 0, 1, 1, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 0, 1, 0, 0, 1, 1, 1, 0, 0, 0, 1, 0,
            1, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 1, 1, 0, 1, 1, 0, 1, 0, 0, 0, 0, 0, 1, 0, 1,
            1, 1, 0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 1, 1, 1, 0, 1, 0, 1, 0, 1, 1, 1, 0, 0, 0, 1, 1, 1,
            1, 0, 0, 1, 0, 0, 1, 0, 1, 1, 1, 1, 0, 0, 0, 1, 1, 0, 0, 0, 0, 1, 0, 0, 1, 0, 1, 1, 0,
            0, 0, 0, 1, 1, 1, 0, 1, 1, 0, 0, 0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 1, 1,
            1, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 0, 0, 0, 1, 0, 1, 0, 0, 1, 0, 0, 1, 1, 0, 0, 0, 0, 1,
            1, 1, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 1, 1, 1, 1, 0, 1, 1, 0, 1, 0, 0, 1, 0, 0, 0, 1, 0,
            1, 0, 1, 1, 1, 0, 1, 0, 1, 1, 1, 1, 0, 1, 1, 0, 0, 1, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1,
            1, 1, 1, 1, 0, 0, 1, 1, 0, 0, 1, 1, 1, 0, 1, 1, 0, 1, 1, 0, 0, 0, 1, 1, 0, 1, 1, 1, 0,
            0, 1, 1, 0, 0, 0, 1, 0, 1, 0, 0, 1, 1, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 1, 1, 0, 1, 1,
            1, 1, 0, 1, 0, 0, 1, 1, 0, 1, 1, 1, 0, 1, 1, 0, 1, 0, 1, 1, 1, 1, 0, 1, 0, 0, 1, 0, 1,
            0, 0, 1, 1, 0, 0, 0, 0, 1, 1, 0, 0, 1, 1, 1, 0, 1, 0, 0, 0, 0, 1, 1, 0, 1, 1, 1, 1, 1,
            0, 0, 1, 0, 0, 1, 0, 1, 0, 0, 0, 1, 1, 1, 1, 0, 1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 1, 1, 0,
            0, 0, 1, 1, 0, 0, 0, 0, 1, 1, 1, 0, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 1, 1, 0, 0, 1, 0, 1,
            0, 1, 1, 1, 0, 1, 1, 1, 1, 1, 0, 0, 0, 1, 1, 0, 1, 1, 0, 1, 1, 0, 1, 1, 1, 0, 0, 1, 1,
            1, 0, 0, 1, 1, 0, 0, 1, 1, 1, 0, 0, 0, 0, 1, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 1,
            0, 0, 0, 1, 0, 1, 1, 1, 1, 0, 0, 1, 0, 0, 1, 1, 0,
        ];
        let m3 = [
            0, 131, 64, 18, 244, 170, 220, 23, 227, 251, 49, 181, 100, 41, 38, 163, 234, 27, 126,
            10, 209, 190, 115, 98, 64, 1, 96, 32, 71, 234, 76, 114, 243, 223, 144, 182, 204, 62,
            155, 226, 96, 238, 236, 150, 71, 106, 54, 184, 51, 107, 169, 39, 7, 174, 250, 1, 41, 4,
            70, 179, 39, 20, 136, 59, 65, 112, 243, 171, 143, 37, 227, 9, 97, 216, 211, 53, 193,
            241, 73, 135, 18, 61, 164, 87, 94, 204, 203, 243, 59, 99, 115, 20, 194, 38, 244, 221,
            175, 74, 97, 157, 13, 242, 81, 236, 19, 24, 119, 193, 149, 223, 27, 110, 115, 56, 74,
            3, 23, 147, 0,
        ];
        let h3 = pedersen_hash(&m3, inp3.len() as u32);
        assert_eq!(
            h3,
            [
                0x37, 0x5f, 0xdd, 0x7b, 0x29, 0xde, 0x6e, 0x22, 0x5e, 0xbb, 0x7a, 0xe4, 0x20, 0x3c,
                0xa5, 0x0e, 0xca, 0x7c, 0x9b, 0xab, 0x97, 0x1c, 0xc6, 0x91, 0x3c, 0x6f, 0x13, 0xed,
                0xf3, 0x27, 0xe8, 0x00
            ]
        );
    }
}
