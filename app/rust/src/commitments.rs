use crate::bolos::c_zemu_log_stack;
use crate::constants::{
    NOTE_POSITION_BASE, PEDERSEN_RANDOMNESS_BASE, VALUE_COMMITMENT_RANDOM_BASE,
    VALUE_COMMITMENT_VALUE_BASE,
};
use crate::crypto::{add_to_point, extended_to_bytes, extended_to_u_bytes};
use blake2s_simd::Params as Blake2sParams;
use jubjub::{AffinePoint, ExtendedPoint, Fr};

use crate::pedersen::*;
use crate::personalization::CRH_NF;
use crate::sapling::sapling_nsk_to_nk;
use crate::utils::{into_fixed_array, shiftsixbits};
use crate::zip32::zip32_nsk_from_seed;
use crate::{crypto, utils, zip32}; // #[inline(never)]

#[inline(never)]
pub fn group_hash_from_diversifier(diversifier_ptr: *const [u8; 11], gd_ptr: *mut [u8; 32]) {
    let diversifier = unsafe { &*diversifier_ptr };
    let gd = unsafe { &mut *gd_ptr };
    let gd_tmp = zip32::pkd_group_hash(diversifier);
    gd.copy_from_slice(&gd_tmp);
}

#[inline(never)]
pub fn prepare_and_hash_input_commitment(
    value: u64,
    g_d_ptr: *const [u8; 32],
    pkd_ptr: *const [u8; 32],
    output_ptr: *mut [u8; 32],
) {
    // Dereference pointers safely within an unsafe block
    let gd = unsafe { &*g_d_ptr };
    let pkd = unsafe { &*pkd_ptr };
    let output_msg = unsafe { &mut *output_ptr };

    // Initialize buffers for input hash and prepared message
    let mut input_hash = [0u8; 73];

    // Convert the value to bytes and reverse the bits
    let vbytes = utils::write_u64_tobytes(value);
    input_hash[0..8].copy_from_slice(&vbytes);

    // Reverse bits for g_d and pk_d and place them into the input hash
    utils::reverse_bits(gd, &mut input_hash[8..40]);
    utils::reverse_bits(pkd, &mut input_hash[40..72]);

    // Perform a bit shift operation on the entire array
    shiftsixbits(&mut input_hash);

    // Compute the Pedersen hash from the prepared input hash
    let h = pedersen_hash_pointbytes(&input_hash, 582);
    output_msg.copy_from_slice(&h);
}

////////////////////////////////////////////////
////////////////////////////////////////////////

#[inline(never)]
pub fn mixed_pedersen(e: &ExtendedPoint, scalar: Fr) -> [u8; 32] {
    let mut p = NOTE_POSITION_BASE * scalar;
    add_to_point(&mut p, e);
    extended_to_bytes(&p)
}

#[inline(never)]
pub fn prf_nf(nk: &[u8; 32], rho: &[u8; 32]) -> [u8; 32] {
    // BLAKE2s Personalization for PRF^nf = BLAKE2s(nk | rho)
    let h = Blake2sParams::new()
        .hash_length(32)
        .personal(CRH_NF)
        .to_state()
        .update(nk)
        .update(rho)
        .finalize();
    let x: [u8; 32] = *h.as_array();
    x
}

//////////////////////////////
//////////////////////////////
#[no_mangle]
pub extern "C" fn compute_nullifier(
    ncm_ptr: *const [u8; 32],
    pos: u64,
    nsk_ptr: *const [u8; 32],
    output_ptr: *mut [u8; 32],
) {
    c_zemu_log_stack(b"compute_nullifier\x00".as_ref());
    let ncm = unsafe { *ncm_ptr };
    let nsk = unsafe { &*nsk_ptr };
    let nk = sapling_nsk_to_nk(nsk);

    crate::bolos::heartbeat();

    let scalar = Fr::from(pos);
    let e = crypto::bytes_to_extended(ncm);
    crate::bolos::heartbeat();

    let rho = mixed_pedersen(&e, scalar);
    crate::bolos::heartbeat();

    let output = unsafe { &mut *output_ptr };
    output.copy_from_slice(&prf_nf(&nk, &rho));
}

//////////////////////////////
//////////////////////////////
#[no_mangle]
pub extern "C" fn compute_note_commitment(
    input_ptr: *mut [u8; 32],
    rcm_ptr: *const [u8; 32],
    value: u64,
    diversifier_ptr: *const [u8; 11],
    pkd_ptr: *const [u8; 32],
) {
    let mut gd = [0u8; 32];
    let diversifier = unsafe { &*diversifier_ptr };
    group_hash_from_diversifier(diversifier, &mut gd);

    let pkd = unsafe { &*pkd_ptr };
    let out = unsafe { &mut *input_ptr };
    prepare_and_hash_input_commitment(value, &gd, pkd, out);

    let rc = unsafe { &*rcm_ptr };
    let mut e = crypto::bytes_to_extended(*out);
    let s = multiply_with_pedersen_base(rc);

    add_to_point(&mut e, &s);

    out.copy_from_slice(&extended_to_u_bytes(&e));
}

//////////////////////////////
//////////////////////////////
#[no_mangle]
pub extern "C" fn compute_note_commitment_fullpoint(
    input_ptr: *mut [u8; 32],
    rcm_ptr: *const [u8; 32],
    value: u64,
    diversifier_ptr: *const [u8; 11],
    pkd_ptr: *const [u8; 32],
) {
    let mut gd = [0u8; 32];
    let diversifier = unsafe { &*diversifier_ptr };

    group_hash_from_diversifier(diversifier, &mut gd);

    let pkd = unsafe { &*pkd_ptr };
    let out = unsafe { &mut *input_ptr };
    prepare_and_hash_input_commitment(value, &gd, pkd, out);

    let rc = unsafe { &*rcm_ptr };
    let mut e = crypto::bytes_to_extended(*out);
    let s = multiply_with_pedersen_base(rc);

    add_to_point(&mut e, &s);

    out.copy_from_slice(&extended_to_bytes(&e));
}

//////////////////////////////
//////////////////////////////

#[inline(never)]
pub fn value_commitment_step1(value: u64) -> ExtendedPoint {
    let scalar = into_fixed_array(value);
    VALUE_COMMITMENT_VALUE_BASE.multiply_bits(&scalar)
}

#[inline(never)]
pub fn value_commitment_step2(rcm: &[u8; 32]) -> ExtendedPoint {
    VALUE_COMMITMENT_RANDOM_BASE.multiply_bits(rcm)
}

#[no_mangle]
pub extern "C" fn compute_value_commitment(
    value: u64,
    rcm_ptr: *const [u8; 32],
    output_ptr: *mut [u8; 32],
) {
    let rc = unsafe { &*rcm_ptr };
    let output_msg = unsafe { &mut *output_ptr };

    //let vcm = value_commitment(value, rc);
    let mut x = value_commitment_step1(value);
    let s = value_commitment_step2(rc);
    add_to_point(&mut x, &s);
    let vcm = extended_to_bytes(&x);
    output_msg.copy_from_slice(&vcm);
}

//////////////////////////////
//////////////////////////////

#[cfg(test)]
mod tests {
    use crate::utils::into_fixed_array;

    use super::*;

    #[inline(never)]
    pub fn note_commitment(
        v: u64,
        g_d: &[u8; 32],
        pk_d: &[u8; 32],
        rcm: &[u8; 32],
    ) -> ExtendedPoint {
        c_zemu_log_stack(b"notecommit\x00".as_ref());
        let mut input_hash = [0u8; 73];

        // Convert the value to bytes and reverse the bits as per protocol
        let vbytes = utils::write_u64_tobytes(v);
        input_hash[0..8].copy_from_slice(&vbytes);

        // Reverse bits for g_d and pk_d and place them into the input hash
        utils::reverse_bits(g_d, &mut input_hash[8..40]);
        utils::reverse_bits(pk_d, &mut input_hash[40..72]);

        // Perform a bit shift operation on the entire array
        shiftsixbits(&mut input_hash);

        // Compute the Pedersen hash to point
        let mut p = pedersen_hash_to_point(&input_hash, 582);

        // Multiply the randomness base by rcm and add to the point
        let s = PEDERSEN_RANDOMNESS_BASE.multiply_bits(rcm);
        p += s;

        p
    }

    #[inline(never)]
    pub fn value_commitment(value: u64, rcm: &[u8; 32]) -> [u8; 32] {
        let scalar = into_fixed_array(value);
        let mut x = VALUE_COMMITMENT_VALUE_BASE.multiply_bits(&scalar);
        x += VALUE_COMMITMENT_RANDOM_BASE.multiply_bits(rcm);
        extended_to_bytes(&x)
    }

    #[test]
    fn test_ncm_c() {
        let v = 100000;
        let mut gd = [0u8; 32];
        let div_ptr = [0u8; 11];
        let pkd = [0u8; 32];
        let rcm = [0u8; 32];
        let output = [0u8; 32];

        let div = &div_ptr;

        group_hash_from_diversifier(div, &mut gd);

        prepare_and_hash_input_commitment(
            v,
            gd.as_ptr() as *const [u8; 32],
            pkd.as_ptr() as *const [u8; 32],
            output.as_ptr() as *mut [u8; 32],
        );

        compute_note_commitment(
            output.as_ptr() as *mut [u8; 32],
            rcm.as_ptr() as *const [u8; 32],
            v,
            div.as_ptr() as *const [u8; 11],
            pkd.as_ptr() as *const [u8; 32],
        );

        assert_eq!(
            output,
            [
                51, 107, 65, 49, 174, 10, 181, 105, 255, 123, 174, 149, 217, 191, 95, 76, 7, 90,
                151, 132, 85, 143, 180, 30, 26, 35, 160, 160, 197, 140, 21, 95
            ]
        );
    }

    #[test]
    fn test_valuecommit() {
        let rcm: [u8; 32] = [
            251, 95, 86, 230, 162, 167, 192, 202, 152, 240, 81, 12, 55, 67, 211, 154, 62, 218, 51,
            222, 254, 165, 64, 86, 12, 133, 142, 230, 82, 160, 204, 2,
        ];

        let value: u64 = 1000000;

        let cvtest = [
            239, 131, 3, 60, 201, 185, 181, 197, 195, 143, 58, 116, 0, 164, 87, 230, 88, 49, 234,
            15, 238, 183, 46, 114, 63, 13, 100, 104, 194, 53, 240, 16,
        ];

        let cv = value_commitment(value, &rcm);
        assert_eq!(cvtest, cv);
    }

    #[test]
    fn test_nf() {
        let pos: u32 = 2578461368;
        let pk_d = [
            0x62, 0xef, 0xd5, 0x43, 0x93, 0xb3, 0x20, 0x09, 0xad, 0x95, 0x33, 0xc0, 0xd9, 0x97,
            0x5f, 0xef, 0xce, 0xab, 0x46, 0xd7, 0x20, 0x92, 0xac, 0x3b, 0x56, 0xd1, 0xf3, 0xb7,
            0x3c, 0x8b, 0xf0, 0x27,
        ];

        let g_d: [u8; 32] = [
            0x88, 0x59, 0xed, 0x93, 0x71, 0xcd, 0x59, 0x8a, 0xf4, 0x72, 0x15, 0xc2, 0x70, 0xa2,
            0x59, 0x95, 0xa3, 0xdd, 0xe4, 0x57, 0x88, 0xca, 0xb9, 0xd2, 0x88, 0xca, 0x62, 0xbf,
            0x6e, 0x60, 0xc0, 0x17,
        ];

        let value: u64 = 17811330145809239872;
        let rcm: [u8; 32] = [
            0x6e, 0xbb, 0xed, 0x74, 0x36, 0x19, 0xa2, 0x56, 0xf9, 0xad, 0x2e, 0x85, 0x88, 0x0c,
            0xfa, 0xa9, 0x09, 0x8a, 0x5f, 0xdb, 0x16, 0x29, 0x99, 0x0d, 0x9a, 0x7d, 0x3b, 0xb9,
            0x3f, 0xc9, 0x00, 0x03,
        ];

        let nk = [
            0x62, 0x44, 0x00, 0x10, 0x3b, 0x65, 0x69, 0xb7, 0x35, 0x8f, 0xe8, 0x0f, 0x6f, 0x6c,
            0xad, 0x43, 0x25, 0xde, 0xfd, 0xa9, 0xd9, 0x49, 0x9c, 0x2b, 0x8f, 0x88, 0x6a, 0x62,
            0x69, 0xa2, 0xaa, 0x52,
        ];

        let h = note_commitment(value, &g_d, &pk_d, &rcm);

        let mp = mixed_pedersen(&h, jubjub::Fr::from_bytes(&into_fixed_array(pos)).unwrap());

        let nf = prf_nf(&nk, &mp);

        let nftest: [u8; 32] = [
            0x4a, 0xb5, 0x57, 0x93, 0x33, 0x81, 0xd9, 0xb0, 0xa2, 0x6a, 0x10, 0xc9, 0x66, 0xdb,
            0x62, 0x4a, 0x18, 0xc5, 0xf4, 0xa5, 0xe5, 0x0c, 0x93, 0x8f, 0x2f, 0x24, 0x11, 0x19,
            0x88, 0x5e, 0x39, 0xb1,
        ];
        assert_eq!(nf, nftest);
    }

    #[test]
    fn test_get_nf() {
        let pos: u64 = 2578461368;

        let seed: [u8; 32] = [
            176, 142, 61, 152, 218, 67, 28, 239, 69, 102, 161, 60, 27, 179, 72, 185, 130, 247, 216,
            231, 67, 180, 59, 182, 37, 87, 186, 81, 153, 75, 18, 87,
        ];

        let cm: [u8; 32] = [
            0x21, 0xc9, 0x46, 0x98, 0xca, 0x32, 0x4b, 0x4c, 0xba, 0xce, 0x29, 0x1d, 0x27, 0xab,
            0xb6, 0x8a, 0xa, 0xaf, 0x27, 0x37, 0xdc, 0x45, 0x56, 0x54, 0x1c, 0x7f, 0xcd, 0xe8,
            0xce, 0x11, 0xdd, 0xe8,
        ];

        let mut nsk = [0u8; 32];
        zip32_nsk_from_seed(&seed, &mut nsk);

        let mut nf = [0u8; 32];
        compute_nullifier(&cm, pos, &nsk, &mut nf);

        let nftest: [u8; 32] = [
            0x25, 0xf1, 0xf2, 0xcf, 0x5e, 0x2c, 0x2b, 0xc3, 0x1d, 0x7, 0xb6, 0x6f, 0x4d, 0x54,
            0xf0, 0x90, 0xad, 0x89, 0xb1, 0x98, 0x89, 0x3f, 0x12, 0xad, 0xae, 0x44, 0x7d, 0xdf,
            0x84, 0xe2, 0x14, 0x5a,
        ];
        assert_eq!(nf, nftest);
    }

    #[test]
    fn test_mixed_pedersen() {
        let v = 312354353u32;
        let scalar = into_fixed_array(v);
        let mp = mixed_pedersen(
            &ExtendedPoint::identity(),
            jubjub::Fr::from_bytes(&scalar).unwrap(),
        );
        assert_eq!(
            mp,
            [
                229, 21, 27, 49, 9, 57, 15, 12, 130, 17, 72, 150, 250, 83, 173, 10, 32, 188, 132,
                68, 124, 203, 153, 66, 197, 109, 156, 189, 116, 231, 80, 75
            ]
        );
    }

    #[test]
    fn test_note_commitment_null() {
        let rcm: [u8; 32] = [
            0x6e, 0xbb, 0xed, 0x74, 0x36, 0x19, 0xa2, 0x56, 0xf9, 0xad, 0x2e, 0x85, 0x88, 0x0c,
            0xfa, 0xa9, 0x09, 0x8a, 0x5f, 0xdb, 0x16, 0x29, 0x99, 0x0d, 0x9a, 0x7d, 0x3b, 0xb9,
            0x3f, 0xc9, 0x00, 0x03,
        ];
        let g_d = [0u8; 32];
        let pk_d = [0u8; 32];
        let value: u64 = 0;

        let cmnul = [
            0x0d, 0x7d, 0xfe, 0x59, 0x28, 0xee, 0x5d, 0x23, 0xbc, 0x93, 0x85, 0x9b, 0xb9, 0x93,
            0x5a, 0x23, 0xe7, 0xa9, 0x9d, 0xda, 0xf9, 0xd0, 0x97, 0x3d, 0x1d, 0xd1, 0x9e, 0xff,
            0xed, 0x3f, 0x29, 0x13,
        ];

        let t = note_commitment(value, &g_d, &pk_d, &rcm);
        let b = AffinePoint::from(&t).get_u().to_bytes();
        assert_eq!(b, cmnul);
    }

    #[test]
    fn test_note_commitment() {
        let rcm: [u8; 32] = [
            0x6e, 0xbb, 0xed, 0x74, 0x36, 0x19, 0xa2, 0x56, 0xf9, 0xad, 0x2e, 0x85, 0x88, 0x0c,
            0xfa, 0xa9, 0x09, 0x8a, 0x5f, 0xdb, 0x16, 0x29, 0x99, 0x0d, 0x9a, 0x7d, 0x3b, 0xb9,
            0x3f, 0xc9, 0x00, 0x03,
        ];
        let g_d: [u8; 32] = [
            0x88, 0x59, 0xed, 0x93, 0x71, 0xcd, 0x59, 0x8a, 0xf4, 0x72, 0x15, 0xc2, 0x70, 0xa2,
            0x59, 0x95, 0xa3, 0xdd, 0xe4, 0x57, 0x88, 0xca, 0xb9, 0xd2, 0x88, 0xca, 0x62, 0xbf,
            0x6e, 0x60, 0xc0, 0x17,
        ];

        let pk_d: [u8; 32] = [
            0x62, 0xef, 0xd5, 0x43, 0x93, 0xb3, 0x20, 0x09, 0xad, 0x95, 0x33, 0xc0, 0xd9, 0x97,
            0x5f, 0xef, 0xce, 0xab, 0x46, 0xd7, 0x20, 0x92, 0xac, 0x3b, 0x56, 0xd1, 0xf3, 0xb7,
            0x3c, 0x8b, 0xf0, 0x27,
        ];

        let value: u64 = 1000000000;

        let cmnul = [
            0xef, 0xa5, 0xc8, 0x8e, 0xd5, 0x02, 0x9e, 0xae, 0xb2, 0x75, 0x83, 0x55, 0xec, 0xdc,
            0x35, 0x1a, 0x9a, 0x45, 0x01, 0x57, 0x77, 0x83, 0x58, 0x37, 0x3e, 0xaa, 0x19, 0x2a,
            0x5d, 0x7f, 0x9d, 0x68,
        ];

        let t = note_commitment(value, &g_d, &pk_d, &rcm);
        let b = AffinePoint::from(&t).get_u().to_bytes();
        assert_eq!(b, cmnul);
    }
}
