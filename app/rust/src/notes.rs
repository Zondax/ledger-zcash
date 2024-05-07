use crate::bolos::blake2b::blake2b32_with_personalization;
use crate::constants::COMPACT_NOTE_SIZE;
use crate::cryptoops::{
    bytes_to_extended, extended_to_bytes, mul_by_cofactor, mult_by_gd, prf_expand,
};
use crate::personalization::KDF_SAPLING_PERSONALIZATION;
use crate::types::Diversifier;
use crate::zip32::niels_multbits;
use byteorder::{ByteOrder, LittleEndian};
use jubjub::Fr;

#[inline(never)]
fn rseed_generate_esk(rseed: &[u8; 32]) -> Fr {
    let bytes = prf_expand(rseed, &[0x05]);
    Fr::from_bytes_wide(&bytes)
}

#[inline(never)]
fn rseed_get_esk(rseed_ptr: *const [u8; 32], output_ptr: *mut [u8; 32]) {
    let rseed = unsafe { &*rseed_ptr };
    let output = unsafe { &mut *output_ptr };
    let p = rseed_generate_esk(rseed);
    output.copy_from_slice(&p.to_bytes());
}

#[no_mangle]
fn get_epk(esk_ptr: *const [u8; 32], d_ptr: *const Diversifier, output_ptr: *mut [u8; 32]) {
    let esk = unsafe { &*esk_ptr }; //ovk, cv, cmu, epk
    let d = unsafe { &*d_ptr };
    let output = unsafe { &mut *output_ptr };
    let epk = mult_by_gd(esk, d);
    output.copy_from_slice(&epk);
}

#[no_mangle]
pub extern "C" fn rseed_get_esk_epk(
    rseed_ptr: *const [u8; 32],
    d_ptr: *const Diversifier,
    output_esk_ptr: *mut [u8; 32],
    output_epk_ptr: *mut [u8; 32],
) {
    crate::bolos::heartbeat();
    let rseed = unsafe { &*rseed_ptr };

    let output_esk = unsafe { &mut *output_esk_ptr };
    let output_epk = unsafe { &mut *output_epk_ptr };

    rseed_get_esk(rseed, output_esk);

    get_epk(output_esk, d_ptr, output_epk);

    crate::bolos::heartbeat();
}

//////////////////////////////
//////////////////////////////

#[inline(never)]
pub fn ka_agree(esk: &[u8; 32], pk_d: &[u8; 32]) -> [u8; 32] {
    let mut y = bytes_to_extended(*pk_d);
    mul_by_cofactor(&mut y);
    niels_multbits(&mut y, esk);
    extended_to_bytes(&y)
}

#[inline(never)]
pub fn sapling_kdf(dh_secret: &[u8; 32], epk: &[u8; 32]) -> [u8; 32] {
    let mut input = [0u8; 64];
    (&mut input[..32]).copy_from_slice(dh_secret);
    (&mut input[32..]).copy_from_slice(epk);
    crate::bolos::heartbeat();
    blake2b32_with_personalization(KDF_SAPLING_PERSONALIZATION, &input)
}

#[no_mangle]
pub extern "C" fn ka_to_key(
    esk_ptr: *const [u8; 32],
    pkd_ptr: *const [u8; 32],
    epk_ptr: *const [u8; 32],
    output_ptr: *mut [u8; 32],
) {
    crate::bolos::heartbeat();
    let esk = unsafe { &*esk_ptr }; //ovk, cv, cmu, epk
    let pkd = unsafe { &*pkd_ptr };
    let epk = unsafe { &*epk_ptr };
    let shared_secret = ka_agree(esk, pkd);
    let key = sapling_kdf(&shared_secret, epk);
    crate::bolos::heartbeat();
    let output = unsafe { &mut *output_ptr }; //ovk, cv, cmu, epk
    output.copy_from_slice(&key);
}

//////////////////////////////
//////////////////////////////

#[no_mangle]
pub extern "C" fn prepare_enccompact_input(
    d_ptr: *const Diversifier,
    value: u64,
    rcm_ptr: *const [u8; 32],
    memotype: u8,
    output_ptr: *mut [u8; COMPACT_NOTE_SIZE + 1],
) {
    let d = unsafe { &*d_ptr };
    let rcm = unsafe { &*rcm_ptr };

    let output = unsafe { &mut *output_ptr };

    let mut input = [0; COMPACT_NOTE_SIZE + 1];
    input[0] = 2;
    input[1..12].copy_from_slice(d);

    let mut vbytes = [0u8; 8];
    LittleEndian::write_u64(&mut vbytes, value);

    input[12..20].copy_from_slice(&vbytes);
    input[20..COMPACT_NOTE_SIZE].copy_from_slice(rcm);
    input[COMPACT_NOTE_SIZE] = memotype;
    output.copy_from_slice(&input);
}

//////////////////////////////
//////////////////////////////

#[inline(never)]
fn rseed_generate_rcm(rseed: &[u8; 32]) -> Fr {
    let bytes = prf_expand(rseed, &[0x04]);
    crate::bolos::heartbeat();
    Fr::from_bytes_wide(&bytes)
}

#[no_mangle]
pub extern "C" fn rseed_get_rcm(rseed_ptr: *const [u8; 32], output_ptr: *mut [u8; 32]) {
    let rseed = unsafe { &*rseed_ptr };
    let output = unsafe { &mut *output_ptr };
    let p = rseed_generate_rcm(rseed);
    output.copy_from_slice(&p.to_bytes());
}

//////////////////////////////
//////////////////////////////

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_katokey() {
        let esk = [
            0x81, 0xc7, 0xb2, 0x17, 0x1f, 0xf4, 0x41, 0x52, 0x50, 0xca, 0xc0, 0x1f, 0x59, 0x82,
            0xfd, 0x8f, 0x49, 0x61, 0x9d, 0x61, 0xad, 0x78, 0xf6, 0x83, 0x0b, 0x3c, 0x60, 0x61,
            0x45, 0x96, 0x2a, 0x0e,
        ];
        let pk_d = [
            0xdb, 0x4c, 0xd2, 0xb0, 0xaa, 0xc4, 0xf7, 0xeb, 0x8c, 0xa1, 0x31, 0xf1, 0x65, 0x67,
            0xc4, 0x45, 0xa9, 0x55, 0x51, 0x26, 0xd3, 0xc2, 0x9f, 0x14, 0xe3, 0xd7, 0x76, 0xe8,
            0x41, 0xae, 0x74, 0x15,
        ];

        let epk = [
            0xde, 0xd6, 0x8f, 0x05, 0xc6, 0x58, 0xfc, 0xae, 0x5a, 0xe2, 0x18, 0x64, 0x6f, 0xf8,
            0x44, 0x40, 0x6f, 0x84, 0x42, 0x67, 0x84, 0x04, 0x0d, 0x0b, 0xef, 0x2b, 0x09, 0xcb,
            0x38, 0x48, 0xc4, 0xdc,
        ];

        let mut output = [0u8; 32];

        ka_to_key(
            esk.as_ptr() as *const [u8; 32],
            pk_d.as_ptr() as *const [u8; 32],
            epk.as_ptr() as *const [u8; 32],
            output.as_mut_ptr() as *mut [u8; 32],
        );

        let shared_secret = ka_agree(&esk, &pk_d);
        let key = sapling_kdf(&shared_secret, &epk);

        assert_eq!(output, key);
    }
}
