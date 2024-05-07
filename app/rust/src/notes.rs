use byteorder::{ByteOrder, LittleEndian};
use crate::constants::COMPACT_NOTE_SIZE;
use crate::zeccrypto::*;
use crate::zip32::multwithgd;

#[no_mangle]
pub fn get_epk(esk_ptr: *const [u8; 32], d_ptr: *const [u8; 11], output_ptr: *mut [u8; 32]) {
    let esk = unsafe { &*esk_ptr }; //ovk, cv, cmu, epk
    let d = unsafe { &*d_ptr };
    let output = unsafe { &mut *output_ptr };
    let epk = multwithgd(esk, d);
    output.copy_from_slice(&epk);
}

#[no_mangle]
pub extern "C" fn rseed_get_esk_epk(
    rseed_ptr: *const [u8; 32],
    d_ptr: *const [u8; 11],
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
    let shared_secret = sapling_ka_agree(esk, pkd);
    let key = kdf_sapling(&shared_secret, epk);
    crate::bolos::heartbeat();
    let output = unsafe { &mut *output_ptr }; //ovk, cv, cmu, epk
    output.copy_from_slice(&key);
}

#[no_mangle]
pub extern "C" fn prepare_enccompact_input(
    d_ptr: *const [u8; 11],
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

        let shared_secret = sapling_ka_agree(&esk, &pk_d);
        let key = kdf_sapling(&shared_secret, &epk);

        assert_eq!(output, key);
    }
}
