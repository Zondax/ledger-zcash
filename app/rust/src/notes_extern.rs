use byteorder::{ByteOrder, LittleEndian};

use crate::notes;
use crate::notes::{get_epk, rseed_generate_rcm, rseed_get_esk};
use crate::types::{CompactNoteExt, Diversifier};

#[no_mangle]
pub extern "C" fn rseed_get_esk_epk(
    rseed_ptr: *const [u8; 32],
    d_ptr: *const Diversifier,
    out_esk_ptr: *mut [u8; 32],
    out_epk_ptr: *mut [u8; 32],
) {
    crate::bolos::heartbeat();
    let rseed = unsafe { &*rseed_ptr };

    let out_esk = unsafe { &mut *out_esk_ptr };
    let out_epk = unsafe { &mut *out_epk_ptr };

    rseed_get_esk(rseed, out_esk);
    get_epk(out_esk, d_ptr, out_epk);

    crate::bolos::heartbeat();
}

#[no_mangle]
pub extern "C" fn rseed_get_rcm(rseed_ptr: *const [u8; 32], out_ptr: *mut [u8; 32]) {
    let rseed = unsafe { &*rseed_ptr };
    let out = unsafe { &mut *out_ptr };
    let p = rseed_generate_rcm(rseed);
    out.copy_from_slice(&p.to_bytes());
}

#[no_mangle]
pub extern "C" fn ka_to_key(
    esk_ptr: *const [u8; 32],
    pkd_ptr: *const [u8; 32],
    epk_ptr: *const [u8; 32],
    out_ptr: *mut [u8; 32],
) {
    let esk = unsafe { &*esk_ptr }; //ovk, cv, cmu, epk
    let pkd = unsafe { &*pkd_ptr };
    let epk = unsafe { &*epk_ptr };
    let out = unsafe { &mut *out_ptr }; //ovk, cv, cmu, epk

    let shared_secret = notes::ka_agree(esk, pkd);
    let key = notes::sapling_kdf(&shared_secret, epk);
    crate::bolos::heartbeat();

    out.copy_from_slice(&key);
}

#[no_mangle]
pub extern "C" fn prepare_compact_note(
    d_ptr: *const Diversifier,
    value: u64,
    rcm_ptr: *const [u8; 32],
    memotype: u8,
    out_ptr: *mut CompactNoteExt,
) {
    let d = unsafe { &*d_ptr };
    let rcm = unsafe { &*rcm_ptr };
    let out = unsafe { &mut *out_ptr };

    *out.version_mut() = 2u8;
    out.diversifier_mut().copy_from_slice(d);
    LittleEndian::write_u64(out.value_mut(), value);
    out.rcm_mut().copy_from_slice(rcm);
    *out.memotype_mut() = memotype;
}
