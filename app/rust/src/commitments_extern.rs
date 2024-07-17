use crate::bolos::c_zemu_log_stack;
use crate::cryptoops::{add_to_point, extended_to_bytes, extended_to_u_bytes};
use crate::pedersen::multiply_with_pedersen_base;
use crate::sapling::sapling_nsk_to_nk;
use crate::types::{Diversifier, NfBytes, NskBytes};
use crate::{commitments, cryptoops};
use jubjub::Fr;

//////////////////////////////
//////////////////////////////
#[no_mangle]
pub extern "C" fn compute_nullifier(
    ncm_ptr: *const [u8; 32],
    note_pos: u64,
    nsk_ptr: *const NskBytes,
    out_ptr: *mut NfBytes,
) {
    c_zemu_log_stack("compute_nullifier\x00");
    let ncm = unsafe { *ncm_ptr };
    let nsk = unsafe { &*nsk_ptr };
    let out = unsafe { &mut *out_ptr };

    let scalar = Fr::from(note_pos);
    let e = cryptoops::bytes_to_extended(ncm);
    crate::bolos::heartbeat();

    let rho = commitments::mixed_pedersen(&e, scalar);
    crate::bolos::heartbeat();

    let nk = sapling_nsk_to_nk(nsk);
    crate::bolos::heartbeat();

    out.copy_from_slice(&commitments::prf_nf(&nk, &rho));
}

//////////////////////////////
//////////////////////////////
#[no_mangle]
pub extern "C" fn compute_note_commitment(
    rcm_ptr: *const [u8; 32],
    value: u64,
    diversifier_ptr: *const Diversifier,
    pkd_ptr: *const [u8; 32],
    out_ptr: *mut [u8; 32],
) {
    c_zemu_log_stack("----[compute_note_commitment]\x00");

    let rcm = unsafe { &*rcm_ptr };
    let diversifier = unsafe { &*diversifier_ptr };
    let pkd = unsafe { &*pkd_ptr };
    let out = unsafe { &mut *out_ptr };

    // commented code was previous implementation
    // and was given an invalid commitment. code is left here
    // for further investigation

    // let mut gd = [0u8; 32];

    let gd = crate::zip32::compute_g_d(diversifier);

    // commitments::group_hash_from_diversifier(diversifier, &mut gd);
    // commitments::prepare_and_hash_input_commitment(value, &gd, pkd, out);
    // let mut e = cryptoops::bytes_to_extended(*out);
    // let s = multiply_with_pedersen_base(rcm);
    // add_to_point(&mut e, &s);

    // TODO: We need to test note_commitment function at runtime
    // to discard any stack/pic issues
    let commitment_point = crate::commitments::note_commitment(value, &gd, pkd, rcm);

    // Convert the commitment point to bytes
    let cm_bytes = group::GroupEncoding::to_bytes(&commitment_point);

    // out.copy_from_slice(&extended_to_u_bytes(&e));
    out.copy_from_slice(cm_bytes.as_ref());
}

//////////////////////////////
//////////////////////////////
#[no_mangle]
pub extern "C" fn compute_note_commitment_fullpoint(
    rcm_ptr: *const [u8; 32],
    value: u64,
    diversifier_ptr: *const Diversifier,
    pkd_ptr: *const [u8; 32],
    out_ptr: *mut [u8; 32],
) {
    let mut gd = [0u8; 32];
    let diversifier = unsafe { &*diversifier_ptr };

    commitments::group_hash_from_diversifier(diversifier, &mut gd);

    let pkd = unsafe { &*pkd_ptr };
    let out = unsafe { &mut *out_ptr };
    commitments::prepare_and_hash_input_commitment(value, &gd, pkd, out);

    let rc = unsafe { &*rcm_ptr };
    let mut e = cryptoops::bytes_to_extended(*out);
    let s = multiply_with_pedersen_base(rc);

    add_to_point(&mut e, &s);

    out.copy_from_slice(&extended_to_bytes(&e));
}

#[no_mangle]
pub extern "C" fn compute_value_commitment(
    rcm_ptr: *const [u8; 32],
    value: u64,
    out_ptr: *mut [u8; 32],
) {
    let rcm = unsafe { &*rcm_ptr };
    let out = unsafe { &mut *out_ptr };

    //let vcm = value_commitment(value, rc);
    let mut x = commitments::value_commitment_step1(value);
    let s = commitments::value_commitment_step2(rcm);
    add_to_point(&mut x, &s);
    let vcm = extended_to_bytes(&x);
    out.copy_from_slice(&vcm);
}
