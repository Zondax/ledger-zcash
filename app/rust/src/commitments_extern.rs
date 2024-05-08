use crate::bolos::c_zemu_log_stack;
use crate::cryptoops::{add_to_point, extended_to_bytes, extended_to_u_bytes};
use crate::pedersen::multiply_with_pedersen_base;
use crate::sapling::sapling_nsk_to_nk;
use crate::types::Diversifier;
use crate::{commitments, cryptoops};
use jubjub::Fr;

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
    let e = cryptoops::bytes_to_extended(ncm);
    crate::bolos::heartbeat();

    let rho = commitments::mixed_pedersen(&e, scalar);
    crate::bolos::heartbeat();

    let output = unsafe { &mut *output_ptr };
    output.copy_from_slice(&commitments::prf_nf(&nk, &rho));
}

//////////////////////////////
//////////////////////////////
#[no_mangle]
pub extern "C" fn compute_note_commitment(
    input_ptr: *mut [u8; 32],
    rcm_ptr: *const [u8; 32],
    value: u64,
    diversifier_ptr: *const Diversifier,
    pkd_ptr: *const [u8; 32],
) {
    let mut gd = [0u8; 32];
    let diversifier = unsafe { &*diversifier_ptr };
    commitments::group_hash_from_diversifier(diversifier, &mut gd);

    let pkd = unsafe { &*pkd_ptr };
    let out = unsafe { &mut *input_ptr };
    commitments::prepare_and_hash_input_commitment(value, &gd, pkd, out);

    let rc = unsafe { &*rcm_ptr };
    let mut e = cryptoops::bytes_to_extended(*out);
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
    diversifier_ptr: *const Diversifier,
    pkd_ptr: *const [u8; 32],
) {
    let mut gd = [0u8; 32];
    let diversifier = unsafe { &*diversifier_ptr };

    commitments::group_hash_from_diversifier(diversifier, &mut gd);

    let pkd = unsafe { &*pkd_ptr };
    let out = unsafe { &mut *input_ptr };
    commitments::prepare_and_hash_input_commitment(value, &gd, pkd, out);

    let rc = unsafe { &*rcm_ptr };
    let mut e = cryptoops::bytes_to_extended(*out);
    let s = multiply_with_pedersen_base(rc);

    add_to_point(&mut e, &s);

    out.copy_from_slice(&extended_to_bytes(&e));
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
    let mut x = commitments::value_commitment_step1(value);
    let s = commitments::value_commitment_step2(rc);
    add_to_point(&mut x, &s);
    let vcm = extended_to_bytes(&x);
    output_msg.copy_from_slice(&vcm);
}
