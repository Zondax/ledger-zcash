use crate::bolos::c_zemu_log_stack;
use crate::cryptoops::random_scalar;
use crate::redjubjub::{sign_complete, sk_to_pk};
use jubjub::Fr;

#[no_mangle]
pub extern "C" fn rsk_to_rk(rsk_ptr: *const [u8; 32], rk_ptr: *mut [u8; 32]) {
    sk_to_pk(rsk_ptr, rk_ptr)
}

#[no_mangle]
pub extern "C" fn sign_redjubjub(
    key_ptr: *const [u8; 32],
    msg_ptr: *const [u8; 64],
    out_ptr: *mut [u8; 64],
) {
    c_zemu_log_stack("sign_redjubjub\x00");
    let key = unsafe { *key_ptr };
    let msg = unsafe { *msg_ptr };
    let output = unsafe { &mut *out_ptr };
    let sk = Fr::from_bytes(&key).unwrap();
    output.copy_from_slice(&sign_complete(&msg, &sk));
}

#[no_mangle]
pub extern "C" fn random_fr(alpha_ptr: *mut [u8; 32]) {
    let alpha = unsafe { &mut *alpha_ptr };
    let fr = random_scalar();
    alpha.copy_from_slice(&fr.to_bytes());
}
