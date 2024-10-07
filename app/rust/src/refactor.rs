use crate::bolos::blake2b::blake2b32_with_personalization;
use crate::personalization::{PRF_OCK_PERSONALIZATION, PRF_SESSION_PERSONALIZATION};

#[no_mangle]
pub extern "C" fn blake2b_prf(input_ptr: *const [u8; 128], out_ptr: *mut [u8; 32]) {
    // todo: move directly to C. No need to get into rust
    let input = unsafe { &*input_ptr }; //ovk, cv, cmu, epk
    let hash = blake2b32_with_personalization(PRF_OCK_PERSONALIZATION, input);
    let output = unsafe { &mut *out_ptr }; //ovk, cv, cmu, epk
    output.copy_from_slice(&hash);
}
