use jubjub::AffinePoint;
use crate::{bolos, constants};
use crate::bolos::canary::c_check_app_canary;

extern "C" {
    fn c_jubjub_scalarmult(point: *mut u8, scalar: *const u8);
    fn c_jubjub_spending_base_scalarmult(point: *mut u8, scalar: *const u8);
}

#[cfg(not(test))]
pub fn sdk_jubjub_scalarmult_spending_base(point: &mut [u8], scalar: &[u8]) {
    unsafe {
        c_jubjub_spending_base_scalarmult(point.as_mut_ptr(), scalar.as_ptr());
        c_check_app_canary();
    }
}

#[cfg(test)]
pub fn sdk_jubjub_scalarmult_spending_base(point: &mut [u8], scalar: &[u8]) {
    let mut scalarbytes = [0u8; 32];
    scalarbytes.copy_from_slice(&scalar);
    let result = constants::SPENDING_KEY_BASE.multiply_bits(&scalarbytes);
    point.copy_from_slice(&AffinePoint::from(result).to_bytes());
}

#[cfg(not(test))]
pub fn sdk_jubjub_scalarmult(point: &mut [u8], scalar: &[u8]) {
    unsafe {
        c_jubjub_scalarmult(point.as_mut_ptr(), scalar.as_ptr());
    }
}

#[cfg(test)]
pub fn sdk_jubjub_scalarmult(point: &mut [u8], scalar: &[u8]) {
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&point);
    let mut scalarbytes = [0u8; 32];
    scalarbytes.copy_from_slice(&scalar);
    let result = AffinePoint::from_bytes(bytes)
        .unwrap()
        .to_niels()
        .multiply_bits(&scalarbytes);
    point.copy_from_slice(&AffinePoint::from(result).to_bytes());
}
