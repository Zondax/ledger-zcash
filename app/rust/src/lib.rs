#![no_std]
#![no_builtins]
#![allow(
    dead_code,
    unused_imports,
    clippy::many_single_char_names,
    clippy::needless_range_loop
)]

extern crate chacha20poly1305;
extern crate core;
#[cfg(test)]
extern crate hex;
#[cfg(test)]
#[macro_use]
extern crate std;

use core::convert::TryInto;
use core::mem;
#[cfg(not(test))]
use core::panic::PanicInfo;

use blake2s_simd::{blake2s, Hash as Blake2sHash, Params as Blake2sParams};
use byteorder::{BigEndian, ByteOrder, LittleEndian};
use jubjub::{AffineNielsPoint, AffinePoint, ExtendedNielsPoint, ExtendedPoint, Fq, Fr};

pub use zxformat::{fpi64_to_str, fpu64_to_str};

use crate::bolos::{c_check_app_canary, c_zemu_log_stack};

mod aead;
mod bolos;
mod commitments;
mod constants;
mod errors;
mod note_encryption;
mod pedersen;
mod redjubjub;
mod sighash;
mod tests_crypto;
mod zeccrypto;
mod zip32;
mod zxformat;

fn debug(_msg: &str) {}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}
