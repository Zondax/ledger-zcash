#![no_std]
#![no_builtins]
#![allow(dead_code, unused_imports)]

extern crate core;

mod bolos;
mod constants;
mod parser;
mod zeccrypto;
mod zxformat;

use jubjub::{AffineNielsPoint, AffinePoint, ExtendedPoint, Fq, Fr};
pub use parser::{_getItem, _getNumItems, _parser_init, _read, _validate};
pub use zxformat::{fpi64_to_str, fpu64_to_str};

use blake2s_simd::{blake2s, Hash as Blake2sHash, Params as Blake2sParams};

fn debug(_msg: &str) {}

use core::convert::TryInto;
use core::mem;
#[cfg(not(test))]
use core::panic::PanicInfo;

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}
