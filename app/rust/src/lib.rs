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

use blake2s_simd::{blake2s, Hash as Blake2sHash, Params as Blake2sParams};
use byteorder::{ByteOrder, LittleEndian};
use core::convert::TryInto;
use core::mem;
use jubjub::{AffineNielsPoint, AffinePoint, ExtendedNielsPoint, ExtendedPoint, Fq, Fr};

mod bitstreamer;
mod bolos;
mod commitments;
mod constants;
mod cryptoops;
mod errors;
mod notes;
mod pedersen;
mod personalization;
mod redjubjub;
mod refactor;
mod sapling;
mod types;
mod utils;
mod zip32;

use ztruct;

#[cfg(not(test))]
use core::panic::PanicInfo;

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}

#[cfg(test)]
extern crate hex;
#[cfg(test)]
#[macro_use]
extern crate std;
