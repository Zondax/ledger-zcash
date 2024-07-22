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

use byteorder::ByteOrder;
use core::convert::TryInto;

mod bitstreamer;
mod bolos;
mod commitments;
mod commitments_extern;
mod constants;
mod cryptoops;
mod errors;
mod notes;
mod notes_extern;
mod pedersen;
mod personalization;
mod redjubjub;
mod redjubjub_extern;
mod refactor;
mod sapling;
mod types;
mod utils;
mod zip32;
mod zip32_extern;

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

#[cfg(test)]
mod tests {
    use simple_logger::SimpleLogger;
    use std::sync::Once;

    static INIT: Once = Once::new();

    pub fn setup_logging() {
        INIT.call_once(|| {
            let _ = SimpleLogger::new().init();
        });
    }
}
