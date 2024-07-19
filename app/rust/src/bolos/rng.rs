use rand::{CryptoRng, RngCore};

pub struct Trng;

impl RngCore for Trng {
    fn next_u32(&mut self) -> u32 {
        let mut out = [0; 4];
        self.fill_bytes(&mut out);
        u32::from_le_bytes(out)
    }

    fn next_u64(&mut self) -> u64 {
        let mut out = [0; 8];
        self.fill_bytes(&mut out);
        u64::from_le_bytes(out)
    }

    #[cfg(not(any(unix, windows)))]
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        unsafe {
            bolos_cx_rng(dest.as_mut_ptr(), dest.len() as u32);
        }
    }

    #[cfg(test)]
    #[cfg(any(unix, windows))]
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        getrandom::getrandom(dest).unwrap()
    }

    #[cfg(not(test))]
    #[cfg(any(unix, windows))]
    fn fill_bytes(&mut self, _dest: &mut [u8]) {}

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl CryptoRng for Trng {}

extern "C" {
    fn bolos_cx_rng(buffer: *mut u8, len: u32);
}

#[test]
fn test_randomness() {
    let mut buf = [0u8; 64];
    Trng.fill_bytes(&mut buf);
    assert_ne!(buf[..], [0u8; 64][..]);
}
