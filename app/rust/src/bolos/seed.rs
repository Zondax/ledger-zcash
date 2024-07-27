use crate::types::Zip32Seed;

extern "C" {
    fn crypto_fillDeviceSeed(seed: *mut u8);
}

#[cfg(not(test))]
pub fn c_device_seed() -> Zip32Seed {
    let mut seed: Zip32Seed = [0; 32];
    unsafe {
        crypto_fillDeviceSeed(seed.as_mut_ptr());
    }
    seed
}

#[cfg(test)]
use lazy_static::lazy_static;

#[cfg(test)]
use parking_lot::ReentrantMutex;

#[cfg(test)]
use std::cell::RefCell;

#[cfg(test)]
lazy_static! {
    static ref CUSTOM_TEST_SEED: ReentrantMutex<RefCell<Option<Zip32Seed>>> =
        ReentrantMutex::new(RefCell::new(None));
}

#[cfg(test)]
pub fn with_device_seed_context<F: FnOnce()>(temporary_seed: Zip32Seed, test: F) {
    let guard = CUSTOM_TEST_SEED.lock();

    guard.replace(Some(temporary_seed));

    // Run the test lambda
    test();

    guard.replace(None);
}

#[cfg(test)]
pub fn c_device_seed() -> Zip32Seed {
    let guard = CUSTOM_TEST_SEED.lock();
    let seed_ref = guard.borrow();

    match &*seed_ref {
        Some(temporary_seed) => {
            // Handle the case where the seed is Some
            // `seed` here is a reference to the value inside Some
            temporary_seed.clone()
        }
        None => {
            let mut seed: Zip32Seed = [0; 32];
            // Handle the case where the override seed is None
            for (i, elem) in seed.iter_mut().enumerate() {
                *elem = i as u8;
            }
            seed
        }
    }
}
