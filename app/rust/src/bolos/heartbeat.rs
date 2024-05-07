#[cfg(not(test))]
extern "C" {
    fn io_heart_beat();
}

// Lets the device breath between computations
pub(crate) fn heartbeat() {
    #[cfg(not(test))]
    unsafe {
        io_heart_beat()
    }
}
