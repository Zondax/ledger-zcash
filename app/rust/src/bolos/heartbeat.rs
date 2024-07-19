#[cfg(not(test))]
extern "C" {
    fn io_heartbeat();
}

// Lets the device breath between computations
pub(crate) fn heartbeat() {
    #[cfg(not(test))]
    unsafe {
        io_heartbeat()
    }
}
