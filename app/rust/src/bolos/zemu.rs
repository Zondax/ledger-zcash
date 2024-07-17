use crate::bolos;

extern "C" {
    fn zemu_log_stack(buffer: *const u8);
}

#[cfg(not(test))]
pub fn c_zemu_log_stack(s: &str) {
    unsafe { zemu_log_stack(s.as_ptr()) }
}

#[cfg(test)]
pub fn c_zemu_log_stack(_s: &str) {}
