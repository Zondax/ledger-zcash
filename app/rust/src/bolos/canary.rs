use crate::bolos;

extern "C" {
    fn check_app_canary();
}

#[cfg(not(test))]
pub fn c_check_app_canary() {
    unsafe { check_app_canary() }
}

#[cfg(test)]
pub fn c_check_app_canary() {}
