use ztruct::create_ztruct;

#[cfg(test)]
mod tests {
    use super::*;

    create_ztruct! {
        pub struct SimpleStruct {
            pub f1: u32,
            pub f2: u32,
        }
    }

    #[test]
    fn test_new() {
        let instance = SimpleStruct::new(0x01020304, 0x05060708);
        assert_eq!(instance.f1(), 0x01020304);
        assert_eq!(instance.f2(), 0x05060708);
        assert_eq!(instance.to_bytes(), &[0x04, 0x03, 0x02, 0x01, 0x08, 0x07, 0x06, 0x05]);
    }

    #[test]
    fn test_from_bytes() {
        let bytes = [0x04, 0x03, 0x02, 0x01, 0x08, 0x07, 0x06, 0x05];
        let instance = SimpleStruct::from_bytes(&bytes);
        assert_eq!(instance.to_bytes(), &bytes);
    }

    #[test]
    fn test_to_bytes() {
        let instance = SimpleStruct::new(0x01020304, 0x05060708);
        let bytes = instance.to_bytes();
        assert_eq!(bytes, &[0x04, 0x03, 0x02, 0x01, 0x08, 0x07, 0x06, 0x05]);
    }

    #[test]
    fn test_to_bytes_mut() {
        let mut instance = SimpleStruct::new(0x01020304, 0x05060708);
        let bytes = instance.to_bytes_mut();
        bytes[0] = 0xFF; // Modify the first byte
        assert_eq!(instance.to_bytes(), &[0xFF, 0x03, 0x02, 0x01, 0x08, 0x07, 0x06, 0x05]);
    }

    #[test]
    fn test_field_accessors() {
        let instance = SimpleStruct::new(0x12345678, 0x9ABCDEF0);
        assert_eq!(instance.f1(), 0x12345678);
        assert_eq!(instance.f2(), 0x9ABCDEF0);
    }

    #[test]
    fn test_mutate_fields() {
        let mut instance = SimpleStruct::new(0x12345678, 0x9ABCDEF0);
        *instance.f1_mut() = 0x87654321;
        *instance.f2_mut() = 0x0FEDCBA9;
        assert_eq!(instance.f1(), 0x87654321);
        assert_eq!(instance.f2(), 0x0FEDCBA9);
    }

    #[test]
    fn test_partial_updates() {
        let mut instance = SimpleStruct::new(0x12345678, 0x9ABCDEF0);
        *instance.f1_mut() = 0x11111111;
        assert_eq!(instance.to_bytes(), &[0x11, 0x11, 0x11, 0x11, 0xF0, 0xDE, 0xBC, 0x9A]);
    }

    #[test]
    fn test_zero_initialization() {
        let instance = SimpleStruct::new(0, 0);
        assert_eq!(instance.f1(), 0);
        assert_eq!(instance.f2(), 0);
        assert_eq!(instance.to_bytes(), &[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    }
}
