#[inline(never)]
pub fn write_u64_tobytes(v: u64) -> [u8; 8] {
    let mut reversed_bytes = [0u8; 8];

    let bytes = v.to_le_bytes();
    reverse_bits(&bytes, &mut reversed_bytes);

    reversed_bytes
}

#[inline(never)]
pub fn reverse_bits(source: &[u8], dest: &mut [u8]) {
    for (i, &byte) in source.iter().enumerate() {
        dest[i] = byte.reverse_bits();
    }
}

#[inline(never)]
pub fn into_fixed_array<T: Into<u128>>(value: T) -> [u8; 32] {
    let bytes = value.into().to_le_bytes();

    let mut scalar = [0u8; 32];

    let size = core::mem::size_of::<T>();
    scalar[..size].copy_from_slice(&bytes[..size]);

    scalar
}
#[inline(never)]
pub fn shiftsixbits(input: &mut [u8; 73]) {
    for i in (1..73).rev() {
        input[i] ^= (input[i - 1] & 0x3F) << 2;
        input[i - 1] >>= 6;
    }
    input[0] ^= 0b1111_1100; // Adjust the first byte after processing the rest
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_revert() {
        let source = [
            0b00000001, 0b00000010, 0b00000100, 0b00001000, 0b00010000, 0b00100000, 0b01000000,
            0b10000000, 0b00000001, 0b00000010, 0b00000100, 0b00001000, 0b00010000, 0b00100000,
            0b01000000, 0b10000000, 0b00000001, 0b00000010, 0b00000100, 0b00001000, 0b00010000,
            0b00100000, 0b01000000, 0b10000000, 0b00000001, 0b00000010, 0b00000100, 0b00001000,
            0b00010000, 0b00100000, 0b01000000, 0b10000000,
        ];
        let mut dest = [0u8; 32];
        reverse_bits(&source, &mut dest);
        let expected = [
            0b10000000, 0b01000000, 0b00100000, 0b00010000, 0b00001000, 0b00000100, 0b00000010,
            0b00000001, 0b10000000, 0b01000000, 0b00100000, 0b00010000, 0b00001000, 0b00000100,
            0b00000010, 0b00000001, 0b10000000, 0b01000000, 0b00100000, 0b00010000, 0b00001000,
            0b00000100, 0b00000010, 0b00000001, 0b10000000, 0b01000000, 0b00100000, 0b00010000,
            0b00001000, 0b00000100, 0b00000010, 0b00000001,
        ];
        assert_eq!(
            dest, expected,
            "Revert function failed to reverse bits correctly."
        );
    }

    #[test]
    fn test_write_u64_tobytes() {
        let v = 0x0123456789ABCDEF;
        let result = write_u64_tobytes(v);
        let expected = [0xF7, 0xB3, 0xD5, 0x91, 0xE6, 0xA2, 0xC4, 0x80];
        assert_eq!(
            result,
            expected,
            "Result: {}, Expected: {}",
            format!("{:X?}", result),
            format!("{:X?}", expected)
        );
    }

    #[test]
    fn test_write_u64_tobytes_1() {
        let v = 0x10E060A020C04080;
        let result = write_u64_tobytes(v);
        let expected = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        assert_eq!(
            result,
            expected,
            "Result: {}, Expected: {}",
            format!("{:X?}", result),
            format!("{:X?}", expected)
        );
    }

    #[test]
    fn test_write_u64_tobytes_2() {
        let v = 0x1000000000000000;
        let result = write_u64_tobytes(v);
        let expected = [0, 0, 0, 0, 0, 0, 0, 8];
        assert_eq!(
            result,
            expected,
            "Result: {}, Expected: {}",
            format!("{:X?}", result),
            format!("{:X?}", expected)
        );
    }

    #[test]
    fn test_write_u64_tobytes_3() {
        let v = 0xf000000000000000;
        let result = write_u64_tobytes(v);
        let expected = [0, 0, 0, 0, 0, 0, 0, 0x0f];
        assert_eq!(
            result,
            expected,
            "Result: {}, Expected: {}",
            format!("{:X?}", result),
            format!("{:X?}", expected)
        );
    }

    #[test]
    fn test_write_u64_tobytes_4() {
        let v = 0xf00000000000000a;
        let result = write_u64_tobytes(v);
        let expected = [0x50, 0, 0, 0, 0, 0, 0, 0x0F];
        assert_eq!(
            result,
            expected,
            "Result: {}, Expected: {}",
            format!("{:X?}", result),
            format!("{:X?}", expected)
        );
    }

    #[test]
    fn test_into32bytearray() {
        let value = 0x0123456789ABCDEFu64;
        let result = into_fixed_array(value);
        let expected = [
            0xEF, 0xCD, 0xAB, 0x89, 0x67, 0x45, 0x23, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        assert_eq!(
            result, expected,
            "u64_to_bytes function failed to convert u64 to 32-byte array correctly."
        );
    }

    #[test]
    fn test_scalar_to_bytes() {
        let pos = 0x12345678u32;
        let result = into_fixed_array(pos);
        let expected = [
            0x78, 0x56, 0x34, 0x12, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0,
        ];
        assert_eq!(
            result, expected,
            "scalar_to_bytes function failed to convert u32 to 32-byte array correctly."
        );
    }
}
