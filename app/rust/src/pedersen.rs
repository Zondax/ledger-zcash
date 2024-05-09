use crate::bitstreamer::Bitstreamer;
use crate::constants::PEDERSEN_RANDOMNESS_BASE;
use crate::cryptoops;
use core::convert::TryInto;
use jubjub::{ExtendedPoint, Fr};

// #[inline(never)]
// fn return_bytes(point: &mut ExtendedPoint) -> [u8; 32] {
//     AffinePoint::from(*point).get_u().to_bytes()
// }

#[inline(never)]
fn squarings(cur: &mut Fr) {
    *cur = cur.double();
    *cur = cur.double();
    *cur = cur.double();
}

#[inline(never)]
fn handle_chunk(bits: u8, cur: &mut Fr, acc: &mut Fr) {
    let mut tmp = *cur;
    if bits & 4 != 0 {
        tmp = tmp.add(cur);
    }
    *cur = cur.double();
    if bits & 2 != 0 {
        tmp = tmp.add(cur);
    }
    if bits & 1 != 0 {
        tmp = tmp.neg();
    }
    *acc = acc.add(&tmp);
}

#[inline(never)]
pub fn pedersen_hash_to_point(m: &[u8], bitsize: u32) -> ExtendedPoint {
    const MAXCOUNTER: u8 = 63;

    let mut counter: u8 = 0;
    let mut pointcounter: usize = 0;

    let mut acc = Fr::zero();

    let mut result_point = ExtendedPoint::identity();

    {
        let mut cur = Fr::one();
        let b = Bitstreamer {
            input_bytes: m,
            byte_index: 0,
            bitsize,
            bit_index: 0,
            curr: m[0] as u32,
            shift: 5,
            carry: 0,
        };

        for bits in b {
            handle_chunk(bits, &mut cur, &mut acc);

            counter += 1;
            if counter == MAXCOUNTER {
                // Reset and move to the next curve point
                cryptoops::add_point(&mut result_point, &acc.to_bytes(), pointcounter);
                counter = 0;
                pointcounter += 1;
                acc = Fr::zero();
                cur = Fr::one();
            } else {
                // Continue processing at the current curve point
                squarings(&mut cur);
            }
        }
    }
    if counter > 0 {
        cryptoops::add_point(&mut result_point, &acc.to_bytes(), pointcounter);
    }

    result_point
}

#[inline(never)]
pub fn pedersen_hash(m: &[u8], bitsize: u32) -> [u8; 32] {
    let result_point = pedersen_hash_to_point(m, bitsize);
    cryptoops::extended_to_u_bytes(&result_point)
}

#[inline(never)]
pub fn pedersen_hash_pointbytes(m: &[u8], bitsize: u32) -> [u8; 32] {
    let result_point = pedersen_hash_to_point(m, bitsize);
    cryptoops::extended_to_bytes(&result_point)
}

#[inline(never)]
pub fn multiply_with_pedersen_base(val: &[u8; 32]) -> ExtendedPoint {
    PEDERSEN_RANDOMNESS_BASE.multiply_bits(val)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bitstreamer() {
        let a: [u8; 2] = [254, 0];
        let mut b = Bitstreamer {
            input_bytes: &a,
            byte_index: 0,
            bitsize: 9,
            bit_index: 0,
            curr: a[0] as u32,
            shift: 5,
            carry: 0,
        };
        assert_eq!(b.next(), Some(7u8));
        assert_eq!(b.next(), Some(7u8));
        assert_eq!(b.next(), Some(4u8));
        assert_eq!(b.next(), None);
    }

    #[test]
    fn test_key_small() {
        let m: [u8; 1] = [0xb0; 1];
        assert_eq!(
            pedersen_hash(&m, 3),
            [
                115, 27, 180, 151, 186, 120, 30, 98, 134, 221, 162, 136, 54, 82, 230, 141, 30, 114,
                188, 151, 176, 20, 4, 182, 255, 43, 30, 173, 67, 98, 64, 22
            ]
        );
    }

    #[test]
    fn test_pedersen_ledger2() {
        let msg = [0u8; 73];
        let mut output = [0u8; 32];

        let h = pedersen_hash_pointbytes(&msg, 582);
        output.copy_from_slice(&h);
        assert_eq!(
            output,
            [
                167, 2, 222, 136, 87, 231, 114, 21, 205, 203, 113, 161, 33, 211, 112, 242, 254,
                188, 220, 168, 69, 43, 195, 12, 137, 90, 235, 198, 118, 84, 124, 185
            ]
        );
    }

    #[test]
    fn test_pedersen_onechunk() {
        let input_bits: [u8; 189] = [
            1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 1, 1, 1, 1, 0, 1, 1, 1, 0, 0, 0, 1, 1, 1, 0, 0, 0,
            0, 1, 0, 0, 0, 0, 1, 0, 0, 1, 1, 1, 0, 1, 0, 1, 1, 0, 1, 0, 0, 0, 1, 1, 0, 1, 0, 0, 0,
            0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 1, 0, 1, 1, 1, 1, 1, 0, 1, 1, 1, 0, 1, 0, 1,
            1, 1, 0, 0, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 1, 1, 1, 0, 0, 0, 0, 1, 1, 1, 0, 1, 1,
            0, 0, 1, 1, 0, 0, 1, 0, 1, 0, 0, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 1, 0, 1,
            1, 1, 0, 1, 0, 0, 1, 1, 1, 1, 1, 0, 0, 1, 0, 1, 0, 1, 0, 0, 1, 1, 0, 1, 0, 0, 0, 1, 0,
            1, 0, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 0, 0,
        ];
        let m = [
            254, 15, 113, 194, 19, 173, 26, 16, 40, 190, 235, 147, 77, 195, 179, 41, 127, 194, 233,
            242, 166, 138, 85, 64,
        ];

        let h = pedersen_hash(&m, input_bits.len() as u32);
        assert_eq!(
            h,
            [
                0xdd, 0xf5, 0x21, 0xad, 0xc3, 0xa5, 0x97, 0xf5, 0xcf, 0x72, 0x29, 0xff, 0x02, 0xcf,
                0xed, 0x7e, 0x94, 0x9f, 0x01, 0xb6, 0x1d, 0xf3, 0xe1, 0xdc, 0xdf, 0xf5, 0x20, 0x76,
                0x31, 0x10, 0xa5, 0x2d
            ]
        );
    }

    #[test]
    fn test_pedersen_big1() {
        let input_bits: [u8; 190] = [
            1, 1, 1, 1, 1, 1, 1, 0, 1, 0, 0, 0, 1, 1, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0,
            0, 1, 1, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 0, 0, 0, 0, 1, 1, 1, 0, 0, 0, 1, 1, 1, 0, 1, 1,
            0, 0, 1, 1, 1, 1, 1, 0, 0, 1, 0, 1, 0, 1, 0, 0, 0, 0, 1, 0, 1, 1, 0, 1, 1, 0, 0, 1, 1,
            1, 1, 1, 0, 1, 0, 0, 0, 1, 0, 1, 0, 1, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1,
            1, 0, 0, 1, 0, 1, 1, 0, 0, 0, 0, 1, 1, 0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1,
            0, 1, 1, 0, 1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 0, 1, 1, 0, 0, 0, 1, 1, 0, 0, 1, 1, 1, 1, 0,
            0, 0, 0, 1, 0, 1, 1, 1, 1, 1, 0, 0, 0, 0, 1, 1,
        ];
        let m = [
            254, 141, 17, 3, 7, 195, 142, 207, 149, 11, 103, 209, 80, 192, 57, 97, 146, 64, 183,
            222, 198, 120, 95, 12,
        ];
        let h = pedersen_hash(&m, input_bits.len() as u32);
        assert_eq!(
            h,
            [
                0x40, 0x0c, 0xf2, 0x1e, 0xeb, 0x6f, 0x8e, 0x59, 0x4a, 0x0e, 0xcd, 0x2b, 0x7f, 0x7a,
                0x68, 0x46, 0x34, 0xd9, 0x6e, 0xdf, 0x51, 0xfb, 0x3d, 0x19, 0x2d, 0x99, 0x40, 0xe6,
                0xc7, 0x47, 0x12, 0x60
            ]
        );
    }

    #[test]
    fn test_pedersen_big2() {
        let inp2: [u8; 756] = [
            1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0,
            1, 0, 1, 1, 1, 1, 0, 1, 0, 1, 1, 0, 0, 1, 1, 1, 0, 0, 0, 0, 1, 1, 0, 0, 1, 0, 0, 1, 1,
            1, 0, 0, 1, 0, 0, 1, 1, 1, 0, 1, 1, 1, 0, 1, 1, 0, 1, 0, 0, 0, 0, 0, 1, 1, 1, 0, 1, 1,
            1, 1, 1, 0, 0, 1, 1, 1, 1, 1, 1, 0, 0, 0, 1, 1, 0, 1, 1, 0, 0, 1, 0, 1, 0, 1, 1, 1, 0,
            1, 0, 0, 0, 0, 0, 1, 0, 0, 1, 1, 1, 0, 0, 0, 1, 0, 1, 1, 1, 0, 0, 0, 1, 1, 0, 1, 1, 1,
            0, 0, 0, 0, 0, 1, 1, 0, 1, 0, 0, 0, 0, 0, 1, 1, 1, 1, 0, 1, 0, 1, 1, 0, 0, 0, 1, 0, 0,
            0, 0, 1, 1, 0, 1, 0, 1, 0, 1, 1, 1, 1, 1, 0, 0, 0, 1, 0, 1, 0, 1, 1, 1, 0, 0, 1, 0, 0,
            1, 1, 0, 0, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 1, 1, 0, 0, 1, 0, 0, 1, 1, 1, 1, 0, 1, 1, 1,
            1, 0, 0, 1, 1, 1, 0, 0, 0, 1, 0, 1, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 1, 1,
            0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 1, 1, 0, 1, 1, 0, 0, 0, 1, 0, 0, 0, 1, 1, 0, 1, 1, 0,
            0, 1, 0, 0, 0, 0, 1, 0, 1, 0, 0, 1, 0, 1, 0, 0, 1, 0, 1, 0, 1, 1, 0, 1, 1, 0, 0, 1, 0,
            1, 1, 1, 1, 1, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 1, 1, 1,
            1, 0, 0, 1, 0, 1, 1, 1, 1, 0, 1, 0, 1, 1, 1, 0, 1, 1, 0, 1, 0, 1, 1, 1, 1, 0, 1, 0, 0,
            1, 1, 0, 0, 0, 1, 0, 0, 1, 1, 0, 1, 1, 1, 0, 0, 0, 0, 0, 1, 1, 1, 0, 0, 1, 0, 1, 0, 1,
            0, 0, 0, 1, 0, 0, 1, 1, 1, 0, 1, 1, 1, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1,
            0, 1, 1, 0, 1, 0, 1, 0, 1, 0, 1, 1, 0, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 1, 0, 0, 1, 0, 0,
            0, 1, 0, 0, 0, 1, 1, 1, 1, 1, 0, 1, 0, 0, 0, 0, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1, 1, 0, 1,
            1, 1, 1, 0, 1, 0, 0, 0, 0, 1, 0, 1, 0, 0, 1, 0, 0, 0, 1, 1, 0, 0, 1, 0, 0, 0, 1, 1, 0,
            0, 1, 0, 0, 1, 1, 0, 1, 0, 1, 0, 0, 0, 1, 0, 1, 1, 0, 1, 0, 0, 0, 1, 1, 1, 0, 1, 0, 0,
            1, 1, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 1, 1, 0, 1, 1, 0, 1, 0, 1, 0, 0, 0,
            1, 0, 1, 0, 1, 0, 1, 1, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1,
            0, 1, 0, 1, 1, 0, 1, 1, 1, 1, 0, 1, 0, 1, 0, 0, 1, 1, 1, 1, 0, 0, 0, 1, 0, 1, 1, 1, 1,
            1, 1, 0, 1, 0, 1, 0, 0, 1, 1, 1, 1, 1, 1, 0, 1, 0, 1, 1, 1, 1, 0, 1, 1, 0, 1, 0, 1, 0,
            1, 0, 0, 1, 0, 0, 0, 1, 0, 1, 0, 1, 1, 0, 0, 0, 1, 1, 1, 1, 1, 0, 1, 0, 1, 0, 0, 1, 0,
            0, 0, 1, 0, 1, 1, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0, 1, 0, 0, 1, 0, 0, 0, 1, 1, 0, 1,
            0, 1, 1, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1,
            1, 1,
        ];
        let m2 = [
            255, 36, 160, 101, 235, 56, 100, 228, 238, 208, 119, 207, 198, 202, 232, 39, 23, 27,
            131, 65, 235, 16, 213, 241, 92, 152, 205, 100, 247, 156, 81, 34, 24, 5, 216, 141, 144,
            165, 43, 101, 240, 136, 5, 121, 122, 237, 122, 98, 110, 14, 84, 78, 249, 4, 45, 86, 50,
            228, 71, 208, 239, 239, 66, 145, 145, 147, 81, 104, 233, 145, 2, 218, 138, 184, 136,
            89, 173, 234, 120, 191, 83, 245, 237, 82, 43, 31, 82, 45, 4, 164, 107, 205, 32, 64,
            112,
        ];
        let h2 = pedersen_hash(&m2, inp2.len() as u32);
        assert_eq!(
            h2,
            [
                0x27, 0xae, 0xf2, 0xe8, 0xeb, 0xed, 0xad, 0x19, 0x39, 0x37, 0x9f, 0x4f, 0x44, 0x7e,
                0xfb, 0xd9, 0x25, 0x5a, 0x87, 0x4c, 0x70, 0x08, 0x81, 0x6a, 0x80, 0xd8, 0xf2, 0xb1,
                0xec, 0x92, 0x41, 0x31
            ]
        );
    }

    #[test]
    fn test_pedersen_big3() {
        let inp3: [u8; 945] = [
            0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0,
            0, 1, 0, 1, 1, 1, 1, 0, 1, 0, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 1, 0, 1, 1, 1, 0, 0, 0, 0,
            0, 1, 0, 1, 1, 1, 1, 1, 1, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 0, 0, 1, 1, 0, 0, 0,
            1, 1, 0, 1, 1, 0, 1, 0, 1, 0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 1, 0, 1, 0, 0, 1, 0, 0, 1, 0,
            0, 1, 1, 0, 1, 0, 1, 0, 0, 0, 1, 1, 1, 1, 1, 0, 1, 0, 1, 0, 0, 0, 0, 1, 1, 0, 1, 1, 0,
            1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 1, 0, 1, 0, 1, 1, 0, 1, 0, 0, 0, 1, 1, 0, 1, 1, 1, 1,
            1, 0, 0, 1, 1, 1, 0, 0, 1, 1, 0, 1, 1, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 1, 1,
            1, 1, 1, 0, 1, 0, 1, 0, 0, 1, 0, 0, 1, 1, 0, 0, 0, 1, 1, 1, 0, 0, 1, 0, 1, 1, 1, 1, 0,
            0, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1, 0, 0, 1, 0, 0, 0, 0, 1, 0, 1, 1, 0, 1, 1, 0, 1, 1,
            0, 0, 1, 1, 0, 0, 0, 0, 1, 1, 1, 1, 1, 0, 1, 0, 0, 1, 1, 0, 1, 1, 1, 1, 1, 0, 0, 0, 1,
            0, 0, 1, 1, 0, 0, 0, 0, 0, 1, 1, 1, 0, 1, 1, 1, 0, 1, 1, 1, 0, 1, 1, 0, 0, 1, 0, 0, 1,
            0, 1, 1, 0, 0, 1, 0, 0, 0, 1, 1, 1, 0, 1, 1, 0, 1, 0, 1, 0, 0, 0, 1, 1, 0, 1, 1, 0, 1,
            0, 1, 1, 1, 0, 0, 0, 0, 0, 1, 1, 0, 0, 1, 1, 0, 1, 1, 0, 1, 0, 1, 1, 1, 0, 1, 0, 1, 0,
            0, 1, 0, 0, 1, 0, 0, 1, 1, 1, 0, 0, 0, 0, 0, 1, 1, 1, 1, 0, 1, 0, 1, 1, 1, 0, 1, 1, 1,
            1, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0,
            0, 1, 0, 0, 0, 1, 1, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 0, 1, 0, 0, 1, 1, 1, 0, 0, 0, 1, 0,
            1, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 1, 1, 0, 1, 1, 0, 1, 0, 0, 0, 0, 0, 1, 0, 1,
            1, 1, 0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 1, 1, 1, 0, 1, 0, 1, 0, 1, 1, 1, 0, 0, 0, 1, 1, 1,
            1, 0, 0, 1, 0, 0, 1, 0, 1, 1, 1, 1, 0, 0, 0, 1, 1, 0, 0, 0, 0, 1, 0, 0, 1, 0, 1, 1, 0,
            0, 0, 0, 1, 1, 1, 0, 1, 1, 0, 0, 0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 1, 1,
            1, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 0, 0, 0, 1, 0, 1, 0, 0, 1, 0, 0, 1, 1, 0, 0, 0, 0, 1,
            1, 1, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 1, 1, 1, 1, 0, 1, 1, 0, 1, 0, 0, 1, 0, 0, 0, 1, 0,
            1, 0, 1, 1, 1, 0, 1, 0, 1, 1, 1, 1, 0, 1, 1, 0, 0, 1, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1,
            1, 1, 1, 1, 0, 0, 1, 1, 0, 0, 1, 1, 1, 0, 1, 1, 0, 1, 1, 0, 0, 0, 1, 1, 0, 1, 1, 1, 0,
            0, 1, 1, 0, 0, 0, 1, 0, 1, 0, 0, 1, 1, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 1, 1, 0, 1, 1,
            1, 1, 0, 1, 0, 0, 1, 1, 0, 1, 1, 1, 0, 1, 1, 0, 1, 0, 1, 1, 1, 1, 0, 1, 0, 0, 1, 0, 1,
            0, 0, 1, 1, 0, 0, 0, 0, 1, 1, 0, 0, 1, 1, 1, 0, 1, 0, 0, 0, 0, 1, 1, 0, 1, 1, 1, 1, 1,
            0, 0, 1, 0, 0, 1, 0, 1, 0, 0, 0, 1, 1, 1, 1, 0, 1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 1, 1, 0,
            0, 0, 1, 1, 0, 0, 0, 0, 1, 1, 1, 0, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 1, 1, 0, 0, 1, 0, 1,
            0, 1, 1, 1, 0, 1, 1, 1, 1, 1, 0, 0, 0, 1, 1, 0, 1, 1, 0, 1, 1, 0, 1, 1, 1, 0, 0, 1, 1,
            1, 0, 0, 1, 1, 0, 0, 1, 1, 1, 0, 0, 0, 0, 1, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 1,
            0, 0, 0, 1, 0, 1, 1, 1, 1, 0, 0, 1, 0, 0, 1, 1, 0,
        ];
        let m3 = [
            0, 131, 64, 18, 244, 170, 220, 23, 227, 251, 49, 181, 100, 41, 38, 163, 234, 27, 126,
            10, 209, 190, 115, 98, 64, 1, 96, 32, 71, 234, 76, 114, 243, 223, 144, 182, 204, 62,
            155, 226, 96, 238, 236, 150, 71, 106, 54, 184, 51, 107, 169, 39, 7, 174, 250, 1, 41, 4,
            70, 179, 39, 20, 136, 59, 65, 112, 243, 171, 143, 37, 227, 9, 97, 216, 211, 53, 193,
            241, 73, 135, 18, 61, 164, 87, 94, 204, 203, 243, 59, 99, 115, 20, 194, 38, 244, 221,
            175, 74, 97, 157, 13, 242, 81, 236, 19, 24, 119, 193, 149, 223, 27, 110, 115, 56, 74,
            3, 23, 147, 0,
        ];
        let h3 = pedersen_hash(&m3, inp3.len() as u32);
        assert_eq!(
            h3,
            [
                0x37, 0x5f, 0xdd, 0x7b, 0x29, 0xde, 0x6e, 0x22, 0x5e, 0xbb, 0x7a, 0xe4, 0x20, 0x3c,
                0xa5, 0x0e, 0xca, 0x7c, 0x9b, 0xab, 0x97, 0x1c, 0xc6, 0x91, 0x3c, 0x6f, 0x13, 0xed,
                0xf3, 0x27, 0xe8, 0x00
            ]
        );
    }
}
