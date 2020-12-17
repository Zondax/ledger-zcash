use core::convert::TryInto;
use core::mem;
use jubjub::{AffineNielsPoint, AffinePoint, ExtendedPoint, Fq, Fr};

use crate::bolos::c_zemu_log_stack;

#[inline(never)]
fn handle_chunk(bits: u8, cur: &mut Fr, acc: &mut Fr) {
    let c = bits & 1;
    let b = bits & 2;
    let a = bits & 4;
    let mut tmp = *cur;
    if a == 4 {
        tmp = tmp.add(cur);
    }
    *cur = cur.double(); // 2^1 * cur
    if b == 2 {
        tmp = tmp.add(cur);
    }
    // conditionally negate
    if c == 1 {
        tmp = tmp.neg();
    }
    *acc = acc.add(&tmp);
}

static NIELSPOINTS: [jubjub::AffineNielsPoint; 6] = [
    AffinePoint::from_raw_unchecked(
        Fq::from_raw([
            0x194e_4292_6f66_1b51,
            0x2f0c_718f_6f0f_badd,
            0xb5ea_25de_7ec0_e378,
            0x73c0_16a4_2ded_9578,
        ]),
        Fq::from_raw([
            0x77bf_abd4_3224_3cca,
            0xf947_2e8b_c04e_4632,
            0x79c9_166b_837e_dc5e,
            0x289e_87a2_d352_1b57,
        ]),
    )
    .to_niels(),
    AffinePoint::from_raw_unchecked(
        Fq::from_raw([
            0xb981_9dc8_2d90_607e,
            0xa361_ee3f_d48f_df77,
            0x52a3_5a8c_1908_dd87,
            0x15a3_6d1f_0f39_0d88,
        ]),
        Fq::from_raw([
            0x7b0d_c53c_4ebf_1891,
            0x1f3a_beeb_98fa_d3e8,
            0xf789_1142_c001_d925,
            0x015d_8c7f_5b43_fe33,
        ]),
    )
    .to_niels(),
    AffinePoint::from_raw_unchecked(
        Fq::from_raw([
            0x76d6_f7c2_b67f_c475,
            0xbae8_e5c4_6641_ae5c,
            0xeb69_ae39_f5c8_4210,
            0x6643_21a5_8246_e2f6,
        ]),
        Fq::from_raw([
            0x80ed_502c_9793_d457,
            0x8bb2_2a7f_1784_b498,
            0xe000_a46c_8e8c_e853,
            0x362e_1500_d24e_ee9e,
        ]),
    )
    .to_niels(),
    AffinePoint::from_raw_unchecked(
        Fq::from_raw([
            0x4c76_7804_c1c4_a2cc,
            0x7d02_d50e_654b_87f2,
            0xedc5_f4a9_cff2_9fd5,
            0x323a_6548_ce9d_9876,
        ]),
        Fq::from_raw([
            0x8471_4bec_a335_70e9,
            0x5103_afa1_a11f_6a85,
            0x9107_0acb_d8d9_47b7,
            0x2f7e_e40c_4b56_cad8,
        ]),
    )
    .to_niels(),
    AffinePoint::from_raw_unchecked(
        Fq::from_raw([
            0x4680_9430_657f_82d1,
            0xefd5_9313_05f2_f0bf,
            0x89b6_4b4e_0336_2796,
            0x3bd2_6660_00b5_4796,
        ]),
        Fq::from_raw([
            0x9996_8299_c365_8aef,
            0xb3b9_d809_5859_d14c,
            0x3978_3238_1406_c9e5,
            0x494b_c521_03ab_9d0a,
        ]),
    )
    .to_niels(),
    AffinePoint::from_raw_unchecked(
        Fq::from_raw([
            0xcb3c_0232_58d3_2079,
            0x1d9e_5ca2_1135_ff6f,
            0xda04_9746_d76d_3ee5,
            0x6344_7b2b_a31b_b28a,
        ]),
        Fq::from_raw([
            0x4360_8211_9f8d_629a,
            0xa802_00d2_c66b_13a7,
            0x64cd_b107_0a13_6a28,
            0x64ec_4689_e8bf_b6e5,
        ]),
    )
    .to_niels(),
];

#[inline(never)]
fn mult_bits(index: usize, bits: &[u8; 32]) -> ExtendedPoint {
    c_zemu_log_stack(b"multbits_begin\x00".as_ref());
    let q = NIELSPOINTS[index];
    q.multiply_bits(bits)
}

#[inline(never)]
pub fn add_to_point(point: &mut ExtendedPoint, p: &ExtendedPoint) {
    c_zemu_log_stack(b"addtopoint_begin\x00".as_ref());
    *point += p;
}

#[inline(never)]
fn add_point(point: &mut ExtendedPoint, acc: &[u8; 32], index: usize) {
    c_zemu_log_stack(b"addpoint_begin\x00".as_ref());
    let p = mult_bits(index, acc);
    add_to_point(point, &p);
}

#[inline(never)]
fn return_bytes(point: &mut ExtendedPoint) -> [u8; 32] {
    AffinePoint::from(*point).get_u().to_bytes()
}

#[inline(never)]
pub fn extended_to_u_bytes(point: &ExtendedPoint) -> [u8; 32] {
    AffinePoint::from(*point).get_u().to_bytes()
}

#[inline(never)]
pub fn extended_to_bytes(point: &ExtendedPoint) -> [u8; 32] {
    c_zemu_log_stack(b"tobytes\x00".as_ref());
    AffinePoint::from(*point).to_bytes()
}

#[inline(never)]
fn squarings(cur: &mut Fr) {
    *cur = cur.double();
    *cur = cur.double();
    *cur = cur.double();
}

pub struct Bitstreamer<'a> {
    pub input_bytes: &'a [u8],
    pub byte_index: usize,
    pub bitsize: u32,
    pub bit_index: u32,
    pub curr: u32,
    pub shift: i8,
    pub carry: i8,
}

impl<'a> Bitstreamer<'a> {
    #[inline(never)]
    fn peek(&self) -> bool {
        self.bit_index < self.bitsize
    }
}

impl<'a> Iterator for Bitstreamer<'a> {
    type Item = u8;
    #[inline(never)]
    fn next(&mut self) -> Option<u8> {
        if self.bit_index >= self.bitsize || self.byte_index >= self.input_bytes.len() {
            return None;
        }
        let s = ((self.curr >> (self.shift as u32)) & 7) as u8;
        self.bit_index += 3;
        if self.shift - 3 < 0 {
            self.byte_index += 1;
            if self.byte_index < self.input_bytes.len() {
                self.carry = ((self.carry - 1) + 3) % 3;
                self.curr <<= 8;
                self.curr += self.input_bytes[self.byte_index] as u32;
                self.shift = 5 + self.carry;
            } else {
                let sh =
                    (((self.carry & 2) + ((self.carry & 2) >> 1)) ^ (self.carry & 1) ^ 1) as u32;
                self.curr <<= sh;
                self.shift = 0;
            }
        } else {
            self.shift -= 3;
        }
        Some(s)
    }
}

#[inline(never)]
pub fn pedersen_hash_to_point(m: &[u8], bitsize: u32) -> ExtendedPoint {
    c_zemu_log_stack(b"pedersen_hash\x00".as_ref());
    const MAXCOUNTER: u8 = 63;

    let mut counter: u8 = 0;
    let mut pointcounter: usize = 0;

    let mut acc = Fr::zero();

    let mut result_point = ExtendedPoint::identity();

    {
        let mut cur = Fr::one();
        let mut b = Bitstreamer {
            input_bytes: m,
            byte_index: 0,
            bitsize,
            bit_index: 0,
            curr: m[0] as u32,
            shift: 5,
            carry: 0,
        };

        while b.peek() {
            let bits = b.next().unwrap();
            handle_chunk(bits, &mut cur, &mut acc);

            counter += 1;
            //check if we need to move to the next curvepoint
            if counter == MAXCOUNTER {
                add_point(&mut result_point, &acc.to_bytes(), pointcounter);
                counter = 0;
                pointcounter += 1;
                acc = Fr::zero();
                cur = Fr::one();
            } else {
                squarings(&mut cur);
            }
        }
    }
    c_zemu_log_stack(b"pedersen_hash_beforeadd\x00".as_ref());
    if counter > 0 {
        add_point(&mut result_point, &acc.to_bytes(), pointcounter);
    }

    result_point
}

#[inline(never)]
pub fn pedersen_hash(m: &[u8], bitsize: u32) -> [u8; 32] {
    let result_point = pedersen_hash_to_point(&m, bitsize);
    extended_to_u_bytes(&result_point)
}

#[inline(never)]
pub fn pedersen_hash_pointbytes(m: &[u8], bitsize: u32) -> [u8; 32] {
    let result_point = pedersen_hash_to_point(&m, bitsize);
    extended_to_bytes(&result_point)
}

//assumption here that ceil(bitsize / 8) == m.len(), so appended with zero bits to fill the bytes
#[no_mangle]
pub extern "C" fn pedersen_hash_73bytes(input: *const [u8; 73], output_ptr: *mut [u8; 32]) {
    let input_msg = unsafe { &*input };
    let output_msg = unsafe { &mut *output_ptr };

    let h = pedersen_hash_pointbytes(input_msg, 582);
    output_msg.copy_from_slice(&h);
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
        assert_eq!(b.next(), Some(7 as u8));
        assert_eq!(b.next(), Some(7 as u8));
        assert_eq!(b.next(), Some(4 as u8));
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
        let output = [0u8; 32];
        pedersen_hash_73bytes(
            msg.as_ptr() as *const [u8; 73],
            output.as_ptr() as *mut [u8; 32],
        );
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
