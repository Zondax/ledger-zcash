use crate::bolos::c_zemu_log_stack;
use jubjub::{AffineNielsPoint, AffinePoint, ExtendedPoint, Fq, Fr};

use core::convert::TryInto;
use core::mem;

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
fn add_to_point(point: &mut ExtendedPoint, p: &ExtendedPoint) {
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

pub fn pedersen_hash(m: &[u8], bitsize: u32) -> [u8; 32] {
    c_zemu_log_stack(b"pedersen_hash\x00".as_ref());
    const MAXCOUNTER: usize = 63;

    let mut counter: usize = 0;
    let mut pointcounter: usize = 0;

    let mut acc = Fr::zero();
    let mut cur = Fr::one();
    let mut result_point = ExtendedPoint::identity();

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
    c_zemu_log_stack(b"pedersen_hash_beforeadd\x00".as_ref());
    if counter > 0 {
        add_point(&mut result_point, &acc.to_bytes(), pointcounter);
    }

    //handle remaining bits if there are any
    c_zemu_log_stack(b"return bytes\x00".as_ref());

    return_bytes(&mut result_point)
}

//assumption here that ceil(bitsize / 8) == m.len(), so appended with zero bits to fill the bytes
//#[inline(never)]

#[no_mangle]
pub extern "C" fn pedersen_hash_1byte(input: u8, output_ptr: *mut [u8; 32]) {
    let input_msg = [input];
    let output_msg = unsafe { &mut *output_ptr };

    let h = pedersen_hash(&input_msg, 3); //fixme: take variable length bitsize?
    output_msg.copy_from_slice(&h);
}
