use crate::pedersen::*;
use byteorder::{BigEndian, ByteOrder, LittleEndian};
use jubjub::{AffineNielsPoint, AffinePoint, ExtendedPoint, Fq, Fr};

use blake2s_simd::{blake2s, Hash as Blake2sHash, Params as Blake2sParams};

pub const PEDERSEN_RANDOMNESS_BASE: AffineNielsPoint = AffinePoint::from_raw_unchecked(
    Fq::from_raw([
        0xa514_3b34_a8e3_6462,
        0xf091_9d06_ffb1_ecda,
        0xa140_9aa1_f33b_ec2c,
        0x26eb_9f8a_9ec7_2a8c,
    ]),
    Fq::from_raw([
        0xd4fc_6365_796c_77ac,
        0x96b7_8bea_fa9c_c44c,
        0x949d_7747_6e26_2c95,
        0x114b_7501_ad10_4c57,
    ]),
)
.to_niels();

pub const VALUE_COMMITMENT_VALUE_BASE: AffineNielsPoint = AffinePoint::from_raw_unchecked(
    Fq::from_raw([
        0x3618_3b2c_b4d7_ef51,
        0x9472_c89a_c043_042d,
        0xd861_8ed1_d15f_ef4e,
        0x273f_910d_9ecc_1615,
    ]),
    Fq::from_raw([
        0xa77a_81f5_0667_c8d7,
        0xbc33_32d0_fa1c_cd18,
        0xd322_94fd_8977_4ad6,
        0x466a_7e3a_82f6_7ab1,
    ]),
)
.to_niels();

pub const VALUE_COMMITMENT_RANDOM_BASE: AffineNielsPoint = AffinePoint::from_raw_unchecked(
    Fq::from_raw([
        0x3bce_3b77_9366_4337,
        0xd1d8_da41_af03_744e,
        0x7ff6_826a_d580_04b4,
        0x6800_f4fa_0f00_1cfc,
    ]),
    Fq::from_raw([
        0x3cae_fab9_380b_6a8b,
        0xad46_f1b0_473b_803b,
        0xe6fb_2a6e_1e22_ab50,
        0x6d81_d3a9_cb45_dedb,
    ]),
)
.to_niels();

pub const NOTE_POSITION_BASE: AffineNielsPoint = AffinePoint::from_raw_unchecked(
    Fq::from_raw([
        0x2ce3_3921_888d_30db,
        0xe81c_ee09_a561_229e,
        0xdb56_b6db_8d80_75ed,
        0x2400_c2e2_e336_2644,
    ]),
    Fq::from_raw([
        0xa3f7_fa36_c72b_0065,
        0xe155_b8e8_ffff_2e42,
        0xfc9e_8a15_a096_ba8f,
        0x6136_9d54_40bf_84a5,
    ]),
)
.to_niels();
#[inline(never)]
pub fn revert(source: &[u8; 32], dest: &mut [u8]) {
    for i in 0..32 {
        let mut uv = source[i];
        for j in 0..8 {
            dest[i] ^= (uv & 1) as u8;
            uv >>= 1;
            if j < 7 {
                dest[i] <<= 1;
            }
        }
    }
}
#[inline(never)]
pub fn note_commitment(v: u64, g_d: &[u8; 32], pk_d: &[u8; 32], rcm: &[u8; 32]) -> ExtendedPoint {
    let mut input_hash = [0u8; 73];

    let mut uv = v;
    for i in 0..8 {
        for j in 0..8 {
            input_hash[i] ^= (uv & 1) as u8;
            uv >>= 1;
            if j < 7 {
                input_hash[i] <<= 1;
            }
        }
    }
    revert(g_d, &mut input_hash[8..40]);
    revert(pk_d, &mut input_hash[40..72]);

    let mut i: usize = 72;
    while i > 0 {
        input_hash[i] ^= (input_hash[i - 1] & 0x3F) << 2;
        input_hash[i - 1] >>= 6;
        i -= 1;
    }
    input_hash[0] ^= 0b1111_1100;

    let p = pedersen_hash_to_point(&input_hash, 6 + 64 + 256 + 256);

    let s = PEDERSEN_RANDOMNESS_BASE.multiply_bits(rcm);

    p + s
}

#[inline(never)]
pub fn value_commitment(value: u64, rcm: &[u8; 32]) -> [u8; 32] {
    let mut scalar = [0u8; 32];
    let mut num = value;
    for i in 0..8 {
        scalar[i] = (num & 255) as u8;
        num >>= 8;
    }
    let x = VALUE_COMMITMENT_VALUE_BASE.multiply_bits(&scalar);
    let y = VALUE_COMMITMENT_RANDOM_BASE.multiply_bits(rcm);
    let z = x + y;
    extended_to_bytes(&z)
}

#[inline(never)]
pub fn mixed_pedersen(e: ExtendedPoint, pos: u32) -> ExtendedPoint {
    let mut scalar = [0u8; 32];
    let mut num = pos;
    for i in 0..4 {
        scalar[i] = (num & 255) as u8;
        num >>= 8;
    }

    let p = NOTE_POSITION_BASE.multiply_bits(&scalar);
    p + e
}

#[inline(never)]
pub fn prf_nf(nk: &[u8; 32], rho: &[u8; 32]) -> [u8; 32] {
    pub const CRH_NF: &[u8; 8] = b"Zcash_nf";
    let h = Blake2sParams::new()
        .hash_length(32)
        .personal(CRH_NF)
        .to_state()
        .update(nk)
        .update(rho)
        .finalize();
    let x: [u8; 32] = *h.as_array();
    x
}
