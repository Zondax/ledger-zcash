use group::Group;
use jubjub::{AffineNielsPoint, AffinePoint, Fq, SubgroupPoint};

pub const SPENDING_KEY_BASE: AffineNielsPoint = AffinePoint::from_raw_unchecked(
    Fq::from_raw([
        0x47bf_4692_0a95_a753,
        0xd5b9_a7d3_ef8e_2827,
        0xd418_a7ff_2675_3b6a,
        0x0926_d4f3_2059_c712,
    ]),
    Fq::from_raw([
        0x3056_32ad_aaf2_b530,
        0x6d65_674d_cedb_ddbc,
        0x53bb_37d0_c21c_fd05,
        0x57a1_019e_6de9_b675,
    ]),
)
.to_niels();

pub const SPENDING_BASE_BYTES: [u8; 32] = [
    48, 181, 242, 170, 173, 50, 86, 48, 188, 221, 219, 206, 77, 103, 101, 109, 5, 253, 28, 194,
    208, 55, 187, 83, 117, 182, 233, 109, 158, 1, 161, 215,
];

pub const PROVING_KEY_BASE: AffineNielsPoint = AffinePoint::from_raw_unchecked(
    Fq::from_raw([
        0x3af2_dbef_b96e_2571,
        0xadf2_d038_f2fb_b820,
        0x7043_03f1_e890_6081,
        0x1457_a502_31cd_e2df,
    ]),
    Fq::from_raw([
        0x467a_f9f7_e05d_e8e7,
        0x50df_51ea_f5a1_49d2,
        0xdec9_0184_0f49_48cc,
        0x54b6_d107_18df_2a7a,
    ]),
)
.to_niels();

pub const PROVING_BASE_BYTES: [u8; 32] = [
    231, 232, 93, 224, 247, 249, 122, 70, 210, 73, 161, 245, 234, 81, 223, 80, 204, 72, 73, 15,
    132, 1, 201, 222, 122, 42, 223, 24, 7, 209, 182, 212,
];

pub const SESSION_KEY_BASE: AffineNielsPoint = AffinePoint::from_raw_unchecked(
    Fq::from_raw([
        0xe4b3_d35d_f1a7_adfe,
        0xcaf5_5d1b_29bf_81af,
        0x8b0f_03dd_d60a_8187,
        0x62ed_cbb8_bf37_87c8,
    ]),
    Fq::from_raw([
        0x0000_0000_0000_000b,
        0x0000_0000_0000_0000,
        0x0000_0000_0000_0000,
        0x0000_0000_0000_0000,
    ]),
)
.to_niels();

pub const COMPACT_NOTE_SIZE: usize = 1 /* version */ + 11 /*diversifier*/ + 8 /*value*/ + 32 /*rcv*/;
//52
pub const NOTE_PLAINTEXT_SIZE: usize = COMPACT_NOTE_SIZE + 512;
pub const OUT_PLAINTEXT_SIZE: usize = 32 /*pk_d*/ + 32 /* esk */;
pub const ENC_COMPACT_SIZE: usize = COMPACT_NOTE_SIZE + 16;
//68
pub const ENC_CIPHERTEXT_SIZE: usize = NOTE_PLAINTEXT_SIZE + 16;
pub const OUT_CIPHERTEXT_SIZE: usize = OUT_PLAINTEXT_SIZE + 16;

pub const DIV_SIZE:             usize = 11;
pub const DIV_DEFAULT_LIST_LEN: usize = 4;
pub const MAX_SIZE_BUF_ADDR:    usize = 143;

pub const FIRSTVALUE:   u32 = 32 ^ 0x8000_0000;
pub const COIN_TYPE:    u32 = 133 ^ 0x8000_0000;

pub const CRH_IVK_PERSONALIZATION: &[u8; 8] = b"Zcashivk";

// ZIP32 Child components
pub const AK_NK: u8 = 0;
pub const DK: u8 = 2;
pub const AK_NSK: u8 = 3;
pub const ASK_NSK: u8 = 4;
pub const DK_AK_NK: u8 = 5;