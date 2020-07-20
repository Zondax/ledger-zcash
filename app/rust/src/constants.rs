use jubjub::{AffineNielsPoint, AffinePoint, Fq};

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

pub const COMPACT_NOTE_SIZE: usize = 1 /* version */ + 11 /*diversifier*/ + 8 /*value*/ + 32 /*rcv*/;
pub const NOTE_PLAINTEXT_SIZE: usize = COMPACT_NOTE_SIZE + 512;
pub const OUT_PLAINTEXT_SIZE: usize = 32 /*pk_d*/ + 32 /* esk */;
pub const ENC_CIPHERTEXT_SIZE: usize = NOTE_PLAINTEXT_SIZE + 16;
pub const OUT_CIPHERTEXT_SIZE: usize = OUT_PLAINTEXT_SIZE + 16;
