/*******************************************************************************
*   (c) 2018 - 2024 Zondax AG
*
*  Licensed under the Apache License, Version 2.0 (the "License");
*  you may not use this file except in compliance with the License.
*  You may obtain a copy of the License at
*
*      http://www.apache.org/licenses/LICENSE-2.0
*
*  Unless required by applicable law or agreed to in writing, software
*  distributed under the License is distributed on an "AS IS" BASIS,
*  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*  See the License for the specific language governing permissions and
*  limitations under the License.
********************************************************************************/

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

pub static NIELSPOINTS: [AffineNielsPoint; 6] = [
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

pub const COMPACT_NOTE_SIZE: usize = 1 /* version */ + 11 /*diversifier*/ + 8 /*value*/ + 32 /*rcv*/;
//52
pub const NOTE_PLAINTEXT_SIZE: usize = COMPACT_NOTE_SIZE + 512;
pub const OUT_PLAINTEXT_SIZE: usize = 32 /*pk_d*/ + 32 /* esk */;
pub const ENC_COMPACT_SIZE: usize = COMPACT_NOTE_SIZE + 16;
//68
pub const ENC_CIPHERTEXT_SIZE: usize = NOTE_PLAINTEXT_SIZE + 16;
pub const OUT_CIPHERTEXT_SIZE: usize = OUT_PLAINTEXT_SIZE + 16;

pub const DIV_SIZE: usize = 11;
pub const DIV_DEFAULT_LIST_LEN: usize = 4;
pub const MAX_SIZE_BUF_ADDR: usize = 143;

/// https://zips.z.cash/zip-0032#key-path-levels
/// m/PURPOSE/COIN/account
pub const ZIP32_PURPOSE: u32 = 0x8000_0020;
pub const ZIP32_COIN_TYPE: u32 = 0x8000_0085;

/// ZIP32 Child components
pub enum Zip32ChildComponents {
    AkNk = 0,
    Dk = 2,
    AkNsk = 3,
    AskNsk = 4,
    DkAkNk = 5,
}
