/*******************************************************************************
*  (c) 2019-2021 Zondax AG
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
#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#define CLA                             0x85

#define HDPATH_LEN_DEFAULT   5

#define HDPATH_0_DEFAULT     (0x80000000u | 0x2cu)
#define HDPATH_1_DEFAULT     (0x80000000u | 0x85)
#define HDPATH_2_DEFAULT     (0x80000000u | 0u)
#define HDPATH_3_DEFAULT     (0u)
#define HDPATH_4_DEFAULT     (0u)

#define HDPATH_0_TESTNET     (0x80000000u | 0x2cu)
#define HDPATH_1_TESTNET     (0x80000000u | 0x1u)

// compressed key
#define PK_LEN_SECP256K1            33u

// sapling address [11+32]
#define ADDR_LEN_SAPLING            43u

// ivk
#define LEN_IVK                     32u

//ak, nsk
#define LEN_PGK                     64u

#define ENABLE_SDK_MULT             0

#define DATA_LENGTH_GET_IVK             4   //ZIP32-path
#define DATA_LENGTH_GET_OVK             4   //ZIP32-path
#define DATA_LENGTH_GET_FVK             4   //ZIP32-path
#define DATA_LENGTH_GET_NF              44  // ZIP32-path + 8-byte note position + 32-byte note commitment
#define DATA_LENGTH_GET_ADDR_SAPLING    4   //ZIP32-path
#define DATA_LENGTH_GET_DIV_LIST        15   //ZIP32-path + 11-byte index
#define DATA_LENGTH_GET_ADDR_DIV        15   //ZIP32-path + 11-byte div

#define INS_GET_VERSION                 0x00
#define INS_GET_ADDR_SECP256K1          0x01
#define INS_SIGN_SECP256K1              0x02
#define INS_GET_DIV_LIST                0x09
#define INS_GET_ADDR_SAPLING_DIV        0x10
#define INS_GET_ADDR_SAPLING            0x11
#define INS_SIGN_SAPLING                0x12

#define INS_INIT_TX                     0xa0
#define INS_KEY_EXCHANGE                0xaa
#define INS_EXTRACT_SPEND               0xa1
#define INS_EXTRACT_OUTPUT              0xa2
#define INS_CHECKANDSIGN                0xa3
#define INS_EXTRACT_SPENDSIG            0xa4
#define INS_EXTRACT_TRANSSIG            0xa5

#define INS_GET_IVK                     0xf0
#define INS_GET_OVK                     0xf1
#define INS_GET_NF                      0xf2
#define INS_GET_FVK                     0xf3
#define INS_CRASH_TEST                  0xff

typedef enum {
    addr_secp256k1 = 0,
    addr_sapling = 1,
    addr_sapling_div = 2,
} address_kind_e;

typedef enum {
    key_ivk = 0,
    key_ovk = 1,
    key_fvk = 2,
    nf = 3
} key_type_e;

#define VIEW_ADDRESS_OFFSET_SECP256K1       PK_LEN_SECP256K1
#define VIEW_ADDRESS_OFFSET_SAPLING         ADDR_LEN_SAPLING

#define MENU_MAIN_APP_LINE1                "Zcash"
#define MENU_MAIN_APP_LINE2                "Ready"
#define APPVERSION_LINE1                   "Zcash"
#define APPVERSION_LINE2                   ("v" APPVERSION)

#define MENU_MAIN_APP_LINE2_SECRET         "?"
#define COIN_SECRET_REQUIRED_CLICKS         0
#define COIN_TICKER "ZEC "

#define COIN_AMOUNT_DECIMAL_PLACES  8
#define CRYPTO_BLOB_SKIP_BYTES      0

#ifdef __cplusplus
}
#endif
