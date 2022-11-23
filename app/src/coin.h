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
#define MENU_MAIN_APP_LINE2                "DO NOT USE!"
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
