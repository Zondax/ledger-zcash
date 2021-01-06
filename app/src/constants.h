/*******************************************************************************
*  (c) 2019 Zondax GmbH
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

// CRYPTO File
#define CHECKSUM_LENGTH         4

#define SK_SECP256K1_SIZE       32
#define PUB_KEY_SIZE            32
#define DER_MAX_SIZE            73
#define AK_SIZE                 32
#define NSK_SIZE                32
#define ASK_SIZE                32
#define DK_SIZE                 32
#define NK_SIZE                 32
#define ED25519_SK_SIZE         32
#define IVK_SIZE                32
#define ZIP32_SEED_SIZE         32
#define RND_SIZE                32
#define NULLIFIER_SIZE          32

#define ESK_SIZE                32
#define EPK_SIZE                32
#define NOTE_COMMITMENT_SIZE    32
#define VALUE_COMMITMENT_SIZE   32
#define HASH_SIZE               32
#define SESSION_KEY_SIZE        32
#define GD_SIZE                 32
#define SHARED_KEY_SIZE         32
#define OUT_KEY_SIZE            32
#define ENC_CIPHER_SIZE         64
#define COMPACT_OUT_SIZE        53
#define MAX_SIZE                172
#define SIG_R_SIZE              32
#define SIG_S_SIZE              32
#define SCRIPT_CONSTS_SIZE      4
#define PEDERSEN_INPUT_SIZE     73
#define CHACHA_NONCE_SIZE       12

#define MASK_HARDENED           0x80000000

#define VERSION_SIZE            2
#define CHECKSUM_SIZE           4
#define VERSION_P2SH            0x1CBD
#define VERSION_P2PKH           0x1CB8
#define BECH32_HRP              "zs"
#define BECH32_HRP_TEST         "ztestsapling"


// NVDATA File
//fixme: maybe increase some of these
#define T_IN_LIST_SIZE          5
#define T_OUT_LIST_SIZE         5
#define SPEND_LIST_SIZE         5
#define OUTPUT_LIST_SIZE        5

#define PKD_SIZE                32
#define RCM_SIZE                32
#define ALPHA_SIZE              32
#define DIV_SIZE                11
#define DIV_LIST_LENGTH         20
#define DIV_DEFAULT_LIST_LEN    10

#define SESSION_KEY_SIZE        32

#define OVK_SIZE                32
#define RSEED_SIZE              32
#define RCM_V_SIZE              32

#define SCRIPT_SIZE             26
#define PATH_SIZE               5

#define SIGNATURE_SIZE          SIG_R_SIZE + SIG_S_SIZE
