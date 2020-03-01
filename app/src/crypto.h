/*******************************************************************************
*   (c) 2019 Zondax GmbH
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

#include <zxmacros.h>
#include "coin.h"
#include <stdbool.h>
#include <sigutils.h>

#ifdef __cplusplus
extern "C" {
#endif

#define HDPATH_LEN_DEFAULT          5u

#define CHECKSUM_LENGTH             4

extern uint32_t hdPath[HDPATH_LEN_DEFAULT];

extern address_kind_e addressKind;

#define VERSION_P2SH            0x1CBD
#define VERSION_P2PKH           0x1CB8
#define BECH32_HRP              "zs"
#define BECH32_HRP_TEST         "ztestsapling"

bool isTestnet();

void crypto_fillSaplingSeed(uint8_t *sk);

void crypto_extractPublicKey(const uint32_t path[HDPATH_LEN_DEFAULT], uint8_t *pubKey, uint16_t pubKeyLen);

uint16_t crypto_fillAddress_secp256k1(uint8_t *buffer, uint16_t bufferLen);

uint16_t crypto_fillAddress_sapling(uint8_t *buffer, uint16_t bufferLen);

uint16_t crypto_sign(uint8_t *signature,
                     uint16_t signatureMaxlen,
                     const uint8_t *message,
                     uint16_t messageLen);

#ifdef __cplusplus
}
#endif
