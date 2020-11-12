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

#ifdef __cplusplus
extern "C" {
#endif

#include <zxerror.h>
#include <zxmacros.h>
#include "coin.h"
#include <stdbool.h>
#include <sigutils.h>

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
zxerr_t  crypto_fillAddress_with_diversifier_sapling(uint8_t *buffer, uint16_t bufferLen, const uint8_t *inputdata, const uint16_t inputdataLen, uint16_t *replyLen);
zxerr_t crypto_diversifier_with_startindex(uint8_t *buffer, uint16_t bufferLen, const uint8_t *inputdata, const uint16_t inputdataLen);

uint16_t crypto_sign(uint8_t *signature,
                     uint16_t signatureMaxlen,
                     const uint8_t *message,
                     uint16_t messageLen);

uint16_t crypto_ivk_sapling(uint8_t *buffer, uint16_t bufferLen);

uint16_t crypto_ovk_sapling(uint8_t *buffer, uint16_t bufferLen);

zxerr_t crypto_checkspend_sapling(uint8_t *buffer, uint16_t bufferLen, const uint8_t *spenddata, uint16_t spenddatalen);

zxerr_t crypto_checkoutput_sapling(uint8_t *buffer, uint16_t bufferLen, const uint8_t *outputdata, const uint16_t outputdatalen);

zxerr_t crypto_checkencryptions_sapling(uint8_t *buffer, uint16_t bufferLen, const uint8_t *outputdata, const uint16_t outputdatalen);

uint16_t crypto_key_exchange(uint8_t *buffer, uint16_t bufferLen,  const uint8_t *txdata, const uint16_t txdatalen);
zxerr_t crypto_extracttx_sapling(uint8_t *buffer, uint16_t bufferLen, const uint8_t *txdata, const uint16_t txdatalen);

zxerr_t crypto_extract_spend_proofkeyandrnd(uint8_t *buffer, uint16_t bufferLen);

zxerr_t crypto_extract_output_rnd(uint8_t *buffer, uint16_t bufferLen);

zxerr_t crypto_signspends_sapling(uint8_t *buffer, uint16_t bufferLen, const uint8_t *signdata, uint16_t signdatalen);

zxerr_t crypto_extract_spend_signature(uint8_t *buffer, uint16_t bufferLen);

zxerr_t crypto_check_prevouts(uint8_t *buffer, uint16_t bufferLen, const uint8_t *txdata, const uint16_t txdatalen);
zxerr_t crypto_check_sequence(uint8_t *buffer, uint16_t bufferLen, const uint8_t *txdata, const uint16_t txdatalen);
zxerr_t crypto_check_outputs(uint8_t *buffer, uint16_t bufferLen, const uint8_t *txdata, const uint16_t txdatalen);
zxerr_t crypto_check_joinsplits(uint8_t *buffer, uint16_t bufferLen, const uint8_t *txdata, const uint16_t txdatalen);
zxerr_t crypto_check_valuebalance(uint8_t *buffer, uint16_t bufferLen, const uint8_t *txdata, const uint16_t txdatalen);

void address_to_script(uint8_t *address, uint8_t *output);
zxerr_t crypto_sign_and_check_transparent(uint8_t *buffer, uint16_t bufferLen, const uint8_t *txdata, const uint16_t txdatalen);
zxerr_t crypto_extract_transparent_signature(uint8_t *buffer, uint16_t bufferLen);
#ifdef __cplusplus
}
#endif
