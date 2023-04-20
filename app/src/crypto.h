/*******************************************************************************
*   (c) 2018 -2022 Zondax AG
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

#include <zxmacros.h>
#include "coin.h"
#include <stdbool.h>
#include <sigutils.h>
#include "zxerror.h"


extern uint32_t hdPath[HDPATH_LEN_DEFAULT];

extern address_kind_e addressKind;

zxerr_t crypto_fillSaplingSeed(uint8_t *sk);

zxerr_t crypto_extractPublicKey(const uint32_t path[HDPATH_LEN_DEFAULT], uint8_t *pubKey, uint16_t pubKeyLen);

zxerr_t crypto_fillAddress_secp256k1(uint8_t *buffer, uint16_t bufferLen, uint16_t *replyLen);

zxerr_t crypto_fillAddress_sapling(uint8_t *buffer, uint16_t bufferLen, uint32_t p, uint16_t *replyLen);
zxerr_t crypto_fillAddress_with_diversifier_sapling(uint8_t *buffer, uint16_t bufferLen, uint32_t p, uint8_t *div,
                                                    uint16_t *replyLen);
zxerr_t crypto_diversifier_with_startindex(uint8_t *buffer, uint32_t p, uint8_t *startindex,
                                           uint16_t *replylen);

zxerr_t crypto_ivk_sapling(uint8_t *buffer, uint16_t bufferLen, uint32_t p, uint16_t *replyLen);
zxerr_t crypto_ovk_sapling(uint8_t *buffer, uint16_t bufferLen, uint32_t p, uint16_t *replyLen);
zxerr_t crypto_fvk_sapling(uint8_t *buffer, uint16_t bufferLen, uint32_t p, uint16_t *replyLen);
zxerr_t crypto_nullifier_sapling(uint8_t *buffer, uint16_t bufferLen, uint64_t notepos,
                                 uint8_t *cm, uint16_t *replyLen);

zxerr_t crypto_hash_messagebuffer(uint8_t *buffer, uint16_t bufferLen, const uint8_t *txdata, uint16_t txdataLen);

zxerr_t crypto_checkspend_sapling(uint8_t *buffer, uint16_t bufferLen, const uint8_t *spenddata, uint16_t spenddatalen, const uint8_t tx_version);

zxerr_t crypto_checkoutput_sapling(uint8_t *buffer, uint16_t bufferLen, const uint8_t *outputdata,
                                   const uint16_t outputdatalen, const uint8_t tx_version);

zxerr_t crypto_checkencryptions_sapling(uint8_t *buffer, uint16_t bufferLen, const uint8_t *outputdata);

uint16_t crypto_key_exchange(uint8_t *buffer, uint16_t bufferLen, const uint8_t *txdata, const uint16_t txdatalen);
zxerr_t crypto_extracttx_sapling(uint8_t *buffer, uint16_t bufferLen, const uint8_t *txdata, const uint16_t txdatalen);

zxerr_t crypto_extract_spend_proofkeyandrnd(uint8_t *buffer, uint16_t bufferLen);

zxerr_t crypto_extract_output_rnd(uint8_t *buffer, uint16_t bufferLen, uint16_t *replyLen);

zxerr_t crypto_signspends_sapling(uint8_t *buffer, uint16_t bufferLen, const uint8_t *signdata, uint16_t signdatalen, const uint8_t tx_version);


zxerr_t crypto_extract_spend_signature(uint8_t *buffer, uint16_t bufferLen);

zxerr_t crypto_check_prevouts(uint8_t *buffer, uint16_t bufferLen, const uint8_t *txdata, const uint8_t tx_version);

zxerr_t crypto_check_sequence(uint8_t *buffer, uint16_t bufferLen, const uint8_t *txdata, const uint8_t tx_version);

zxerr_t crypto_check_outputs(uint8_t *buffer, uint16_t bufferLen, const uint8_t *txdata, const uint16_t txdatalen, const uint8_t tx_version);

zxerr_t crypto_check_joinsplits(uint8_t *buffer, uint16_t bufferLen, const uint8_t *txdata, const uint8_t tx_version);

zxerr_t crypto_check_valuebalance(uint8_t *buffer, uint16_t bufferLen, const uint8_t *txdata, const uint8_t tx_version);

void address_to_script(uint8_t *address, uint8_t *output);
zxerr_t
crypto_sign_and_check_transparent(uint8_t *buffer, uint16_t bufferLen, const uint8_t *txdata, const uint16_t txdatalen);
zxerr_t crypto_extract_transparent_signature(uint8_t *buffer, uint16_t bufferLen);
#ifdef __cplusplus
}
#endif
