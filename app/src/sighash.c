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

#include <inttypes.h>
#include <zxmacros.h>
#include <zxformat.h>
#include "os.h"
#include "cx.h"
#include "nvdata.h"
#include "sighash.h"
#include "index_sapling.h"
#include "txid.h"

#define  ZCASH_PREVOUTS_HASH_PERSONALIZATION "ZcashPrevoutHash"
#define  ZCASH_SEQUENCE_HASH_PERSONALIZATION "ZcashSequencHash"
#define  ZCASH_OUTPUTS_HASH_PERSONALIZATION "ZcashOutputsHash"
//#define  ZCASH_JOINSPLITS_HASH_PERSONALIZATION "ZcashJSplitsHash" not supported
#define CTX_ZCASH_SHIELDED_SPENDS_HASH_PERSONALIZATION "ZcashSSpendsHash"
#define CTX_ZCASH_SHIELDED_OUTPUTS_HASH_PERSONALIZATION "ZcashSOutputHash"

//const uint8_t CONSENSUS_BRANCH_ID_SAPLING[4] = {0x76, 0xb8, 0x09, 0xBB};       // sapling
//const uint8_t CONSENSUS_BRANCH_ID_ORCHARD[4] = {0xC2, 0xD6, 0xD0, 0xB4};       // orchard
//
const uint8_t CONSENSUS_BRANCH_ID_SAPLING[4] = {0xBB, 0x09, 0xB8, 0x76};       // sapling
const uint8_t CONSENSUS_BRANCH_ID_ORCHARD[4] = {0xB4, 0xD0, 0xD6, 0xC2};       // orchard

void sapling_transparent_prevouts_hash(const uint8_t *input, uint8_t *output) {
    const uint8_t n = t_inlist_len();
    cx_blake2b_t ctx;
    cx_blake2b_init2_no_throw(&ctx, 256, NULL, 0, (uint8_t *) ZCASH_PREVOUTS_HASH_PERSONALIZATION, 16);

    if (n == 0) {
        cx_hash_no_throw(&ctx.header, CX_LAST, 0, 0, output, HASH_SIZE);
        return;
    }

    const uint8_t *data = input + INDEX_TIN_PREVOUT;
    for (uint8_t i = 0; i < n - 1; i++, data += T_IN_TX_LEN) {
        cx_hash_no_throw(&ctx.header, 0, data, 36, NULL, 0);
    }
    cx_hash_no_throw(&ctx.header, CX_LAST, data, 36, output, HASH_SIZE);
}

void sapling_transparent_sequence_hash(const uint8_t *input, uint8_t *output) {
    const uint8_t n = t_inlist_len();

    cx_blake2b_t ctx;
    cx_blake2b_init2_no_throw(&ctx, 256, NULL, 0, (uint8_t *) ZCASH_SEQUENCE_HASH_PERSONALIZATION, 16);

    if (n == 0) {
        cx_hash_no_throw(&ctx.header, CX_LAST, 0, 0, output, HASH_SIZE);
        return;
    }

    const uint8_t *data = input + INDEX_TIN_SEQ;
    for (uint8_t i = 0; i < n - 1; i++, data += T_IN_TX_LEN) {
        cx_hash_no_throw(&ctx.header, 0, data, 4, NULL, 0);
    }
    cx_hash_no_throw(&ctx.header, CX_LAST, data, 4, output, HASH_SIZE);
}

void v4_transparent_outputs_hash(uint8_t *output) {
    const uint8_t n = t_outlist_len();

    cx_blake2b_t ctx;
    cx_blake2b_init2_no_throw(&ctx, 256, NULL, 0, (uint8_t *) ZCASH_OUTPUTS_HASH_PERSONALIZATION, 16);

    if (n == 0) {
        cx_hash_no_throw(&ctx.header, CX_LAST, 0, 0, output, HASH_SIZE);
        return;
    }

    uint8_t data[34];
    uint8_t i = 0;
    for (; i < n - 1; i++) {
        t_output_item_t *item = t_outlist_retrieve_item(i);
        MEMCPY(data, (uint8_t * ) & (item->value), 8);
        MEMCPY(data + 8, item->address, SCRIPT_SIZE);
        cx_hash_no_throw(&ctx.header, 0, data, sizeof(data), NULL, 0);
    }
    t_output_item_t *item = t_outlist_retrieve_item(i);
    MEMCPY(data, (uint8_t * ) & (item->value), 8);
    MEMCPY(data + 8, item->address, SCRIPT_SIZE);
    cx_hash_no_throw(&ctx.header, CX_LAST, data, sizeof(data), output, HASH_SIZE);
}


void shielded_output_hash(const uint8_t *input, uint16_t inputlen, uint8_t *output) {
    if (inputlen == 0) {
        MEMZERO(output, HASH_SIZE);
        return;
    }
    cx_blake2b_t ctx;
    cx_blake2b_init2_no_throw(&ctx, 256, NULL, 0, (uint8_t *) CTX_ZCASH_SHIELDED_OUTPUTS_HASH_PERSONALIZATION, 16);
    cx_hash_no_throw(&ctx.header, CX_LAST, input, inputlen, output, HASH_SIZE);
}

void shielded_spend_hash(const uint8_t *input, uint16_t inputlen, uint8_t *output) {
    if (inputlen == 0) {
        MEMZERO(output, HASH_SIZE);
        return;
    }
    cx_blake2b_t ctx;
    cx_blake2b_init2_no_throw(&ctx, 256, NULL, 0, (uint8_t *) CTX_ZCASH_SHIELDED_SPENDS_HASH_PERSONALIZATION, 16);
    cx_hash_no_throw(&ctx.header, CX_LAST, input, inputlen, output, HASH_SIZE);
}

static void signature_hash_v4(const uint8_t *input, uint16_t inputlen, uint8_t *output) {
    zemu_log_stack("signature_hash_v4");
    cx_blake2b_t ctx;

    uint8_t personalization[16] = {0};
    MEMCPY(personalization, "ZcashSigHash", 12);
    MEMCPY(personalization + 12, CONSENSUS_BRANCH_ID_ORCHARD, 4);

    cx_blake2b_init2_no_throw(&ctx, 256, NULL, 0, (uint8_t *) personalization, 16);

    cx_hash_no_throw(&ctx.header, CX_LAST, input, inputlen, output, HASH_SIZE);
}

static void signature_hash_v5(const uint8_t *input, uint8_t *start_signdata, uint8_t index, signable_input type, uint8_t *output) {
    zemu_log_stack("signature_hash_v5");
    cx_blake2b_t ctx;

    uint8_t personalization[16] = {0};
    MEMCPY(personalization, "ZcashTxHash_", 12);
    MEMCPY(personalization + 12, CONSENSUS_BRANCH_ID_ORCHARD, 4);
    cx_blake2b_init2_no_throw(&ctx, 256, NULL, 0, (uint8_t *) personalization, 16);

    uint8_t header_digest[32] = {0};
    uint8_t transparent_digest[32] = {0};
    uint8_t sapling_digest[32] = {0};
    uint8_t orchard_digest[32] = {0};

    hash_header_txid_data(start_signdata, header_digest);
    transparent_sig_digest(input, start_signdata, index, type, transparent_digest);
    hash_sapling_txid_data(start_signdata, sapling_digest);
    hash_empty_orchard_txid_data(orchard_digest);

    cx_hash_no_throw(&ctx.header, 0, header_digest, HASH_SIZE, NULL, 0);
    cx_hash_no_throw(&ctx.header, 0, transparent_digest, HASH_SIZE, NULL, 0);
    cx_hash_no_throw(&ctx.header, 0, sapling_digest, HASH_SIZE, NULL, 0);
    cx_hash_no_throw(&ctx.header, CX_LAST, orchard_digest, HASH_SIZE, output, HASH_SIZE);
}

void signature_hash(const uint8_t *txdata, uint8_t *start_signdata, uint16_t inputlen, const uint8_t tx_version, uint8_t *output){
    if (tx_version == TX_VERSION_SAPLING) {
        signature_hash_v4(start_signdata, inputlen, output);
    }
    else if (tx_version == TX_VERSION_NU5)
    {
        signature_hash_v5(txdata, start_signdata, 0, shielded, output);
    }
}

static void signature_script_hash_v4(const uint8_t *input, uint16_t inputlen, uint8_t *script, uint16_t scriptlen, uint8_t *output) {
    cx_blake2b_t ctx;

	uint8_t personalization[16] = {0};
    MEMCPY(personalization, "ZcashSigHash", 12);
    MEMCPY(personalization + 12, CONSENSUS_BRANCH_ID_ORCHARD, 4);

    cx_blake2b_init2_no_throw(&ctx, 256, NULL, 0, (uint8_t *) personalization, 16);
    cx_hash_no_throw(&ctx.header, 0, input, inputlen, NULL, 0);

    cx_hash_no_throw(&ctx.header, CX_LAST, script, scriptlen, output, HASH_SIZE);
}

void signature_script_hash(const uint8_t *input, uint8_t *start_signdata, uint16_t inputlen, uint8_t *script, uint16_t scriptlen, uint8_t index, const uint8_t tx_version, uint8_t *output) {
    if (tx_version==TX_VERSION_SAPLING) {
        signature_script_hash_v4(start_signdata, inputlen, script, scriptlen, output);
    }
    else if (tx_version == TX_VERSION_NU5)
    {
        signature_hash_v5(input, start_signdata, index, transparent, output);
    }
}

