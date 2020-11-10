/*******************************************************************************
*   (c) 2018 Zondax GmbH
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
#include <zbuffer.h>
#include "os.h"
#include "cx.h"
#include "nvdata.h"
#include "index_sapling.h"

#define  ZCASH_PREVOUTS_HASH_PERSONALIZATION "ZcashPrevoutHash"
#define  ZCASH_SEQUENCE_HASH_PERSONALIZATION "ZcashSequencHash"
#define  ZCASH_OUTPUTS_HASH_PERSONALIZATION "ZcashOutputsHash"
//#define  ZCASH_JOINSPLITS_HASH_PERSONALIZATION "ZcashJSplitsHash" not supported
#define CTX_ZCASH_SHIELDED_SPENDS_HASH_PERSONALIZATION "ZcashSSpendsHash"
#define CTX_ZCASH_SHIELDED_OUTPUTS_HASH_PERSONALIZATION "ZcashSOutputHash"


void prevouts_hash(uint8_t *input, uint8_t *output){
    cx_blake2b_t ctx;
    cx_blake2b_init2(&ctx, 256, NULL, 0, (uint8_t *)ZCASH_PREVOUTS_HASH_PERSONALIZATION, 16);
    uint8_t n = t_inlist_len();

    if (n == 0){
        cx_hash(&ctx.header, CX_LAST, NULL, 0, output, 256);
        return;
    }

    for(uint8_t i = 0; i < n; i++) {
        uint8_t *data = input + INDEX_TIN_PREVOUT + i * T_IN_TX_LEN;
        if (i == n - 1) {
            cx_hash(&ctx.header, CX_LAST, data, 36, output, 256);
        }else{
            cx_hash(&ctx.header, 0, data, 36, NULL, 0);
        }
    }
}

void sequence_hash(uint8_t *input, uint8_t *output){
    cx_blake2b_t ctx;
    cx_blake2b_init2(&ctx, 256, NULL, 0, (uint8_t *)ZCASH_SEQUENCE_HASH_PERSONALIZATION, 16);
    uint8_t n = t_inlist_len();

    if (n == 0){
        cx_hash(&ctx.header, CX_LAST, NULL, 0, output, 256);
        return;
    }

    for(uint8_t i = 0; i < n; i++) {
        uint8_t *data = input + INDEX_TIN_SEQ + i * T_IN_TX_LEN;
        if (i == n - 1) {
            cx_hash(&ctx.header, CX_LAST, data, 4, output, 256);
        }else{
            cx_hash(&ctx.header, 0, data, 4, NULL, 0);
        }
    }
}

void outputs_hash(uint8_t *output){
    cx_blake2b_t ctx;
    cx_blake2b_init2(&ctx, 256, NULL, 0, (uint8_t *)ZCASH_OUTPUTS_HASH_PERSONALIZATION, 16);
    uint8_t data[34];
    uint8_t n = t_outlist_len();
    if(n == 0){
        cx_hash(&ctx.header, CX_LAST, NULL, 0, output, 256);
        return;
    }

    for(uint8_t i = 0; i < n; i++) {
        t_output_item_t *item = t_outlist_retrieve_item(i);
        MEMCPY(data,(uint8_t *)&(item->value),8);
        MEMCPY(data + 8,item->address,26);
        if (i == n - 1) {
            cx_hash(&ctx.header, CX_LAST, data, sizeof(data), output, 256);
        }else{
            cx_hash(&ctx.header, 0, data, sizeof(data), NULL, 0);
        }
    }
}

/* NOT SUPPORTED
void joinsplits_hash(uint8_t *input, uint16_t inputlen, uint8_t *output){

}
 */

void shielded_output_hash(uint8_t *input, uint16_t inputlen, uint8_t *output){
    cx_blake2b_t ctx;
    cx_blake2b_init2(&ctx, 256, NULL, 0, (uint8_t *)CTX_ZCASH_SHIELDED_OUTPUTS_HASH_PERSONALIZATION, 16);
    cx_hash(&ctx.header, CX_LAST, input, inputlen, output, 256);
}

void shielded_spend_hash(uint8_t *input, uint16_t inputlen, uint8_t *output){
    cx_blake2b_t ctx;
    cx_blake2b_init2(&ctx, 256, NULL, 0, (uint8_t *)CTX_ZCASH_SHIELDED_SPENDS_HASH_PERSONALIZATION, 16);
    cx_hash(&ctx.header, CX_LAST, input, inputlen, output, 256);
}

void signature_hash(uint8_t *input, uint16_t inputlen, uint8_t *output){
    const uint8_t CTX_ZCASH_SHIELDED_SIGNATURE_HASH_PERSONALIZATION[] = {90, 99, 97, 115, 104, 83, 105, 103, 72, 97, 115, 104, 187, 9, 184, 118};
    cx_blake2b_t ctx;
    cx_blake2b_init2(&ctx, 256, NULL, 0, (uint8_t *)CTX_ZCASH_SHIELDED_SIGNATURE_HASH_PERSONALIZATION, 16);
    cx_hash(&ctx.header, CX_LAST, input, inputlen, output, 256);
}

void signature_script_hash(uint8_t *input, uint16_t inputlen, uint8_t *script, uint16_t scriptlen, uint8_t *output){
    const uint8_t CTX_ZCASH_SHIELDED_SIGNATURE_HASH_PERSONALIZATION[] = {90, 99, 97, 115, 104, 83, 105, 103, 72, 97, 115, 104, 187, 9, 184, 118};
    cx_blake2b_t ctx;
    cx_blake2b_init2(&ctx, 256, NULL, 0, (uint8_t *)CTX_ZCASH_SHIELDED_SIGNATURE_HASH_PERSONALIZATION, 16);
    cx_hash(&ctx.header, 0, input, inputlen, NULL, 0);
    cx_hash(&ctx.header, CX_LAST, script, scriptlen, output, 256);
}

