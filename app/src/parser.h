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

#include "parser_common.h"
#include "parser_txdef.h"
#include "hexutils.h"
#include "crypto.h"

#define NUM_ITEMS_TIN       2       //address, value
#define NUM_ITEMS_TOUT      2       //address, value
#define NUM_ITEMS_SSPEND    2       //address, value
#define NUM_ITEMS_SOUT      4       //address, value, memotype, OVK?
#define NUM_ITEMS_CONST     1       //txfee

typedef struct {
    uint32_t path;
    uint8_t div[11];
} parser_addr_div_t;

parser_error_t parser_sapling_path_with_div(const uint8_t *data, size_t dataLen, parser_addr_div_t *prs);
parser_error_t parser_sapling_path(const uint8_t *data, size_t dataLen, uint32_t *p);

void view_tx_state();

const char *parser_getErrorDescription(parser_error_t err);

//// parses a tx buffer
parser_error_t parser_parse(parser_context_t *ctx, const uint8_t *data, size_t dataLen, parser_tx_t *tx_obj);

//// verifies tx fields
parser_error_t parser_validate(const parser_context_t *ctx);

//// returns the number of items in the current parsing context
parser_error_t parser_getNumItems(const parser_context_t *ctx, uint8_t *num_items);

// retrieves a readable output for each field / page
parser_error_t parser_getItem(const parser_context_t *ctx,
                              uint8_t displayIdx,
                              char *outKey, uint16_t outKeyLen,
                              char *outValue, uint16_t outValueLen,
                              uint8_t pageIdx, uint8_t *pageCount);

void parser_resetState();

#ifdef __cplusplus
}
#endif
