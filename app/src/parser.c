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

#include <stdio.h>
#include <zxmacros.h>
#include <zxformat.h>
#include "app_mode.h"
#include "parser.h"
#include "parser_impl.h"
#include "parser_common.h"

#include "coin.h"
#include "parser_txdef.h"
#include "rslib.h"
#include "nvdata.h"
#include "bech32.h"
#include "base58.h"
#include "view.h"
#include <os_io_seproxyhal.h>

#define DEFAULT_MEMOTYPE        0xf6

#if defined(TARGET_NANOX) || defined(TARGET_NANOS2)
// For some reason NanoX requires this function
void __assert_fail(const char * assertion, const char * file, unsigned int line, const char * function){
    while(1) {};
}
#endif

typedef enum {
    type_tin = 0,
    type_tout = 1,
    type_sspend = 2,
    type_sout = 3,
    type_txfee = 4,
} sapling_parser_type_e;

typedef struct {
    sapling_parser_type_e type;
    uint8_t index;
} parser_sapling_t;

parser_error_t parser_sapling_path_with_div(const uint8_t *data, size_t dataLen, parser_addr_div_t *prs) {
    if (dataLen < 15) {
        return parser_context_unexpected_size;
    }
    parser_context_t pars_ctx;
    parser_error_t pars_err;
    pars_ctx.offset = 0;
    pars_ctx.buffer = data;
    pars_ctx.bufferLen = 4;
    uint32_t p = 0;
    pars_err = _readUInt32(&pars_ctx, &p);
    if (pars_err != parser_ok) {
        return pars_err;
    }
    prs->path = p | 0x80000000;
    memcpy(prs->div, data + 4, 11);
    return parser_ok;
}

parser_error_t parser_sapling_path(const uint8_t *data, size_t dataLen, uint32_t *p) {
    if (dataLen < 4) {
        return parser_context_unexpected_size;
    }
    parser_context_t pars_ctx;
    parser_error_t pars_err;
    pars_ctx.offset = 0;
    pars_ctx.buffer = data;
    pars_ctx.bufferLen = 4;
    pars_err = _readUInt32(&pars_ctx, p);
    if (pars_err != parser_ok) {
        return pars_err;
    }
    *p |= 0x80000000;
    return parser_ok;
}

void view_tx_state() {
    uint8_t state = get_state();
    switch (state) {
        case STATE_PROCESSED_INPUTS:
        case STATE_PROCESSED_SPEND_EXTRACTIONS: {
            view_message_show("Zcash", "Step [1/5]");
            break;
        }

        case STATE_PROCESSED_ALL_EXTRACTIONS: {
            view_message_show("Zcash", "Step [2/5]");
            break;
        }

        case STATE_CHECKING_ALL_TXDATA: {
            view_message_show("Zcash", "Step [3/5]");
            break;
        }

        case STATE_VERIFIED_ALL_TXDATA: {
            view_message_show("Zcash", "Step [4/5]");
            break;
        }

        case STATE_SIGNED_TX: {
            view_message_show("Zcash", "Step [5/5]");
            break;
        }

        default: {
            view_idle_show(0, NULL);
        }
    }
    UX_WAIT_DISPLAYED();
    return;
}

parser_error_t parser_parse(parser_context_t *ctx, const uint8_t *data, size_t dataLen, parser_tx_t *tx_obj) {
    CHECK_PARSER_ERR(parser_init(ctx, data, dataLen))



    return parser_ok;
}

parser_error_t parser_validate(const parser_context_t *ctx) {
    // Iterate through all items to check that all can be shown and are valid
    uint8_t numItems = 0;
    CHECK_PARSER_ERR(parser_getNumItems(ctx, &numItems))

    char tmpKey[30];
    char tmpVal[30];

    for (uint8_t idx = 0; idx < numItems; idx++) {
        uint8_t pageCount = 0;
        CHECK_PARSER_ERR(parser_getItem(ctx, idx, tmpKey, sizeof(tmpKey), tmpVal, sizeof(tmpVal), 0, &pageCount))
    }

    return parser_ok;
}

parser_error_t parser_sapling_display_value(uint64_t value, char *outVal,
                                            uint16_t outValLen, uint8_t pageIdx,
                                            uint8_t *pageCount) {
    char tmpBuffer[100];
    fpuint64_to_str(tmpBuffer, sizeof(tmpBuffer), value, 8);
    pageString(outVal, outValLen, tmpBuffer, pageIdx, pageCount);
    return parser_ok;
}

parser_error_t parser_sapling_display_address_t(uint8_t *addr, char *outVal,
                                                uint16_t outValLen, uint8_t pageIdx,
                                                uint8_t *pageCount) {
    MEMZERO(outVal, outValLen);

    uint8_t address[VERSION_SIZE + CX_RIPEMD160_SIZE + CX_SHA256_SIZE];
    address[0] = VERSION_P2PKH >> 8;
    address[1] = VERSION_P2PKH & 0xFF;
    MEMCPY(address + VERSION_SIZE, addr + 4, CX_RIPEMD160_SIZE);

    cx_hash_sha256(address,
                   VERSION_SIZE + CX_RIPEMD160_SIZE,
                   address + VERSION_SIZE + CX_RIPEMD160_SIZE,
                   CX_SHA256_SIZE);

    cx_hash_sha256(address + VERSION_SIZE + CX_RIPEMD160_SIZE, CX_SHA256_SIZE,
                   address + VERSION_SIZE + CX_RIPEMD160_SIZE, CX_SHA256_SIZE);

    uint8_t tmpBuffer[60];
    size_t outLen = sizeof(tmpBuffer);

    int err = encode_base58(address, VERSION_SIZE + CX_RIPEMD160_SIZE + CHECKSUM_SIZE, tmpBuffer, &outLen);
    if (err != 0) {
        return parser_unexpected_error;
    }

    ZEMU_LOGF(50, "addr size %d\n", outLen)

    pageString(outVal, outValLen, (char *) tmpBuffer, pageIdx, pageCount);
    return parser_ok;
}

parser_error_t parser_sapling_display_address_s(uint8_t *div, uint8_t *pkd, char *outVal,
                                                uint16_t outValLen, uint8_t pageIdx,
                                                uint8_t *pageCount) {

    uint8_t address[DIV_SIZE + PKD_SIZE];
    MEMCPY(address, div, DIV_SIZE);
    MEMCPY(address + DIV_SIZE, pkd, PKD_SIZE);
    char tmpBuffer[100];
    bech32EncodeFromBytes(tmpBuffer, sizeof(tmpBuffer),
                          BECH32_HRP,
                          address,
                          sizeof(address),
                          1, BECH32_ENCODING_BECH32);
    pageString(outVal, outValLen, tmpBuffer, pageIdx, pageCount);
    return parser_ok;
}

parser_error_t parser_sapling_getTypes(const uint16_t displayIdx, parser_sapling_t *prs) {
    uint16_t index = displayIdx;

    if (index < t_inlist_len() * NUM_ITEMS_TIN && t_inlist_len() > 0) {
        prs->type = type_tin;
        prs->index = index;
        return parser_ok;
    }
    index -= t_inlist_len() * NUM_ITEMS_TIN;
    if (index < t_outlist_len() * NUM_ITEMS_TOUT && t_outlist_len() > 0) {
        prs->type = type_tout;
        prs->index = index;
        return parser_ok;
    }
    index -= t_outlist_len() * NUM_ITEMS_TOUT;
    if (index < spendlist_len() * NUM_ITEMS_SSPEND && spendlist_len() > 0) {
        prs->type = type_sspend;
        prs->index = index;
        return parser_ok;
    }
    index -= spendlist_len() * NUM_ITEMS_SSPEND;
    if (index < outputlist_len() * NUM_ITEMS_SOUT && outputlist_len() > 0) {
        prs->type = type_sout;
        prs->index = index;
        return parser_ok;
    }
    prs->type = type_txfee;
    return parser_ok;
}

parser_error_t parser_getNumItems(const parser_context_t *ctx, uint8_t *num_items) {
    *num_items = t_inlist_len() * NUM_ITEMS_TIN +
                 t_outlist_len() * NUM_ITEMS_TOUT +
                 spendlist_len() * NUM_ITEMS_SSPEND +
                 outputlist_len() * NUM_ITEMS_SOUT +
                 NUM_ITEMS_CONST;

    return parser_ok;
}

parser_error_t parser_getItem(const parser_context_t *ctx,
                              uint8_t displayIdx,
                              char *outKey, uint16_t outKeyLen,
                              char *outVal, uint16_t outValLen,
                              uint8_t pageIdx, uint8_t *pageCount) {
    MEMZERO(outKey, outKeyLen);
    MEMZERO(outVal, outValLen);
    snprintf(outKey, outKeyLen, "?");
    snprintf(outVal, outValLen, "?");
    *pageCount = 1;

    uint8_t numItems;
    CHECK_PARSER_ERR(parser_getNumItems(ctx, &numItems))
    CHECK_APP_CANARY()


    if (displayIdx < 0 || displayIdx >= numItems) {
        return parser_no_data;
    }

    parser_sapling_t prs;
    MEMZERO(&prs, sizeof(parser_sapling_t));
    CHECK_PARSER_ERR(parser_sapling_getTypes(displayIdx, &prs));

    // FIXME: what decimals to take for ZECs?

    switch (prs.type) {
        case type_tin : {
            uint8_t itemnum = prs.index / NUM_ITEMS_TIN;
            t_input_item_t *item = t_inlist_retrieve_item(itemnum);
            uint8_t itemtype = prs.index % NUM_ITEMS_TIN;

            switch (itemtype) {
                case 0: {
                    snprintf(outKey, outKeyLen, "T-in addr");
                    return parser_sapling_display_address_t(item->script, outVal, outValLen, pageIdx, pageCount);
                }
                case 1: {
                    snprintf(outKey, outKeyLen, "T-in (ZEC)");
                    return parser_sapling_display_value(item->value, outVal, outValLen, pageIdx, pageCount);
                }
            }
        }

        case type_tout : {
            uint8_t itemnum = prs.index / NUM_ITEMS_TOUT;
            t_output_item_t *item = t_outlist_retrieve_item(itemnum);
            uint8_t itemtype = prs.index % NUM_ITEMS_TOUT;
            switch (itemtype) {
                case 0: {
                    snprintf(outKey, outKeyLen, "T-out addr");
                    return parser_sapling_display_address_t(item->address, outVal, outValLen, pageIdx, pageCount);
                }
                case 1: {
                    snprintf(outKey, outKeyLen, "T-out (ZEC)");
                    return parser_sapling_display_value(item->value, outVal, outValLen, pageIdx, pageCount);
                }
            }
        }
        case type_sspend: {
            uint8_t itemnum = prs.index / NUM_ITEMS_SSPEND;
            spend_item_t *item = spendlist_retrieve_item(itemnum);
            uint8_t itemtype = prs.index % NUM_ITEMS_SSPEND;
            switch (itemtype) {
                case 0: {
                    snprintf(outKey, outKeyLen, "S-in addr");
                    return parser_sapling_display_address_s(item->div, item->pkd, outVal, outValLen, pageIdx,
                                                            pageCount);
                }
                case 1: {
                    snprintf(outKey, outKeyLen, "S-in (ZEC)");
                    return parser_sapling_display_value(item->value, outVal, outValLen, pageIdx, pageCount);
                }
            }
        }

        case type_sout: {

            uint8_t itemnum = prs.index / NUM_ITEMS_SOUT;
            output_item_t *item = outputlist_retrieve_item(itemnum);
            uint8_t itemtype = prs.index % NUM_ITEMS_SOUT;
            switch (itemtype) {
                case 0: {
                    snprintf(outKey, outKeyLen, "S-out addr");
                    return parser_sapling_display_address_s(item->div, item->pkd, outVal, outValLen, pageIdx,
                                                            pageCount);
                }
                case 1: {
                    snprintf(outKey, outKeyLen, "S-out (ZEC)");
                    return parser_sapling_display_value(item->value, outVal, outValLen, pageIdx, pageCount);
                }
                case 2: {
                    snprintf(outKey, outKeyLen, "S-out Memotype");
                    if (item->memotype == DEFAULT_MEMOTYPE) {
                        snprintf(outVal, outValLen, "Default");
                    } else {
                        snprintf(outVal, outValLen, "Custom");
                    }
                    return parser_ok;
                }

                case 3: {
                    snprintf(outKey, outKeyLen, "S-out OVK");
                    uint8_t dummy[OVK_SIZE];
                    MEMZERO(dummy, sizeof(dummy));
                    if (item->ovk[0] == 0x01) {
                        char tmpBuffer[100];
                        array_to_hexstr(tmpBuffer, sizeof(tmpBuffer), item->ovk + 1, OVK_SIZE);
                        pageString(outVal, outValLen, tmpBuffer, pageIdx, pageCount);
                        return parser_ok;
                    } else {
                        snprintf(outVal, outValLen, "None");
                    }
                    return parser_ok;
                }
            }
        }

        case type_txfee: {
            snprintf(outKey, outKeyLen, "Fee");
            return parser_sapling_display_value(get_totalvalue(), outVal, outValLen, pageIdx, pageCount);
        }

        default: {
            return parser_no_data;
        }
    }
    return parser_ok;
}

const char *parser_getErrorDescription(parser_error_t err) {
    switch (err) {
        // General errors
        case parser_ok:
            return "No error";
        case parser_no_data:
            return "No more data";
        case parser_init_context_empty:
            return "Initialized empty context";
        case parser_display_idx_out_of_range:
            return "display_idx_out_of_range";
        case parser_display_page_out_of_range:
            return "display_page_out_of_range";
        case parser_unexpected_error:
            return "Unexpected internal error";
        case parser_no_memory_for_state:
            return "No enough memory for parser state";
            /////////// Context specific
        case parser_context_mismatch:
            return "context prefix is invalid";
        case parser_context_unexpected_size:
            return "context unexpected size";
        case parser_context_invalid_chars:
            return "context invalid chars";
            // Required fields error
            // Coin specific
        case parser_invalid_output_script:
            return "Invalid output script";
        case parser_unexpected_type:
            return "Unexpected data type";
        case parser_unexpected_method:
            return "Unexpected method";
        case parser_unexpected_buffer_end:
            return "Unexpected buffer end";
        case parser_unexpected_value:
            return "Unexpected value";
        case parser_unexpected_number_items:
            return "Unexpected number of items";
        case parser_unexpected_characters:
            return "Unexpected characters";
        case parser_unexpected_field:
            return "Unexpected field";
        case parser_value_out_of_range:
            return "Value out of range";
        case parser_invalid_address:
            return "Invalid address format";
        default:
            return "Unrecognized error code";
    }
}
