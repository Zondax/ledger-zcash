/*******************************************************************************
*  (c) 2019 Zondax AG
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

#include <zxmacros.h>
#include "parser_impl.h"
#include "parser_txdef.h"
#include "coin.h"
#include "crypto.h"
#include "zxformat.h"

parser_error_t parser_init_context(parser_context_t *ctx, const uint8_t *buffer, uint16_t bufferSize) {
    ctx->offset = 0;
    ctx->buffer = NULL;
    ctx->bufferLen = 0;

    if (bufferSize == 0 || buffer == NULL) {
        // Not available, use defaults
        return parser_init_context_empty;
    }

    ctx->buffer = buffer;
    ctx->bufferLen = bufferSize;

    ZEMU_LOGF(100, "init_context %d bytes", bufferSize);

    return parser_ok;
}

parser_error_t parser_init(parser_context_t *ctx, const uint8_t *buffer, uint16_t bufferSize) {
    CHECK_PARSER_ERR(parser_init_context(ctx, buffer, bufferSize))
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
            // Coin specific
        case parser_not_allowed:
            return "Not allowed";
        case parser_not_supported:
            return "Not supported";
        case parser_unexpected_buffer_end:
            return "Unexpected buffer end";
        case parser_unexpected_value:
            return "Unexpected value";
        case parser_value_out_of_range:
            return "Value out of range";
        case parser_value_too_many_bytes:
            return "Value too many bytes";
        case parser_unexpected_module:
            return "Unexpected module";
        case parser_unexpected_callIndex:
            return "Unexpected call index";
        case parser_unexpected_unparsed_bytes:
            return "Unexpected unparsed bytes";
        case parser_print_not_supported:
            return "Value cannot be printed";
        case parser_tx_nesting_not_supported:
            return "Call nesting not supported";
        case parser_tx_nesting_limit_reached:
            return "Max nested calls reached";
        case parser_tx_call_vec_too_large:
            return "Call vector exceeds limit";
        case parser_swap_tx_wrong_dest_addr:
            return "Swap destination addresses do not match";
        case parser_swap_tx_wrong_amount:
            return "Swap amounts do not match";
        default:
            return "Unrecognized error code";
    }
}

GEN_DEF_READFIX_UNSIGNED(8)

GEN_DEF_READFIX_UNSIGNED(16)

GEN_DEF_READFIX_UNSIGNED(32)

GEN_DEF_READFIX_UNSIGNED(64)

GEN_DEF_READFIX_SIGNED(64)
