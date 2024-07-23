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
#pragma once

#include <zxmacros.h>

#include "parser_common.h"
#include "parser_txdef.h"
#include "zxtypes.h"

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

// Checks that there are at least SIZE bytes available in the buffer
#define CTX_CHECK_AVAIL(CTX, SIZE)                                    \
    if ((CTX) == NULL || ((CTX)->offset + SIZE) > (CTX)->bufferLen) { \
        return parser_unexpected_buffer_end;                          \
    }

#define CTX_CHECK_AND_ADVANCE(CTX, SIZE) \
    CTX_CHECK_AVAIL((CTX), (SIZE))       \
    (CTX)->offset += (SIZE);

// Checks function input is valid
#define CHECK_INPUT()          \
    if (v == NULL) {           \
        return parser_no_data; \
    }                          \
    CTX_CHECK_AVAIL(c, 1)  // Checks that there is something available in the buffer

#define CLEAN_AND_CHECK()           \
    MEMZERO(outValue, outValueLen); \
    if (v == NULL) {                \
        *pageCount = 0;             \
        return parser_no_data;      \
    }

#define GEN_DEF_READARRAY(SIZE)      \
    v->_ptr = c->buffer + c->offset; \
    CTX_CHECK_AND_ADVANCE(c, SIZE)   \
    return parser_ok;

#define GEN_DEF_TOSTRING_ARRAY(SIZE)                                              \
    CLEAN_AND_CHECK();                                                            \
    if (v->_ptr == NULL || outValueLen == 0) return parser_unexpected_buffer_end; \
    const uint16_t outLenNormalized = (outValueLen - 1) / 2;                      \
    *pageCount = SIZE / outLenNormalized;                                         \
    if (SIZE % outLenNormalized != 0) *pageCount += 1;                            \
    const uint16_t pageOffset = pageIdx * outLenNormalized;                       \
    uint16_t loopmax = outLenNormalized;                                          \
    if (loopmax > SIZE - pageOffset) loopmax = SIZE - pageOffset;                 \
    for (uint16_t i = 0; i < loopmax; i++) {                                      \
        const uint16_t offset = i << 1u;                                          \
        const uint8_t *c = v->_ptr + pageOffset;                                  \
        snprintf(outValue + offset, outValueLen - offset, "%02x", c[i]);          \
    }                                                                             \
    return parser_ok;

#define GEN_DEC_READFIX_UNSIGNED(BITS) parser_error_t _readUInt##BITS(parser_context_t *ctx, uint##BITS##_t *value)
#define GEN_DEF_READFIX_UNSIGNED(BITS)                                              \
    parser_error_t _readUInt##BITS(parser_context_t *ctx, uint##BITS##_t *value) {  \
        if (value == NULL) return parser_no_data;                                   \
        *value = 0u;                                                                \
        for (uint8_t i = 0u; i < (BITS##u >> 3u); i++, ctx->offset++) {             \
            if (ctx->offset >= ctx->bufferLen) return parser_unexpected_buffer_end; \
            *value += (uint##BITS##_t) * (ctx->buffer + ctx->offset) << (8u * i);   \
        }                                                                           \
        return parser_ok;                                                           \
    }
#define GEN_DEC_READFIX_SIGNED(BITS) parser_error_t _readInt##BITS(parser_context_t *ctx, int##BITS##_t *value)
#define GEN_DEF_READFIX_SIGNED(BITS)                                                \
    parser_error_t _readInt##BITS(parser_context_t *ctx, int##BITS##_t *value) {    \
        if (value == NULL) return parser_no_data;                                   \
        *value = 0;                                                                 \
        for (int8_t i = 0; i < (BITS >> 3); i++, ctx->offset++) {                   \
            if (ctx->offset >= ctx->bufferLen) return parser_unexpected_buffer_end; \
            *value += (int##BITS##_t) * (ctx->buffer + ctx->offset) << (8 * i);     \
        }                                                                           \
        return parser_ok;                                                           \
    }

GEN_DEC_READFIX_UNSIGNED(8);

GEN_DEC_READFIX_UNSIGNED(16);

GEN_DEC_READFIX_UNSIGNED(32);

GEN_DEC_READFIX_UNSIGNED(64);

GEN_DEC_READFIX_SIGNED(64);

parser_error_t parser_init(parser_context_t *ctx, const uint8_t *buffer, uint16_t bufferSize);

#ifdef __cplusplus
}
#endif
