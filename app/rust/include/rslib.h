#pragma once

#include <stdint.h>
#include "parser_common.h"

void get_ak(const uint8_t *sk_ptr, uint8_t *ak_ptr);

void get_nk(const uint8_t *sk_ptr, uint8_t *nk_ptr);

void get_ivk(const uint8_t *ak_ptr, const uint8_t *nk_ptr, uint8_t *ivk_ptr);

void get_diversifier(const uint8_t *secret_key, uint8_t *diversifier);

void get_pkd(const uint8_t *ivk_ptr, const uint8_t *diversifier_ptr, uint8_t *pkd);

void get_address(const uint8_t *secret_key, const uint8_t *ivk, uint8_t *address);

parser_error_t _read(parser_context_t *ctx, const uint8_t *data, uint16_t dataLen);

parser_error_t _validate(const parser_context_t *ctx);

parser_error_t _getNumItems(const parser_context_t *ctx, uint16_t *num_items);

parser_error_t _getItem(const parser_context_t *ctx,
                              int8_t displayIdx,
                              char *outKey, uint16_t outKeyLen,
                              char *outValue, uint16_t outValueLen,
                              uint8_t pageIdx, uint8_t *pageCount);

