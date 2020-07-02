#pragma once

#include <stdint.h>
#include "parser_common.h"
#include "parser_txdef.h"

/****************************** others ********************************************************************************/

void get_ak(const uint8_t *sk_ptr, uint8_t *ak_ptr);

void ask_to_ak(const uint8_t *ask_ptr, uint8_t *ak_ptr);

void nsk_to_nk(const uint8_t *nsk_ptr, uint8_t *nk_ptr);

void get_nk(const uint8_t *sk_ptr, uint8_t *nk_ptr);

void get_ivk(const uint8_t *ak_ptr, const uint8_t *nk_ptr, uint8_t *ivk_ptr);

void get_pkd(const uint8_t *ivk_ptr, const uint8_t *diversifier_ptr, uint8_t *pkd);

void get_address(const uint8_t *sk_ptr, const uint8_t *ivk, uint8_t *address);

void get_diversifier_list(const uint8_t *sk_ptr, uint8_t *diversifier_list);

void get_diversifier_fromlist(const uint8_t *diversifier_list, uint8_t *diversifier);

void zip32_master(const uint8_t *seed_ptr, uint8_t *sk_ptr, uint8_t *dk_ptr);

void zip32_child(const uint8_t *seed_ptr, uint8_t *dk, uint8_t *ask, uint8_t *nsk); //fixme

parser_error_t _parser_init(parser_context_t *ctx, const uint8_t *buffer, uint16_t bufferSize, uint16_t *alloc_size);

parser_error_t _read(const parser_context_t *c, parser_tx_t *v);

parser_error_t _validate(const parser_context_t *ctx, const parser_tx_t *v);

uint8_t _getNumItems(const parser_context_t *ctx, const parser_tx_t *v);

parser_error_t _getItem(const parser_context_t *ctx,
                              int8_t displayIdx,
                              char *outKey, uint16_t outKeyLen,
                              char *outValue, uint16_t outValueLen,
                              uint8_t pageIdx, uint8_t *pageCount,
                              const parser_tx_t *v);

void do_pedersen_hash(const uint8_t *input_ptr, uint8_t *output_ptr);