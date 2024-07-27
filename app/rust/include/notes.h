#pragma once

#include <stdint.h>

void rseed_get_esk_epk(const uint8_t *rseed_ptr, uint8_t *d_ptr, uint8_t *output_esk_ptr, uint8_t *output_epk_ptr);

void rseed_get_rcm(const uint8_t *rseed_ptr, uint8_t *output_ptr);

void ka_to_key(uint8_t *esk_ptr, uint8_t *pkd_ptr, uint8_t *epk_ptr, uint8_t *output_ptr);

void prepare_compact_note(uint8_t *d, uint64_t value, uint8_t *rcm_ptr, uint8_t memotype, uint8_t *out_ptr);
