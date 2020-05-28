#pragma once

#include <stdint.h>

void get_ak(const uint8_t *sk_ptr, uint8_t *ak_ptr);

void ask_to_ak(const uint8_t *ask_ptr, uint8_t *ak_ptr);

void nsk_to_nk(const uint8_t *nsk_ptr, uint8_t *nk_ptr);

void get_nk(const uint8_t *sk_ptr, uint8_t *nk_ptr);

void get_ivk(const uint8_t *ak_ptr, const uint8_t *nk_ptr, uint8_t *ivk_ptr);

void get_diversifier(const uint8_t *sk_ptr, uint8_t *diversifier);

void get_pkd(const uint8_t *ivk_ptr, const uint8_t *diversifier_ptr, uint8_t *pkd);

void get_address(const uint8_t *sk_ptr, const uint8_t *ivk, uint8_t *address);

void get_diversifier_list(const uint8_t *sk_ptr, uint8_t *diversifier_list);

void get_diversifier_fromlist(const uint8_t *diversifier_list, uint8_t *diversifier);

void zip32_master(const uint8_t *seed_ptr, uint8_t *sk_ptr, uint8_t *dk_ptr);

void zip32_child(const uint8_t *seed_ptr, uint8_t *dk, uint8_t *ask, uint8_t *nsk); //fixme
