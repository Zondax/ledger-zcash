#pragma once

void get_pkd(uint32_t zip32_account, const uint8_t *diversifier_ptr, uint8_t *pkd);

void get_pkd_from_seed(uint32_t zip32_account, const uint8_t *start_index, uint8_t *diversifier_ptr, uint8_t *pkd);

bool diversifier_is_valid(const uint8_t *diversifier);

void diversifier_get_list(uint32_t zip32_account, const uint8_t *startindex, uint8_t *diversifier_list);

void diversifier_find_valid(uint32_t zip32_account, uint8_t *default_diversifier);

//////////////////////////////////

void zip32_child_ask_nsk(uint32_t account, uint8_t *ask, uint8_t *nsk);

void zip32_child_proof_key(uint32_t account, uint8_t *ak_ptr, uint8_t *nsk_ptr);

void zip32_nsk(uint32_t zip32_account, uint8_t *nsk);

void zip32_ovk(uint32_t zip32_account, uint8_t *ovk);

void zip32_ivk(uint32_t zip32_account, uint8_t *ivk);

void zip32_fvk(uint32_t zip32_account, uint8_t *fvk_ptr);
