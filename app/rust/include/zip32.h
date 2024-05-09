#pragma once

#define ZIP32_SIZE 32

void get_pkd(const uint8_t (*seed_ptr)[ZIP32_SIZE],
             uint32_t zip32_account,
             const uint8_t *diversifier_ptr,
             uint8_t (*pkd)[32]);

void get_pkd_from_seed(const uint8_t (*seed_ptr)[ZIP32_SIZE],
                       uint32_t zip32_account,
                       const uint8_t *start_index,
                       uint8_t *diversifier_ptr,
                       uint8_t (*pkd)[32]);

bool diversifier_is_valid(const uint8_t *diversifier);

void diversifier_get_list(const uint8_t (*seed_ptr)[ZIP32_SIZE],
                          uint32_t zip32_account,
                          const uint8_t *startindex,
                          uint8_t *diversifier_list);

void diversifier_find_valid(const uint8_t (*seed_ptr)[ZIP32_SIZE], uint32_t zip32_account, uint8_t *default_diversifier);

void zip32_child_ask_nsk(const uint8_t (*seed_ptr)[ZIP32_SIZE], uint32_t pos, uint8_t *ask, uint8_t *nsk);

void zip32_nsk_from_seed(const uint8_t (*seed_ptr)[ZIP32_SIZE], uint32_t zip32_account, uint8_t *nsk);

void zip32_ovk(const uint8_t (*seed_ptr)[ZIP32_SIZE], uint32_t zip32_account, uint8_t *ovk);

void zip32_child_proof_key(const uint8_t (*seed_ptr)[ZIP32_SIZE], uint32_t account, uint8_t *ak_ptr, uint8_t *nsk_ptr);

void zip32_ivk(const uint8_t (*seed_ptr)[ZIP32_SIZE], uint32_t zip32_account, uint8_t *ivk);

void zip32_fvk(const uint8_t (*seed_ptr)[ZIP32_SIZE], uint32_t zip32_account, uint8_t *fvk_ptr);
