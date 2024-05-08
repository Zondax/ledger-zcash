void get_pkd(const uint8_t *seed_ptr, const uint32_t pos, const uint8_t *diversifier_ptr, uint8_t *pkd);

void
get_pkd_from_seed(const uint8_t *seed_ptr, const uint32_t pos, const uint8_t *start_index, uint8_t *diversifier_ptr,
                  uint8_t *pkd);

void get_diversifier_list(const uint8_t *sk_ptr, uint8_t *diversifier_list);

void get_diversifier_fromlist(const uint8_t *diversifier_list, uint8_t *diversifier);

bool diversifier_is_valid(const uint8_t *diversifier);

void get_diversifier_list_withstartindex(const uint8_t *seed_ptr, const uint32_t pos, const uint8_t *startindex,
                                         uint8_t *diversifier_list);

void get_default_diversifier_list_withstartindex(const uint8_t *seed_ptr, const uint32_t pos, uint8_t *startindex,
                                                 uint8_t *diversifier_list);

void
get_default_diversifier_without_start_index(const uint8_t *see_ptr, const uint32_t pos, uint8_t *default_diversifier);

// void zip32_master(const uint8_t *seed_ptr, uint8_t *sk_ptr, uint8_t *dk_ptr);

void zip32_child_ask_nsk(const uint8_t *seed_ptr, uint8_t *ask, uint8_t *nsk, const uint32_t pos);

void zip32_nsk_from_seed(const uint8_t *seed_ptr, uint32_t zip32_account, uint8_t *nsk);

void zip32_ovk(const uint8_t *seed_ptr, const uint32_t zip32_account, uint8_t *ovk);

void zip32_child_proof_key(const uint8_t *seed_ptr, uint8_t *ak_ptr, uint8_t *nsk_ptr, const uint32_t pos);


///////////////////////////// checked
void zip32_ivk(const uint8_t *seed_ptr, const uint32_t zip32_account, uint8_t *ivk);
void zip32_fvk(const uint8_t *seed_ptr, uint32_t pos, uint8_t *fvk_ptr);
