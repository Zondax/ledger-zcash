void compute_note_commitment(uint8_t *inputptr, const uint8_t *rcmptr, const uint64_t value, const uint8_t *diversifier_ptr,
                             const uint8_t *pkd);

void compute_note_commitment_fullpoint(uint8_t *inputptr, const uint8_t *rcmptr, const uint64_t value,
                                       const uint8_t *diversifier_ptr, const uint8_t *pkd);

void compute_value_commitment(const uint64_t value, const uint8_t *rcmptr, uint8_t *output);

void compute_nullifier(uint8_t *ncmptr, uint64_t pos, const uint8_t *nsk_ptr, uint8_t *outputptr);
