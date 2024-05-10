#pragma once

void compute_nullifier(uint8_t *ncm_ptr, uint64_t note_pos, const uint8_t *nsk_ptr, uint8_t *out_ptr);

void compute_note_commitment(
    const uint8_t *rcm_ptr, const uint64_t value, const uint8_t *diversifier_ptr, const uint8_t *pkd, uint8_t *out_ptr);

void compute_note_commitment_fullpoint(
    const uint8_t *rcm_ptr, const uint64_t value, const uint8_t *diversifier_ptr, const uint8_t *pkd, uint8_t *out_ptr);

void compute_value_commitment(const uint8_t *rcm_ptr, const uint64_t value, uint8_t *out_ptr);
