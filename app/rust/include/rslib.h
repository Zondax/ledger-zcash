#pragma once

#include <stdint.h>

#include "parser_common.h"
#include "parser_txdef.h"

#include "zip32.h"
#include "notes.h"
#include "commitments.h"

void blake2b_prf(uint8_t *inputptr, uint8_t *outptr);

void random_fr(uint8_t *alpha_ptr);
void randomized_secret_from_seed(uint8_t *seed_ptr, uint32_t pos, uint8_t *alpha_ptr, uint8_t *output_ptr);

void get_rk(uint8_t *ask_ptr, uint8_t *alpha_ptr, uint8_t *output_ptr);
void rsk_to_rk(const uint8_t *rsk_ptr, uint8_t *rk_ptr);
void sign_redjubjub(uint8_t *key_ptr, uint8_t *msg_ptr, uint8_t *out_ptr);
