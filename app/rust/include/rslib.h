#pragma once

#include <stdint.h>

#include "parser_common.h"
#include "parser_txdef.h"

/****************************** others
 * ********************************************************************************/

//ZIP32 functions
void ask_to_ak(const uint8_t *ask_ptr, uint8_t *ak_ptr);

void nsk_to_nk(const uint8_t *nsk_ptr, uint8_t *nk_ptr);

void get_pkd(const uint8_t *seed_ptr, const uint32_t pos, const uint8_t *diversifier_ptr, uint8_t *pkd);

void group_hash_from_div(const uint8_t *diversifier_ptr, uint8_t *gd);

void get_diversifier_list(const uint8_t *sk_ptr, uint8_t *diversifier_list);

void get_diversifier_fromlist(const uint8_t *diversifier_list, uint8_t *diversifier);

bool is_valid_diversifier(const uint8_t *diversifier);

void get_diversifier_list_withstartindex(const uint8_t *seed_ptr, const uint32_t pos, const uint8_t *startindex, uint8_t *diversifier_list);

void get_default_diversifier_list_withstartindex(const uint8_t *seed_ptr, const uint32_t pos, uint8_t *startindex, uint8_t *diversifier_list);

void zip32_master(const uint8_t *seed_ptr, uint8_t *sk_ptr, uint8_t *dk_ptr);

void zip32_child_ask_nsk(const uint8_t *seed_ptr, uint8_t *ask, uint8_t *nsk, const uint32_t pos);

void zip32_ivk(const uint8_t *ak_ptr, uint8_t *ivk_ptr, const uint32_t pos);

void zip32_ovk(const uint8_t *seed_ptr, uint8_t *ovk, const uint32_t pos);

void zip32_child_proof_key(const uint8_t *seed_ptr, uint8_t *ak_ptr, uint8_t *nsk_ptr, const uint32_t pos);

//Rseed
void rseed_get_esk_epk(const uint8_t *seed_ptr, uint8_t *d_ptr, uint8_t *output_esk_ptr, uint8_t *output_epk_ptr);

void rseed_get_rcm(const uint8_t *input, uint8_t *output_ptr);

//Commitments
void compute_note_commitment(uint8_t *inputptr, const uint8_t *rcmptr,const uint64_t value,const uint8_t *gd, const uint8_t *pkd);

void compute_note_commitment_fullpoint(uint8_t *inputptr, const uint8_t *rcmptr,const uint64_t value,const uint8_t *gd, const uint8_t *pkd);

void compute_value_commitment(const uint64_t value, const uint8_t *rcmptr, uint8_t *output);

void compute_nullifier(uint8_t *ncmptr, uint64_t pos, uint8_t *nkptr, uint8_t *outputptr);

void compute_valueBalance_commitment(const uint64_t u64, uint8_t *output);

//Note encryption
void blake2b_prf(uint8_t *inputptr, uint8_t *outptr);

void ka_to_key(uint8_t *esk_ptr, uint8_t *pkd_ptr, uint8_t *epk_ptr, uint8_t *output_ptr);

void prepare_enccompact_input(uint8_t *d, uint64_t value, uint8_t *rcm, uint8_t memotype, uint8_t *output);

//RedJubjub
void random_fr(uint8_t *alpha_ptr);

void randomized_secret_from_seed(uint8_t *seed_ptr, uint32_t pos, uint8_t *alpha_ptr, uint8_t *output_ptr);

void randomized_secret(uint8_t *sk_ptr, uint8_t *alpha_ptr, uint8_t *output_ptr);

void sk_to_pk(uint8_t *sk_ptr, uint8_t *pk_ptr);

void randomize_pk(uint8_t *alpha_ptr, uint8_t *pk_ptr);

void sign_redjubjub(uint8_t *key_ptr, uint8_t *msg_ptr, uint8_t *out_ptr);

//Session key
void sessionkey_agree(uint8_t *scalar_ptr, uint8_t *point_ptr, uint8_t *output_ptr);

void pubkey_gen(uint8_t *scalar_ptr, uint8_t *output_ptr);
