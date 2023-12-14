#include "aes.h"
#include "coin.h"
#include "cx.h"
#include "jubjub.h"
#include "os.h"
#include <bolos_target.h>
#include <inttypes.h>
#include <zxformat.h>
#include <zxmacros.h>
#include "zcash_utils.h"

#define CTX_REDJUBJUB "Zcash_RedJubjubH"
#define CTX_REDJUBJUB_LEN 16
#define CTX_REDJUBJUB_HASH_LEN 64

#define CTX_EXPAND_SEED "Zcash_ExpandSeed"
#define CTX_EXPAND_SEED_LEN 16
#define CTX_EXPAND_SEED_HASH_LEN 64

#include <bolos_target.h>
#include <inttypes.h>
#include <stddef.h>

#if defined(TARGET_NANOS) || defined(TARGET_NANOX) ||                          \
    defined(TARGET_NANOS2) || defined(TARGET_STAX)
#include "lcx_rng.h"
unsigned char *bolos_cx_rng(uint8_t *buffer, size_t len) {
  cx_rng_no_throw(buffer, len);
  return buffer;
}
#endif

zxerr_t c_blake2b32_withpersonal(const uint8_t *person, const uint8_t *a,
                              uint32_t a_len, uint8_t *out) {
  if (person == NULL || a == NULL || out == NULL) {
    return zxerr_no_data;
  }
  cx_blake2b_t ctx = {0};
  CHECK_CX_OK(cx_blake2b_init2_no_throw(&ctx, 256, NULL, 0, (uint8_t *)person, 16));
  CHECK_CX_OK(cx_hash_no_throw(&ctx.header, CX_LAST, a, a_len, out, 256));
  return zxerr_ok;
};

zxerr_t c_blake2b64_withpersonal(const uint8_t *person, const uint8_t *a,
                              uint32_t a_len, uint8_t *out) {
  if (person == NULL || a == NULL || out == NULL) {
    return zxerr_no_data;
  }

  cx_blake2b_t ctx = {0};
  CHECK_CX_OK(cx_blake2b_init2_no_throw(&ctx, 512, NULL, 0, (uint8_t *)person, 16));
  CHECK_CX_OK(cx_hash_no_throw(&ctx.header, CX_LAST, a, a_len, out, 512));
  return zxerr_ok;
};

zxerr_t c_zcash_blake2b_redjubjub(const uint8_t *a, uint32_t a_len,
                               const uint8_t *b, uint32_t b_len, uint8_t *out) {
  if (a == NULL || b == NULL || out == NULL) {
    return zxerr_no_data;
  }

  cx_blake2b_t ctx = {0};
  CHECK_CX_OK(cx_blake2b_init2_no_throw(&ctx, 8 * CTX_REDJUBJUB_HASH_LEN, NULL, 0,(uint8_t *)CTX_REDJUBJUB, CTX_REDJUBJUB_LEN));
  CHECK_CX_OK(cx_hash_no_throw(&ctx.header, 0, a, a_len, NULL, 0));
  CHECK_CX_OK(cx_hash_no_throw(&ctx.header, CX_LAST, b, b_len, out, CTX_REDJUBJUB_HASH_LEN));
  return zxerr_ok;
}

zxerr_t c_zcash_blake2b_expand_seed(const uint8_t *a, uint32_t a_len,
                                 const uint8_t *b, uint32_t b_len, uint8_t *out) {
  if (a == NULL || b == NULL || out == NULL) {
    return zxerr_no_data;
  }

  cx_blake2b_t ctx = {0};
  CHECK_CX_OK(cx_blake2b_init2_no_throw(&ctx, 8 * CTX_EXPAND_SEED_HASH_LEN, NULL, 0,(uint8_t *)CTX_EXPAND_SEED, CTX_EXPAND_SEED_LEN));
  CHECK_CX_OK(cx_hash_no_throw(&ctx.header, 0, a, a_len, NULL, 0));
  CHECK_CX_OK(cx_hash_no_throw(&ctx.header, CX_LAST, b, b_len, out,CTX_EXPAND_SEED_HASH_LEN));
  return zxerr_ok;
}

zxerr_t c_zcash_blake2b_expand_vec_two(const uint8_t *a, uint32_t a_len,
                                    const uint8_t *b, uint32_t b_len,
                                    const uint8_t *c, uint32_t c_len,
                                    uint8_t *out) {
  if (a == NULL || b == NULL || c == NULL || out == NULL) {
    return zxerr_no_data;
  }

  cx_blake2b_t ctx = {0};
  CHECK_CX_OK(cx_blake2b_init2_no_throw(&ctx, 8 * CTX_EXPAND_SEED_HASH_LEN, NULL, 0, (uint8_t *)CTX_EXPAND_SEED, CTX_EXPAND_SEED_LEN));
  CHECK_CX_OK(cx_hash_no_throw(&ctx.header, 0, a, a_len, NULL, 0));
  CHECK_CX_OK(cx_hash_no_throw(&ctx.header, 0, b, b_len, NULL, 0));
  CHECK_CX_OK(cx_hash_no_throw(&ctx.header, CX_LAST, c, c_len, out, CTX_EXPAND_SEED_HASH_LEN));
  return zxerr_ok;
}

zxerr_t c_zcash_blake2b_expand_vec_four(const uint8_t *a, uint32_t a_len,
                                     const uint8_t *b, uint32_t b_len,
                                     const uint8_t *c, uint32_t c_len,
                                     const uint8_t *d, uint32_t d_len,
                                     const uint8_t *e, uint32_t e_len,
                                     uint8_t *out) {
  if (a == NULL || b == NULL || c == NULL || d == NULL || e == NULL || out == NULL) {
    return zxerr_no_data;
  }

  cx_blake2b_t ctx = {0};
  CHECK_CX_OK(cx_blake2b_init2_no_throw(&ctx, 8 * CTX_EXPAND_SEED_HASH_LEN, NULL, 0, (uint8_t *)CTX_EXPAND_SEED, CTX_EXPAND_SEED_LEN));
  CHECK_CX_OK(cx_hash_no_throw(&ctx.header, 0, a, a_len, NULL, 0));
  CHECK_CX_OK(cx_hash_no_throw(&ctx.header, 0, b, b_len, NULL, 0));
  CHECK_CX_OK(cx_hash_no_throw(&ctx.header, 0, c, c_len, NULL, 0));
  CHECK_CX_OK(cx_hash_no_throw(&ctx.header, 0, d, d_len, NULL, 0));
  CHECK_CX_OK(cx_hash_no_throw(&ctx.header, CX_LAST, e, e_len, out, CTX_EXPAND_SEED_HASH_LEN));
  return zxerr_ok;
}

zxerr_t zcash_blake2b_hash_two(const uint8_t *perso, uint32_t perso_len,
                            const uint8_t *a, uint32_t a_len, const uint8_t *b,
                            uint32_t b_len, uint8_t *out, uint32_t out_len) {
  if (perso == NULL || a == NULL || b == NULL || out == NULL) {
    return zxerr_no_data;
  }

  cx_blake2b_t zcashHashBlake2b = {0};
  CHECK_CX_OK(cx_blake2b_init2_no_throw(&zcashHashBlake2b, 8 * out_len, NULL, 0, (uint8_t *)perso, perso_len));
  CHECK_CX_OK(cx_hash_no_throw(&zcashHashBlake2b.header, 0, a, a_len, NULL, 0));
  CHECK_CX_OK(cx_hash_no_throw(&zcashHashBlake2b.header, CX_LAST, b, b_len, out, out_len));
  return zxerr_ok;
}

uint16_t fp_uint64_to_str(char *out, uint16_t outLen, const uint64_t value,
                          uint8_t decimals) {
  return fpuint64_to_str(out, outLen, value, decimals);
}

void check_canary() {}

void _zemu_log_stack(uint8_t *buffer) { zemu_log_stack((char *)buffer); }

void c_aes256_encryptblock(const uint8_t *key, const uint8_t *in,
                           uint8_t *out) {
  struct AES_ctx ctx;
  AES_init_ctx(&ctx, key);

  // encrypts in place, so we copy and encrypt
  MEMCPY(out, in, AES_BLOCKLEN);
  AES_ECB_encrypt(&ctx, out);
}

void c_jubjub_scalarmult(uint8_t *point, const uint8_t *scalar) {
  jubjub_extendedpoint p;
  jubjub_fq scal;
  MEMCPY(scal, scalar, JUBJUB_FIELD_BYTES);
  SWAP_ENDIAN_BYTES(scal);

  if (jubjub_extendedpoint_frombytes(&p, point) != zxerr_ok ||
      jubjub_extendedpoint_scalarmult(&p, scal) != zxerr_ok ||
      jubjub_extendedpoint_tobytes(point, &p) != zxerr_ok) {

    MEMZERO(point, JUBJUB_FIELD_BYTES);
  }
}

void c_jubjub_spending_base_scalarmult(uint8_t *point, const uint8_t *scalar) {
  jubjub_extendedpoint p;
  jubjub_fq scal;
  MEMCPY(scal, scalar, JUBJUB_FIELD_BYTES);
  SWAP_ENDIAN_BYTES(scal);
  MEMCPY(&p, &JUBJUB_GEN, sizeof(jubjub_extendedpoint));
  if (jubjub_extendedpoint_scalarmult(&p, scal) != zxerr_ok ||
      jubjub_extendedpoint_tobytes(point, &p) != zxerr_ok) {

    MEMZERO(point, JUBJUB_FIELD_BYTES);
  }
}
