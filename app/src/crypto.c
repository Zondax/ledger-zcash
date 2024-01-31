/*******************************************************************************
 *   (c) 2018 -2022 Zondax AG
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 ********************************************************************************/

#include "crypto.h"
#include "base58.h"
#include "bech32.h"
#include "chacha.h"
#include "coin.h"
#include "constants.h"
#include "index_NU5.h"
#include "index_sapling.h"
#include "lcx_ripemd160.h"
#include "nvdata.h"
#include "parser_common.h"
#include "parser_impl.h"
#include "rslib.h"
#include "sighash.h"
#include "txid.h"
#include "zip-0317.h"
#include "zxformat.h"
#include "zxmacros.h"

uint32_t hdPath[HDPATH_LEN_DEFAULT];

#define CHECK_ZXERROR_AND_CLEAN(CALL)                                          \
  do {                                                                         \
    zxerr_t __zxerror = CALL;                                                  \
    if (__zxerror != zxerr_ok) {                                               \
      MEMZERO(&tmp, sizeof(tmp));                                              \
      MEMZERO(buffer, bufferLen);                                              \
      return __zxerror;                                                        \
    }                                                                          \
  } while (0);

typedef enum {
  EXTRACT_SAPLING_E0 = 0xE0,
  EXTRACT_SAPLING_E1 = 0xE1,
  EXTRACT_SAPLING_E2 = 0xE2,
  EXTRACT_SAPLING_E3 = 0xE3,
  EXTRACT_SAPLING_E4 = 0xE4,
  EXTRACT_SAPLING_E5 = 0xE5,
  EXTRACT_SAPLING_E6 = 0xE6,
  EXTRACT_SAPLING_E7 = 0xE7,
  EXTRACT_SAPLING_E8 = 0xE8,
  EXTRACT_SAPLING_E9 = 0xE9,
  EXTRACT_SAPLING_EA = 0xEA,
  EXTRACT_SAPLING_EB = 0xEB,
  EXTRACT_SAPLING_EC = 0xEC,
  EXTRACT_SAPLING_ED = 0xED,
} extract_sapling_e;

#include "cx.h"

typedef struct {
  uint8_t publicKey[PK_LEN_SECP256K1];
  uint8_t address[50];
} __attribute__((packed)) answer_t;

zxerr_t ripemd160(uint8_t *in, uint16_t inLen, uint8_t *out) {
  if (in == NULL || out == NULL) {
    return zxerr_no_data;
  }

  cx_ripemd160_t rip160;
  cx_ripemd160_init(&rip160);
  const cx_err_t error = cx_hash_no_throw(&rip160.header, CX_LAST, in, inLen, out, CX_RIPEMD160_SIZE);

  return error == CX_OK ? zxerr_ok : zxerr_invalid_crypto_settings;
}

// According to 5.6 Encodings of Addresses and Keys
typedef struct {
  // [ADDRESS                              ]
  // [EXTENDED RIPEMD-160][Checksum 4-bytes]
  // [EXTENDED RIPEMD-160][Checksum-------------------------]
  // [version][RIPEMD-160]
  union {
    uint8_t address[VERSION_SIZE + CX_RIPEMD160_SIZE + CHECKSUM_SIZE];

    struct {
      uint8_t extended_ripe[VERSION_SIZE + CX_RIPEMD160_SIZE];
      uint8_t sha256_checksum[CX_SHA256_SIZE];
    };

    union {
      // [EXTENDED RIPEMD-160]
      // [version][RIPEMD-160]
      struct {
        uint8_t version[VERSION_SIZE];
        uint8_t ripe_sha256_pk[CX_RIPEMD160_SIZE];
      };
    };
  };

  // Temporary buffers
  union {
    uint8_t sha256_pk[CX_SHA256_SIZE];
    uint8_t sha256_extended_ripe[CX_SHA256_SIZE];
  };
} __attribute__((packed)) address_temp_t;

static zxerr_t crypto_extractPublicKey(uint8_t *pubKey, uint16_t pubKeyLen) {
  if (pubKey == NULL || pubKeyLen < PK_LEN_SECP256K1) {
    return zxerr_invalid_crypto_settings;
  }

  cx_ecfp_public_key_t cx_publicKey = {0};
  cx_ecfp_private_key_t cx_privateKey = {0};
  uint8_t privateKeyData[64] = {0};

  zxerr_t error = zxerr_unknown;
  CATCH_CXERROR(os_derive_bip32_no_throw(CX_CURVE_256K1, hdPath, HDPATH_LEN_DEFAULT, privateKeyData, NULL));
  CATCH_CXERROR(cx_ecfp_init_private_key_no_throw(CX_CURVE_256K1, privateKeyData, SK_SECP256K1_SIZE, &cx_privateKey));
  CATCH_CXERROR(cx_ecfp_init_public_key_no_throw(CX_CURVE_256K1, NULL, 0, &cx_publicKey));
  CATCH_CXERROR(cx_ecfp_generate_pair_no_throw(CX_CURVE_256K1, &cx_publicKey, &cx_privateKey, 1));

  cx_publicKey.W[0] = cx_publicKey.W[64] & 1 ? 0x03 : 0x02; // "Compress" public key in place
  memcpy(pubKey, cx_publicKey.W, PK_LEN_SECP256K1);
  error = zxerr_ok;

catch_cx_error:
  MEMZERO(&cx_privateKey, sizeof(cx_privateKey));
  MEMZERO(privateKeyData, sizeof(privateKeyData));

  if (error != zxerr_ok) {
    MEMZERO(pubKey, pubKeyLen);
  }

  return error;
}

// handleGetAddrSecp256K1
zxerr_t crypto_fillAddress_secp256k1(uint8_t *buffer, uint16_t buffer_len,
                                     uint16_t *replyLen) {
  if (buffer_len < sizeof(answer_t)) {
    return zxerr_unknown;
  }

  zemu_log_stack("crypto_fillAddress_secp256k1");

  *replyLen = 0;
  MEMZERO(buffer, buffer_len);
  answer_t *const answer = (answer_t *)buffer;

  CHECK_ZXERR(crypto_extractPublicKey(answer->publicKey,
                                      sizeof_field(answer_t, publicKey)));

  address_temp_t address_temp;

  // extended-ripemd-160 = [version][ripemd-160(sha256(pk))]
  address_temp.version[0] = VERSION_P2PKH >> 8;
  address_temp.version[1] = VERSION_P2PKH & 0xFF;
  cx_hash_sha256(answer->publicKey, PK_LEN_SECP256K1, address_temp.sha256_pk,
                 CX_SHA256_SIZE); // SHA256
  CHECK_ZXERR(ripemd160(address_temp.sha256_pk, CX_SHA256_SIZE,
                        address_temp.ripe_sha256_pk)); // RIPEMD-160

  // checksum = sha256(sha256(extended-ripe))
  cx_hash_sha256(address_temp.extended_ripe, CX_RIPEMD160_SIZE + VERSION_SIZE,
                 address_temp.sha256_extended_ripe, CX_SHA256_SIZE);
  cx_hash_sha256(address_temp.sha256_extended_ripe, CX_SHA256_SIZE,
                 address_temp.sha256_checksum, CX_SHA256_SIZE);

  // 7. 25 bytes BTC address = [extended ripemd-160][checksum]
  // Encode as base58
  size_t outLen = sizeof_field(answer_t, address);
  int err = encode_base58(address_temp.address,
                          VERSION_SIZE + CX_RIPEMD160_SIZE + CHECKSUM_SIZE,
                          answer->address, &outLen);
  if (err != 0) {
    return zxerr_unknown;
  }
  *replyLen = PK_LEN_SECP256K1 + outLen;
  return zxerr_ok;
}

zxerr_t crypto_fillSaplingSeed(uint8_t *sk) {
  zemu_log_stack("crypto_fillSaplingSeed");

  // Generate randomness using a fixed path related to the device mnemonic
  const uint32_t path[HDPATH_LEN_DEFAULT] = {
      0x8000002c, 0x80000085, MASK_HARDENED, MASK_HARDENED, MASK_HARDENED,
  };
  MEMZERO(sk, ED25519_SK_SIZE);

  zxerr_t error = zxerr_unknown;
  CATCH_CXERROR(os_derive_bip32_with_seed_no_throw(HDW_NORMAL, CX_CURVE_Ed25519,
                                                   path, HDPATH_LEN_DEFAULT, sk,
                                                   NULL, NULL, 0));
  error = zxerr_ok;

catch_cx_error:
  if (error != zxerr_ok) {
    MEMZERO(sk, 64);
  }

  return error;
}

// handleInitTX step 1/2
zxerr_t crypto_extracttx_sapling(uint8_t *buffer, uint16_t bufferLen,
                                 const uint8_t *txdata,
                                 const uint16_t txdatalen) {
  zemu_log_stack("crypto_extracttx_sapling");
  MEMZERO(buffer, bufferLen);
  uint8_t t_in_len = *txdata;
  uint8_t t_out_len = *(txdata + 1);
  uint8_t spend_len = *(txdata + 2);
  uint8_t output_len = *(txdata + 3);

  transaction_reset();

  if ((spend_len > 0 && output_len < 2) ||
      (spend_len == 0 && output_len == 1)) {
    return (zxerr_t)EXTRACT_SAPLING_E0;
  }

  if (txdatalen < 4 || txdatalen - 4 != t_in_len * T_IN_INPUT_LEN +
                                            t_out_len * T_OUT_INPUT_LEN +
                                            spend_len * SPEND_INPUT_LEN +
                                            output_len * OUTPUT_INPUT_LEN) {
    return (zxerr_t)EXTRACT_SAPLING_E1;
  }

  if (t_in_len == 0 && t_out_len == 0 && spend_len == 0 && output_len == 0) {
    return (zxerr_t)EXTRACT_SAPLING_E2;
  }

  uint8_t *start = (uint8_t *)txdata;
  start += 4;

  parser_context_t pars_ctx;
  parser_error_t pars_err;

  for (int i = 0; i < t_in_len; i++) {
    uint32_t *path = (uint32_t *)(start + INDEX_INPUT_TIN_PATH);
    uint8_t *script = (uint8_t *)(start + INDEX_INPUT_TIN_SCRIPT);

    pars_ctx.offset = 0;
    pars_ctx.buffer = start + INDEX_INPUT_TIN_VALUE;
    pars_ctx.bufferLen = 8;
    uint64_t v = 0;
    pars_err = _readUInt64(&pars_ctx, &v);
    if (pars_err != parser_ok) {
      return (zxerr_t)EXTRACT_SAPLING_E3;
    }
    zxerr_t err = t_inlist_append_item(path, script, v);
    if (err != zxerr_ok) {
      return (zxerr_t)EXTRACT_SAPLING_E4;
    }
    start += T_IN_INPUT_LEN;
  }

  for (int i = 0; i < t_out_len; i++) {
    uint8_t *addr = (uint8_t *)(start + INDEX_INPUT_TOUT_ADDR);
    pars_ctx.offset = 0;
    pars_ctx.buffer = start + INDEX_INPUT_TOUT_VALUE;
    pars_ctx.bufferLen = 8;
    uint64_t v = 0;
    pars_err = _readUInt64(&pars_ctx, &v);
    if (pars_err != parser_ok) {
      return (zxerr_t)EXTRACT_SAPLING_E5;
    }
    zxerr_t err = t_outlist_append_item(addr, v);
    if (err != zxerr_ok) {
      return (zxerr_t)EXTRACT_SAPLING_E6;
    }
    start += T_OUT_INPUT_LEN;
  }

  for (int i = 0; i < spend_len; i++) {
    pars_ctx.offset = 0;
    pars_ctx.buffer = start + INDEX_INPUT_SPENDPOS;
    pars_ctx.bufferLen = 4;
    uint32_t p = 0;
    pars_err = _readUInt32(&pars_ctx, &p);
    if (pars_err != parser_ok) {
      return (zxerr_t)EXTRACT_SAPLING_E7;
    }

    pars_ctx.offset = 0;
    pars_ctx.buffer = start + INDEX_INPUT_INPUTVALUE;
    pars_ctx.bufferLen = 8;
    uint64_t v = 0;
    pars_err = _readUInt64(&pars_ctx, &v);
    if (pars_err != parser_ok) {
      return (zxerr_t)EXTRACT_SAPLING_E8;
    }

    uint8_t *div = start + INDEX_INPUT_INPUTDIV;
    uint8_t *pkd = start + INDEX_INPUT_INPUTPKD;
    uint8_t rnd1[RND_SIZE];
    uint8_t rnd2[RND_SIZE];
    random_fr(rnd1);
    random_fr(rnd2);

    zxerr_t err = spendlist_append_item(p, v, div, pkd, rnd1, rnd2);
    if (err != zxerr_ok) {
      return (zxerr_t)EXTRACT_SAPLING_E9;
    }
    start += SPEND_INPUT_LEN;
  }

  for (int i = 0; i < output_len; i++) {
    uint8_t *div = start + INDEX_INPUT_OUTPUTDIV;
    uint8_t *pkd = start + INDEX_INPUT_OUTPUTPKD;

    pars_ctx.offset = 0;
    pars_ctx.buffer = start + INDEX_INPUT_OUTPUTVALUE;
    pars_ctx.bufferLen = 8;
    uint64_t v = 0;
    pars_err = _readUInt64(&pars_ctx, &v);
    if (pars_err != parser_ok) {
      return (zxerr_t)EXTRACT_SAPLING_EA;
    }

    uint8_t *memotype = start + INDEX_INPUT_OUTPUTMEMO;
    uint8_t *ovk = start + INDEX_INPUT_OUTPUTOVK;

    if (ovk[0] != 0x00 && ovk[0] != 0x01) {
      return (zxerr_t)EXTRACT_SAPLING_EB;
    }

    uint8_t hash_seed[OVK_SET_SIZE] = {0};
    if (ovk[0] == 0x00) {
      cx_rng(hash_seed + 1, OVK_SIZE);
      ovk = hash_seed;
    }

    uint8_t rnd1[RND_SIZE] = {0};
    uint8_t rnd2[RND_SIZE] = {0};
    random_fr(rnd1);
    cx_rng(rnd2, RND_SIZE);
    zxerr_t err = outputlist_append_item(div, pkd, v, *memotype, ovk, rnd1, rnd2);
    if (err != zxerr_ok) {
      return (zxerr_t)EXTRACT_SAPLING_EC;
    }
    start += OUTPUT_INPUT_LEN;
  }

  uint64_t tx_value__flash = get_totalvalue();
#ifdef HAVE_ZIP0317
  if (tx_value__flash != zip_0317(t_in_len, t_out_len, spend_len, output_len)) {
    return (zxerr_t)EXTRACT_SAPLING_ED;
  }
#else
  if (tx_value__flash != 1000) {
    return (zxerr_t)EXTRACT_SAPLING_ED;
  }
#endif

  if (spend_len > 0) {
    set_state(STATE_PROCESSED_INPUTS); // need both spend info and output info
                                       // (as spend > 0 => output >= 2)
  } else if (output_len > 0) {
    set_state(
        STATE_PROCESSED_SPEND_EXTRACTIONS); // we can have shielded outputs only
  } else {
    set_state(STATE_PROCESSED_ALL_EXTRACTIONS); // We can have transparent
                                                // inputs/outputs only
  }

  return zxerr_ok; // some code for all_good
}

typedef struct {
  union {
    // STEP 1
    struct {
      uint8_t zip32_seed[ZIP32_SEED_SIZE];
      uint8_t sk[ED25519_SK_SIZE];
    } step1;

    struct {
      uint8_t ask[ASK_SIZE];
      uint8_t nsk[NSK_SIZE];
    } step2;
  };
} tmp_spendinfo_s;

// handleExtractSpendData
zxerr_t crypto_extract_spend_proofkeyandrnd(uint8_t *buffer,
                                            uint16_t bufferLen) {
  if (!spendlist_more_extract()) {
    return zxerr_unknown;
  }

  if (get_state() != STATE_PROCESSED_INPUTS) {
    return zxerr_unknown;
  }

  uint8_t *out = (uint8_t *)buffer;
  MEMZERO(out, bufferLen);

  const spend_item_t *next = spendlist_extract_next();
  if (next == NULL) {
    return zxerr_unknown;
  }

  tmp_spendinfo_s tmp = {0};

  CHECK_ZXERROR_AND_CLEAN(crypto_fillSaplingSeed(tmp.step1.zip32_seed))
  CHECK_APP_CANARY()

  // Gets ak and nsk
  zip32_child_proof_key(tmp.step1.zip32_seed, out, out + AK_SIZE, next->path);
  CHECK_APP_CANARY()

  MEMZERO(&tmp, sizeof(tmp_spendinfo_s));

  MEMCPY(out + AK_SIZE + NSK_SIZE, next->rcmvalue, RCM_SIZE);
  MEMCPY(out + AK_SIZE + NSK_SIZE + RCM_SIZE, next->alpha, ALPHA_SIZE);

  if (!spendlist_more_extract()) {
    set_state(STATE_PROCESSED_SPEND_EXTRACTIONS);
  }

  return zxerr_ok;
}

// handleExtractOutputData
zxerr_t crypto_extract_output_rnd(uint8_t *buffer, uint16_t bufferLen,
                                  uint16_t *replyLen) {
  if (!outputlist_more_extract()) {
    return zxerr_unknown;
  }

  if (get_state() != STATE_PROCESSED_SPEND_EXTRACTIONS) {
    return zxerr_unknown;
  }

  uint8_t *out = (uint8_t *)buffer;
  MEMZERO(out, bufferLen);

  const output_item_t *next = outputlist_extract_next();
  if (next == NULL) {
    return zxerr_unknown;
  }
  MEMCPY(out, next->rcmvalue, RCM_V_SIZE);
  MEMCPY(out + RCM_V_SIZE, next->rseed, RSEED_SIZE);

  if (next->ovk[0] == 0x00) {
    MEMCPY(out + RCM_V_SIZE + RSEED_SIZE, next->ovk + 1, OVK_SIZE);
    *replyLen = RCM_V_SIZE + RSEED_SIZE + OVK_SIZE;
  } else {
    *replyLen = RCM_V_SIZE + RSEED_SIZE;
  }

  if (!outputlist_more_extract()) {
    set_state(STATE_PROCESSED_ALL_EXTRACTIONS);
  }
  return zxerr_ok;
}

// handleCheckandSign step 1/11
zxerr_t crypto_check_prevouts(uint8_t *buffer, uint16_t bufferLen,
                              const uint8_t *txdata, const uint8_t tx_version) {
  zemu_log_stack("crypto_check_prevouts");
  MEMZERO(buffer, bufferLen);

  if (get_state() != STATE_CHECKING_ALL_TXDATA) {
    return zxerr_unknown;
  }

  uint8_t hash[HASH_SIZE] = {0};
  size_t prevouts_hash_offset = 0;
  if (tx_version == TX_VERSION_SAPLING) {
    sapling_transparent_prevouts_hash(txdata, hash);
    prevouts_hash_offset = SAPLING_INDEX_HASH_PREVOUTSHASH;
  } else if (tx_version == TX_VERSION_NU5) {
    nu5_transparent_prevouts_hash(txdata, hash);
    prevouts_hash_offset = NU5_INDEX_HASH_PREVOUTSHASH;
  } else {
    return zxerr_unknown;
  }

  if (MEMCMP(hash, txdata + start_sighashdata() + prevouts_hash_offset,
             HASH_SIZE) != 0) {
    return zxerr_unknown;
  }
  return zxerr_ok;
}

// handleCheckandSign step 2/11
zxerr_t crypto_check_sequence(uint8_t *buffer, uint16_t bufferLen,
                              const uint8_t *txdata, const uint8_t tx_version) {
  zemu_log_stack("crypto_check_sequence");
  MEMZERO(buffer, bufferLen);

  if (get_state() != STATE_CHECKING_ALL_TXDATA) {
    return zxerr_unknown;
  }

  uint8_t hash[HASH_SIZE] = {0};
  size_t sequence_hash_offset = 0;

  if (tx_version == TX_VERSION_SAPLING) {
    sapling_transparent_sequence_hash(txdata, hash);
    sequence_hash_offset = SAPLING_INDEX_HASH_SEQUENCEHASH;
  } else if (tx_version == TX_VERSION_NU5) {
    nu5_transparent_sequence_hash(txdata, hash);
    sequence_hash_offset = NU5_INDEX_HASH_SEQUENCEHASH;
  } else {
    return zxerr_unknown;
  }

  if (MEMCMP(hash, txdata + start_sighashdata() + sequence_hash_offset,
             HASH_SIZE) != 0) {
    return zxerr_unknown;
  }
  return zxerr_ok;
}

// handleCheckandSign step 3/11
zxerr_t crypto_check_outputs(uint8_t *buffer, uint16_t bufferLen,
                             const uint8_t *txdata, const uint16_t txdatalen,
                             const uint8_t tx_version) {
  zemu_log_stack("crypto_check_outputs");
  if (start_sighashdata() + SAPLING_LENGTH_HASH_DATA != txdatalen) {
    return zxerr_unknown;
  }

  if (get_state() != STATE_CHECKING_ALL_TXDATA) {
    return zxerr_unknown;
  }

  MEMZERO(buffer, bufferLen);
  uint8_t hash[HASH_SIZE] = {0};
  size_t sapling_outputs_hash_offset = 0;

  if (tx_version == TX_VERSION_SAPLING) {
    v4_transparent_outputs_hash(hash);
    sapling_outputs_hash_offset = SAPLING_INDEX_HASH_OUTPUTSHASH;
  } else if (tx_version == TX_VERSION_NU5) {
    nu5_transparent_outputs_hash(hash);
    sapling_outputs_hash_offset = NU5_INDEX_HASH_OUTPUTSHASH;
  } else {
    return zxerr_unknown;
  }

  if (MEMCMP(hash, txdata + start_sighashdata() + sapling_outputs_hash_offset,
             HASH_SIZE) != 0) {
    return zxerr_unknown;
  }
  return zxerr_ok;
}

// handleCheckandSign step 4/11
zxerr_t crypto_check_joinsplits(uint8_t *buffer, uint16_t bufferLen,
                                const uint8_t *txdata,
                                const uint8_t tx_version) {
  if (tx_version == TX_VERSION_SAPLING) {
    zemu_log_stack("crypto_check_joinsplits");
    MEMZERO(buffer, bufferLen);

    if (get_state() != STATE_CHECKING_ALL_TXDATA) {
      return zxerr_unknown;
    }

    uint8_t hash[HASH_SIZE] = {0};
    if (MEMCMP(hash,
               txdata + start_sighashdata() + SAPLING_INDEX_HASH_JOINSPLITSHASH,
               HASH_SIZE) != 0) {
      return zxerr_unknown;
    }
  }
  return zxerr_ok;
}

// handleCheckandSign step 5/11
zxerr_t crypto_check_valuebalance(uint8_t *buffer, uint16_t bufferLen,
                                  const uint8_t *txdata,
                                  const uint8_t tx_version) {
  zemu_log_stack("crypto_check_valuebalance");
  MEMZERO(buffer, bufferLen);

  if (get_state() != STATE_CHECKING_ALL_TXDATA) {
    return zxerr_unknown;
  }
  parser_context_t pars_ctx;
  parser_error_t pars_err;
  size_t value_balance_offset = 0;
  if (tx_version == TX_VERSION_SAPLING) {
    value_balance_offset = SAPLING_INDEX_HASH_VALUEBALANCE;
  } else if (tx_version == TX_VERSION_NU5) {
    value_balance_offset = NU5_INDEX_HASH_VALUEBALANCE;
  } else {
    return zxerr_unknown;
  }
  pars_ctx.offset = 0;
  pars_ctx.buffer = txdata + start_sighashdata() + value_balance_offset;
  pars_ctx.bufferLen = 8;
  int64_t v = 0;
  pars_err = _readInt64(&pars_ctx, &v);
  if (pars_err != parser_ok) {
    return 0;
  }

  int64_t valuebalance = get_valuebalance();
  int64_t *value_flash = (int64_t *)&valuebalance;
  if (MEMCMP(&v, value_flash, 8) != 0) {
    return zxerr_unknown;
  }
  return zxerr_ok;
}

typedef struct {
  union {
    struct {
      uint8_t pedersen_input[PEDERSEN_INPUT_SIZE];
    };
    struct {
      uint8_t pedersen_hash[HASH_SIZE];
    };

    struct {
      uint8_t ncm_full[NOTE_COMMITMENT_SIZE];
    };
    struct {
      uint8_t nf[NULLIFIER_SIZE];
    };

    struct {
      uint8_t spend_hash[HASH_SIZE];
    };
  };
} tmp_buf_checkspend;

typedef struct {
  union {
    // STEP 1
    struct {
      uint8_t zip32_seed[ZIP32_SEED_SIZE];
    } step1;

    struct {
      uint8_t ask[ASK_SIZE];
      uint8_t nsk[NSK_SIZE];
    } step2;

    struct {
      uint8_t rk[PUB_KEY_SIZE];
      uint8_t nsk[NSK_SIZE];
    } step3;

    struct {
      uint8_t cv[VALUE_COMMITMENT_SIZE];
      uint8_t nsk[NSK_SIZE];
    } step4;
  };
} tmp_checkspend;

// handleCheckandSign step 6/11
zxerr_t crypto_checkspend_sapling(uint8_t *buffer, uint16_t bufferLen,
                                  const uint8_t *txdata,
                                  const uint16_t txdatalen,
                                  const uint8_t tx_version) {
  zemu_log_stack("crypto_checkspend_sapling");
  MEMZERO(buffer, bufferLen);

  const size_t length_hash_data = (tx_version == TX_VERSION_SAPLING)
                                      ? SAPLING_LENGTH_HASH_DATA
                                      : NU5_LENGTH_HASH_DATA;

  if (length_t_in_data() + length_spenddata() + length_outputdata() +
          length_hash_data !=
      txdatalen) {
    return zxerr_unknown;
  }

  if (get_state() != STATE_CHECKING_ALL_TXDATA) {
    return zxerr_unknown;
  }

  uint8_t *out = buffer;
  tmp_buf_checkspend *const tmp_buf = (tmp_buf_checkspend *)buffer;

  uint8_t *start_spenddata =
      (uint8_t *)(txdata + length_t_in_data() + length_spend_old_data());
  uint8_t *start_spendolddata = (uint8_t *)(txdata + length_t_in_data());

  tmp_checkspend tmp = {0};

  // the path in zip32 is [FIRST_VALUE, COIN_TYPE, p] where p is u32 and last
  // part of hdPath
  const uint8_t spendListSize = spendlist_len();

  for (uint8_t i = 0; i < spendListSize; i++) {
    CHECK_ZXERROR_AND_CLEAN(crypto_fillSaplingSeed(tmp.step1.zip32_seed))
    const spend_item_t *item = spendlist_retrieve_item(i);
    if (item == NULL) {
      return zxerr_unknown;
    }

    // we later need nsk
    zip32_child_ask_nsk(tmp.step1.zip32_seed, tmp.step2.ask, tmp.step2.nsk,
                        item->path);
    get_rk(tmp.step2.ask, (uint8_t *)item->alpha, tmp.step3.rk);
    if (MEMCMP(tmp.step3.rk,
               start_spenddata + INDEX_SPEND_RK + i * SPEND_TX_LEN,
               PUB_KEY_SIZE) != 0) {
      CHECK_ZXERROR_AND_CLEAN(zxerr_unknown)
    }

    // step4.cv = step3.rk.
    compute_value_commitment(item->value, item->rcmvalue, tmp.step4.cv);
    if (MEMCMP(tmp.step4.cv,
               start_spenddata + INDEX_SPEND_VALUECMT + i * SPEND_TX_LEN,
               VALUE_COMMITMENT_SIZE) != 0) {
      CHECK_ZXERROR_AND_CLEAN(zxerr_unknown)
    }

    compute_note_commitment_fullpoint(tmp_buf->pedersen_hash,
                                      start_spendolddata + INDEX_SPEND_OLD_RCM +
                                          i * SPEND_OLD_TX_LEN,
                                      item->value, item->div, item->pkd);

    uint64_t notepos = 0;
    {
      parser_context_t pars_ctx;
      parser_error_t pars_err;

      pars_ctx.offset = 0;
      pars_ctx.buffer =
          start_spendolddata + INDEX_SPEND_OLD_NOTEPOS + i * SPEND_OLD_TX_LEN;
      pars_ctx.bufferLen = 8;
      pars_err = _readUInt64(&pars_ctx, &notepos);
      if (pars_err != parser_ok) {
        CHECK_ZXERROR_AND_CLEAN(zxerr_unknown)
      }
    }
    compute_nullifier(tmp_buf->ncm_full, notepos, tmp.step4.nsk, tmp_buf->nf);
    if (MEMCMP(tmp_buf->nf, start_spenddata + INDEX_SPEND_NF + i * SPEND_TX_LEN,
               NULLIFIER_SIZE) != 0) {
      CHECK_ZXERROR_AND_CLEAN(zxerr_unknown)
    }

    MEMZERO(out, bufferLen);
    MEMZERO(&tmp, sizeof(tmp_checkspend));
  }

  size_t sapling_spend_offset = 0;
  if (tx_version == TX_VERSION_SAPLING) {
    if (spendlist_len() > 0) {
      shielded_spend_hash(start_spenddata, length_spend_new_data(),
                          tmp_buf->spend_hash);
    }
    sapling_spend_offset = SAPLING_INDEX_HASH_SHIELDEDSPENDHASH;
  } else if (tx_version == TX_VERSION_NU5) {
    nu5_hash_sapling_spends(start_spenddata, tmp_buf->spend_hash);
    sapling_spend_offset = NU5_INDEX_HASH_SHIELDEDSPENDHASH;
  } else {
    CHECK_ZXERROR_AND_CLEAN(zxerr_unknown)
  }

  if (MEMCMP(tmp_buf->spend_hash,
             txdata + start_sighashdata() + sapling_spend_offset,
             HASH_SIZE) != 0) {
    CHECK_ZXERROR_AND_CLEAN(zxerr_unknown)
  }
  MEMZERO(out, bufferLen);

  return zxerr_ok; // or some code for ok
}

typedef struct {
  uint8_t shielded_output_hash[HASH_SIZE];
} tmp_buf_checkoutput;

typedef struct {
  union {
    struct {
      uint8_t gd[GD_SIZE];   // computed from receiver diversifier
      uint8_t pkd[PKD_SIZE]; // get this from host and show on screen for
                             // verification
    } step2;

    struct {
      uint8_t pedersen_input[PEDERSEN_INPUT_SIZE];
    } step3;

    struct {
      uint8_t notecommitment[NOTE_COMMITMENT_SIZE];
      uint8_t valuecommitment[VALUE_COMMITMENT_SIZE];
    } step4;
  };
} tmp_checkoutput;

// handleCheckandSign step 7/11
zxerr_t crypto_checkoutput_sapling(uint8_t *buffer, uint16_t bufferLen,
                                   const uint8_t *txdata,
                                   const uint16_t txdatalen,
                                   const uint8_t tx_version) {
  zemu_log_stack("crypto_checkoutput_sapling");
  MEMZERO(buffer, bufferLen);

  if (get_state() != STATE_CHECKING_ALL_TXDATA) {
    return zxerr_unknown;
  }

  const size_t length_hash_data = (tx_version == TX_VERSION_SAPLING)
                                      ? SAPLING_LENGTH_HASH_DATA
                                      : NU5_LENGTH_HASH_DATA;
  if (length_t_in_data() + length_spenddata() + length_outputdata() +
          length_hash_data !=
      txdatalen) {
    return zxerr_unknown;
  }

  const uint8_t *start_outputdata =
      (uint8_t *)(txdata + length_t_in_data() + length_spenddata());

  zemu_log_stack("crypto_checkoutput_sapling");

  tmp_checkoutput ncm = {0};

  uint8_t rcm[RCM_SIZE] = {0};

  // the path in zip32 is [FIRST_VALUE, COIN_TYPE, p] where p is u32 and last
  // part of hdPath
  const uint8_t outputListLen = outputlist_len();
  for (uint8_t i = 0; i < outputListLen; i++) {
    const output_item_t *item = outputlist_retrieve_item(i);
    if (item == NULL) {
      MEMZERO(&ncm, sizeof(tmp_checkoutput));
      return zxerr_unknown;
    }

    rseed_get_rcm(item->rseed, rcm);
    compute_note_commitment(ncm.step4.notecommitment, rcm, item->value,
                            item->div, item->pkd);
    compute_value_commitment(item->value, item->rcmvalue,
                             ncm.step4.valuecommitment);

    if (MEMCMP(ncm.step4.valuecommitment,
               start_outputdata + INDEX_OUTPUT_VALUECMT + i * OUTPUT_TX_LEN,
               VALUE_COMMITMENT_SIZE) != 0) {
      MEMZERO(&ncm, sizeof(tmp_checkoutput));
      return zxerr_unknown;
    }

    if (MEMCMP(ncm.step4.notecommitment,
               start_outputdata + INDEX_OUTPUT_NOTECMT + i * OUTPUT_TX_LEN,
               NOTE_COMMITMENT_SIZE) != 0) {
      MEMZERO(&ncm, sizeof(tmp_checkoutput));
      return zxerr_unknown;
    }

    MEMZERO(&ncm, sizeof(tmp_checkoutput));
  }

  tmp_buf_checkoutput *const tmp_buf = (tmp_buf_checkoutput *)buffer;

  size_t sapling_output_offset = 0;
  if (tx_version == TX_VERSION_SAPLING) {
    if (outputlist_len() > 0) {
      shielded_output_hash(start_outputdata, length_outputdata(),
                           tmp_buf->shielded_output_hash);
    }
    sapling_output_offset = SAPLING_INDEX_HASH_SHIELDEDOUTPUTHASH;
  } else if (tx_version == TX_VERSION_NU5) {
    nu5_hash_sapling_outputs(start_outputdata, tmp_buf->shielded_output_hash);
    sapling_output_offset = NU5_INDEX_HASH_SHIELDEDOUTPUTHASH;
  } else {
    return zxerr_unknown;
  }

  if (MEMCMP(tmp_buf->shielded_output_hash,
             txdata + start_sighashdata() + sapling_output_offset,
             HASH_SIZE) != 0) {
    return zxerr_unknown;
  }

  return zxerr_ok; // or some code for ok
}

typedef struct {
  union {
    // STEP 1
    struct { // MAX SIZE --> 160
      uint8_t dummy[MAX_SIZE - EPK_SIZE - ESK_SIZE];
      uint8_t epk[EPK_SIZE]; // computed from receiver diversifier
      uint8_t esk[ESK_SIZE];
    } step1;

    struct {
      uint8_t chachanonce[CHACHA_NONCE_SIZE];
      uint8_t compactout[COMPACT_OUT_SIZE];
      uint8_t sharedkey[SHARED_KEY_SIZE];
      uint8_t epk[EPK_SIZE];
      uint8_t esk[ESK_SIZE];
    } step2;

    struct {
      uint8_t dummy[MAX_SIZE - OVK_SIZE - VALUE_COMMITMENT_SIZE -
                    NOTE_COMMITMENT_SIZE - EPK_SIZE - ESK_SIZE];
      uint8_t ovk[OVK_SIZE];
      uint8_t valuecmt[VALUE_COMMITMENT_SIZE];
      uint8_t notecmt[NOTE_COMMITMENT_SIZE];
      uint8_t epk[EPK_SIZE];
      uint8_t esk[ESK_SIZE];
    } step3;

    struct {
      uint8_t dummy[MAX_SIZE - PRF_INPUT_SIZE - ESK_SIZE];
      uint8_t prfinput[PRF_INPUT_SIZE];
      uint8_t esk[ESK_SIZE];
    } step4;

    struct {
      uint8_t outkey[OUT_KEY_SIZE];
      uint8_t dummy[MAX_SIZE - OUT_KEY_SIZE - PKD_SIZE - ESK_SIZE];
      uint8_t pkd[PKD_SIZE];
      uint8_t esk[ESK_SIZE];
    } step5;

    struct {
      uint8_t outkey[OUT_KEY_SIZE];
      uint8_t
          dummy[MAX_SIZE - OUT_KEY_SIZE - ENC_CIPHER_SIZE - CHACHA_NONCE_SIZE];
      uint8_t chachanonce[CHACHA_NONCE_SIZE];
      uint8_t encciph[ENC_CIPHER_SIZE];
    } step6;

    struct {
      uint8_t hashseed[OVK_SET_SIZE];
      uint8_t outkey[OUT_KEY_SIZE];
      uint8_t encciph_part1[ENC_CIPHER_HALVE_SIZE];
      uint8_t encciph_part2[ENC_CIPHER_HALVE_SIZE];
      uint8_t chachanonce[CHACHA_NONCE_SIZE];
    } step3b;
    struct {
      uint8_t hashseed[OVK_SET_SIZE];
      uint8_t outkey[OUT_KEY_SIZE];
      uint8_t encciph[ENC_CIPHER_SIZE];
      uint8_t chachanonce[CHACHA_NONCE_SIZE];
    } step4b;
  };
} tmp_enc;

// handleCheckandSign step 8/11
zxerr_t crypto_checkencryptions_sapling(uint8_t *buffer, uint16_t bufferLen,
                                        const uint8_t *txdata) {
  zemu_log_stack("crypto_checkencryptions_sapling");
  MEMZERO(buffer, bufferLen);
  tmp_enc *tmp = (tmp_enc *)buffer;

  const uint8_t *start_outputdata =
      (uint8_t *)(txdata + length_t_in_data() + length_spenddata());

  // the path in zip32 is [FIRST_VALUE, COIN_TYPE, p] where p is u32 and last
  // part of hdPath
  for (uint8_t i = 0; i < outputlist_len(); i++) {
    // retrieve info on list of outputs stored in flash
    const output_item_t *item = outputlist_retrieve_item(i);
    if (item == NULL) {
      return zxerr_unknown;
    }
    // compute random ephemeral private and public keys (esk,epk) from seed and
    // diversifier
    rseed_get_esk_epk(item->rseed, (uint8_t *)item->div, tmp->step1.esk,
                      tmp->step1.epk);
    CHECK_APP_CANARY()

    // compare the computed epk to that provided in the transaction data
    if (MEMCMP(tmp->step1.epk,
               start_outputdata + INDEX_OUTPUT_EPK + i * OUTPUT_TX_LEN,
               EPK_SIZE) != 0) {
      return zxerr_unknown;
    }

    // get shared key (used as encryption key) from esk, epk and pkd
    ka_to_key(tmp->step1.esk, (uint8_t *)item->pkd, tmp->step1.epk,
              tmp->step2.sharedkey);
    CHECK_APP_CANARY()
    // encode (div, value rseed and memotype) into step2.compactout ready to be
    // encrypted
    prepare_enccompact_input((uint8_t *)item->div, item->value,
                             (uint8_t *)item->rseed, item->memotype,
                             tmp->step2.compactout);
    CHECK_APP_CANARY()
    MEMZERO(tmp->step2.chachanonce, CHACHA_NONCE_SIZE);
    // encrypt the previously obtained encoding, and store it in
    // step2.compactoutput (reusing the same memory for input and output)
    chacha(tmp->step2.compactout, tmp->step2.compactout, COMPACT_OUT_SIZE,
           tmp->step2.sharedkey, tmp->step2.chachanonce, 1);
    CHECK_APP_CANARY()
    // check that the computed encryption is the same as that provided in the
    // transaction data
    if (MEMCMP(tmp->step2.compactout,
               start_outputdata + INDEX_OUTPUT_ENC + i * OUTPUT_TX_LEN,
               COMPACT_OUT_SIZE) != 0) {
      return zxerr_unknown;
    }

    // if an ovk was provided
    if (item->ovk[0] != 0x00) {
      // copy ovk, the value commitment and note-commitment from flash memory
      // and transaction to local tmp structure so as to hash
      MEMCPY(tmp->step3.ovk, item->ovk + 1, OVK_SIZE);
      MEMCPY(tmp->step3.valuecmt,
             start_outputdata + INDEX_OUTPUT_VALUECMT + i * OUTPUT_TX_LEN,
             VALUE_COMMITMENT_SIZE);
      MEMCPY(tmp->step3.notecmt,
             start_outputdata + INDEX_OUTPUT_NOTECMT + i * OUTPUT_TX_LEN,
             NOTE_COMMITMENT_SIZE);
      // Note that tmp->step4.prfinput is the same memory chunk as the
      // concatenation of tmp->step3.ovk || tmp->step3.valuecmt ||
      // tmp->step3.notecmt || tmp->step3.epk so next we hash that
      // concatenation, and store hash in tmp->step5.outkey
      blake2b_prf(tmp->step4.prfinput, tmp->step5.outkey);
      CHECK_APP_CANARY()

      // get pkd from flash memory, store it in tmp->step5.pkd
      MEMCPY(tmp->step5.pkd, item->pkd, PKD_SIZE);

      MEMZERO(tmp->step6.chachanonce, CHACHA_NONCE_SIZE);

      // tmp->step6.encciph = tmp->step5.pkd || tmp->step5.esk
      // encrypt that, using as encryption key the output of the blake2b PRF
      // store resulting ciphertext in tmp->step6.encciph
      chacha(tmp->step6.encciph, tmp->step6.encciph, ENC_CIPHER_SIZE,
             tmp->step6.outkey, tmp->step6.chachanonce, 1);
      CHECK_APP_CANARY()

      // check that the computed encryption is the same as that provided in the
      // transaction data
      if (MEMCMP(tmp->step6.encciph,
                 start_outputdata + INDEX_OUTPUT_OUT + i * OUTPUT_TX_LEN,
                 ENC_CIPHER_SIZE) != 0) {
        return zxerr_unknown;
      }

      // if no ovk was provided
    } else {
      // copy the contents of flash memory for ovk, and hash it. This hash will
      // be the encryption key
      MEMCPY(tmp->step3b.hashseed, item->ovk, OVK_SET_SIZE);
      cx_hash_sha256(tmp->step3b.hashseed, OVK_SET_SIZE, tmp->step3b.outkey,
                     CX_SHA256_SIZE);
      // replace the first 0x00 of the copied ovk with 0x01, hash again, this
      // will be the first half of the plaintext to encrypt
      tmp->step3b.hashseed[0] = 0x01;
      cx_hash_sha256(tmp->step3b.hashseed, OVK_SET_SIZE,
                     tmp->step3b.encciph_part1, CX_SHA256_SIZE);
      // replace the first 0x01 of the copied ovk with 0x02, hash again, this
      // will be the second half of the plaintext to encrypt
      tmp->step3b.hashseed[0] = 0x02;
      cx_hash_sha256(tmp->step3b.hashseed, OVK_SET_SIZE,
                     tmp->step3b.encciph_part2, CX_SHA256_SIZE);
      MEMZERO(tmp->step3b.chachanonce, CHACHA_NONCE_SIZE);
      // tmp->step4b.encciph = tmp->step3b.encciph_part1 ||
      // tmp->step3b.encciph_part2 encrypt and compare computed encryption to
      // that provided in the transaction data
      chacha(tmp->step4b.encciph, tmp->step4b.encciph, ENC_CIPHER_SIZE,
             tmp->step4b.outkey, tmp->step4b.chachanonce, 1);
      if (MEMCMP(tmp->step4b.encciph,
                 start_outputdata + INDEX_OUTPUT_OUT + i * OUTPUT_TX_LEN,
                 ENC_CIPHER_SIZE) != 0) {
        return zxerr_unknown;
      }
    }
    CHECK_APP_CANARY()
    MEMZERO(buffer, bufferLen);
  }

  MEMZERO(buffer, bufferLen);
  return zxerr_ok; // or some code for ok
}

static zxerr_t address_to_script(uint8_t *address, uint8_t *output) {
  if (address == NULL || output == NULL) {
    return zxerr_no_data;
  }

  uint8_t script[SCRIPT_SIZE] = {0};
  script[0] = 0x19;
  script[1] = 0x76;
  script[2] = 0xa9;
  script[3] = 0x14;

  uint8_t tmp[HASH_SIZE] = {0};
  cx_hash_sha256(address, PK_LEN_SECP256K1, tmp, CX_SHA256_SIZE);

  CHECK_ZXERR(ripemd160(tmp, CX_SHA256_SIZE, script + SCRIPT_CONSTS_SIZE));

  script[24] = 0x88;
  script[25] = 0xac;
  MEMCPY(output, script, SCRIPT_SIZE);
  return zxerr_ok;
}

typedef struct {
  union {
    // STEP 1
    struct {
      uint8_t r[SIG_R_SIZE];
      uint8_t s[SIG_S_SIZE];
      uint8_t v;
      // DER signature max size should be 73
      // https://bitcoin.stackexchange.com/questions/77191/what-is-the-maximum-size-of-a-der-encoded-ecdsa-signature#77192
      uint8_t der_signature[DER_MAX_SIZE];
    } step1;

    struct {
      uint8_t rs[SIG_R_SIZE + SIG_S_SIZE];
      uint8_t dummy[DER_MAX_SIZE + 1];
    } step2;
  };
} __attribute__((packed)) signature_tr;

// handleCheckandSign step 9/11
zxerr_t crypto_sign_and_check_transparent(uint8_t *buffer, uint16_t bufferLen,
                                          const uint8_t *txdata,
                                          const uint16_t txdatalen,
                                          const uint8_t tx_version) {
  zemu_log_stack("crypto_sign_and_check_transparent");
  if (t_inlist_len() == 0) {
    return zxerr_ok;
  }
  MEMZERO(buffer, bufferLen);

  // todo: not always SAPLING_LENGTH_HASH_DATA
  if (length_t_in_data() + length_spenddata() + length_outputdata() +
          SAPLING_LENGTH_HASH_DATA !=
      txdatalen) {
    return zxerr_unknown;
  }

  if (get_state() != STATE_VERIFIED_ALL_TXDATA) {
    return zxerr_unknown;
  }

  uint8_t *start_tindata = (uint8_t *)txdata;
  uint8_t *start_signdata = (uint8_t *)(txdata + start_sighashdata());

  uint8_t *out = (uint8_t *)buffer;
  MEMZERO(out, bufferLen);

  cx_ecfp_public_key_t cx_publicKey = {0};
  cx_ecfp_private_key_t cx_privateKey = {0};
  uint8_t privateKeyData[64] = {0};
  uint8_t pubKey[PUB_KEY_SIZE + 1] = {0};
  uint8_t script[SCRIPT_SIZE] = {0};
  uint8_t message_digest[HASH_SIZE] = {0};

  unsigned int info = 0;
  signature_tr *const signature = (signature_tr *)buffer;
  // Temporarily get sk from Ed25519
  zxerr_t error = zxerr_unknown;
  CHECK_APP_CANARY()
  const u_int8_t tInListLen = t_inlist_len();
  for (uint8_t i = 0; i < tInListLen; i++) {
    const t_input_item_t *item = t_inlist_retrieve_item(i);

    CATCH_CXERROR(os_derive_bip32_no_throw(
        CX_CURVE_256K1, item->path, HDPATH_LEN_DEFAULT, privateKeyData, NULL));
    CATCH_CXERROR(cx_ecfp_init_private_key_no_throw(
        CX_CURVE_256K1, privateKeyData, SK_SECP256K1_SIZE, &cx_privateKey));
    CATCH_CXERROR(cx_ecfp_init_public_key_no_throw(CX_CURVE_256K1, NULL, 0,
                                                   &cx_publicKey));
    CATCH_CXERROR(cx_ecfp_generate_pair_no_throw(CX_CURVE_256K1, &cx_publicKey,
                                                 &cx_privateKey, 1));

    for (int j = 0; j < PUB_KEY_SIZE; j++) {
      pubKey[j] = cx_publicKey.W[SIG_S_SIZE + SIG_R_SIZE - j];
    }
    cx_publicKey.W[0] = cx_publicKey.W[SIG_S_SIZE + SIG_R_SIZE] & 1
                            ? 0x03
                            : 0x02; // "Compress" public key in place
    if ((cx_publicKey.W[SIG_R_SIZE] & 1) != 0) {
      pubKey[PUB_KEY_SIZE - 1] |= 0x80;
    }
    MEMCPY(pubKey, cx_publicKey.W, PK_LEN_SECP256K1);
    address_to_script(pubKey, script);
    if (MEMCMP(script,
               (uint8_t *)(start_tindata + INDEX_TIN_SCRIPT + i * T_IN_TX_LEN),
               SCRIPT_SIZE) != 0) {
      goto catch_cx_error;
    }
    if (MEMCMP(item->script, script, SCRIPT_SIZE) != 0) {
      goto catch_cx_error;
    }

    uint64_t value = 0;
    {
      parser_context_t pars_ctx;
      parser_error_t pars_err;

      pars_ctx.offset = 0;
      pars_ctx.buffer = start_tindata + INDEX_TIN_VALUE + i * T_IN_TX_LEN;
      pars_ctx.bufferLen = 8;
      pars_err = _readUInt64(&pars_ctx, &value);
      if (pars_err != parser_ok) {
        goto catch_cx_error;
      }
    }

    if (value != item->value) {
      goto catch_cx_error;
    }
    signature_script_hash(start_tindata, start_signdata,
                          SAPLING_LENGTH_HASH_DATA,
                          start_tindata + i * T_IN_TX_LEN, T_IN_TX_LEN, i,
                          tx_version, message_digest);
    size_t signatureLen = DER_MAX_SIZE;
    CATCH_CXERROR(cx_ecdsa_sign_no_throw(
        &cx_privateKey, CX_RND_RFC6979 | CX_LAST, CX_SHA256, message_digest,
        CX_SHA256_SIZE, signature->step1.der_signature, &signatureLen, &info));

    if (convertDERtoRSV(signature->step1.der_signature, info,
                        signature->step1.r, signature->step1.s,
                        &signature->step1.v) != no_error ||
        transparent_signatures_append(signature->step2.rs) != zxerr_ok) {
      goto catch_cx_error;
    }
  }
  error = zxerr_ok;

catch_cx_error:
  MEMZERO(&cx_publicKey, sizeof(cx_publicKey));
  MEMZERO(&cx_privateKey, sizeof(cx_privateKey));
  MEMZERO(privateKeyData, sizeof(privateKeyData));
  MEMZERO(pubKey, sizeof(pubKey));
  MEMZERO(script, sizeof(script));
  MEMZERO(message_digest, sizeof(message_digest));

  return error;
}

typedef struct {
  union {
    // STEP 1
    struct {
      uint8_t zip32_seed[ZIP32_SEED_SIZE];
    } step1;

    struct {
      uint8_t ask[ASK_SIZE];
      uint8_t nsk[NSK_SIZE];
    } step2;
    // STEP 2
    struct {
      uint8_t rsk[ASK_SIZE];
    } step3;
  };
} tmp_sign_s;

// handleCheckandSign step 10/11
zxerr_t crypto_signspends_sapling(uint8_t *buffer, uint16_t bufferLen,
                                  const uint8_t *txdata,
                                  const uint16_t txdatalen,
                                  const uint8_t tx_version) {
  zemu_log_stack("crypto_signspends_sapling");
  if (spendlist_len() == 0) {
    return zxerr_ok;
  }

  MEMZERO(buffer, bufferLen);

  if (get_state() != STATE_VERIFIED_ALL_TXDATA) {
    return zxerr_unknown;
  }

  if (length_t_in_data() + length_spenddata() + length_outputdata() +
          SAPLING_LENGTH_HASH_DATA !=
      txdatalen) {
    return zxerr_unknown;
  }

  uint8_t *start_signdata = (uint8_t *)(txdata + start_sighashdata());
  uint8_t message[HASH_SIZE + 32] = {0};
  signature_hash(txdata, start_signdata, SAPLING_LENGTH_HASH_DATA, tx_version,
                 message + 32);
  tmp_sign_s tmp = {0};

  // the path in zip32 is [FIRST_VALUE, COIN_TYPE, p] where p is u32 and last
  // part of hdPath
  //  Temporarily get sk from Ed25519
  const uint8_t spendListLen = spendlist_len();
  for (uint8_t i = 0; i < spendListLen; i++) {
    CHECK_ZXERROR_AND_CLEAN(crypto_fillSaplingSeed(tmp.step1.zip32_seed))
    const spend_item_t *item = spendlist_retrieve_item(i);
    if (item == NULL) {
      CHECK_ZXERROR_AND_CLEAN(zxerr_unknown)
    }
    // combining these causes a stack overflow
    randomized_secret_from_seed(tmp.step1.zip32_seed, item->path,
                                (uint8_t *)item->alpha, tmp.step3.rsk);
    rsk_to_rk((uint8_t *)tmp.step3.rsk, message);

    sign_redjubjub(tmp.step3.rsk, message, buffer);
    CHECK_ZXERROR_AND_CLEAN(spend_signatures_append(buffer))
    MEMZERO(&tmp, sizeof(tmp_sign_s));
    CHECK_APP_CANARY()
  }

  MEMZERO(&tmp, sizeof(tmp_sign_s));
  return zxerr_ok;
}

// handleExtractTransparentSignature
zxerr_t crypto_extract_transparent_signature(uint8_t *buffer,
                                             uint16_t bufferLen) {
  if (!transparent_signatures_more_extract()) {
    return zxerr_unknown;
  }

  if (get_state() != STATE_SIGNED_TX) {
    return zxerr_unknown;
  }

  MEMZERO(buffer, bufferLen);
  return get_next_transparent_signature(buffer);
}

// handleExtractSpendSignature
zxerr_t crypto_extract_spend_signature(uint8_t *buffer, uint16_t bufferLen) {
  if (!spend_signatures_more_extract()) {
    return zxerr_unknown;
  }

  if (get_state() != STATE_SIGNED_TX) {
    return zxerr_unknown;
  }

  MEMZERO(buffer, bufferLen);
  return get_next_spend_signature(buffer);
}

// handleInitTX step 2/2 -- AND -- handleCheckandSign step 11/11
zxerr_t crypto_hash_messagebuffer(uint8_t *buffer, uint16_t bufferLen,
                                  const uint8_t *txdata, uint16_t txdataLen) {
  if (bufferLen < CX_SHA256_SIZE) {
    return zxerr_unknown;
  }
  cx_hash_sha256(txdata, txdataLen, buffer, CX_SHA256_SIZE); // SHA256
  return zxerr_ok;
}

typedef struct {
  uint8_t ivk[IVK_SIZE];
  uint8_t default_div[DIV_SIZE];
} tmp_sapling_ivk_and_default_div;

// handleGetKeyIVK: return the incoming viewing key for a given path and the
// default diversifier
zxerr_t crypto_ivk_sapling(uint8_t *buffer, uint16_t bufferLen, uint32_t p,
                           uint16_t *replyLen) {
  zemu_log_stack("crypto_ivk_sapling");

  tmp_sapling_ivk_and_default_div *out =
      (tmp_sapling_ivk_and_default_div *)buffer;
  MEMZERO(buffer, bufferLen);

  // the path in zip32 is [FIRST_VALUE, COIN_TYPE, p] where p is u32 and last
  // part of hdPath
  uint8_t zip32_seed[ZIP32_SEED_SIZE] = {0};

  // Temporarily get sk from Ed25519
  if (crypto_fillSaplingSeed(zip32_seed) != zxerr_ok) {
    MEMZERO(buffer, bufferLen);
    MEMZERO(zip32_seed, sizeof(zip32_seed));
    *replyLen = 0;
    return zxerr_unknown;
  }

  CHECK_APP_CANARY()
  // get incomming viewing key
  zip32_ivk(zip32_seed, out->ivk, p);
  CHECK_APP_CANARY()
  // get default diversifier for start index 0
  get_default_diversifier_without_start_index(zip32_seed, p, out->default_div);
  MEMZERO(zip32_seed, sizeof(zip32_seed));
  CHECK_APP_CANARY()
  *replyLen = IVK_SIZE + DIV_SIZE;
  return zxerr_ok;
}

// handleGetKeyOVK
zxerr_t crypto_ovk_sapling(uint8_t *buffer, uint16_t bufferLen, uint32_t p,
                           uint16_t *replyLen) {
  MEMZERO(buffer, bufferLen);

  zemu_log_stack("crypto_ovk_sapling");
  uint8_t zip32_seed[ZIP32_SEED_SIZE] = {0};

  // Temporarily get sk from Ed25519
  if (crypto_fillSaplingSeed(zip32_seed) != zxerr_ok) {
    MEMZERO(zip32_seed, sizeof(zip32_seed));
    MEMZERO(buffer, bufferLen);
    *replyLen = 0;
    return zxerr_unknown;
  }
  CHECK_APP_CANARY()

  zip32_ovk(zip32_seed, buffer, p);
  CHECK_APP_CANARY()
  MEMZERO(zip32_seed, sizeof(zip32_seed));

  *replyLen = OVK_SIZE;
  return zxerr_ok;
}

typedef struct {
  uint8_t fvk[AK_SIZE + NK_SIZE + OVK_SIZE];
} tmp_sapling_fvk;

// handleGetKeyFVK: return the full viewing key for a given path
zxerr_t crypto_fvk_sapling(uint8_t *buffer, uint16_t bufferLen, uint32_t p,
                           uint16_t *replyLen) {

  zemu_log_stack("crypto_fvk_sapling");

  MEMZERO(buffer, bufferLen);
  tmp_sapling_fvk *out = (tmp_sapling_fvk *)buffer;

  // the path in zip32 is [FIRST_VALUE, COIN_TYPE, p] where p is u32 and last
  // part of hdPath
  uint8_t zip32_seed[ZIP32_SEED_SIZE] = {0};

  // Temporarily get sk from Ed25519
  if (crypto_fillSaplingSeed(zip32_seed) != zxerr_ok) {
    MEMZERO(zip32_seed, sizeof(zip32_seed));
    MEMZERO(buffer, bufferLen);
    *replyLen = 0;
    return zxerr_unknown;
  }
  CHECK_APP_CANARY()

  // get full viewing key
  zip32_fvk(zip32_seed, out->fvk, p);
  CHECK_APP_CANARY()

  MEMZERO(zip32_seed, sizeof(zip32_seed));
  *replyLen = AK_SIZE + NK_SIZE + OVK_SIZE;
  return zxerr_ok;
}

// handleGetNullifier
zxerr_t crypto_nullifier_sapling(uint8_t *buffer, uint16_t bufferLen,
                                 uint64_t notepos, uint8_t *cm,
                                 uint16_t *replyLen) {
  zemu_log_stack("crypto_nullifier_sapling");

  MEMZERO(buffer, bufferLen);

  uint8_t zip32_seed[ZIP32_SEED_SIZE] = {0};
  uint8_t nsk[NSK_SIZE] = {0};

  if (crypto_fillSaplingSeed(zip32_seed) != zxerr_ok) {
    MEMZERO(zip32_seed, sizeof(zip32_seed));
    MEMZERO(buffer, bufferLen);
    *replyLen = 0;
    return zxerr_unknown;
  }
  CHECK_APP_CANARY()
  // nk can be computed from nsk which itself can be computed from the seed.
  zip32_nsk_from_seed(zip32_seed, nsk);
  compute_nullifier(cm, notepos, nsk, buffer);
  CHECK_APP_CANARY()

  MEMZERO(zip32_seed, sizeof(zip32_seed));
  MEMZERO(nsk, sizeof(nsk));
  *replyLen = NULLIFIER_SIZE;
  return zxerr_ok;
}

// handleGetDiversifierList
zxerr_t crypto_diversifier_with_startindex(uint8_t *buffer, uint32_t p,
                                           const uint8_t *startindex,
                                           uint16_t *replylen) {
  zemu_log_stack("crypto_get_diversifiers_sapling");

  // the path in zip32 is [FIRST_VALUE, COIN_TYPE, p] where p is u32 and last
  // part of hdPath
  uint8_t zip32_seed[ZIP32_SEED_SIZE] = {0};

  // Temporarily get sk from Ed25519
  if (crypto_fillSaplingSeed(zip32_seed) != zxerr_ok) {
    MEMZERO(zip32_seed, sizeof(zip32_seed));
    *replylen = 0;
    return zxerr_unknown;
  }
  CHECK_APP_CANARY()

  get_diversifier_list_withstartindex(zip32_seed, p, startindex, buffer);
  for (int i = 0; i < DIV_LIST_LENGTH; i++) {
    if (!is_valid_diversifier(buffer + i * DIV_SIZE)) {
      MEMZERO(buffer + i * DIV_SIZE, DIV_SIZE);
    }
  }

  MEMZERO(zip32_seed, sizeof(zip32_seed));
  *replylen = DIV_LIST_LENGTH * DIV_SIZE;
  return zxerr_ok;
}

typedef struct {
  union {
    struct {
      uint8_t diversifier[DIV_SIZE];
      uint8_t pkd[PKD_SIZE];
    };
    struct {
      uint8_t address_raw[ADDR_LEN_SAPLING];
      char address_bech32[100];
    };
    struct {
      uint8_t dummy[ADDR_LEN_SAPLING];
      uint8_t startindex[DIV_INDEX_SIZE];
    };
  };
} tmp_buf_addr_s;

// handleGetAddrSaplingDiv
zxerr_t crypto_fillAddress_with_diversifier_sapling(uint8_t *buffer,
                                                    uint16_t bufferLen,
                                                    uint32_t p, uint8_t *div,
                                                    uint16_t *replyLen) {
  if (bufferLen < sizeof(tmp_buf_addr_s)) {
    return zxerr_unknown;
  }

  MEMZERO(buffer, bufferLen);

  zemu_log_stack("crypto_fillAddress_with_div_sapling");

  tmp_buf_addr_s *const out = (tmp_buf_addr_s *)buffer;

  uint8_t zip32_seed[ZIP32_SEED_SIZE] = {0};

  // Initialize diversifier
  MEMCPY(out->diversifier, div, DIV_SIZE);
  if (!is_valid_diversifier(out->diversifier)) {
    return zxerr_unknown;
  }

  // Temporarily get sk from Ed25519
  if (crypto_fillSaplingSeed(zip32_seed) != zxerr_ok) {
    MEMZERO(zip32_seed, sizeof(zip32_seed));
    *replyLen = 0;
    return zxerr_unknown;
  }
  CHECK_APP_CANARY()

  // Initialize pkd
  get_pkd(zip32_seed, p, out->diversifier, out->pkd);
  CHECK_APP_CANARY()

  MEMZERO(zip32_seed, sizeof(zip32_seed));

  // To simplify the code and avoid making copies, read the 'address_raw' variable.
  // This variable completely overlaps with the 'diversifier' and 'pkd' fields.
  // Therefore, using 'address_raw' is equivalent to have [diversifier(11) | pkd(32)]
  if (bech32EncodeFromBytes(out->address_bech32,
                            sizeof_field(tmp_buf_addr_s, address_bech32),
                            BECH32_HRP, out->address_raw,
                            sizeof_field(tmp_buf_addr_s, address_raw), 1,
                            BECH32_ENCODING_BECH32) != zxerr_ok) {

    MEMZERO(out, bufferLen);
    *replyLen = 0;
    return zxerr_unknown;
  }

  CHECK_APP_CANARY()
  *replyLen = sizeof_field(tmp_buf_addr_s, address_raw) +
              strlen((const char *)out->address_bech32);
  return zxerr_ok;
}

// handleGetAddrSapling
zxerr_t crypto_fillAddress_sapling(uint8_t *buffer, uint16_t bufferLen,
                                   uint32_t p, uint16_t *replyLen) {
  if (bufferLen < sizeof(tmp_buf_addr_s)) {
    return zxerr_unknown;
  }

  zemu_log_stack("crypto_fillAddress_sapling");
  tmp_buf_addr_s *const out = (tmp_buf_addr_s *)buffer;
  MEMZERO(buffer, bufferLen);

  // the path in zip32 is [FIRST_VALUE, COIN_TYPE, p] where p is u32 and last
  // part of hdPath
  uint8_t zip32_seed[ZIP32_SEED_SIZE] = {0};

  // Temporarily get sk from Ed25519
  if (crypto_fillSaplingSeed(zip32_seed) != zxerr_ok) {
    MEMZERO(zip32_seed, sizeof(zip32_seed));
    *replyLen = 0;
    return zxerr_unknown;
  }
  CHECK_APP_CANARY()

  get_pkd_from_seed(zip32_seed, p, out->startindex, out->diversifier, out->pkd);
  MEMZERO(out + DIV_SIZE, MAX_SIZE_BUF_ADDR - DIV_SIZE);
  CHECK_APP_CANARY()

  MEMZERO(zip32_seed, sizeof(zip32_seed));
  if (bech32EncodeFromBytes(out->address_bech32,
                            sizeof_field(tmp_buf_addr_s, address_bech32),
                            BECH32_HRP, out->address_raw,
                            sizeof_field(tmp_buf_addr_s, address_raw), 1,
                            BECH32_ENCODING_BECH32) != zxerr_ok) {
    MEMZERO(out, bufferLen);
    *replyLen = 0;
    return zxerr_unknown;
  }
  CHECK_APP_CANARY()

  *replyLen = sizeof_field(tmp_buf_addr_s, address_raw) +
              strlen((const char *)out->address_bech32);
  return zxerr_ok;
}
