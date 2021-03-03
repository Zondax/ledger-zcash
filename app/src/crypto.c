/*******************************************************************************
*   (c) 2019 Zondax GmbH
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
#include "constants.h"
#include "coin.h"
#include "zxmacros.h"
#include "base58.h"
#include "rslib.h"
#include "bech32.h"
#include "nvdata.h"
#include "sighash.h"
#include "index_sapling.h"
#include "parser_impl.h"
#include "parser_common.h"
#include "chacha.h"
#include "common/app_main.h"

uint32_t hdPath[HDPATH_LEN_DEFAULT];

bool isTestnet() {
    return hdPath[0] == HDPATH_0_TESTNET &&
           hdPath[1] == HDPATH_1_TESTNET;
}

#if defined(TARGET_NANOS) || defined(TARGET_NANOX)
#include "cx.h"

typedef struct {
    uint8_t publicKey[PK_LEN_SECP256K1];
    uint8_t address[50];
} __attribute__((packed)) answer_t;

void ripemd160(uint8_t *in, uint16_t inLen, uint8_t *out) {
    cx_ripemd160_t rip160;
    cx_ripemd160_init(&rip160);
    cx_hash(&rip160.header, CX_LAST, in, inLen, out, CX_RIPEMD160_SIZE);
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

zxerr_t crypto_fillAddress_secp256k1(uint8_t *buffer, uint16_t buffer_len, uint16_t *replyLen) {
    if (buffer_len < sizeof(answer_t)) {
        *replyLen =  0;
        return zxerr_unknown;
    }

    zemu_log_stack("crypto_fillAddress_secp256k1");

    MEMZERO(buffer, buffer_len);
    answer_t *const answer = (answer_t *) buffer;

    crypto_extractPublicKey(hdPath, answer->publicKey, sizeof_field(answer_t, publicKey));

    address_temp_t address_temp;

    // extended-ripemd-160 = [version][ripemd-160(sha256(pk))]
    address_temp.version[0] = VERSION_P2PKH >> 8;
    address_temp.version[1] = VERSION_P2PKH & 0xFF;
    cx_hash_sha256(answer->publicKey, PK_LEN_SECP256K1, address_temp.sha256_pk, CX_SHA256_SIZE);      // SHA256
    ripemd160(address_temp.sha256_pk, CX_SHA256_SIZE, address_temp.ripe_sha256_pk);         // RIPEMD-160

    // checksum = sha256(sha256(extended-ripe))
    cx_hash_sha256(address_temp.extended_ripe, CX_RIPEMD160_SIZE + VERSION_SIZE, address_temp.sha256_extended_ripe, CX_SHA256_SIZE);
    cx_hash_sha256(address_temp.sha256_extended_ripe, CX_SHA256_SIZE, address_temp.sha256_checksum, CX_SHA256_SIZE);

    // 7. 25 bytes BTC address = [extended ripemd-160][checksum]
    // Encode as base58
    size_t outLen = sizeof_field(answer_t, address);
    int err = encode_base58(address_temp.address, VERSION_SIZE + CX_RIPEMD160_SIZE + CHECKSUM_SIZE, answer->address, &outLen);
    if(err != 0){
        return zxerr_unknown;
    }
    *replyLen = PK_LEN_SECP256K1 + outLen;
    return zxerr_ok;
}

void crypto_extractPublicKey(const uint32_t path[HDPATH_LEN_DEFAULT], uint8_t *pubKey, uint16_t pubKeyLen) {
    cx_ecfp_public_key_t cx_publicKey;
    cx_ecfp_private_key_t cx_privateKey;
    uint8_t privateKeyData[SK_SECP256K1_SIZE];

    if (pubKeyLen < PK_LEN_SECP256K1) {
        return;
    }

    BEGIN_TRY
    {
        TRY {
            os_perso_derive_node_bip32(CX_CURVE_256K1,
                                       path,
                                       HDPATH_LEN_DEFAULT,
                                       privateKeyData, NULL);

            cx_ecfp_init_private_key(CX_CURVE_256K1, privateKeyData, SK_SECP256K1_SIZE, &cx_privateKey);
            cx_ecfp_init_public_key(CX_CURVE_256K1, NULL, 0, &cx_publicKey);
            cx_ecfp_generate_pair(CX_CURVE_256K1, &cx_publicKey, &cx_privateKey, 1);
        }
        FINALLY {
            MEMZERO(&cx_privateKey, sizeof(cx_privateKey));
            MEMZERO(privateKeyData, SK_SECP256K1_SIZE);
        }
    }
    END_TRY;

    // Format pubkey
    for (int i = 0; i < PUB_KEY_SIZE; i++) {
        pubKey[i] = cx_publicKey.W[64 - i];
    }
    cx_publicKey.W[0] = cx_publicKey.W[64] & 1 ? 0x03 : 0x02; // "Compress" public key in place
    if ((cx_publicKey.W[PUB_KEY_SIZE] & 1) != 0) {
        pubKey[PUB_KEY_SIZE - 1] |= 0x80;
    }

    memcpy(pubKey, cx_publicKey.W, PK_LEN_SECP256K1);
}

void crypto_fillSaplingSeed(uint8_t *sk) {
    // Get seed from Ed25519
    MEMZERO(sk, ED25519_SK_SIZE);
    //fixme: make sure this path is not used somewhere else for signing
    // Generate randomness using a fixed path related to the device mnemonic
    const uint32_t path[HDPATH_LEN_DEFAULT] = {
            0x8000002c,
            0x80000085,
            MASK_HARDENED,
            MASK_HARDENED,
            MASK_HARDENED,
    };

    os_perso_derive_node_bip32_seed_key(HDW_NORMAL, CX_CURVE_Ed25519,
                                        path, HDPATH_LEN_DEFAULT,
                                        sk,
                                        NULL,
                                        NULL, 0);
}

zxerr_t crypto_extracttx_sapling(uint8_t *buffer, uint16_t bufferLen, const uint8_t *txdata, const uint16_t txdatalen) {
    zemu_log_stack("crypto_extracttxdata_sapling");
    MEMZERO(buffer, bufferLen);
    uint8_t t_in_len = *txdata;
    uint8_t t_out_len = *(txdata+1);
    uint8_t spend_len = *(txdata+2);
    uint8_t output_len = *(txdata+3);

    transaction_reset();

    if((spend_len > 0 && output_len < 2) || (spend_len == 0 && output_len == 1)){
        return zxerr_unknown;
    }

    if(txdatalen < 4 || txdatalen - 4 != t_in_len * T_IN_INPUT_LEN + t_out_len * T_OUT_INPUT_LEN + spend_len * SPEND_INPUT_LEN + output_len * OUTPUT_INPUT_LEN){
        return zxerr_unknown;
    }

    if (t_in_len == 0 && t_out_len == 0 && spend_len == 0 && output_len == 0){
        return zxerr_unknown;
    }

    uint8_t *start = (uint8_t *)txdata;
    start += 4;

    parser_context_t pars_ctx;
    parser_error_t pars_err;

    for(int i = 0; i < t_in_len; i++){
        uint32_t *path = (uint32_t *)(start + INDEX_INPUT_TIN_PATH);
        uint8_t *script = (uint8_t *)(start + INDEX_INPUT_TIN_SCRIPT);

        pars_ctx.offset = 0;
        pars_ctx.buffer = start + INDEX_INPUT_TIN_VALUE;
        pars_ctx.bufferLen = 8;
        uint64_t v = 0;
        pars_err = _readUInt64(&pars_ctx, &v);
        if (pars_err != parser_ok){
            return zxerr_unknown;
        }
        zxerr_t err = t_inlist_append_item(path, script, v);
        if (err != zxerr_ok){
            return zxerr_unknown;
        }
        start += T_IN_INPUT_LEN;
    }

    for(int i = 0; i < t_out_len; i++){
        uint8_t *addr = (uint8_t *)(start + INDEX_INPUT_TOUT_ADDR);
        pars_ctx.offset = 0;
        pars_ctx.buffer = start + INDEX_INPUT_TOUT_VALUE;
        pars_ctx.bufferLen = 8;
        uint64_t v = 0;
        pars_err = _readUInt64(&pars_ctx, &v);
        if (pars_err != parser_ok){
            return zxerr_unknown;
        }
        zxerr_t err = t_outlist_append_item(addr, v);
        if (err != zxerr_ok){
            return zxerr_unknown;
        }
        start += T_OUT_INPUT_LEN;
    }

    for(int i = 0; i < spend_len; i++){
        pars_ctx.offset = 0;
        pars_ctx.buffer = start + INDEX_INPUT_SPENDPOS;
        pars_ctx.bufferLen = 4;
        uint32_t p = 0;
        pars_err = _readUInt32(&pars_ctx, &p);
        if (pars_err != parser_ok){
            return zxerr_unknown;
        }

        pars_ctx.offset = 0;
        pars_ctx.buffer = start + INDEX_INPUT_INPUTVALUE;
        pars_ctx.bufferLen = 8;
        uint64_t v = 0;
        pars_err = _readUInt64(&pars_ctx, &v);
        if (pars_err != parser_ok){
            return zxerr_unknown;
        }

        uint8_t *div = start + INDEX_INPUT_INPUTDIV;
        uint8_t *pkd = start + INDEX_INPUT_INPUTPKD;
        uint8_t rnd1[RND_SIZE];
        uint8_t rnd2[RND_SIZE];
        random_fr(rnd1);
        random_fr(rnd2);

        zxerr_t err = spendlist_append_item(p,v,div, pkd, rnd1,rnd2);
        if (err != zxerr_ok){
            return zxerr_unknown;
        }
        start += SPEND_INPUT_LEN;
    }
    for(int i = 0; i < output_len; i++){
        uint8_t *div = start + INDEX_INPUT_OUTPUTDIV;
        uint8_t *pkd = start + INDEX_INPUT_OUTPUTPKD;

        pars_ctx.offset = 0;
        pars_ctx.buffer = start + INDEX_INPUT_OUTPUTVALUE;
        pars_ctx.bufferLen = 8;
        uint64_t v = 0;
        pars_err = _readUInt64(&pars_ctx, &v);
        if (pars_err != parser_ok){
            return zxerr_unknown;
        }

        uint8_t *memotype = start + INDEX_INPUT_OUTPUTMEMO;
        uint8_t *ovk = start + INDEX_INPUT_OUTPUTOVK;
        if(ovk[0] != 0x00 && ovk[0] != 0x01){
            zemu_log_stack("invalid OVK SET");
            return zxerr_unknown;
        }
        uint8_t hash_seed[OVK_SET_SIZE];
        if(ovk[0] == 0x00){
            MEMZERO(hash_seed,OVK_SET_SIZE);
            cx_rng(hash_seed + 1, OVK_SIZE);
            ovk = hash_seed;
        }

        uint8_t rnd1[RND_SIZE];
        uint8_t rnd2[RND_SIZE];
        random_fr(rnd1);
        cx_rng(rnd2, RND_SIZE);
        zxerr_t err = outputlist_append_item(div, pkd, v, *memotype, ovk, rnd1, rnd2);
        if (err != zxerr_ok){
            return zxerr_unknown;
        }
        start += OUTPUT_INPUT_LEN;
    }

    uint64_t value_flash = get_valuebalance();
    if (value_flash != 1000){
        return zxerr_unknown;
    }

    if (spend_len > 0){
        set_state(STATE_PROCESSED_INPUTS); //need both spend info and output info (as spend > 0 => output >= 2)
    }else if (output_len > 0){
        set_state(STATE_PROCESSED_SPEND_EXTRACTIONS); //we can have shielded outputs only
    }else{
        set_state(STATE_PROCESSED_ALL_EXTRACTIONS); //We can have transparent inputs/outputs only
    }

    return zxerr_ok; //some code for all_good
}


typedef struct {
    union {
        // STEP 1
        struct {
            uint8_t dk[DK_SIZE];
            uint8_t zip32_seed[ZIP32_SEED_SIZE];
            uint8_t sk[ED25519_SK_SIZE];
        } step1;

        struct {
            uint8_t dk[DK_SIZE];
            uint8_t ask[ASK_SIZE];
            uint8_t nsk[NSK_SIZE];
        } step2;
    };
} tmp_spendinfo_s;

zxerr_t crypto_extract_spend_proofkeyandrnd(uint8_t *buffer, uint16_t bufferLen){
    if(!spendlist_more_extract()){
        return zxerr_unknown;
    }

    if(get_state() != STATE_PROCESSED_INPUTS){
        return zxerr_unknown;
    }

    uint8_t *out = (uint8_t *) buffer;
    MEMZERO(out, bufferLen);

    const spend_item_t *next = spendlist_extract_next();
    if (next == NULL){
        return zxerr_unknown;
    }

    tmp_spendinfo_s tmp;
    MEMZERO(&tmp, sizeof(tmp_spendinfo_s));

    BEGIN_TRY
    {
        TRY
        {
            crypto_fillSaplingSeed(tmp.step1.zip32_seed);
            CHECK_APP_CANARY();

            zip32_child(tmp.step1.zip32_seed, tmp.step2.dk, tmp.step2.ask, out + AK_SIZE, next->path);
            CHECK_APP_CANARY();
        }
        FINALLY
        {
            // do something here?
        }
    }
    END_TRY;
    CHECK_APP_CANARY();

    ask_to_ak(tmp.step2.ask,out);
    MEMZERO(&tmp, sizeof(tmp_spendinfo_s));
    CHECK_APP_CANARY();
    MEMCPY(out+AK_SIZE+NSK_SIZE, next->rcm, RCM_SIZE);
    MEMCPY(out+AK_SIZE+NSK_SIZE+RCM_SIZE, next->alpha,ALPHA_SIZE);

    if(!spendlist_more_extract()){
        set_state(STATE_PROCESSED_SPEND_EXTRACTIONS);
    }

    return zxerr_ok;
}

zxerr_t crypto_extract_output_rnd(uint8_t *buffer, uint16_t bufferLen, uint16_t *replyLen){
    if(!outputlist_more_extract()){
        return zxerr_unknown;
    }

    if(get_state() != STATE_PROCESSED_SPEND_EXTRACTIONS){
        return zxerr_unknown;
    }

    uint8_t *out = (uint8_t *) buffer;
    MEMZERO(out, bufferLen);

    const output_item_t *next = outputlist_extract_next();
    if (next == NULL){
        return zxerr_unknown;
    }
    MEMCPY(out, next->rcmvalue, RCM_V_SIZE);
    MEMCPY(out+RCM_V_SIZE, next->rseed, RSEED_SIZE);

    if(next->ovk[0] == 0x00){
        MEMCPY(out+RCM_V_SIZE + RSEED_SIZE, next->ovk + 1, OVK_SIZE);
        *replyLen = RCM_V_SIZE + RSEED_SIZE + OVK_SIZE;
    }else{
        *replyLen = RCM_V_SIZE + RSEED_SIZE;
    }

    if(!outputlist_more_extract()){
        set_state(STATE_PROCESSED_ALL_EXTRACTIONS);
    }
    return zxerr_ok;
}

zxerr_t crypto_check_prevouts(uint8_t *buffer, uint16_t bufferLen, const uint8_t *txdata, const uint16_t txdatalen){
    zemu_log_stack("crypto_checkprevoouts_sapling");
    MEMZERO(buffer, bufferLen);

    if(get_state() != STATE_CHECKING_ALL_TXDATA){
        return zxerr_unknown;
    }

    uint8_t hash[HASH_SIZE];
    prevouts_hash(txdata,hash);

    if(MEMCMP(hash, txdata + start_sighashdata() + INDEX_HASH_PREVOUTSHASH, HASH_SIZE) != 0){
        return zxerr_unknown;
    }
    return zxerr_ok;
}

zxerr_t crypto_check_sequence(uint8_t *buffer, uint16_t bufferLen, const uint8_t *txdata, const uint16_t txdatalen){
    zemu_log_stack("crypto_checksequence_sapling");
    MEMZERO(buffer, bufferLen);

    if(get_state() != STATE_CHECKING_ALL_TXDATA){
        return zxerr_unknown;
    }

    uint8_t hash[HASH_SIZE];
    sequence_hash(txdata, hash);
    if(MEMCMP(hash, txdata + start_sighashdata() + INDEX_HASH_SEQUENCEHASH, HASH_SIZE) != 0){
        return zxerr_unknown;
    }
    return zxerr_ok;
}

zxerr_t crypto_check_outputs(uint8_t *buffer, uint16_t bufferLen, const uint8_t *txdata, const uint16_t txdatalen){
    zemu_log_stack("crypto_checkoutputs_sapling");
    if(length_t_in_data() + length_spenddata() + length_outputdata() + LENGTH_HASH_DATA != txdatalen){
        return zxerr_unknown;
    }

    if(get_state() != STATE_CHECKING_ALL_TXDATA){
        return zxerr_unknown;
    }

    MEMZERO(buffer, bufferLen);
    uint8_t hash[HASH_SIZE];
    outputs_hash(hash);
    if(MEMCMP(hash, txdata + start_sighashdata() + INDEX_HASH_OUTPUTSHASH, HASH_SIZE) != 0){
        return zxerr_unknown;
    }
    return zxerr_ok;
}

zxerr_t crypto_check_joinsplits(uint8_t *buffer, uint16_t bufferLen, const uint8_t *txdata, const uint16_t txdatalen){
    zemu_log_stack("crypto_checkjoinsplits_sapling");
    MEMZERO(buffer, bufferLen);

    if(get_state() != STATE_CHECKING_ALL_TXDATA){
        return zxerr_unknown;
    }
    uint8_t hash[HASH_SIZE];
    MEMZERO(hash,sizeof(hash));
    if(MEMCMP(hash, txdata + start_sighashdata() + INDEX_HASH_JOINSPLITSHASH, HASH_SIZE) != 0){
        return zxerr_unknown;
    }
    return zxerr_ok;
}

zxerr_t crypto_check_valuebalance(uint8_t *buffer, uint16_t bufferLen, const uint8_t *txdata, const uint16_t txdatalen){
    zemu_log_stack("crypto_checkvaluebalance_sapling");
    MEMZERO(buffer, bufferLen);

    if(get_state() != STATE_CHECKING_ALL_TXDATA){
        return zxerr_unknown;
    }
    parser_context_t pars_ctx;
    parser_error_t pars_err;

    pars_ctx.offset = 0;
    pars_ctx.buffer = txdata + start_sighashdata() + INDEX_HASH_VALUEBALANCE;
    pars_ctx.bufferLen = 8;
    uint64_t v = 0;
    pars_err = _readUInt64(&pars_ctx, &v);
    if (pars_err != parser_ok){
        return 0;
    }

    uint64_t valuebalance = get_valuebalance();
    uint8_t *value_flash = (uint8_t *)&valuebalance;
    if(MEMCMP(txdata + start_sighashdata() + INDEX_HASH_VALUEBALANCE, value_flash, 8) != 0){
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

        struct {
            uint8_t gd[GD_SIZE];
            uint8_t nsk[NSK_SIZE];
        } step5;

        struct {
            uint8_t gd[GD_SIZE];
            uint8_t nk[NSK_SIZE];
        } step6;

    };
} tmp_checkspend;

zxerr_t crypto_checkspend_sapling(uint8_t *buffer, uint16_t bufferLen, const uint8_t *txdata, const uint16_t txdatalen) {
    MEMZERO(buffer, bufferLen);

    if(length_t_in_data() + length_spenddata() + length_outputdata() + LENGTH_HASH_DATA != txdatalen){
        return zxerr_unknown;
    }

    if(get_state() != STATE_CHECKING_ALL_TXDATA){
        return zxerr_unknown;
    }

    zemu_log_stack("crypto_checkspend_sapling");

    uint8_t *out = buffer;

    tmp_buf_checkspend *const tmp_buf = (tmp_buf_checkspend *) buffer;
    MEMZERO(tmp_buf, bufferLen);

    uint8_t *start_spenddata = (uint8_t *)(txdata + length_t_in_data() + length_spend_old_data());
    uint8_t *start_spendolddata = (uint8_t *)(txdata + length_t_in_data());

    tmp_checkspend tmp;
    MEMZERO(&tmp, sizeof(tmp_checkspend));

    //the path in zip32 is [FIRST_VALUE, COIN_TYPE, p] where p is u32 and last part of hdPath
    BEGIN_TRY
    {
        TRY
        {
            // Temporarily get sk from Ed25519
            CHECK_APP_CANARY();

            for(uint8_t i = 0; i < spendlist_len(); i++){
                crypto_fillSaplingSeed(tmp.step1.zip32_seed);
                const spend_item_t *item = spendlist_retrieve_item(i);
                if (item == NULL){
                    CLOSE_TRY;
                    return zxerr_unknown;
                }
                zip32_child_ask_nsk(tmp.step1.zip32_seed, tmp.step2.ask, tmp.step2.nsk, item->path);

                randomized_secret(tmp.step2.ask, (uint8_t *)item->alpha, tmp.step2.ask);
                sk_to_pk(tmp.step2.ask, tmp.step3.rk);

                if(MEMCMP(tmp.step3.rk, start_spenddata + INDEX_SPEND_RK + i * SPEND_TX_LEN,PUB_KEY_SIZE) != 0){
                    CLOSE_TRY;
                    MEMZERO(&tmp, sizeof(tmp_checkspend));
                    return zxerr_unknown;
                }

                compute_value_commitment(item->value,item->rcm,tmp.step4.cv);
                if (MEMCMP(tmp.step4.cv, start_spenddata + INDEX_SPEND_VALUECMT + i *SPEND_TX_LEN,VALUE_COMMITMENT_SIZE) != 0){
                    MEMZERO(&tmp, sizeof(tmp_checkspend));
                    MEMZERO(out,bufferLen);
                    CLOSE_TRY;
                    return zxerr_unknown;
                }

                group_hash_from_div(item->div, tmp.step5.gd);
                prepare_input_notecmt(item->value, tmp.step5.gd, item->pkd, tmp_buf->pedersen_input);
                pedersen_hash_73bytes(tmp_buf->pedersen_input,tmp_buf->pedersen_hash);
                compute_note_commitment_fullpoint(tmp_buf->pedersen_hash, start_spendolddata + INDEX_SPEND_OLD_RCM + i * SPEND_OLD_TX_LEN);
                nsk_to_nk(tmp.step5.nsk,tmp.step6.nk);
                uint64_t notepos = 0;
                {
                    parser_context_t pars_ctx;
                    parser_error_t pars_err;

                    pars_ctx.offset = 0;
                    pars_ctx.buffer = start_spendolddata + INDEX_SPEND_OLD_NOTEPOS + i * SPEND_OLD_TX_LEN;
                    pars_ctx.bufferLen = 8;
                    pars_err = _readUInt64(&pars_ctx, &notepos);
                    if (pars_err != parser_ok){
                        CLOSE_TRY;
                        return zxerr_unknown;
                    }
                }
                //void compute_nullifier(uint8_t *ncmptr, uint64_t pos, uint8_t *nkptr, uint8_t *outputptr);
                compute_nullifier(tmp_buf->ncm_full, notepos, tmp.step6.nk, tmp_buf->nf);
                if (MEMCMP(tmp_buf->nf, start_spenddata + INDEX_SPEND_NF + i * SPEND_TX_LEN, NULLIFIER_SIZE) != 0){
                    //maybe spendlist_reset();
                    MEMZERO(out, bufferLen);
                    MEMZERO(&tmp, sizeof(tmp_checkspend));
                    CLOSE_TRY;
                    return zxerr_unknown;
                }

                MEMZERO(out, bufferLen);
                MEMZERO(&tmp, sizeof(tmp_checkspend));

            }

            MEMZERO(&tmp, sizeof(tmp_checkspend));
        }
        FINALLY
        {
            // Not necessary, but just in case
            MEMZERO(out, bufferLen);
            MEMZERO(&tmp, sizeof(tmp_checkspend));
        }
    }
    END_TRY;

    MEMZERO(out, bufferLen);
    if (spendlist_len() > 0){
        shielded_spend_hash(start_spenddata, length_spend_new_data(), tmp_buf->spend_hash);
    }
    if(MEMCMP(tmp_buf->spend_hash, txdata + start_sighashdata() + INDEX_HASH_SHIELDEDSPENDHASH, HASH_SIZE) != 0){
        return zxerr_unknown;
    }
    MEMZERO(out,bufferLen);

    return zxerr_ok; //or some code for ok
}

typedef struct {
    uint8_t shielded_output_hash[HASH_SIZE];
} tmp_buf_checkoutput;

typedef struct {
    union {
        struct {
            uint8_t gd[GD_SIZE]; //computed from receiver diversifier
            uint8_t pkd[PKD_SIZE]; //get this from host and show on screen for verification
        } step2;

        struct {
            uint8_t pedersen_input[PEDERSEN_INPUT_SIZE];
        } step3;

        struct{
            uint8_t notecommitment[NOTE_COMMITMENT_SIZE];
            uint8_t valuecommitment[VALUE_COMMITMENT_SIZE];
        } step4;
    };
} tmp_checkoutput;

zxerr_t crypto_checkoutput_sapling(uint8_t *buffer, uint16_t bufferLen, const uint8_t *txdata, const uint16_t txdatalen) {
    MEMZERO(buffer, bufferLen);

    if(get_state() != STATE_CHECKING_ALL_TXDATA){
        return zxerr_unknown;
    }

    if(length_t_in_data() + length_spenddata() + length_outputdata() + LENGTH_HASH_DATA != txdatalen){
        return zxerr_unknown;
    }

    uint8_t *start_outputdata = (uint8_t *) (txdata + length_t_in_data() + length_spenddata());

    zemu_log_stack("crypto_checkoutput_sapling");

    uint8_t *out = (uint8_t *) buffer;
    MEMZERO(out, bufferLen);

    tmp_checkoutput ncm;
    MEMZERO(&ncm, sizeof(tmp_checkoutput));

    uint8_t rcm[RCM_SIZE];

    //the path in zip32 is [FIRST_VALUE, COIN_TYPE, p] where p is u32 and last part of hdPath
    BEGIN_TRY
    {
        TRY
        {
            for(uint8_t i = 0; i < outputlist_len(); i++){
                const output_item_t *item = outputlist_retrieve_item(i);
                if (item == NULL){
                    CLOSE_TRY;
                    return zxerr_unknown;
                }
                group_hash_from_div(item->div, ncm.step2.gd);

                prepare_input_notecmt(item->value, ncm.step2.gd, item->pkd, ncm.step3.pedersen_input);

                pedersen_hash_73bytes(ncm.step3.pedersen_input,ncm.step4.notecommitment);
                rseed_get_rcm(item->rseed,rcm);
                compute_note_commitment(ncm.step4.notecommitment,rcm);
                compute_value_commitment(item->value, item->rcmvalue, ncm.step4.valuecommitment);

                if (MEMCMP(ncm.step4.valuecommitment, start_outputdata + INDEX_OUTPUT_VALUECMT + i * OUTPUT_TX_LEN,VALUE_COMMITMENT_SIZE) != 0){
                    MEMZERO(&ncm, sizeof(tmp_checkoutput));
                    CLOSE_TRY;
                    return zxerr_unknown;
                }

                if(MEMCMP(ncm.step4.notecommitment, start_outputdata + INDEX_OUTPUT_NOTECMT + i * OUTPUT_TX_LEN,NOTE_COMMITMENT_SIZE) != 0){
                    MEMZERO(&ncm, sizeof(tmp_checkoutput));
                    CLOSE_TRY;
                    return zxerr_unknown;
                }
                MEMZERO(&ncm, sizeof(tmp_checkoutput));
            }
            MEMZERO(&ncm, sizeof(tmp_checkoutput));
        }
        FINALLY
        {
            // Not necessary, but just in case
            MEMZERO(&ncm, sizeof(tmp_checkoutput));
        }
    }
    END_TRY;

    tmp_buf_checkoutput *const tmp_buf = (tmp_buf_checkoutput *) buffer;
    MEMZERO(out, bufferLen);

    if (outputlist_len() > 0){
        shielded_output_hash(start_outputdata, length_outputdata(), tmp_buf->shielded_output_hash);
    }
    if(MEMCMP(tmp_buf->shielded_output_hash, txdata + start_sighashdata() + INDEX_HASH_SHIELDEDOUTPUTHASH, HASH_SIZE) != 0){
        return zxerr_unknown;
    }

    return zxerr_ok; //or some code for ok
}

typedef struct {
    union {
        // STEP 1
        struct { // MAX SIZE --> 160
            uint8_t dummy[MAX_SIZE - EPK_SIZE - ESK_SIZE];
            uint8_t epk[EPK_SIZE]; //computed from receiver diversifier
            uint8_t esk[ESK_SIZE];
        } step1;

        struct{
            uint8_t chachanonce[CHACHA_NONCE_SIZE];
            uint8_t compactout[COMPACT_OUT_SIZE];
            uint8_t sharedkey[SHARED_KEY_SIZE];
            uint8_t epk[EPK_SIZE];
            uint8_t esk[ESK_SIZE];
        } step2;

        struct{
            uint8_t dummy[MAX_SIZE - OVK_SIZE - VALUE_COMMITMENT_SIZE - NOTE_COMMITMENT_SIZE - EPK_SIZE - ESK_SIZE];
            uint8_t ovk[OVK_SIZE];
            uint8_t valuecmt[VALUE_COMMITMENT_SIZE];
            uint8_t notecmt[NOTE_COMMITMENT_SIZE];
            uint8_t epk[EPK_SIZE];
            uint8_t esk[ESK_SIZE];
        }step3;

        struct{
            uint8_t dummy[MAX_SIZE - PRF_INPUT_SIZE - ESK_SIZE];
            uint8_t prfinput[PRF_INPUT_SIZE];
            uint8_t esk[ESK_SIZE];
        }step4;

        struct{
            uint8_t outkey[OUT_KEY_SIZE];
            uint8_t dummy[MAX_SIZE - OUT_KEY_SIZE - PKD_SIZE - ESK_SIZE];
            uint8_t pkd[PKD_SIZE];
            uint8_t esk[ESK_SIZE];
        }step5;

        struct{
            uint8_t outkey[OUT_KEY_SIZE];
            uint8_t dummy[MAX_SIZE - OUT_KEY_SIZE - ENC_CIPHER_SIZE - CHACHA_NONCE_SIZE];
            uint8_t chachanonce[CHACHA_NONCE_SIZE];
            uint8_t encciph[ENC_CIPHER_SIZE];
        }step6;

        struct{
            uint8_t hashseed[OVK_SET_SIZE];
            uint8_t outkey[OUT_KEY_SIZE];
            uint8_t encciph_part1[ENC_CIPHER_HALVE_SIZE];
            uint8_t encciph_part2[ENC_CIPHER_HALVE_SIZE];
            uint8_t chachanonce[CHACHA_NONCE_SIZE];
        }step3b;
        struct{
            uint8_t hashseed[OVK_SET_SIZE];
            uint8_t outkey[OUT_KEY_SIZE];
            uint8_t encciph[ENC_CIPHER_SIZE];
            uint8_t chachanonce[CHACHA_NONCE_SIZE];
        }step4b;
    };
} tmp_enc;

zxerr_t crypto_checkencryptions_sapling(uint8_t *buffer, uint16_t bufferLen, const uint8_t *txdata, const uint16_t txdatalen) {
    MEMZERO(buffer, bufferLen);

    uint8_t *out = (uint8_t *) buffer;
    MEMZERO(out, bufferLen);

    tmp_enc *tmp = (tmp_enc *)buffer;
    MEMZERO(tmp, sizeof(tmp_enc));

    zemu_log_stack("crypto_checkencryptions_sapling");

    uint8_t *start_outputdata = (uint8_t *)(txdata + length_t_in_data() + length_spenddata());

    //the path in zip32 is [FIRST_VALUE, COIN_TYPE, p] where p is u32 and last part of hdPath
    for(uint8_t i = 0; i < outputlist_len(); i++){
        const output_item_t *item = outputlist_retrieve_item(i);
        if (item == NULL){
            MEMZERO(out, bufferLen);
            return zxerr_unknown;
        }
        rseed_get_esk(item->rseed,tmp->step1.esk);
        CHECK_APP_CANARY();
        get_epk(tmp->step1.esk, (uint8_t *) item->div, tmp->step1.epk);
        CHECK_APP_CANARY();
        if (MEMCMP(tmp->step1.epk, start_outputdata + INDEX_OUTPUT_EPK + i * OUTPUT_TX_LEN, EPK_SIZE) != 0){
            MEMZERO(out, bufferLen);
            return zxerr_unknown;
        }

        ka_to_key(tmp->step1.esk, (uint8_t *) item->pkd, tmp->step1.epk, tmp->step2.sharedkey);
        CHECK_APP_CANARY();
        prepare_enccompact_input((uint8_t *) item->div, item->value, (uint8_t *) item->rseed, item->memotype, tmp->step2.compactout);
        CHECK_APP_CANARY();
        MEMZERO(tmp->step2.chachanonce,CHACHA_NONCE_SIZE);
        chacha(tmp->step2.compactout, tmp->step2.compactout, COMPACT_OUT_SIZE, tmp->step2.sharedkey, tmp->step2.chachanonce,1);
        CHECK_APP_CANARY();
        if (MEMCMP(tmp->step2.compactout, start_outputdata + INDEX_OUTPUT_ENC + i * OUTPUT_TX_LEN, COMPACT_OUT_SIZE) != 0){
            MEMZERO(out, bufferLen);
            return zxerr_unknown;
        }

        if(item->ovk[0] != 0x00){
            zemu_log_stack("OVK SET");
            MEMCPY(tmp->step3.ovk, item->ovk + 1, OVK_SIZE);
            MEMCPY(tmp->step3.valuecmt, start_outputdata + INDEX_OUTPUT_VALUECMT + i* OUTPUT_TX_LEN,VALUE_COMMITMENT_SIZE);
            MEMCPY(tmp->step3.notecmt, start_outputdata + INDEX_OUTPUT_NOTECMT + i* OUTPUT_TX_LEN,NOTE_COMMITMENT_SIZE);

            blake2b_prf(tmp->step4.prfinput, tmp->step5.outkey);
            CHECK_APP_CANARY();
            MEMCPY(tmp->step5.pkd, item->pkd, PKD_SIZE);

            MEMZERO(tmp->step6.chachanonce,CHACHA_NONCE_SIZE);

            chacha(tmp->step6.encciph, tmp->step6.encciph, ENC_CIPHER_SIZE, tmp->step6.outkey, tmp->step6.chachanonce,1);
            CHECK_APP_CANARY();
            if (MEMCMP(tmp->step6.encciph, start_outputdata + INDEX_OUTPUT_OUT + i * OUTPUT_TX_LEN, ENC_CIPHER_SIZE) != 0){
                MEMZERO(out, bufferLen);
                return zxerr_unknown;
            }

        }else{
            zemu_log_stack("OVK NOT SET");
            MEMCPY(tmp->step3b.hashseed, item->ovk, OVK_SET_SIZE);
            cx_hash_sha256(tmp->step3b.hashseed, OVK_SET_SIZE, tmp->step3b.outkey, CX_SHA256_SIZE);
            tmp->step3b.hashseed[0] = 0x01;
            cx_hash_sha256(tmp->step3b.hashseed, OVK_SET_SIZE, tmp->step3b.encciph_part1, CX_SHA256_SIZE);
            tmp->step3b.hashseed[0] = 0x02;
            cx_hash_sha256(tmp->step3b.hashseed, OVK_SET_SIZE, tmp->step3b.encciph_part2, CX_SHA256_SIZE);
            MEMZERO(tmp->step3b.chachanonce,CHACHA_NONCE_SIZE);
            chacha(tmp->step4b.encciph, tmp->step4b.encciph, ENC_CIPHER_SIZE, tmp->step4b.outkey, tmp->step4b.chachanonce,1);
            if (MEMCMP(tmp->step4b.encciph, start_outputdata + INDEX_OUTPUT_OUT + i * OUTPUT_TX_LEN, ENC_CIPHER_SIZE) != 0){
                MEMZERO(out, bufferLen);
                return zxerr_unknown;
            }
        }
        CHECK_APP_CANARY();
        MEMZERO(out, bufferLen);
    }

    MEMZERO(out, bufferLen);
    return zxerr_ok; //or some code for ok
}

void address_to_script(uint8_t *address, uint8_t *output){
    uint8_t script[SCRIPT_SIZE];
    script[0] = 0x19;
    script[1] = 0x76;
    script[2] = 0xa9;
    script[3] = 0x14;

    uint8_t tmp[HASH_SIZE];
    cx_hash_sha256(address, PK_LEN_SECP256K1, tmp, CX_SHA256_SIZE);
    ripemd160(tmp, CX_SHA256_SIZE, script + SCRIPT_CONSTS_SIZE);
    script[24] = 0x88;
    script[25] = 0xac;
    MEMCPY(output,script,SCRIPT_SIZE);
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

zxerr_t crypto_sign_and_check_transparent(uint8_t *buffer, uint16_t bufferLen, const uint8_t *txdata, const uint16_t txdatalen) {
    zemu_log_stack("crypto_signchecktransparent_sapling");
    if(t_inlist_len() == 0){
        return zxerr_ok;
    }
    MEMZERO(buffer, bufferLen);

    if(length_t_in_data() + length_spenddata() + length_outputdata() + LENGTH_HASH_DATA != txdatalen){
        return zxerr_unknown;
    }

    if(get_state() != STATE_VERIFIED_ALL_TXDATA ){
        return zxerr_unknown;
    }

    uint8_t *start_tindata = (uint8_t *)txdata;
    uint8_t *start_signdata = (uint8_t *)(txdata + start_sighashdata());

    uint8_t *out = (uint8_t *) buffer;
    MEMZERO(out, bufferLen);

    cx_ecfp_public_key_t cx_publicKey;
    cx_ecfp_private_key_t cx_privateKey;
    uint8_t privateKeyData[SK_SECP256K1_SIZE];
    uint8_t pubKey[PUB_KEY_SIZE+1];
    uint8_t script[SCRIPT_SIZE];
    uint8_t message_digest[HASH_SIZE];

    unsigned int info = 0;
    signature_tr *const signature = (signature_tr *) buffer;
    int signatureLength;

    BEGIN_TRY
    {
        TRY
        {
            // Temporarily get sk from Ed25519
            CHECK_APP_CANARY();
            for(uint8_t i = 0; i < t_inlist_len(); i++){
                t_input_item_t *item = t_inlist_retrieve_item(i);

                os_perso_derive_node_bip32(CX_CURVE_256K1,
                                       item->path,
                                       HDPATH_LEN_DEFAULT,
                                       privateKeyData, NULL);
                cx_ecfp_init_private_key(CX_CURVE_256K1, privateKeyData, SK_SECP256K1_SIZE, &cx_privateKey);
                cx_ecfp_init_public_key(CX_CURVE_256K1, NULL, 0, &cx_publicKey);
                cx_ecfp_generate_pair(CX_CURVE_256K1, &cx_publicKey, &cx_privateKey, 1);

                for (int i = 0; i < PUB_KEY_SIZE; i++) {
                    pubKey[i] = cx_publicKey.W[SIG_S_SIZE + SIG_R_SIZE - i];
                 }
                cx_publicKey.W[0] = cx_publicKey.W[SIG_S_SIZE + SIG_R_SIZE] & 1 ? 0x03 : 0x02; // "Compress" public key in place
                if ((cx_publicKey.W[SIG_R_SIZE] & 1) != 0) {
                    pubKey[PUB_KEY_SIZE - 1] |= 0x80;
                }
                MEMCPY(pubKey, cx_publicKey.W, PK_LEN_SECP256K1);
                address_to_script(pubKey,script);
                if(MEMCMP(script,(uint8_t *)(start_tindata + INDEX_TIN_SCRIPT + i * T_IN_TX_LEN), SCRIPT_SIZE) != 0){
                    CLOSE_TRY;
                    return zxerr_unknown;
                }
                if(MEMCMP(item->script, script,SCRIPT_SIZE) !=0){
                    CLOSE_TRY;
                    return zxerr_unknown;
                }

                uint64_t value = 0;
                {
                    parser_context_t pars_ctx;
                    parser_error_t pars_err;

                    pars_ctx.offset = 0;
                    pars_ctx.buffer = start_tindata + INDEX_TIN_VALUE + i * T_IN_TX_LEN;
                    pars_ctx.bufferLen = 8;
                    pars_err = _readUInt64(&pars_ctx, &value);
                    if (pars_err != parser_ok){
                        CLOSE_TRY;
                        return zxerr_unknown;
                    }
                }

                if(value != item->value){
                    return zxerr_unknown;
                }
                signature_script_hash(start_signdata, LENGTH_HASH_DATA, start_tindata + i * T_IN_TX_LEN, T_IN_TX_LEN, message_digest);
                signatureLength = cx_ecdsa_sign(&cx_privateKey,
                                            CX_RND_RFC6979 | CX_LAST,
                                            CX_SHA256,
                                            message_digest,
                                            CX_SHA256_SIZE,
                                            signature->step1.der_signature,
                                            DER_MAX_SIZE,
                                            &info);
                err_convert_e err = convertDERtoRSV(signature->step1.der_signature, info,  signature->step1.r, signature->step1.s, &signature->step1.v);
                if (err != no_error) {
                    CLOSE_TRY;
                    return zxerr_unknown;
                }
                zxerr_t zxerr = transparent_signatures_append(signature->step2.rs);
                if(zxerr != zxerr_ok){
                    CLOSE_TRY;
                    return zxerr;
                }
            }

        }
        FINALLY
        {
            // Not necessary, but just in case
        }
    }
    END_TRY;

    CHECK_APP_CANARY();
    return zxerr_ok;
}


typedef struct {
    union {
        // STEP 1
        struct {
            uint8_t dk[DK_SIZE];
            uint8_t zip32_seed[ZIP32_SEED_SIZE];
        } step1;

        struct {
            uint8_t dk[DK_SIZE];
            uint8_t ask[ASK_SIZE];
            uint8_t nsk[NSK_SIZE];
        } step2;
        // STEP 2
        struct {
            uint8_t rsk[ASK_SIZE];
        } step3;
    };
} tmp_sign_s;

zxerr_t crypto_signspends_sapling(uint8_t *buffer, uint16_t bufferLen, const uint8_t *txdata, const uint16_t txdatalen) {
    zemu_log_stack("crypto_signspends_sapling");
    if(spendlist_len() == 0){
        return zxerr_ok;
    }

    MEMZERO(buffer, bufferLen);

    if(get_state() != STATE_VERIFIED_ALL_TXDATA ){
        return zxerr_unknown;
    }

    if(length_t_in_data() + length_spenddata() + length_outputdata() + LENGTH_HASH_DATA != txdatalen){
        return zxerr_unknown;
    }

    uint8_t *start_signdata = (uint8_t *)(txdata + start_sighashdata());

    uint8_t sighash[HASH_SIZE];

    uint8_t *out = (uint8_t *) buffer;
    MEMZERO(out, bufferLen);

    signature_hash(start_signdata,LENGTH_HASH_DATA,sighash);

    tmp_sign_s tmp;
    MEMZERO(&tmp, sizeof(tmp_sign_s));

    //the path in zip32 is [FIRST_VALUE, COIN_TYPE, p] where p is u32 and last part of hdPath
    BEGIN_TRY
    {
        TRY
        {
            // Temporarily get sk from Ed25519
            CHECK_APP_CANARY();
            for(uint8_t i = 0; i < spendlist_len(); i++){
                crypto_fillSaplingSeed(tmp.step1.zip32_seed);
                const spend_item_t *item = spendlist_retrieve_item(i);
                if (item == NULL){
                    CLOSE_TRY;
                    return zxerr_unknown;
                }

                zip32_child(tmp.step1.zip32_seed, tmp.step2.dk, tmp.step2.ask, tmp.step2.nsk, item->path);

                randomized_secret(tmp.step2.ask, (uint8_t *)item->alpha, tmp.step3.rsk);
                sign_redjubjub((uint8_t *)tmp.step3.rsk, (uint8_t *)sighash, (uint8_t *)out);
                zxerr_t zxerr = spend_signatures_append(out);
                if(zxerr != zxerr_ok){
                    CLOSE_TRY;
                    return zxerr;
                }
                MEMZERO(&tmp, sizeof(tmp_sign_s));
            }

            MEMZERO(&tmp, sizeof(tmp_sign_s));
        }
        FINALLY
        {
            // Not necessary, but just in case
            MEMZERO(&tmp, sizeof(tmp_sign_s));
        }
    }
    END_TRY;

    CHECK_APP_CANARY();
    return zxerr_ok;
}

zxerr_t crypto_extract_transparent_signature(uint8_t *buffer, uint16_t bufferLen){
    if(!transparent_signatures_more_extract()){
        return zxerr_unknown;
    }

    if(get_state() != STATE_SIGNED_TX){
        return zxerr_unknown;
    }

    uint8_t *out = (uint8_t *) buffer;
    MEMZERO(out, bufferLen);

    zxerr_t err = get_next_transparent_signature(out);
    return err;
}

zxerr_t crypto_extract_spend_signature(uint8_t *buffer, uint16_t bufferLen){
    if(!spend_signatures_more_extract()){
        return zxerr_unknown;
    }

    if(get_state() != STATE_SIGNED_TX){
        return zxerr_unknown;
    }

    uint8_t *out = (uint8_t *) buffer;
    MEMZERO(out, bufferLen);

    zxerr_t err = get_next_spend_signature(out);
    return err;
}

zxerr_t crypto_hash_messagebuffer(uint8_t *buffer, uint16_t bufferLen, const uint8_t *txdata, uint16_t txdataLen){
    if(bufferLen < CX_SHA256_SIZE){
        return zxerr_unknown;
    }
    cx_hash_sha256(txdata, txdataLen, buffer, CX_SHA256_SIZE);      // SHA256
    return zxerr_ok;
}

typedef struct {
    union {
        // STEP 1
        struct {
            uint8_t dk[DK_SIZE];
            uint8_t zip32_seed[ZIP32_SEED_SIZE];
            uint8_t sk[ED25519_SK_SIZE];
        } step1;

        struct {
            uint8_t dk[DK_SIZE];
            uint8_t ask[ASK_SIZE];
            uint8_t nsk[NSK_SIZE];
        } step2;
        // STEP 2
        struct {
            uint8_t ivk[IVK_SIZE];
            uint8_t ak[AK_SIZE];
            uint8_t nk[NK_SIZE];
        } step3;
    };
} tmp_sapling_addr_s;

zxerr_t crypto_ivk_sapling(uint8_t *buffer, uint16_t bufferLen, uint32_t p, uint16_t *replyLen) {
    MEMZERO(buffer, bufferLen);

    zemu_log_stack("crypto_ivk_sapling");

    uint8_t *out = buffer;
    MEMZERO(out, bufferLen);

    tmp_sapling_addr_s tmp;
    MEMZERO(&tmp, sizeof(tmp_sapling_addr_s));

    //the path in zip32 is [FIRST_VALUE, COIN_TYPE, p] where p is u32 and last part of hdPath
    BEGIN_TRY
    {
        TRY
        {
            // Temporarily get sk from Ed25519
            crypto_fillSaplingSeed(tmp.step1.zip32_seed);
            CHECK_APP_CANARY();
            zip32_child(tmp.step1.zip32_seed, tmp.step2.dk, tmp.step2.ask, tmp.step2.nsk, p);
            ask_to_ak(tmp.step2.ask,tmp.step3.ak);
            nsk_to_nk(tmp.step2.nsk,tmp.step3.nk);
            CHECK_APP_CANARY();

            get_ivk(tmp.step3.ak, tmp.step3.nk, out);
            CHECK_APP_CANARY();

            MEMZERO(&tmp, sizeof(tmp_sapling_addr_s));
        }
        FINALLY
        {
            // Not necessary, but just in case
            MEMZERO(&tmp, sizeof(tmp_sapling_addr_s));
        }
    }
    END_TRY;
    CHECK_APP_CANARY();
    *replyLen = IVK_SIZE;
    return zxerr_ok;
}

zxerr_t crypto_ovk_sapling(uint8_t *buffer, uint16_t bufferLen, uint32_t p, uint16_t *replyLen){
    MEMZERO(buffer, bufferLen);

    zemu_log_stack("crypto_ovk_sapling");

    uint8_t *out = (uint8_t *) buffer;
    MEMZERO(out, bufferLen);

    tmp_sapling_addr_s tmp;
    MEMZERO(&tmp, sizeof(tmp_sapling_addr_s));

    BEGIN_TRY
    {
        TRY
        {
            // Temporarily get sk from Ed25519
            crypto_fillSaplingSeed(tmp.step1.zip32_seed);
            CHECK_APP_CANARY();
            zip32_ovk(tmp.step1.zip32_seed,out,p);
            MEMZERO(&tmp,sizeof(tmp));
            CHECK_APP_CANARY();
        }
        FINALLY
        {
            MEMZERO(&tmp,sizeof(tmp));
        }
    }
    END_TRY;
    CHECK_APP_CANARY();
    *replyLen = OVK_SIZE;
    return zxerr_ok;
}

zxerr_t crypto_diversifier_with_startindex(uint8_t *buffer, uint16_t bufferLen, uint32_t p, uint8_t *startindex, uint16_t *replylen) {
    zemu_log_stack("crypto_get_diversifiers_sapling");

    tmp_sapling_addr_s tmp;
    MEMZERO(&tmp, sizeof(tmp_sapling_addr_s));
    //the path in zip32 is [FIRST_VALUE, COIN_TYPE, p] where p is u32 and last part of hdPath

    BEGIN_TRY
    {
        TRY
        {
            // Temporarily get sk from Ed25519
            crypto_fillSaplingSeed(tmp.step1.zip32_seed);
            CHECK_APP_CANARY();

            zip32_child(tmp.step1.zip32_seed, tmp.step2.dk, tmp.step2.ask, tmp.step2.nsk, p);
            MEMZERO(tmp.step2.ask,sizeof_field(tmp_sapling_addr_s, step2.ask));
            MEMZERO(tmp.step2.nsk,sizeof_field(tmp_sapling_addr_s, step2.nsk));
            CHECK_APP_CANARY();

            get_diversifier_list_withstartindex(tmp.step2.dk,startindex,buffer);
            for(int i = 0; i < DIV_LIST_LENGTH; i++){
                if (!is_valid_diversifier(buffer+i*DIV_SIZE)){
                    MEMZERO(buffer+i*DIV_SIZE,DIV_SIZE);
                }
            }

            MEMZERO(&tmp, sizeof(tmp_sapling_addr_s));

        }
        FINALLY
        {
            // Not necessary, but just in case
            MEMZERO(&tmp, sizeof(tmp_sapling_addr_s));
        }
    }
    END_TRY;
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
            uint8_t diversifierlist[DIV_DEFAULT_LIST_LEN * DIV_SIZE];
        };
    };
} tmp_buf_addr_s;

zxerr_t crypto_fillAddress_with_diversifier_sapling(uint8_t *buffer, uint16_t bufferLen, uint32_t p, uint8_t *div, uint16_t *replyLen) {
    if (bufferLen < sizeof(tmp_buf_addr_s)) {
        return zxerr_unknown;
    }

    MEMZERO(buffer, bufferLen);

    zemu_log_stack("crypto_fillAddress_sapling");

    tmp_buf_addr_s *const out = (tmp_buf_addr_s *) buffer;
    MEMZERO(out, bufferLen);

    tmp_sapling_addr_s tmp;
    MEMZERO(&tmp, sizeof(tmp_sapling_addr_s));

    MEMCPY(out->diversifier, div, DIV_SIZE);
    if (!is_valid_diversifier(out->diversifier)){
        return zxerr_unknown;
    }

    BEGIN_TRY
    {
        TRY
        {
            // Temporarily get sk from Ed25519
            crypto_fillSaplingSeed(tmp.step1.zip32_seed);
            CHECK_APP_CANARY();

            zip32_child(tmp.step1.zip32_seed, tmp.step2.dk, tmp.step2.ask, tmp.step2.nsk, p);
            ask_to_ak(tmp.step2.ask,tmp.step3.ak);
            nsk_to_nk(tmp.step2.nsk,tmp.step3.nk);
            CHECK_APP_CANARY();

            MEMZERO(tmp.step2.dk, sizeof_field(tmp_sapling_addr_s, step2.dk));

            get_ivk(tmp.step3.ak, tmp.step3.nk, tmp.step3.ivk);
            CHECK_APP_CANARY();
            MEMZERO(tmp.step3.ak, sizeof_field(tmp_sapling_addr_s, step3.ak));
            MEMZERO(tmp.step3.nk, sizeof_field(tmp_sapling_addr_s, step3.nk));

            zemu_log_stack("get_pkd");

            get_pkd(tmp.step3.ivk, out->diversifier, out->pkd);
            CHECK_APP_CANARY();
            MEMZERO(tmp.step3.ivk, sizeof_field(tmp_sapling_addr_s, step3.ivk));
        }
        FINALLY
        {
            // Not necessary, but just in case
            MEMZERO(&tmp, sizeof(tmp_sapling_addr_s));
        }
    }
    END_TRY;

    zxerr_t berr = bech32EncodeFromBytes(out->address_bech32, sizeof_field(tmp_buf_addr_s, address_bech32),
                          BECH32_HRP,
                          out->address_raw,
                          sizeof_field(tmp_buf_addr_s, address_raw),
                          1);
    if(berr != zxerr_ok){
        MEMZERO(out, bufferLen);
        MEMZERO(&tmp, sizeof(tmp_sapling_addr_s));
        *replyLen = 0;
        return berr;
    }
    CHECK_APP_CANARY();

    *replyLen = sizeof_field(tmp_buf_addr_s, address_raw) + strlen((const char *) out->address_bech32);
    return zxerr_ok;
}


zxerr_t crypto_fillAddress_sapling(uint8_t *buffer, uint16_t bufferLen, uint32_t p, uint16_t *replyLen) {
    if (bufferLen < sizeof(tmp_buf_addr_s)) {
        return zxerr_unknown;
    }

    MEMZERO(buffer, bufferLen);

    zemu_log_stack("crypto_fillAddress_sapling");

    tmp_buf_addr_s *const out = (tmp_buf_addr_s *) buffer;
    MEMZERO(out, bufferLen);

    tmp_sapling_addr_s tmp;
    MEMZERO(&tmp, sizeof(tmp_sapling_addr_s));
    //the path in zip32 is [FIRST_VALUE, COIN_TYPE, p] where p is u32 and last part of hdPath
    BEGIN_TRY
    {
        TRY
        {
            // Temporarily get sk from Ed25519
            crypto_fillSaplingSeed(tmp.step1.zip32_seed);
            CHECK_APP_CANARY();

            zip32_child(tmp.step1.zip32_seed, tmp.step2.dk, tmp.step2.ask, tmp.step2.nsk,p);
            ask_to_ak(tmp.step2.ask,tmp.step3.ak);
            nsk_to_nk(tmp.step2.nsk,tmp.step3.nk);
            CHECK_APP_CANARY();

            bool found = false;
            while(!found){
                get_default_diversifier_list_withstartindex(tmp.step2.dk, out->startindex, out->diversifierlist);
                uint8_t *ptr = out->diversifierlist;
                for(uint8_t i = 0; i < DIV_DEFAULT_LIST_LEN; i++, ptr += DIV_SIZE){
                    if(!found && is_valid_diversifier(ptr)){
                        MEMCPY(out->diversifier, ptr, DIV_SIZE);
                        MEMZERO(out + DIV_SIZE, MAX_SIZE_BUF_ADDR - DIV_SIZE);
                        MEMZERO(tmp.step2.dk, sizeof_field(tmp_sapling_addr_s, step2.dk));
                        found = true;
                    }
                }
            }
            CHECK_APP_CANARY();
            if(!is_valid_diversifier(out->diversifier)){
                *replyLen = 0;
                CLOSE_TRY;
                return zxerr_unknown;
            }

            get_ivk(tmp.step3.ak, tmp.step3.nk, tmp.step3.ivk);
            CHECK_APP_CANARY();
            MEMZERO(tmp.step3.ak, sizeof_field(tmp_sapling_addr_s, step3.ak));
            MEMZERO(tmp.step3.nk, sizeof_field(tmp_sapling_addr_s, step3.nk));

            zemu_log_stack("get_pkd");
            get_pkd(tmp.step3.ivk, out->diversifier, out->pkd);
            CHECK_APP_CANARY();
            MEMZERO(tmp.step3.ivk, sizeof_field(tmp_sapling_addr_s, step3.ivk));
        }
        FINALLY
        {
            // Not necessary, but just in case
            MEMZERO(&tmp, sizeof(tmp_sapling_addr_s));
        }
    }
    END_TRY;

    zxerr_t berr = bech32EncodeFromBytes(out->address_bech32, sizeof_field(tmp_buf_addr_s, address_bech32),
                          BECH32_HRP,
                          out->address_raw,
                          sizeof_field(tmp_buf_addr_s, address_raw),
                          1);
    if(berr != zxerr_ok){
        MEMZERO(out, bufferLen);
        MEMZERO(&tmp, sizeof(tmp_sapling_addr_s));
        *replyLen = 0;
        return berr;
    }

    CHECK_APP_CANARY();

    *replyLen = sizeof_field(tmp_buf_addr_s, address_raw) + strlen((const char *) out->address_bech32);
    return zxerr_ok;
}

#endif

