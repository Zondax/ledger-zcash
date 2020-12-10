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
#include "view.h"

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

uint16_t crypto_fillAddress_secp256k1(uint8_t *buffer, uint16_t buffer_len) {
    if (buffer_len < sizeof(answer_t)) {
        return 0;
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
    encode_base58(address_temp.address, VERSION_SIZE + CX_RIPEMD160_SIZE + CHECKSUM_SIZE, answer->address, &outLen);

    return PK_LEN_SECP256K1 + outLen;
}

void crypto_extractPublicKey(const uint32_t path[HDPATH_LEN_DEFAULT], uint8_t *pubKey, uint16_t pubKeyLen) {
    cx_ecfp_public_key_t cx_publicKey;
    cx_ecfp_private_key_t cx_privateKey;
    uint8_t privateKeyData[32];

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

            cx_ecfp_init_private_key(CX_CURVE_256K1, privateKeyData, 32, &cx_privateKey);
            cx_ecfp_init_public_key(CX_CURVE_256K1, NULL, 0, &cx_publicKey);
            cx_ecfp_generate_pair(CX_CURVE_256K1, &cx_publicKey, &cx_privateKey, 1);
        }
        FINALLY {
            MEMZERO(&cx_privateKey, sizeof(cx_privateKey));
            MEMZERO(privateKeyData, 32);
        }
    }
    END_TRY;

    // Format pubkey
    for (int i = 0; i < 32; i++) {
        pubKey[i] = cx_publicKey.W[64 - i];
    }
    cx_publicKey.W[0] = cx_publicKey.W[64] & 1 ? 0x03 : 0x02; // "Compress" public key in place
    if ((cx_publicKey.W[32] & 1) != 0) {
        pubKey[31] |= 0x80;
    }

    memcpy(pubKey, cx_publicKey.W, PK_LEN_SECP256K1);
}

typedef struct {
    uint8_t r[32];
    uint8_t s[32];
    uint8_t v;

    // DER signature max size should be 73
    // https://bitcoin.stackexchange.com/questions/77191/what-is-the-maximum-size-of-a-der-encoded-ecdsa-signature#77192
    uint8_t der_signature[73];

} __attribute__((packed)) signature_t;

uint16_t crypto_sign(uint8_t *buffer, uint16_t signatureMaxlen, const uint8_t *message, uint16_t messageLen) {
    uint8_t tmp[CX_SHA256_SIZE];
    uint8_t message_digest[CX_SHA256_SIZE];

    // FIXME: Demonstrate double sha256 hashing. During M2 fully compatible signatures will be delivered
    // This partial process demonstrate we cna overcome memory limitations
    cx_hash_sha256(message, messageLen, tmp, CX_SHA256_SIZE);
    cx_hash_sha256(tmp, CX_SHA256_SIZE, message_digest, CX_SHA256_SIZE);

    /// Now sign
    cx_ecfp_private_key_t cx_privateKey;
    uint8_t privateKeyData[32];
    int signatureLength;
    unsigned int info = 0;

    signature_t *const signature = (signature_t *) buffer;

    BEGIN_TRY
    {
        TRY
        {
            // Generate keys
            os_perso_derive_node_bip32(CX_CURVE_256K1,
                                       hdPath,
                                       HDPATH_LEN_DEFAULT,
                                       privateKeyData, NULL);

            cx_ecfp_init_private_key(CX_CURVE_256K1, privateKeyData, 32, &cx_privateKey);

            // Sign
            signatureLength = cx_ecdsa_sign(&cx_privateKey,
                                            CX_RND_RFC6979 | CX_LAST,
                                            CX_SHA256,
                                            message_digest,
                                            CX_SHA256_SIZE,
                                            signature->der_signature,
                                            sizeof_field(signature_t, der_signature),
                                            &info);

        }
        FINALLY {
            MEMZERO(&cx_privateKey, sizeof(cx_privateKey));
            MEMZERO(privateKeyData, 32);
        }
    }
    END_TRY;

    err_convert_e err = convertDERtoRSV(signature->der_signature, info,  signature->r, signature->s, &signature->v);
    if (err != no_error) {
        // Error while converting so return length 0
        return 0;
    }

    // return actual size using value from signatureLength
    return sizeof_field(signature_t, r) + sizeof_field(signature_t, s) + sizeof_field(signature_t, v) + signatureLength;
}

void crypto_fillSaplingSeed(uint8_t *sk) {
    // Get seed from Ed25519
    MEMZERO(sk, 32);
    //fixme: make sure this path is not used somewhere else for signing
    // Generate randomness using a fixed path related to the device mnemonic
    const uint32_t path[HDPATH_LEN_DEFAULT] = {
            0x8000002c,
            0x80000085,
            0x80000000,
            0x80000000,
            0x80000000,
    };

    os_perso_derive_node_bip32_seed_key(HDW_NORMAL, CX_CURVE_Ed25519,
                                        path, HDPATH_LEN_DEFAULT,
                                        sk,
                                        NULL,
                                        NULL, 0);
}

typedef struct {
    union {
        struct {
            uint8_t diversifier[11];
            uint8_t pkd[32];
        };
        struct {
            uint8_t address_raw[43];
            char address_bech32[100];
        };
        struct {
            uint8_t dummy[43];
            uint8_t diversifierlist[110];
        };

        struct {
            uint8_t ivk[32];
        };

        struct {
            uint8_t ak[32];
            uint8_t nsk[32];
            uint8_t rcm[32];
            uint8_t alpha[32];
        };
    };
} tmp_buf_s;

typedef struct {
    union {
        // STEP 1
        struct {
            uint32_t pos;
            uint8_t dk[32];
            uint8_t zip32_seed[32];
            uint8_t sk[32];
        } step1;

        struct {
            uint32_t pos;
            uint8_t dk[32];
            uint8_t ask[32];
            uint8_t nsk[32];
        } step2;
        // STEP 2
        struct {
            uint32_t pos;
            uint8_t ivk[32];
            uint8_t ak[32];
            uint8_t nk[32];
        } step3;
    };
} tmp_sampling_s;

uint16_t crypto_key_exchange(uint8_t *buffer, uint16_t bufferLen,  const uint8_t *txdata, const uint16_t txdatalen) {
    uint8_t pubkey[32];
    MEMCPY(pubkey, txdata, 32);
    uint8_t rnd1[32];
    uint8_t sessionkey[32];
    random_fr(rnd1);
    sessionkey_agree(rnd1,pubkey,sessionkey);
    set_session_key(sessionkey);
    pubkey_gen(rnd1,buffer);
    return 32;
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
        uint8_t rnd1[32];
        uint8_t rnd2[32];
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
        uint8_t rnd1[32];
        uint8_t rnd2[32];
        random_fr(rnd1);
        cx_rng(rnd2, 32);
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

zxerr_t crypto_extract_spend_proofkeyandrnd(uint8_t *buffer, uint16_t bufferLen){
    if(bufferLen < sizeof(tmp_buf_s)){
        return zxerr_unknown;
    }

    if(!spendlist_more_extract()){
        return zxerr_unknown;
    }

    if(get_state() != STATE_PROCESSED_INPUTS){
        return zxerr_unknown;
    }

    //todo: warning that proofkey is extracted
    uint8_t *out = (uint8_t *) buffer;
    MEMZERO(out, bufferLen);

    const spend_item_t *next = spendlist_extract_next();
    if (next == NULL){
        return zxerr_unknown;
    }

    tmp_sampling_s tmp;
    MEMZERO(&tmp, sizeof(tmp_sampling_s));

    BEGIN_TRY
    {
        TRY
        {
            crypto_fillSaplingSeed(tmp.step1.zip32_seed);
            CHECK_APP_CANARY();

            zip32_child(tmp.step1.zip32_seed, tmp.step2.dk, tmp.step2.ask, out + 32, next->path);
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
    MEMZERO(&tmp, sizeof(tmp_sampling_s));
    CHECK_APP_CANARY();
    MEMCPY(out+64, next->rcm, 32);
    MEMCPY(out+96, next->alpha,32);

    if(!spendlist_more_extract()){
        set_state(STATE_PROCESSED_SPEND_EXTRACTIONS);
    }

    return zxerr_ok;
}

zxerr_t crypto_extract_output_rnd(uint8_t *buffer, uint16_t bufferLen){
    if(bufferLen < sizeof(tmp_buf_s)){
        return zxerr_unknown;
    }

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
    MEMCPY(out, next->rcmvalue, 32);
    MEMCPY(out+32, next->rseed,32);

    if(!outputlist_more_extract()){
        set_state(STATE_PROCESSED_ALL_EXTRACTIONS);
        view_message_show("Zcash", "Step [2/5]");
        UX_WAIT_DISPLAYED();
    }
    return zxerr_ok;
}

typedef struct {
    union {
        struct {
            uint8_t gd[32]; //computed from receiver diversifier
            uint8_t pkd[32]; //get this from host and show on screen for verification
        } step2;

        struct {
            uint8_t inputhash[73];
        } step3;

        struct{
            uint8_t notecommitment[32];
            uint8_t valuecommitment[32];
        } step4;
    };
} tmp_notecommit;

zxerr_t crypto_check_prevouts(uint8_t *buffer, uint16_t bufferLen, const uint8_t *txdata, const uint16_t txdatalen){
    zemu_log_stack("crypto_checkprevoouts_sapling");
    if (bufferLen < sizeof(tmp_buf_s)) {
        return zxerr_unknown;
    }
    MEMZERO(buffer, bufferLen);

    if(get_state() != STATE_PROCESSED_ALL_EXTRACTIONS){
        return zxerr_unknown;
    }

    view_message_show("Zcash", "Step [3/5]");
    UX_WAIT_DISPLAYED();

    uint8_t hash[32];
    prevouts_hash(txdata,hash);

    if(MEMCMP(hash, txdata + start_sighashdata() + INDEX_HASH_PREVOUTSHASH, 32) != 0){
        return zxerr_unknown;
    }
    return zxerr_ok;
}

zxerr_t crypto_check_sequence(uint8_t *buffer, uint16_t bufferLen, const uint8_t *txdata, const uint16_t txdatalen){
    zemu_log_stack("crypto_checksequence_sapling");
    if (bufferLen < sizeof(tmp_buf_s)) {
        return zxerr_unknown;
    }
    MEMZERO(buffer, bufferLen);
    if(get_state() != STATE_PROCESSED_ALL_EXTRACTIONS){
        return zxerr_unknown;
    }

    uint8_t hash[32];
    sequence_hash(txdata, hash);
    if(MEMCMP(hash, txdata + start_sighashdata() + INDEX_HASH_SEQUENCEHASH, 32) != 0){
        return zxerr_unknown;
    }
    return zxerr_ok;
}

zxerr_t crypto_check_outputs(uint8_t *buffer, uint16_t bufferLen, const uint8_t *txdata, const uint16_t txdatalen){
    zemu_log_stack("crypto_checkoutputs_sapling");
    if (bufferLen < sizeof(tmp_buf_s)) {
        return zxerr_unknown;
    }
    if(length_t_in_data() + length_spenddata() + length_outputdata() + LENGTH_HASH_DATA != txdatalen){
        return zxerr_unknown;
    }
    if(get_state() != STATE_PROCESSED_ALL_EXTRACTIONS){
        return zxerr_unknown;
    }

    MEMZERO(buffer, bufferLen);
    uint8_t hash[32];
    outputs_hash(hash);
    if(MEMCMP(hash, txdata + start_sighashdata() + INDEX_HASH_OUTPUTSHASH, 32) != 0){
        return zxerr_unknown;
    }
    return zxerr_ok;
}

zxerr_t crypto_check_joinsplits(uint8_t *buffer, uint16_t bufferLen, const uint8_t *txdata, const uint16_t txdatalen){
    zemu_log_stack("crypto_checkjoinsplits_sapling");
    if (bufferLen < sizeof(tmp_buf_s)) {
        return zxerr_unknown;
    }
    MEMZERO(buffer, bufferLen);
    if(get_state() != STATE_PROCESSED_ALL_EXTRACTIONS){
        return zxerr_unknown;
    }
    uint8_t hash[32];
    MEMZERO(hash,sizeof(hash));
    if(MEMCMP(hash, txdata + start_sighashdata() + INDEX_HASH_JOINSPLITSHASH, 32) != 0){
        return zxerr_unknown;
    }
    return zxerr_ok;
}

zxerr_t crypto_check_valuebalance(uint8_t *buffer, uint16_t bufferLen, const uint8_t *txdata, const uint16_t txdatalen){
    zemu_log_stack("crypto_checkvaluebalance_sapling");
    if (bufferLen < sizeof(tmp_buf_s)) {
        return zxerr_unknown;
    }
    MEMZERO(buffer, bufferLen);
    if(get_state() != STATE_PROCESSED_ALL_EXTRACTIONS){
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
        // STEP 1
        struct {
            uint8_t zip32_seed[32];
        } step1;

        struct {
            uint8_t ask[32];
            uint8_t nsk[32];
        } step2;
    };
} tmp_checkspend;

zxerr_t crypto_checkspend_sapling(uint8_t *buffer, uint16_t bufferLen, const uint8_t *txdata, const uint16_t txdatalen) {
    if (bufferLen < sizeof(tmp_buf_s)) {
        return zxerr_unknown;
    }
    MEMZERO(buffer, bufferLen);

    if(length_t_in_data() + length_spenddata() + length_outputdata() + LENGTH_HASH_DATA != txdatalen){
        return zxerr_unknown;
    }

    if(get_state() != STATE_PROCESSED_ALL_EXTRACTIONS){
        return zxerr_unknown;
    }

    zemu_log_stack("crypto_checkspend_sapling");

    uint8_t *out = (uint8_t *) buffer;
    MEMZERO(out, bufferLen);

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
                    return 0;
                }
                zip32_child_ask_nsk(tmp.step1.zip32_seed, tmp.step2.ask, tmp.step2.nsk, item->path);

                randomized_secret(tmp.step2.ask, (uint8_t *)item->alpha, tmp.step2.ask);
                sk_to_pk(tmp.step2.ask, tmp.step2.ask);

                if(MEMCMP(tmp.step2.ask, start_spenddata + INDEX_SPEND_RK + i * SPEND_TX_LEN,32) != 0){
                    //maybe spendlist_reset();
                    MEMZERO(&tmp, sizeof(tmp_checkspend));
                    return zxerr_unknown;
                }

                compute_value_commitment(item->value,item->rcm,tmp.step2.ask);
                if (MEMCMP(tmp.step2.ask, start_spenddata + INDEX_SPEND_VALUECMT + i *SPEND_TX_LEN,32) != 0){
                    //maybe spendlist_reset();
                    MEMZERO(&tmp, sizeof(tmp_checkspend));
                    return zxerr_unknown;
                }

                group_hash_from_div(item->div, tmp.step2.ask);
                prepare_input_notecmt(item->value, tmp.step2.ask, item->pkd, out);
                pedersen_hash_73bytes(out,out);
                compute_note_commitment_fullpoint(out, start_spendolddata + INDEX_SPEND_OLD_RCM + i * SPEND_OLD_TX_LEN);
                nsk_to_nk(tmp.step2.nsk,tmp.step2.nsk);
                uint64_t notepos = 0;
                {
                    parser_context_t pars_ctx;
                    parser_error_t pars_err;

                    pars_ctx.offset = 0;
                    pars_ctx.buffer = start_spendolddata + INDEX_SPEND_OLD_NOTEPOS + i * SPEND_OLD_TX_LEN;
                    pars_ctx.bufferLen = 8;
                    pars_err = _readUInt64(&pars_ctx, &notepos);
                    if (pars_err != parser_ok){
                        return 0;
                    }
                }

                compute_nullifier(out, notepos, tmp.step2.nsk, out);
                if (MEMCMP(out, start_spenddata + INDEX_SPEND_NF + i * SPEND_TX_LEN,32) != 0){
                    //maybe spendlist_reset();
                    MEMZERO(out, bufferLen);
                    MEMZERO(&tmp, sizeof(tmp_checkspend));
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
        shielded_spend_hash(start_spenddata, length_spend_new_data(), out);
    }
    if(MEMCMP(out, txdata + start_sighashdata() + INDEX_HASH_SHIELDEDSPENDHASH, 32) != 0){
        return zxerr_unknown;
    }

    return zxerr_ok; //or some code for ok
}

zxerr_t crypto_checkoutput_sapling(uint8_t *buffer, uint16_t bufferLen, const uint8_t *txdata, const uint16_t txdatalen) {
    if (bufferLen < sizeof(tmp_buf_s)) {
        return zxerr_unknown;
    }
    MEMZERO(buffer, bufferLen);

    if(get_state() != STATE_PROCESSED_ALL_EXTRACTIONS){
        return zxerr_unknown;
    }

    if(length_t_in_data() + length_spenddata() + length_outputdata() + LENGTH_HASH_DATA != txdatalen){
        return zxerr_unknown;
    }

    uint8_t *start_outputdata = (uint8_t *) (txdata + length_t_in_data() + length_spenddata());

    zemu_log_stack("crypto_checkoutput_sapling");

    uint8_t *out = (uint8_t *) buffer;
    MEMZERO(out, bufferLen);

    tmp_notecommit ncm;
    MEMZERO(&ncm, sizeof(tmp_notecommit));

    uint8_t rcm[32];

    //the path in zip32 is [FIRST_VALUE, COIN_TYPE, p] where p is u32 and last part of hdPath
    BEGIN_TRY
    {
        TRY
        {
            for(uint8_t i = 0; i < outputlist_len(); i++){
                const output_item_t *item = outputlist_retrieve_item(i);
                if (item == NULL){
                    return 0;
                }
                group_hash_from_div(item->div, ncm.step2.gd);

                prepare_input_notecmt(item->value, ncm.step2.gd, item->pkd, ncm.step3.inputhash);

                pedersen_hash_73bytes(ncm.step3.inputhash,ncm.step4.notecommitment);
                rseed_get_rcm(item->rseed,rcm);
                compute_note_commitment(ncm.step4.notecommitment,rcm);
                compute_value_commitment(item->value, item->rcmvalue, ncm.step4.valuecommitment);

                if (MEMCMP(ncm.step4.valuecommitment, start_outputdata + INDEX_OUTPUT_VALUECMT + i * OUTPUT_TX_LEN,32) != 0 || MEMCMP(ncm.step4.notecommitment, start_outputdata + INDEX_OUTPUT_NOTECMT + i * OUTPUT_TX_LEN,32) != 0){
                    MEMZERO(&ncm, sizeof(tmp_notecommit));
                    return zxerr_unknown;
                }
                MEMZERO(&ncm, sizeof(tmp_notecommit));
            }
            MEMZERO(&ncm, sizeof(tmp_notecommit));
        }
        FINALLY
        {
            // Not necessary, but just in case
            MEMZERO(&ncm, sizeof(tmp_notecommit));
        }
    }
    END_TRY;

    MEMZERO(out, bufferLen);
    if (outputlist_len() > 0){
        shielded_output_hash(start_outputdata, length_outputdata(), out);
    }
    if(MEMCMP(out, txdata + start_sighashdata() + INDEX_HASH_SHIELDEDOUTPUTHASH, 32) != 0){
        return zxerr_unknown;
    }

    return zxerr_ok; //or some code for ok
}

typedef struct {
    union {
        // STEP 1
        struct {
            uint8_t dummy[96];
            uint8_t epk[32]; //computed from receiver diversifier
            uint8_t esk[32];
        } step1;

        struct{
            uint8_t dummy[11];
            uint8_t compactout[53];
            uint8_t sharedkey[32];
            uint8_t epk[32];
            uint8_t esk[32];
        } step2;

        struct{
            uint8_t ovk[32];
            uint8_t valuecmt[32];
            uint8_t notecmt[32];
            uint8_t epk[32];
            uint8_t esk[32];
        }step3;

        struct{
            uint8_t prfinput[128];
            uint8_t esk[32];
        }step4;

        struct{
            uint8_t outkey[32];
            uint8_t dummy[64];
            uint8_t pkd[32];
            uint8_t esk[32];
        }step5;

        struct{
            uint8_t outkey[32];
            uint8_t dummy[64];
            uint8_t encciph[64];
        }step6;
    };
} tmp_enc;

zxerr_t crypto_checkencryptions_sapling(uint8_t *buffer, uint16_t bufferLen, const uint8_t *txdata, const uint16_t txdatalen) {
    if (bufferLen < sizeof(tmp_buf_s)) {
        return zxerr_unknown;
    }
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

        get_epk(tmp->step1.esk, (uint8_t *) item->div, tmp->step1.epk);
        if (MEMCMP(tmp->step1.epk, start_outputdata + INDEX_OUTPUT_EPK + i * OUTPUT_TX_LEN, 32) != 0){
            MEMZERO(out, bufferLen);
            return zxerr_unknown;
        }

        ka_to_key(tmp->step1.esk, (uint8_t *) item->pkd, tmp->step1.epk, tmp->step2.sharedkey);
        prepare_enccompact_input((uint8_t *) item->div, item->value, (uint8_t *) item->rseed, item->memotype, tmp->step2.compactout);

        uint8_t nonce[12] = {0,0,0,0,0,0,0,0,0,0,0,0};
        uint32_t counter = 1;
        chacha(tmp->step2.compactout, tmp->step2.compactout, 53, tmp->step2.sharedkey, nonce,counter);

        if (MEMCMP(tmp->step2.compactout, start_outputdata + INDEX_OUTPUT_ENC + i * OUTPUT_TX_LEN, 53) != 0){
            MEMZERO(out, bufferLen);
            return zxerr_unknown;
        }

        MEMCPY(tmp->step3.ovk, item->ovk, 32);
        MEMZERO(out + 160, 32);
        if(MEMCMP(tmp->step3.ovk, out + 160, 32) != 0){
            MEMCPY(tmp->step3.valuecmt, start_outputdata + INDEX_OUTPUT_VALUECMT + i* OUTPUT_TX_LEN,32);
            MEMCPY(tmp->step3.notecmt, start_outputdata + INDEX_OUTPUT_NOTECMT + i* OUTPUT_TX_LEN,32);

            blake2b_prf(tmp->step4.prfinput, tmp->step5.outkey);
            MEMCPY(tmp->step5.pkd, item->pkd, 32);

            counter = 1;

            chacha(tmp->step6.encciph, tmp->step6.encciph, 64, tmp->step6.outkey, nonce,counter);

            if (MEMCMP(tmp->step6.encciph, start_outputdata + INDEX_OUTPUT_OUT + i * OUTPUT_TX_LEN, 64) != 0){
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
    uint8_t script[26];
    script[0] = 0x19;
    script[1] = 0x76;
    script[2] = 0xa9;
    script[3] = 0x14;

    uint8_t tmp[32];
    cx_hash_sha256(address, PK_LEN_SECP256K1, tmp, CX_SHA256_SIZE);
    ripemd160(tmp, CX_SHA256_SIZE, script+4);
    script[24] = 0x88;
    script[25] = 0xac;
    MEMCPY(output,script,26);
}

typedef struct {
    union {
        // STEP 1
        struct {
            uint8_t r[32];
            uint8_t s[32];
            uint8_t v;
            // DER signature max size should be 73
            // https://bitcoin.stackexchange.com/questions/77191/what-is-the-maximum-size-of-a-der-encoded-ecdsa-signature#77192
            uint8_t der_signature[73];
        } step1;

        struct {
            uint8_t rs[64];
            uint8_t dummy[74];
        } step2;
    };
} __attribute__((packed)) signature_tr;

zxerr_t crypto_sign_and_check_transparent(uint8_t *buffer, uint16_t bufferLen, const uint8_t *txdata, const uint16_t txdatalen) {
    zemu_log_stack("crypto_signchecktransparent_sapling");
    if(t_inlist_len() == 0){
        return zxerr_ok;
    }
    if (bufferLen < sizeof(tmp_buf_s)) {
        return zxerr_unknown;
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
    uint8_t privateKeyData[32];
    uint8_t pubKey[33];
    uint8_t script[26];
    uint8_t message_digest[32];

    unsigned int info = 0;
    signature_tr *const signature = (signature_tr *) buffer;
    int signatureLength;

    view_message_show("Zcash", "Step [4/5]");
    UX_WAIT_DISPLAYED();

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
                cx_ecfp_init_private_key(CX_CURVE_256K1, privateKeyData, 32, &cx_privateKey);
                cx_ecfp_init_public_key(CX_CURVE_256K1, NULL, 0, &cx_publicKey);
                cx_ecfp_generate_pair(CX_CURVE_256K1, &cx_publicKey, &cx_privateKey, 1);

                for (int i = 0; i < 32; i++) {
                    pubKey[i] = cx_publicKey.W[64 - i];
                 }
                cx_publicKey.W[0] = cx_publicKey.W[64] & 1 ? 0x03 : 0x02; // "Compress" public key in place
                if ((cx_publicKey.W[32] & 1) != 0) {
                    pubKey[31] |= 0x80;
                }
                MEMCPY(pubKey, cx_publicKey.W, PK_LEN_SECP256K1);
                address_to_script(pubKey,script);
                if(MEMCMP(script,(uint8_t *)(start_tindata + INDEX_TIN_SCRIPT + i * T_IN_TX_LEN), 26) != 0){
                    return zxerr_unknown;
                }
                if(MEMCMP(item->script, script,26) !=0){
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
                        return 0;
                    }
                }

                if(value != item->value){
                    return zxerr_unknown;
                }
                signature_script_hash(start_signdata, 220, start_tindata + i * T_IN_TX_LEN, T_IN_TX_LEN, message_digest);
                signatureLength = cx_ecdsa_sign(&cx_privateKey,
                                            CX_RND_RFC6979 | CX_LAST,
                                            CX_SHA256,
                                            message_digest,
                                            CX_SHA256_SIZE,
                                            signature->step1.der_signature,
                                            73,
                                            &info);
                err_convert_e err = convertDERtoRSV(signature->step1.der_signature, info,  signature->step1.r, signature->step1.s, &signature->step1.v);
                if (err != no_error) {
                // Error while converting so return length 0
                return zxerr_unknown;
                }
                transparent_signatures_append(signature->step2.rs);
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

zxerr_t crypto_signspends_sapling(uint8_t *buffer, uint16_t bufferLen, const uint8_t *txdata, const uint16_t txdatalen) {
    zemu_log_stack("crypto_signspends_sapling");
    if(spendlist_len() == 0){
        return zxerr_ok;
    }

    if (bufferLen < sizeof(tmp_buf_s)) {
        return zxerr_unknown;
    }
    MEMZERO(buffer, bufferLen);

    if(get_state() != STATE_VERIFIED_ALL_TXDATA ){
        return zxerr_unknown;
    }

    if(length_t_in_data() + length_spenddata() + length_outputdata() + LENGTH_HASH_DATA != txdatalen){
        return zxerr_unknown;
    }

    uint8_t *start_signdata = (uint8_t *)(txdata + start_sighashdata());

    uint8_t sighash[32];

    uint8_t *out = (uint8_t *) buffer;
    MEMZERO(out, bufferLen);

    signature_hash(start_signdata,LENGTH_HASH_DATA,sighash);

    tmp_sampling_s tmp;
    MEMZERO(&tmp, sizeof(tmp_sampling_s));

    //the path in zip32 is [FIRST_VALUE, COIN_TYPE, p] where p is u32 and last part of hdPath
    BEGIN_TRY
    {
        TRY
        {
            // Temporarily get sk from Ed25519
            CHECK_APP_CANARY();
            //fixme: can we get rid of loading the side n times?
            for(uint8_t i = 0; i < spendlist_len(); i++){
                crypto_fillSaplingSeed(tmp.step1.zip32_seed);
                const spend_item_t *item = spendlist_retrieve_item(i);
                /*if (item == NULL){
                    return 0;
                }
                */
                zip32_child(tmp.step1.zip32_seed, tmp.step2.dk, tmp.step2.ask, tmp.step2.nsk, item->path);

                randomized_secret(tmp.step2.ask, (uint8_t *)item->alpha, tmp.step2.ask);
                sign_redjubjub((uint8_t *)tmp.step2.ask, (uint8_t *)sighash, (uint8_t *)out);
                spend_signatures_append(out);
                MEMZERO(&tmp, sizeof(tmp_sampling_s));
            }

            MEMZERO(&tmp, sizeof(tmp_sampling_s));
        }
        FINALLY
        {
            // Not necessary, but just in case
            MEMZERO(&tmp, sizeof(tmp_sampling_s));
        }
    }
    END_TRY;

    view_message_show("Zcash", "Step [5/5]");
    UX_WAIT_DISPLAYED();

    CHECK_APP_CANARY();
    return zxerr_ok;
}

zxerr_t crypto_extract_transparent_signature(uint8_t *buffer, uint16_t bufferLen){
    if(bufferLen < sizeof(tmp_buf_s)){
        return zxerr_unknown;
    }

    if(!transparent_signatures_more_extract()){
        return zxerr_unknown;
    }

    if(get_state() != STATE_VERIFIED_ALL_TXDATA){
        return zxerr_unknown;
    }

    uint8_t *out = (uint8_t *) buffer;
    MEMZERO(out, bufferLen);

    zxerr_t err = get_next_transparent_signature(out);
    return err;
}

zxerr_t crypto_extract_spend_signature(uint8_t *buffer, uint16_t bufferLen){
    if(bufferLen < sizeof(tmp_buf_s)){
        return zxerr_unknown;
    }

    if(!spend_signatures_more_extract()){
        return zxerr_unknown;
    }

    if(get_state() != STATE_VERIFIED_ALL_TXDATA){
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

uint16_t crypto_ivk_sapling(uint8_t *buffer, uint16_t bufferLen) {
    if (bufferLen < sizeof(tmp_buf_s)) {
        return 0;
    }

    parser_context_t pars_ctx;
    parser_error_t pars_err;
    pars_ctx.offset = 0;
    pars_ctx.buffer = buffer + OFFSET_DATA;
    pars_ctx.bufferLen = 4;
    uint32_t p = 0;
    pars_err = _readUInt32(&pars_ctx, &p);
    if (pars_err != parser_ok){
        return zxerr_unknown;
    }

    MEMZERO(buffer, bufferLen);

    zemu_log_stack("crypto_ivk_sapling");

    tmp_buf_s *const out = (tmp_buf_s *) buffer;
    MEMZERO(out, bufferLen);

    tmp_sampling_s tmp;
    MEMZERO(&tmp, sizeof(tmp_sampling_s));

    //the path in zip32 is [FIRST_VALUE, COIN_TYPE, p] where p is u32 and last part of hdPath
    tmp.step1.pos = p | 0x80000000;
    BEGIN_TRY
    {
        TRY
        {
            // Temporarily get sk from Ed25519
            crypto_fillSaplingSeed(tmp.step1.zip32_seed);
            CHECK_APP_CANARY();
            zip32_child(tmp.step1.zip32_seed, tmp.step2.dk, tmp.step2.ask, tmp.step2.nsk, tmp.step1.pos);
            ask_to_ak(tmp.step2.ask,tmp.step3.ak);
            nsk_to_nk(tmp.step2.nsk,tmp.step3.nk);
            CHECK_APP_CANARY();

            get_ivk(tmp.step3.ak, tmp.step3.nk, out->ivk);
            CHECK_APP_CANARY();

            MEMZERO(&tmp, sizeof(tmp_sampling_s));
        }
        FINALLY
        {
            // Not necessary, but just in case
            MEMZERO(&tmp, sizeof(tmp_sampling_s));
        }
    }
    END_TRY;
    CHECK_APP_CANARY();
    return sizeof_field(tmp_buf_s, ivk);
}

uint16_t crypto_ovk_sapling(uint8_t *buffer, uint16_t bufferLen) {
    if (bufferLen < sizeof(tmp_buf_s)) {
        return 0;
    }

    parser_context_t pars_ctx;
    parser_error_t pars_err;
    pars_ctx.offset = 0;
    pars_ctx.buffer = buffer + OFFSET_DATA;
    pars_ctx.bufferLen = 4;
    uint32_t p = 0;
    pars_err = _readUInt32(&pars_ctx, &p);
    if (pars_err != parser_ok){
        return zxerr_unknown;
    }

    MEMZERO(buffer, bufferLen);

    zemu_log_stack("crypto_ovk_sapling");

    uint8_t *out = (uint8_t *) buffer;
    MEMZERO(out, bufferLen);

    tmp_sampling_s tmp;
    MEMZERO(&tmp, sizeof(tmp_sampling_s));

    tmp.step1.pos = p | 0x80000000;

    BEGIN_TRY
    {
        TRY
        {
            // Temporarily get sk from Ed25519
            crypto_fillSaplingSeed(tmp.step1.zip32_seed);
            CHECK_APP_CANARY();
            zip32_ovk(tmp.step1.zip32_seed,out,tmp.step1.pos);
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
    return 32;
}

zxerr_t crypto_diversifier_with_startindex(uint8_t *buffer, uint16_t bufferLen, uint16_t *replylen) {
    if (bufferLen < sizeof(tmp_buf_s)) {
        return zxerr_unknown;
    }

    parser_context_t pars_ctx;
    parser_error_t pars_err;
    pars_ctx.offset = 0;
    pars_ctx.buffer = buffer + OFFSET_DATA;
    pars_ctx.bufferLen = 4;
    uint32_t p = 0;
    pars_err = _readUInt32(&pars_ctx, &p);
    if (pars_err != parser_ok){
        return zxerr_unknown;
    }

    uint8_t startindex[11];
    MEMCPY(startindex, (uint8_t *)(buffer + OFFSET_DATA + 4), 11);

    zemu_log_stack("crypto_get_diversifiers_sapling");

    tmp_sampling_s tmp;
    MEMZERO(&tmp, sizeof(tmp_sampling_s));
    //the path in zip32 is [FIRST_VALUE, COIN_TYPE, p] where p is u32 and last part of hdPath
    tmp.step1.pos = p | 0x80000000;

    BEGIN_TRY
    {
        TRY
        {
            // Temporarily get sk from Ed25519
            crypto_fillSaplingSeed(tmp.step1.zip32_seed);
            CHECK_APP_CANARY();

            zip32_child(tmp.step1.zip32_seed, tmp.step2.dk, tmp.step2.ask, tmp.step2.nsk, tmp.step1.pos);
            MEMZERO(tmp.step2.ask,sizeof_field(tmp_sampling_s, step2.ask));
            MEMZERO(tmp.step2.nsk,sizeof_field(tmp_sampling_s, step2.nsk));
            CHECK_APP_CANARY();

            get_diversifier_list_withstartindex(tmp.step2.dk,startindex,buffer);
            for(int i = 0; i < 20; i++){
                if (!is_valid_diversifier(buffer+i*11)){
                    MEMZERO(buffer+i*11,11);
                }
            }

            MEMZERO(&tmp, sizeof(tmp_sampling_s));

        }
        FINALLY
        {
            // Not necessary, but just in case
            MEMZERO(&tmp, sizeof(tmp_sampling_s));
        }
    }
    END_TRY;
    *replylen = 220;
    return zxerr_ok;
}

zxerr_t crypto_fillAddress_with_diversifier_sapling(uint8_t *buffer, uint16_t bufferLen, uint16_t *replyLen) {
    if (bufferLen < sizeof(tmp_buf_s)) {
        return zxerr_unknown;
    }

    parser_context_t pars_ctx;
    parser_error_t pars_err;
    pars_ctx.offset = 0;
    pars_ctx.buffer = buffer + OFFSET_DATA;
    pars_ctx.bufferLen = 4;
    uint32_t p = 0;
    pars_err = _readUInt32(&pars_ctx, &p);
    if (pars_err != parser_ok){
        return zxerr_unknown;
    }

    uint8_t div[11];
    MEMCPY(div, (uint8_t *)(buffer + OFFSET_DATA + 4), 11);

    MEMZERO(buffer, bufferLen);

    zemu_log_stack("crypto_fillAddress_sapling");

    tmp_buf_s *const out = (tmp_buf_s *) buffer;
    MEMZERO(out, bufferLen);

    tmp_sampling_s tmp;
    MEMZERO(&tmp, sizeof(tmp_sampling_s));

    tmp.step1.pos = p | 0x80000000;

    MEMCPY(out->diversifier, div, 11);
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

            zip32_child(tmp.step1.zip32_seed, tmp.step2.dk, tmp.step2.ask, tmp.step2.nsk, tmp.step1.pos);
            ask_to_ak(tmp.step2.ask,tmp.step3.ak);
            nsk_to_nk(tmp.step2.nsk,tmp.step3.nk);
            CHECK_APP_CANARY();

            MEMZERO(tmp.step2.dk, sizeof_field(tmp_sampling_s, step2.dk));

            get_ivk(tmp.step3.ak, tmp.step3.nk, tmp.step3.ivk);
            CHECK_APP_CANARY();
            MEMZERO(tmp.step3.ak, sizeof_field(tmp_sampling_s, step3.ak));
            MEMZERO(tmp.step3.nk, sizeof_field(tmp_sampling_s, step3.nk));

            zemu_log_stack("get_pkd");

            get_pkd(tmp.step3.ivk, out->diversifier, out->pkd);
            CHECK_APP_CANARY();
            MEMZERO(tmp.step3.ivk, sizeof_field(tmp_sampling_s, step3.ivk));
        }
        FINALLY
        {
            // Not necessary, but just in case
            MEMZERO(&tmp, sizeof(tmp_sampling_s));
        }
    }
    END_TRY;

    bech32EncodeFromBytes(out->address_bech32, sizeof_field(tmp_buf_s, address_bech32),
                          BECH32_HRP,
                          out->address_raw,
                          sizeof_field(tmp_buf_s, address_raw),
                          1);
    CHECK_APP_CANARY();

    *replyLen = sizeof_field(tmp_buf_s, address_raw) + strlen((const char *) out->address_bech32);
    return zxerr_ok;
}


uint16_t crypto_fillAddress_sapling(uint8_t *buffer, uint16_t bufferLen) {
    if (bufferLen < sizeof(tmp_buf_s)) {
        return 0;
    }

    parser_context_t pars_ctx;
    parser_error_t pars_err;
    pars_ctx.offset = 0;
    pars_ctx.buffer = buffer + OFFSET_DATA;
    pars_ctx.bufferLen = 4;
    uint32_t p = 0;
    pars_err = _readUInt32(&pars_ctx, &p);
    if (pars_err != parser_ok){
        return zxerr_unknown;
    }

    MEMZERO(buffer, bufferLen);

    zemu_log_stack("crypto_fillAddress_sapling");

    tmp_buf_s *const out = (tmp_buf_s *) buffer;
    MEMZERO(out, bufferLen);

    tmp_sampling_s tmp;
    MEMZERO(&tmp, sizeof(tmp_sampling_s));
    //the path in zip32 is [FIRST_VALUE, COIN_TYPE, p] where p is u32 and last part of hdPath
    tmp.step1.pos = p | 0x80000000;
    BEGIN_TRY
    {
        TRY
        {
            // Temporarily get sk from Ed25519
            crypto_fillSaplingSeed(tmp.step1.zip32_seed);
            CHECK_APP_CANARY();

            zip32_child(tmp.step1.zip32_seed, tmp.step2.dk, tmp.step2.ask, tmp.step2.nsk, tmp.step1.pos);
            ask_to_ak(tmp.step2.ask,tmp.step3.ak);
            nsk_to_nk(tmp.step2.nsk,tmp.step3.nk);
            CHECK_APP_CANARY();

            get_diversifier_list(tmp.step2.dk, out->diversifierlist);
            CHECK_APP_CANARY();
            MEMZERO(tmp.step2.dk, sizeof_field(tmp_sampling_s, step2.dk));

            //MEMZERO(tmp.step1.zip32_seed, sizeof_field(tmp_sampling_s, step1.zip32_seed));
            get_diversifier_fromlist(out->diversifier,out->diversifierlist);
            CHECK_APP_CANARY();
            if(!is_valid_diversifier(out->diversifier)){
                return 0;
            }

            get_ivk(tmp.step3.ak, tmp.step3.nk, tmp.step3.ivk);
            CHECK_APP_CANARY();
            MEMZERO(tmp.step3.ak, sizeof_field(tmp_sampling_s, step3.ak));
            MEMZERO(tmp.step3.nk, sizeof_field(tmp_sampling_s, step3.nk));

            zemu_log_stack("get_pkd");
            get_pkd(tmp.step3.ivk, out->diversifier, out->pkd);
            CHECK_APP_CANARY();
            MEMZERO(tmp.step3.ivk, sizeof_field(tmp_sampling_s, step3.ivk));
        }
        FINALLY
        {
            // Not necessary, but just in case
            MEMZERO(&tmp, sizeof(tmp_sampling_s));
        }
    }
    END_TRY;

    bech32EncodeFromBytes(out->address_bech32, sizeof_field(tmp_buf_s, address_bech32),
                          BECH32_HRP,
                          out->address_raw,
                          sizeof_field(tmp_buf_s, address_raw),
                          1);
    CHECK_APP_CANARY();

    return sizeof_field(tmp_buf_s, address_raw) + strlen((const char *) out->address_bech32);
}

#endif

