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

uint32_t hdPath[HDPATH_LEN_DEFAULT];

bool isTestnet() {
    return hdPath[0] == HDPATH_0_TESTNET &&
           hdPath[1] == HDPATH_1_TESTNET;
}

#if defined(TARGET_NANOS) || defined(TARGET_NANOX)
#include "cx.h"

void ripemd160(uint8_t *in, uint16_t inLen, uint8_t *out) {
    cx_ripemd160_t rip160;
    cx_ripemd160_init(&rip160);
    cx_hash(&rip160.header, CX_LAST, in, inLen, out, CX_RIPEMD160_SIZE);
}

typedef struct {
    uint8_t publicKey[SECP256K1_PK_LEN];
    uint8_t address[50];
} __attribute__((packed)) answer_t;

#define VERSION_SIZE            2
#define CHECKSUM_SIZE           4

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

    MEMZERO(buffer, buffer_len);
    answer_t *const answer = (answer_t *) buffer;

    crypto_extractPublicKey(hdPath, answer->publicKey, sizeof_field(answer_t, publicKey));

    address_temp_t address_temp;

    // extended-ripemd-160 = [version][ripemd-160(sha256(pk))]
    address_temp.version[0] = VERSION_P2PKH >> 8;
    address_temp.version[1] = VERSION_P2PKH & 0xFF;
    cx_hash_sha256(answer->publicKey, SECP256K1_PK_LEN, address_temp.sha256_pk, CX_SHA256_SIZE);      // SHA256
    ripemd160(address_temp.sha256_pk, CX_SHA256_SIZE, address_temp.ripe_sha256_pk);         // RIPEMD-160

    // checksum = sha256(sha256(extended-ripe))
    cx_hash_sha256(address_temp.extended_ripe, CX_RIPEMD160_SIZE + VERSION_SIZE, address_temp.sha256_extended_ripe, CX_SHA256_SIZE);
    cx_hash_sha256(address_temp.sha256_extended_ripe, CX_SHA256_SIZE, address_temp.sha256_checksum, CX_SHA256_SIZE);

    // 7. 25 bytes BTC address = [extended ripemd-160][checksum]
    // Encode as base58
    size_t outLen = sizeof_field(answer_t, address);
    encode_base58(address_temp.address, VERSION_SIZE + CX_RIPEMD160_SIZE + CHECKSUM_SIZE, answer->address, &outLen);

    return SECP256K1_PK_LEN + outLen;
}

void crypto_extractPublicKey(const uint32_t path[HDPATH_LEN_DEFAULT], uint8_t *pubKey, uint16_t pubKeyLen) {
    cx_ecfp_public_key_t cx_publicKey;
    cx_ecfp_private_key_t cx_privateKey;
    uint8_t privateKeyData[32];

    if (pubKeyLen < SECP256K1_PK_LEN) {
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

    memcpy(pubKey, cx_publicKey.W, SECP256K1_PK_LEN);
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

    // Generate randomness using a fixed path related to the device mnemonic
    uint32_t path[HDPATH_LEN_DEFAULT] = {
            0x8000002c,
            0x80000085,
            0x80000000,
            0x80000000,
            0x80000000,
    };

    // FIXME: Zemu/Speculos still does not emulate the derivation correctly
    // FIXME: so the seed that is generated is still fixed
    // This is fine for Milestone 1

    os_perso_derive_node_bip32_seed_key(HDW_ED25519_SLIP10, CX_CURVE_Ed25519,
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
    };
} tmp_buf_s;

typedef struct {
    union {
        // STEP 1
        struct {
            uint8_t sk_new[32];
            uint8_t dk_new[32];
            uint8_t sk[32];
        } step1;

        struct {
            uint8_t sk[32];
            uint8_t ak[32];
            uint8_t nk[32];
        } step2;
        // STEP 2
        struct {
            uint8_t ivk[32];
            uint8_t ak[32];
            uint8_t nk[32];
        } step3;
    };
} tmp_sampling_s;

uint16_t crypto_fillAddress_sapling(uint8_t *buffer, uint16_t bufferLen) {
    if (bufferLen < sizeof(tmp_buf_s)) {
        return 0;
    }

    tmp_buf_s *out = (tmp_buf_s *) buffer;
    MEMZERO(out, bufferLen);

    tmp_sampling_s tmp;
    MEMZERO(&tmp, sizeof(tmp_sampling_s));

    BEGIN_TRY
    {
        TRY
        {
            // Temporarily get sk from Ed25519
            //crypto_fillSaplingSeed(tmp.step1.sk);

            zip32_master(tmp.step1.sk,tmp.step1.sk_new,tmp.step1.dk_new);
            MEMZERO(tmp.step1.sk, sizeof_field(tmp_sampling_s, step1.sk));
            CHECK_APP_CANARY();
            //get_diversifier_list(tmp.step1.sk, out);
            /*
            CHECK_APP_CANARY();
            MEMZERO(tmp.step1.sk, sizeof_field(tmp_sampling_s, step1.sk));
      //      get_diversifier_fromlist(out->diversifier,out->diversifierlist);
            CHECK_APP_CANARY();
*/
            get_diversifier(tmp.step1.dk_new, out->diversifier);
            MEMZERO(tmp.step1.dk_new, sizeof_field(tmp_sampling_s, step1.dk_new));

            get_ak(tmp.step1.sk_new, tmp.step2.ak);
            get_nk(tmp.step1.sk_new, tmp.step2.nk);
            MEMZERO(tmp.step1.sk_new, sizeof_field(tmp_sampling_s, step1.sk_new));

            // Here we can clear up the seed

            get_ivk(tmp.step3.ak, tmp.step3.nk, tmp.step3.ivk);
            CHECK_APP_CANARY();
            MEMZERO(tmp.step3.ak, sizeof_field(tmp_sampling_s, step3.ak));
            MEMZERO(tmp.step3.nk, sizeof_field(tmp_sampling_s, step3.nk));

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
                          sizeof_field(tmp_buf_s, address_raw));

    return sizeof_field(tmp_buf_s, address_raw) + strlen((const char *) out->address_bech32);
}

#endif

