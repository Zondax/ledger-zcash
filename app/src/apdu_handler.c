/*******************************************************************************
 *   (c) 2018, 2019 Zondax GmbH
 *   (c) 2016 Ledger
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

#include <os.h>
#include <os_io_seproxyhal.h>
#include <string.h>

#include "actions.h"
#include "app_main.h"
#include "coin.h"
#include "crypto.h"
#include "tx.h"
#include "view.h"
#include "zxmacros.h"
#include "chacha.h"
#include "addr.h"
#include "key.h"

__Z_INLINE void handleExtractSpendSignature(volatile uint32_t *flags,
                                       volatile uint32_t *tx, uint32_t rx) {
    zxerr_t err = crypto_extract_spend_signature(G_io_apdu_buffer, IO_APDU_BUFFER_SIZE - 2);

    if (err == zxerr_ok) {
        *tx = 64;
        THROW(APDU_CODE_OK);
    } else {
        THROW(APDU_CODE_DATA_INVALID);
    }
}

__Z_INLINE void handleExtractTransparentSignature(volatile uint32_t *flags,
                                            volatile uint32_t *tx, uint32_t rx) {
    zxerr_t err = crypto_extract_transparent_signature(G_io_apdu_buffer, IO_APDU_BUFFER_SIZE - 2);
    if (err == zxerr_ok){
        *tx = 64;
        THROW(APDU_CODE_OK);
    } else {
        *tx = 0;
        THROW(APDU_CODE_DATA_INVALID);
    }
}

__Z_INLINE void handleExtractSpendData(volatile uint32_t *flags,
                             volatile uint32_t *tx, uint32_t rx) {
    zxerr_t err = crypto_extract_spend_proofkeyandrnd(G_io_apdu_buffer, IO_APDU_BUFFER_SIZE - 2);
    if (err == zxerr_ok) {
        *tx = 128;
        THROW(APDU_CODE_OK);
    } else {
        *tx = 0;
        THROW(APDU_CODE_DATA_INVALID);
    }

}

__Z_INLINE void handleExtractOutputData(volatile uint32_t *flags,
                                       volatile uint32_t *tx, uint32_t rx) {
    zxerr_t err = crypto_extract_output_rnd(G_io_apdu_buffer, IO_APDU_BUFFER_SIZE - 2);
    if (err == zxerr_ok) {
        *tx = 64;
        THROW(APDU_CODE_OK);
    } else {
        *tx = 0;
        THROW(APDU_CODE_DATA_INVALID);
    }
}

__Z_INLINE void handleInitTX(volatile uint32_t *flags,
                             volatile uint32_t *tx, uint32_t rx) {
    if (!process_chunk(tx, rx)) {
        THROW(APDU_CODE_OK);
    }
    zxerr_t err = init_tx();
    //todo: show things in screen and confirm
    if (err == zxerr_ok) {
        *tx = 32;
        THROW(APDU_CODE_OK);
    } else {
        *tx = 0;
        THROW(APDU_CODE_DATA_INVALID);
    }
}

__Z_INLINE void handleKeyExchange(volatile uint32_t *flags,
                                  volatile uint32_t *tx, uint32_t rx) {
    if (!process_chunk(tx, rx)) {
        THROW(APDU_CODE_OK);
    }
    uint8_t len = key_exchange();
    if (len > 0) {
        *tx = len;
        THROW(APDU_CODE_OK);
    } else {
        *tx = 0;
        THROW(APDU_CODE_DATA_INVALID);
    }
}

__Z_INLINE void handleGetKeyIVK(volatile uint32_t *flags,
                                volatile uint32_t *tx, uint32_t rx) {
    extractHDPath(rx, OFFSET_DATA);

    uint8_t requireConfirmation = G_io_apdu_buffer[OFFSET_P1];

    if (!requireConfirmation) {
        THROW(APDU_CODE_COMMAND_NOT_ALLOWED);
    }

    app_retrieve_key(key_ivk);
    view_review_init(key_getItem, key_getNumItems, app_reply_key);
    view_review_show();
    *flags |= IO_ASYNCH_REPLY;
}

__Z_INLINE void handleGetKeyOVK(volatile uint32_t *flags,
                                volatile uint32_t *tx, uint32_t rx) {
    extractHDPath(rx, OFFSET_DATA);

    uint8_t requireConfirmation = G_io_apdu_buffer[OFFSET_P1];

    if (!requireConfirmation) {
        THROW(APDU_CODE_COMMAND_NOT_ALLOWED);
    }

    app_retrieve_key(key_ovk);
    view_review_init(key_getItem, key_getNumItems, app_reply_key);
    view_review_show();
    *flags |= IO_ASYNCH_REPLY;
}

__Z_INLINE void handleCheckandSign(volatile uint32_t *flags,
                                   volatile uint32_t *tx, uint32_t rx) {
    if (!process_chunk(tx, rx)) {
        THROW(APDU_CODE_OK);
    }
    zxerr_t err = check_and_sign_tx();
    if (err == zxerr_ok) {
        *tx = 32;
        THROW(APDU_CODE_OK);
    } else {
        *tx = 0;
        THROW(APDU_CODE_DATA_INVALID);
    }
}

__Z_INLINE void handleGetAddrSecp256K1(volatile uint32_t *flags,
                                       volatile uint32_t *tx, uint32_t rx) {
    extractHDPath(rx, OFFSET_DATA);

    uint8_t requireConfirmation = G_io_apdu_buffer[OFFSET_P1];

    if (requireConfirmation) {
        app_fill_address(addr_secp256k1);
        view_review_init(addr_getItem, addr_getNumItems, app_reply_address);
        view_review_show();
        *flags |= IO_ASYNCH_REPLY;
        return;
    }
    *tx = app_fill_address(addr_secp256k1);
    THROW(APDU_CODE_OK);
}


__Z_INLINE void handleGetAddrSaplingDiv(volatile uint32_t *flags,
                                        volatile uint32_t *tx, uint32_t rx) {
    if (!process_chunk(tx, rx)) {
        THROW(APDU_CODE_OK);
    }
    extractHDPath(rx, OFFSET_DATA);
    uint16_t replyLen;

    uint8_t requireConfirmation = G_io_apdu_buffer[OFFSET_P1];

    zemu_log_stack("handleGetAddrSapling");
    address_state.kind = addr_sapling_div;

    if (requireConfirmation) {
        get_addr_with_diversifier(&replyLen);
        view_review_init(addr_getItem, addr_getNumItems, app_reply_address);
        view_review_show();
        *flags |= IO_ASYNCH_REPLY;
        return;
    }
    zxerr_t err = get_addr_with_diversifier(&replyLen);
    if (err == zxerr_ok) {
        *tx = replyLen;
        THROW(APDU_CODE_OK);
    } else {
        *tx = 0;
        THROW(APDU_CODE_DATA_INVALID);
    }
}

__Z_INLINE void handleGetDiversifierList(volatile uint32_t *flags,
                                         volatile uint32_t *tx, uint32_t rx) {
    if (!process_chunk(tx, rx)) {
        THROW(APDU_CODE_OK);
    }
    extractHDPath(rx, OFFSET_DATA);
    zxerr_t err = get_diversifier_list_with_startindex();
    if (err == zxerr_ok) {
        *tx = 220;
        THROW(APDU_CODE_OK);
    } else {
        *tx = 0;
        THROW(APDU_CODE_DATA_INVALID);
    }
}

__Z_INLINE void handleSignSecp256K1(volatile uint32_t *flags,
                                    volatile uint32_t *tx, uint32_t rx) {
    if (!process_chunk(tx, rx)) {
        THROW(APDU_CODE_OK);
    }

    const char *error_msg = tx_parse();

    if (error_msg != NULL) {
        int error_msg_length = strlen(error_msg);
        MEMCPY(G_io_apdu_buffer, error_msg, error_msg_length);
        *tx += (error_msg_length);
        THROW(APDU_CODE_DATA_INVALID);
    }

    // FIXME:
    //view_sign_show();
    *flags |= IO_ASYNCH_REPLY;
}

__Z_INLINE void handleGetAddrSapling(volatile uint32_t *flags,
                                     volatile uint32_t *tx, uint32_t rx) {
    extractHDPath(rx, OFFSET_DATA);
    uint8_t requireConfirmation = G_io_apdu_buffer[OFFSET_P1];

    zemu_log_stack("handleGetAddrSapling");

    if (requireConfirmation) {
        app_fill_address(addr_sapling);
        view_review_init(addr_getItem, addr_getNumItems, app_reply_address);
        view_review_show();
        *flags |= IO_ASYNCH_REPLY;
        return;
    }

    *tx = app_fill_address(addr_sapling);
    THROW(APDU_CODE_OK);
}

__Z_INLINE void handleSignSapling(volatile uint32_t *flags,
                                  volatile uint32_t *tx, uint32_t rx) {
    THROW(APDU_CODE_COMMAND_NOT_ALLOWED);
}

#if defined(APP_TESTING)
#include "rslib.h"

typedef struct {
    union {
        //todo: add zip32
        struct{
            uint8_t seed[32];
            uint8_t dk[32];
            uint8_t ask[32];
        } keyphase1;

         struct {
            uint8_t diversifier[11]; //get this from host and show on screen for verification
            uint8_t dummy1[21];
            uint8_t ivk[32]; //maybe compute self or from host (already needed by host earlier)
            uint8_t dummy2[9];
            uint8_t dummyxxx[23];
        } step1;

        // STEP 1
        struct {
            uint8_t gd[32]; //computed from receiver diversifier
            uint8_t pkd[32]; //get this from host and show on screen for verification
            uint8_t dummy[9];
            uint8_t dummyxxx[23];
        } step2;

        struct {
            uint8_t inputhash[73];
            uint8_t dummyxxx[23];
        } step3;

        struct{
            uint8_t notecommitment[32];
            uint8_t valuecommitment[32];
            uint8_t dummy[9];
            uint8_t dummyxxx[23];
        } step4;
    };
} tmp_notecommit;

typedef struct {
    union {
        //todo: add zip32
        struct{
            uint8_t ovk[32];
            uint8_t cv[32];
            uint8_t cmu[32];
            uint8_t epk[32];
        } keyphase1;

        struct {
            uint8_t input[128];
        } keyphase2;

        struct {
            uint8_t key[32];
            uint8_t pkd[32]; //
            uint8_t esk[32];
            uint8_t dummy[32];
        } keyphase3;

        struct {
            uint8_t key[32];
            uint8_t input[64];
            uint8_t dummy[32];
        } keyphase4;

        struct {
            uint8_t key[32];
            uint8_t output[80];
            uint8_t dummy[16];
        } keyphase5;

        //todo: we need a few extra bytes in this union here for smooth transition

        struct {
            uint8_t epk[32];
            uint8_t pkd[32]; //
            uint8_t esk[32];
            uint8_t dummy[32];
        } kaphase;

        struct {
            uint8_t sk[32];
            uint8_t alpha[32]; //
            uint8_t pk[32];
            uint8_t rsk[32];
        } jubjub;

        struct {
            uint8_t key[32];
            uint8_t d[11];
            uint64_t value;
            uint8_t rcm[32];
            uint8_t dummy2;
        } encphase1;

        struct {
            uint8_t key[32];
            uint8_t inputenc[52];
        } encphase2;
    };
} tmp_enc;
void handleTest(volatile uint32_t *flags, volatile uint32_t *tx, uint32_t rx) {
    uint8_t buffer[52];
    uint8_t compact[52] = {0x01, 0xdc, 0xe7, 0x7e, 0xbc, 0xec, 0x0a, 0x26, 0xaf, 0xd6, 0x99, 0x8c, 0x00, 0xe1, 0xf5,
            0x05, 0x00, 0x00, 0x00, 0x00, 0x39, 0x17, 0x6d, 0xac, 0x39, 0xac, 0xe4, 0x98, 0x0e, 0xcc,
            0x8d, 0x77, 0x8e, 0x89, 0x86, 0x02, 0x55, 0xec, 0x36, 0x15, 0x06, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    uint8_t esk[32] = {0x6d, 0xf8, 0x5b, 0x17, 0x89, 0xb0, 0xb7, 0x8b, 0x46, 0x10, 0xf2, 0x5d, 0x36, 0x8c, 0xb5,
        0x11, 0x14, 0x0a, 0x7c, 0x0a, 0xf3, 0xbc, 0x3d, 0x2a, 0x22, 0x6f, 0x92, 0x7d, 0xe6, 0x02,
        0xa7, 0xf1};
    uint8_t nonce[12] = {0,0,0,0,0,0,0,0,0,0,0,0};
    uint32_t counter = 1;
    chacha(buffer, compact, 52,
                     esk, nonce,
                     counter);
    CHECK_APP_CANARY();
    MEMCPY(G_io_apdu_buffer, buffer, 52);
    *tx = 52;
}
#endif

void handleApdu(volatile uint32_t *flags, volatile uint32_t *tx, uint32_t rx) {
    uint16_t sw = 0;

    BEGIN_TRY
    {
        TRY
        {
            if (G_io_apdu_buffer[OFFSET_CLA] != CLA) {
                THROW(APDU_CODE_CLA_NOT_SUPPORTED);
            }

            if (rx < APDU_MIN_LENGTH) {
                THROW(APDU_CODE_WRONG_LENGTH);
            }

            switch (G_io_apdu_buffer[OFFSET_INS]) {
                case INS_GET_VERSION: {
                    handle_getversion(flags, tx, rx);
                    break;
                }

                case INS_GET_ADDR_SECP256K1: {
                    handleGetAddrSecp256K1(flags, tx, rx);
                    break;
                }

                case INS_GET_IVK: {
                    handleGetKeyIVK(flags, tx, rx);
                    break;
                }

                case INS_GET_OVK: {
                    handleGetKeyOVK(flags, tx, rx);
                    break;
                }

                case INS_INIT_TX: {
                    handleInitTX(flags, tx, rx);
                    break;
                }

                case INS_KEY_EXCHANGE: {
                    handleKeyExchange(flags, tx, rx);
                    break;
                }

                case INS_EXTRACT_SPEND: {
                    handleExtractSpendData(flags, tx, rx);
                    break;
                }

                case INS_EXTRACT_OUTPUT: {
                    handleExtractOutputData(flags, tx, rx);
                    break;
                }

                case INS_CHECKANDSIGN: {
                    handleCheckandSign(flags, tx, rx);
                    break;
                }

                case INS_EXTRACT_SPENDSIG: {
                    handleExtractSpendSignature(flags, tx, rx);
                    break;
                }

                case INS_EXTRACT_TRANSSIG: {
                    handleExtractTransparentSignature(flags, tx, rx);
                    break;
                }

                case INS_SIGN_SECP256K1: {
                    handleSignSecp256K1(flags, tx, rx);
                    break;
                }

                case INS_GET_ADDR_SAPLING: {
                    handleGetAddrSapling(flags, tx, rx);
                    break;
                }
                case INS_GET_DIV_LIST: {
                    handleGetDiversifierList(flags, tx, rx);
                    break;
                }

                case INS_GET_ADDR_SAPLING_DIV: {
                    handleGetAddrSaplingDiv(flags, tx, rx);
                    break;
                }

                case INS_SIGN_SAPLING: {
                    handleSignSapling(flags, tx, rx);
                    break;
                }

#if defined(APP_TESTING)
                    case INS_TEST: {
                        handleTest(flags, tx, rx);
                        /*
                        G_io_apdu_buffer[0] = 0xCA;
                        G_io_apdu_buffer[1] = 0xFE;
                        *tx = 3;
                        */
                        THROW(APDU_CODE_OK);
                        break;
                    }
#endif
                default:
                    THROW(APDU_CODE_INS_NOT_SUPPORTED);
            }
        }
        CATCH(EXCEPTION_IO_RESET)
        { THROW(EXCEPTION_IO_RESET); }
        CATCH_OTHER(e)
        {
            switch (e & 0xF000) {
                case 0x6000:
                case APDU_CODE_OK:
                    sw = e;
                    break;
                default:
                    sw = 0x6800 | (e & 0x7FF);
                    break;
            }
            G_io_apdu_buffer[*tx] = sw >> 8;
            G_io_apdu_buffer[*tx + 1] = sw;
            *tx += 2;
        }
        FINALLY
        {}
    }
    END_TRY;
}
