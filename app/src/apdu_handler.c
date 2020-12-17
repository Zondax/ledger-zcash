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
#include "addr.h"
#include "key.h"
#include "parser.h"
#include "nvdata.h"

__Z_INLINE void handleExtractSpendSignature(volatile uint32_t *flags,
                                       volatile uint32_t *tx, uint32_t rx) {
    *tx = 0;
    if(rx != APDU_MIN_LENGTH){
        THROW(APDU_CODE_COMMAND_NOT_ALLOWED);
    }
    if(G_io_apdu_buffer[OFFSET_DATA_LEN] != 0){
        THROW(APDU_CODE_COMMAND_NOT_ALLOWED);
    }
    zxerr_t err = crypto_extract_spend_signature(G_io_apdu_buffer, IO_APDU_BUFFER_SIZE - 2);

    if (err == zxerr_ok) {
        *tx = 64;
        THROW(APDU_CODE_OK);
    } else {
        *tx = 0;
        THROW(APDU_CODE_DATA_INVALID);
    }
}

__Z_INLINE void handleExtractTransparentSignature(volatile uint32_t *flags,
                                            volatile uint32_t *tx, uint32_t rx) {
    *tx = 0;
    if(rx != APDU_MIN_LENGTH){
        THROW(APDU_CODE_COMMAND_NOT_ALLOWED);
    }

    if(G_io_apdu_buffer[OFFSET_DATA_LEN] != 0){
        THROW(APDU_CODE_COMMAND_NOT_ALLOWED);
    }
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
    *tx = 0;
    if(rx != APDU_MIN_LENGTH){
        THROW(APDU_CODE_COMMAND_NOT_ALLOWED);
    }

    if(G_io_apdu_buffer[OFFSET_DATA_LEN] != 0){
        THROW(APDU_CODE_COMMAND_NOT_ALLOWED);
    }
    zxerr_t err = crypto_extract_spend_proofkeyandrnd(G_io_apdu_buffer, IO_APDU_BUFFER_SIZE - 2);
    view_tx_state();
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
    *tx = 0;
    if(rx != APDU_MIN_LENGTH){
        THROW(APDU_CODE_COMMAND_NOT_ALLOWED);
    }

    if(G_io_apdu_buffer[OFFSET_DATA_LEN] != 0){
        THROW(APDU_CODE_COMMAND_NOT_ALLOWED);
    }
    zxerr_t err = crypto_extract_output_rnd(G_io_apdu_buffer, IO_APDU_BUFFER_SIZE - 2);
    view_tx_state();
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
    *tx = 0;
    zxerr_t err = init_tx();
    if (err != zxerr_ok) {
        *tx = 0;
        THROW(APDU_CODE_DATA_INVALID);
    }

    view_review_init(tx_getItem, tx_getNumItems, app_reply_hash);
    view_review_show();
    *flags |= IO_ASYNCH_REPLY;
}

__Z_INLINE void handleGetKeyIVK(volatile uint32_t *flags,
                                volatile uint32_t *tx, uint32_t rx) {
    *tx = 0;
    if(rx < APDU_MIN_LENGTH){
        THROW(APDU_CODE_COMMAND_NOT_ALLOWED);
    }

    if(rx - APDU_MIN_LENGTH != DATA_LENGTH_GET_IVK){
        THROW(APDU_CODE_COMMAND_NOT_ALLOWED);
    }

    if(G_io_apdu_buffer[OFFSET_DATA_LEN] != DATA_LENGTH_GET_IVK){
        THROW(APDU_CODE_COMMAND_NOT_ALLOWED);
    }

    uint8_t requireConfirmation = G_io_apdu_buffer[OFFSET_P1];

    if (!requireConfirmation) {
        THROW(APDU_CODE_COMMAND_NOT_ALLOWED);
    }

    uint32_t zip32path = 0;
    parser_error_t prserr = parser_sapling_path(G_io_apdu_buffer + OFFSET_DATA, DATA_LENGTH_GET_IVK,
                                                &zip32path);
    MEMZERO(G_io_apdu_buffer, IO_APDU_BUFFER_SIZE);
    if (prserr != parser_ok) {
        *tx = 0;
        THROW(APDU_CODE_DATA_INVALID);
    }
    key_state.kind = key_ivk;
    uint16_t replyLen = 0;

    zxerr_t err = crypto_ivk_sapling(G_io_apdu_buffer, IO_APDU_BUFFER_SIZE - 2, zip32path, &replyLen);
    if(err != zxerr_ok){
        *tx = 0;
        THROW(APDU_CODE_DATA_INVALID);
    }
    view_review_init(key_getItem, key_getNumItems, app_reply_key);
    view_review_show();
    *flags |= IO_ASYNCH_REPLY;
}

__Z_INLINE void handleGetKeyOVK(volatile uint32_t *flags,
                                volatile uint32_t *tx, uint32_t rx) {
    *tx = 0;
    if(rx < APDU_MIN_LENGTH){
        THROW(APDU_CODE_COMMAND_NOT_ALLOWED);
    }

    if(rx - APDU_MIN_LENGTH != DATA_LENGTH_GET_OVK){
        THROW(APDU_CODE_COMMAND_NOT_ALLOWED);
    }

    if(G_io_apdu_buffer[OFFSET_DATA_LEN] != DATA_LENGTH_GET_OVK){
        THROW(APDU_CODE_COMMAND_NOT_ALLOWED);
    }

    uint8_t requireConfirmation = G_io_apdu_buffer[OFFSET_P1];

    if (!requireConfirmation) {
        THROW(APDU_CODE_COMMAND_NOT_ALLOWED);
    }

    uint32_t zip32path = 0;
    parser_error_t prserr = parser_sapling_path(G_io_apdu_buffer + OFFSET_DATA, DATA_LENGTH_GET_IVK,
                                                &zip32path);
    MEMZERO(G_io_apdu_buffer, IO_APDU_BUFFER_SIZE);
    if (prserr != parser_ok) {
        *tx = 0;
        THROW(APDU_CODE_DATA_INVALID);
    }
    key_state.kind = key_ovk;
    uint16_t replyLen = 0;

    zxerr_t err = crypto_ovk_sapling(G_io_apdu_buffer, IO_APDU_BUFFER_SIZE - 2, zip32path, &replyLen);
    if(err != zxerr_ok){
        *tx = 0;
        THROW(APDU_CODE_DATA_INVALID);
    }
    key_state.len = replyLen;

    view_review_init(key_getItem, key_getNumItems, app_reply_key);
    view_review_show();
    *flags |= IO_ASYNCH_REPLY;
}

__Z_INLINE void handleCheckandSign(volatile uint32_t *flags,
                                   volatile uint32_t *tx, uint32_t rx) {
    if (!process_chunk(tx, rx)) {
        THROW(APDU_CODE_OK);
    }
    *tx = 0;
    zxerr_t err = check_and_sign_tx();
    if (err != zxerr_ok) {
        *tx = 0;
        view_idle_show(0, NULL);
        transaction_reset();
        THROW(APDU_CODE_DATA_INVALID);
    }else{
        *tx = 32;
        THROW(APDU_CODE_OK);
    }
}

__Z_INLINE void handleGetAddrSecp256K1(volatile uint32_t *flags,
                                       volatile uint32_t *tx, uint32_t rx) {
    extractHDPath(rx, OFFSET_DATA);
    *tx = 0;
    uint8_t requireConfirmation = G_io_apdu_buffer[OFFSET_P1];
    uint16_t replyLen = 0;

    zxerr_t err = crypto_fillAddress_secp256k1(G_io_apdu_buffer, IO_APDU_BUFFER_SIZE - 2, &replyLen);
    if(err != zxerr_ok) {
        *tx = 0;
        THROW(APDU_CODE_DATA_INVALID);
    }

    address_state.kind = addr_secp256k1;
    address_state.len = replyLen;

    if (requireConfirmation) {
        view_review_init(addr_getItem, addr_getNumItems, app_reply_address);
        view_review_show();
        *flags |= IO_ASYNCH_REPLY;
        return;
    }
    *tx = replyLen;
    THROW(APDU_CODE_OK);
}


__Z_INLINE void handleGetAddrSaplingDiv(volatile uint32_t *flags,
                                        volatile uint32_t *tx, uint32_t rx) {
    *tx = 0;
    if(rx < APDU_MIN_LENGTH){
        THROW(APDU_CODE_COMMAND_NOT_ALLOWED);
    }

    if(rx - APDU_MIN_LENGTH != DATA_LENGTH_GET_ADDR_DIV){
        THROW(APDU_CODE_COMMAND_NOT_ALLOWED);
    }

    if(G_io_apdu_buffer[OFFSET_DATA_LEN] != DATA_LENGTH_GET_ADDR_DIV){
        THROW(APDU_CODE_COMMAND_NOT_ALLOWED);
    }

    uint8_t requireConfirmation = G_io_apdu_buffer[OFFSET_P1];

    uint16_t replyLen = 0;

    zemu_log_stack("handleGetAddrSapling_withdiv");

    parser_addr_div_t parser_addr;
    MEMZERO(&parser_addr, sizeof(parser_addr_div_t));

    parser_error_t prserr = parser_sapling_path_with_div(G_io_apdu_buffer + OFFSET_DATA, DATA_LENGTH_GET_ADDR_DIV, &parser_addr);
    MEMZERO(G_io_apdu_buffer, IO_APDU_BUFFER_SIZE);
    if(prserr != parser_ok){
        *tx = 0;
        THROW(APDU_CODE_DATA_INVALID);
    }
    zxerr_t err = crypto_fillAddress_with_diversifier_sapling(G_io_apdu_buffer, IO_APDU_BUFFER_SIZE - 3, parser_addr.path, parser_addr.div, &replyLen);
    if(err != zxerr_ok){
        *tx = 0;
        THROW(APDU_CODE_DATA_INVALID);
    }
    address_state.kind = addr_sapling_div;
    address_state.len = replyLen;

    if (requireConfirmation) {
        view_review_init(addr_getItem, addr_getNumItems, app_reply_address);
        view_review_show();
        *flags |= IO_ASYNCH_REPLY;
        return;
    }
    *tx = replyLen;
    THROW(APDU_CODE_OK);
}

__Z_INLINE void handleGetDiversifierList(volatile uint32_t *flags,
                                         volatile uint32_t *tx, uint32_t rx) {
    *tx = 0;
    if(rx < APDU_MIN_LENGTH){
        THROW(APDU_CODE_COMMAND_NOT_ALLOWED);
    }

    if(rx - APDU_MIN_LENGTH != DATA_LENGTH_GET_DIV_LIST){
        THROW(APDU_CODE_COMMAND_NOT_ALLOWED);
    }

    if(G_io_apdu_buffer[OFFSET_DATA_LEN] != DATA_LENGTH_GET_DIV_LIST){
        THROW(APDU_CODE_COMMAND_NOT_ALLOWED);
    }

    uint16_t replyLen = 0;

    zemu_log_stack("handleGetAddrSapling_divlist");

    parser_addr_div_t parser_addr;
    MEMZERO(&parser_addr, sizeof(parser_addr_div_t));

    parser_error_t prserr = parser_sapling_path_with_div(G_io_apdu_buffer + OFFSET_DATA, DATA_LENGTH_GET_DIV_LIST, &parser_addr);
    MEMZERO(G_io_apdu_buffer, IO_APDU_BUFFER_SIZE);
    if(prserr != parser_ok){
        *tx = 0;
        THROW(APDU_CODE_DATA_INVALID);
    }
    zxerr_t err = crypto_diversifier_with_startindex(G_io_apdu_buffer, IO_APDU_BUFFER_SIZE - 2, parser_addr.path, parser_addr.div, &replyLen);

    if (err == zxerr_ok) {
        *tx = replyLen;
        THROW(APDU_CODE_OK);
    } else {
        *tx = 0;
        THROW(APDU_CODE_DATA_INVALID);
    }
}

__Z_INLINE void handleGetAddrSapling(volatile uint32_t *flags,
                                     volatile uint32_t *tx, uint32_t rx) {
    *tx = 0;
    if(rx < APDU_MIN_LENGTH){
        THROW(APDU_CODE_COMMAND_NOT_ALLOWED);
    }

    if(rx - APDU_MIN_LENGTH != DATA_LENGTH_GET_ADDR_SAPLING){
        THROW(APDU_CODE_COMMAND_NOT_ALLOWED);
    }

    if(G_io_apdu_buffer[OFFSET_DATA_LEN] != DATA_LENGTH_GET_ADDR_SAPLING){
        THROW(APDU_CODE_COMMAND_NOT_ALLOWED);
    }

    uint8_t requireConfirmation = G_io_apdu_buffer[OFFSET_P1];

    zemu_log_stack("handleGetAddrSapling");

    uint32_t zip32path = 0;
    parser_error_t prserr = parser_sapling_path(G_io_apdu_buffer + OFFSET_DATA, DATA_LENGTH_GET_ADDR_SAPLING,
                                                    &zip32path);
    MEMZERO(G_io_apdu_buffer, IO_APDU_BUFFER_SIZE);
    if (prserr != parser_ok) {
        *tx = 0;
        THROW(APDU_CODE_DATA_INVALID);
    }
    uint16_t replyLen = 0;
    zxerr_t err = crypto_fillAddress_sapling(G_io_apdu_buffer,IO_APDU_BUFFER_SIZE - 2, zip32path, &replyLen);
    if(err != zxerr_ok){
        *tx = 0;
        THROW(APDU_CODE_DATA_INVALID);
    }
    address_state.kind = addr_sapling;
    address_state.len = replyLen;

    if (requireConfirmation) {
        view_review_init(addr_getItem, addr_getNumItems, app_reply_address);
        view_review_show();
        *flags |= IO_ASYNCH_REPLY;
        return;
    }

    *tx = replyLen;
    THROW(APDU_CODE_OK);
}

__Z_INLINE void handleSignSapling(volatile uint32_t *flags,
                                  volatile uint32_t *tx, uint32_t rx) {
    THROW(APDU_CODE_COMMAND_NOT_ALLOWED);
}

#if defined(APP_TESTING)
void handleTest(volatile uint32_t *flags, volatile uint32_t *tx, uint32_t rx) {

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
