/*******************************************************************************
 *   (c) Zondax AG
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
#pragma once

#include <os.h>
#include <os_io_seproxyhal.h>

#include "actions.h"
#include "addr.h"
#include "apdu_errors.h"
#include "app_main.h"
#include "app_mode.h"
#include "coin.h"
#include "crypto.h"
#include "handler_path.h"
#include "key.h"
#include "nvdata.h"
#include "parser.h"
#include "tx.h"
#include "view.h"
#include "view_internal.h"
#include "zxmacros.h"

__Z_INLINE void handleGetAddrSecp256K1(volatile uint32_t *flags, volatile uint32_t *tx, uint32_t rx) {
    ZEMU_LOGF(100, "----[handleGetAddrSecp256K1]\n");
    *tx = 0;

    extractHDPathTransparent(rx, OFFSET_DATA);

    uint8_t requireConfirmation = G_io_apdu_buffer[OFFSET_P1];
    uint16_t replyLen = 0;

    zxerr_t err = crypto_fillAddress_secp256k1(G_io_apdu_buffer, IO_APDU_BUFFER_SIZE - 2, &replyLen);
    if (err != zxerr_ok) {
        ZEMU_LOGF(100, "Err: %d\n", err);
        *tx = 0;
        THROW(APDU_CODE_DATA_INVALID);
    }

    action_addrResponse.len = replyLen;

    if (requireConfirmation) {
        view_review_init(addr_getItem, addr_getNumItems, app_reply_address);
        view_review_show(REVIEW_ADDRESS);
        *flags |= IO_ASYNCH_REPLY;
        return;
    }
    *tx = replyLen;
    THROW(APDU_CODE_OK);
}

__Z_INLINE void handleGetAddrSapling(volatile uint32_t *flags, volatile uint32_t *tx, uint32_t rx) {
    ZEMU_LOGF(100, "----[handleGetAddrSapling]\n");
    *tx = 0;

    if (rx < APDU_MIN_LENGTH) {
        ZEMU_LOGF(100, "rx: %d\n", rx);
        THROW(APDU_CODE_COMMAND_NOT_ALLOWED);
    }

    if (rx != (uint32_t)(APDU_DATA_LENGTH_GET_ADDR_SAPLING + APDU_MIN_LENGTH)) {
        ZEMU_LOGF(100, "rx: %d\n", rx);
        THROW(APDU_CODE_COMMAND_NOT_ALLOWED);
    }

    if (G_io_apdu_buffer[OFFSET_DATA_LEN] != APDU_DATA_LENGTH_GET_ADDR_SAPLING) {
        ZEMU_LOGF(100, "len: %d\n", G_io_apdu_buffer[OFFSET_DATA_LEN]);
        THROW(APDU_CODE_COMMAND_NOT_ALLOWED);
    }

    extractHDPathSapling(rx, OFFSET_DATA);

    uint8_t requireConfirmation = G_io_apdu_buffer[OFFSET_P1];

    uint16_t replyLen = 0;
    zxerr_t err = crypto_fillAddress_sapling(G_io_apdu_buffer, IO_APDU_BUFFER_SIZE - 2, hdPath.sapling_path[2], &replyLen);
    if (err != zxerr_ok) {
        ZEMU_LOGF(100, "Err: %d\n", err);
        *tx = 0;
        THROW(APDU_CODE_DATA_INVALID);
    }
    action_addrResponse.len = replyLen;

    if (requireConfirmation) {
        view_review_init(addr_getItem, addr_getNumItems, app_reply_address);
        view_review_show(REVIEW_ADDRESS);
        *flags |= IO_ASYNCH_REPLY;
        return;
    }

    *tx = replyLen;
    THROW(APDU_CODE_OK);
}

__Z_INLINE void handleGetAddrSaplingDiv(volatile uint32_t *flags, volatile uint32_t *tx, uint32_t rx) {
    ZEMU_LOGF(100, "----[handleGetAddrSapling_withdiv]\n");

    *tx = 0;
    if (rx < APDU_MIN_LENGTH) {
        ZEMU_LOGF(100, "rx: %d\n", rx);
        THROW(APDU_CODE_COMMAND_NOT_ALLOWED);
    }

    if (rx - APDU_MIN_LENGTH != APDU_DATA_LENGTH_GET_ADDR_DIV) {
        ZEMU_LOGF(100, "rx: %d\n", rx);
        THROW(APDU_CODE_COMMAND_NOT_ALLOWED);
    }

    if (G_io_apdu_buffer[OFFSET_DATA_LEN] != APDU_DATA_LENGTH_GET_ADDR_DIV) {
        ZEMU_LOGF(100, "len: %d\n", G_io_apdu_buffer[OFFSET_DATA_LEN]);
        THROW(APDU_CODE_COMMAND_NOT_ALLOWED);
    }

    extractHDPathSaplingDiv(rx, OFFSET_DATA);

    uint8_t requireConfirmation = G_io_apdu_buffer[OFFSET_P1];

    uint16_t replyLen = 0;

    zxerr_t err = crypto_fillAddress_with_diversifier_sapling(G_io_apdu_buffer, IO_APDU_BUFFER_SIZE - 3,
                                                              hdPath.saplingdiv_path[2], hdPath.saplingdiv_div, &replyLen);

    if (err != zxerr_ok) {
        ZEMU_LOGF(100, "Err: %d\n", err);
        *tx = 0;
        THROW(APDU_CODE_DATA_INVALID);
    }
    action_addrResponse.len = replyLen;

    if (requireConfirmation) {
        view_review_init(addr_getItem, addr_getNumItems, app_reply_address);
        view_review_show(REVIEW_ADDRESS);
        *flags |= IO_ASYNCH_REPLY;
        return;
    }
    *tx = replyLen;
    THROW(APDU_CODE_OK);
}
