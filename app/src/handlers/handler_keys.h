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



// Transmitted notes are stored on the blockchain in encrypted form.
// If the note was sent to Alice, she uses her incoming viewing key (IVK)
// to decrypt the note (so that she can subsequently send it).
// This function also returns the default diversifier to reduce interactions
// between host and device
__Z_INLINE void handleGetKeyIVK(volatile uint32_t *flags, volatile uint32_t *tx, uint32_t rx) {
    zemu_log("----[handleGetKeyIVK]\n");

    *tx = 0;
    if (rx - APDU_MIN_LENGTH != APDU_DATA_LENGTH_GET_IVK) {
        ZEMU_LOGF(100, "Wrong length! %d\n", rx);
        THROW(APDU_CODE_COMMAND_NOT_ALLOWED);
    }

    extractHDPathSapling(rx, OFFSET_DATA);

    key_state.kind = key_ivk;

    uint16_t replyLen = 0;

    zxerr_t err = crypto_ivk_sapling(G_io_apdu_buffer, IO_APDU_BUFFER_SIZE - 2, hdPath.sapling_path[2], &replyLen);
    if (err != zxerr_ok) {
        *tx = 0;
        THROW(APDU_CODE_DATA_INVALID);
    }
    key_state.len = (uint8_t)replyLen;

    if (app_mode_expert() || !keys_permission_granted) {
        view_review_init(key_getItem, key_getNumItems, app_reply_key);
        view_review_show(REVIEW_GENERIC);
        *flags |= IO_ASYNCH_REPLY;
        return;
    }

    *tx = replyLen;
    THROW(APDU_CODE_OK);
}

// If Bob sends a note to Alice (stored on the blockchain in encrypted form),
// he can decrypt using his outgoing viewing key (OVK).
__Z_INLINE void handleGetKeyOVK(volatile uint32_t *flags, volatile uint32_t *tx, uint32_t rx) {
    zemu_log("----[handleGetKeyOVK]\n");

    *tx = 0;
    if (rx - APDU_MIN_LENGTH != APDU_DATA_LENGTH_GET_OVK) {
        ZEMU_LOGF(100, "Wrong length! %d\n", rx);
        THROW(APDU_CODE_COMMAND_NOT_ALLOWED);
    }

    extractHDPathSapling(rx, OFFSET_DATA);

    key_state.kind = key_ovk;
    uint16_t replyLen = 0;

    zxerr_t err = crypto_ovk_sapling(G_io_apdu_buffer, IO_APDU_BUFFER_SIZE - 2, hdPath.sapling_path[2], &replyLen);
    if (err != zxerr_ok) {
        *tx = 0;
        THROW(APDU_CODE_DATA_INVALID);
    }
    key_state.len = (uint8_t)replyLen;

    if (app_mode_expert() || !keys_permission_granted) {
        view_review_init(key_getItem, key_getNumItems, app_reply_key);
        view_review_show(REVIEW_GENERIC);
        *flags |= IO_ASYNCH_REPLY;
    }

    *tx = replyLen;
    THROW(APDU_CODE_OK);
}

// Get the sapling full viewing key (ak, nk, ovk)
__Z_INLINE void handleGetKeyFVK(volatile uint32_t *flags, volatile uint32_t *tx, uint32_t rx) {
    zemu_log("----[handleGetKeyFVK]\n");

    *tx = 0;
    if (rx - APDU_MIN_LENGTH != APDU_DATA_LENGTH_GET_FVK) {
        ZEMU_LOGF(100, "Wrong length! %d\n", rx);
        THROW(APDU_CODE_COMMAND_NOT_ALLOWED);
    }

    extractHDPathSapling(rx, OFFSET_DATA);

    key_state.kind = key_fvk;
    uint16_t replyLen = 0;

    zxerr_t err = crypto_fvk_sapling(G_io_apdu_buffer,

                                     IO_APDU_BUFFER_SIZE - 2, hdPath.sapling_path[2], &replyLen);

    if (err != zxerr_ok) {
        *tx = 0;
        THROW(APDU_CODE_DATA_INVALID);
    }
    key_state.len = (uint8_t)replyLen;

    if (app_mode_expert() || !keys_permission_granted) {
        view_review_init(key_getItem, key_getNumItems, app_reply_key);
        view_review_show(REVIEW_GENERIC);
        *flags |= IO_ASYNCH_REPLY;
    }

    *tx = replyLen;
    THROW(APDU_CODE_OK);
}


// Get the sapling diversifiable full viewing key (ak, nk, ovk)
__Z_INLINE void handleGetKeyDFVK(volatile uint32_t *flags, volatile uint32_t *tx, uint32_t rx) {
    zemu_log("----[handleGetKeyDFVK]\n");

    *tx = 0;
    if (rx - APDU_MIN_LENGTH != APDU_DATA_LENGTH_GET_DFVK) {
        ZEMU_LOGF(100, "Wrong length! %d\n", rx);
        THROW(APDU_CODE_COMMAND_NOT_ALLOWED);
    }

    extractHDPathSapling(rx, OFFSET_DATA);

    key_state.kind = key_dfvk;
    uint16_t replyLen = 0;

    zxerr_t err = crypto_dfvk_sapling(G_io_apdu_buffer,

                                     IO_APDU_BUFFER_SIZE - 2, hdPath.sapling_path[2], &replyLen);

    if (err != zxerr_ok) {
        *tx = 0;
        THROW(APDU_CODE_DATA_INVALID);
    }
    key_state.len = (uint8_t)replyLen;

    if (app_mode_expert() || !keys_permission_granted) {
        view_review_init(key_getItem, key_getNumItems, app_reply_key);
        view_review_show(REVIEW_GENERIC);
        *flags |= IO_ASYNCH_REPLY;
    }

    *tx = replyLen;
    THROW(APDU_CODE_OK);
}

// Computing the note nullifier nf is required in order to spend the note.
// Computing nf requires the associated (private) nullifier deriving key nk
// and the note position pos.
// (nk is part of the full viewing key fvk = (ak, nk, ovk) )
__Z_INLINE void handleGetNullifier(volatile uint32_t *flags, volatile uint32_t *tx, uint32_t rx) {
    *tx = 0;

    if (rx - APDU_MIN_LENGTH != APDU_DATA_LENGTH_GET_NF) {
        ZEMU_LOGF(100, "Wrong length! %d\n", rx);
        THROW(APDU_CODE_COMMAND_NOT_ALLOWED);
    }

    extractHDPathSapling(rx, OFFSET_DATA);

    // get note position from payload
    uint64_t notepos = 0;
    memcpy(&notepos, G_io_apdu_buffer + OFFSET_DATA + ZIP32_PATH_SIZE, NOTE_POSITION_SIZE);

    // get note commitment from payload
    uint8_t cm[NOTE_COMMITMENT_SIZE] = {0};
    memcpy(cm, G_io_apdu_buffer + OFFSET_DATA + ZIP32_PATH_SIZE + NOTE_POSITION_SIZE, NOTE_COMMITMENT_SIZE);

    MEMZERO(G_io_apdu_buffer, IO_APDU_BUFFER_SIZE);

    key_state.kind = nf;
    uint16_t replyLen = 0;

    // this needs to get Full viewing key = (ak, nk, ovk) and note position, to
    // then compute nullifier G_io_apdu_buffer contains zip32path, note position,
    // note commitment
    zxerr_t err =
        crypto_nullifier_sapling(G_io_apdu_buffer, IO_APDU_BUFFER_SIZE - 2, hdPath.sapling_path[2], notepos, cm, &replyLen);

    if (err != zxerr_ok) {
        zemu_log("Failed to get nullifier!\n");
        *tx = 0;
        THROW(APDU_CODE_DATA_INVALID);
    }
    key_state.len = (uint8_t)replyLen;

    if (app_mode_expert() || !keys_permission_granted) {
        view_review_init(key_getItem, key_getNumItems, app_reply_key);
        view_review_show(REVIEW_GENERIC);
        *flags |= IO_ASYNCH_REPLY;
    }

    *tx = replyLen;
    THROW(APDU_CODE_OK);
}

__Z_INLINE void handleGetDiversifierList(volatile uint32_t *tx, uint32_t rx) {
    zemu_log("----[handleGetDiversifierList]\n");

    *tx = 0;
    if (rx - APDU_MIN_LENGTH != APDU_DATA_LENGTH_GET_DIV_LIST) {
        ZEMU_LOGF(100, "incorrect input size %d\n", rx);
        THROW(APDU_CODE_COMMAND_NOT_ALLOWED);
    }

    if (G_io_apdu_buffer[OFFSET_DATA_LEN] != APDU_DATA_LENGTH_GET_DIV_LIST) {
        zemu_log_stack("payload too small");
        THROW(APDU_CODE_COMMAND_NOT_ALLOWED);
    }

    uint16_t replyLen = 0;

    zemu_log_stack("handleGetDiversifierList");

    extractHDPathSapling(rx, OFFSET_DATA);

    zxerr_t err =
        crypto_diversifier_with_startindex(G_io_apdu_buffer, hdPath.saplingdiv_path[2], hdPath.saplingdiv_div, &replyLen);

    if (err == zxerr_ok) {
        *tx = replyLen;
        THROW(APDU_CODE_OK);
    } else {
        *tx = 0;
        THROW(APDU_CODE_DATA_INVALID);
    }
}
