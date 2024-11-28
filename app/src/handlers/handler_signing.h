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
#include <string.h>
#include <ux.h>

#include "actions.h"
#include "addr.h"
#include "apdu_errors.h"
#include "app_main.h"
#include "app_mode.h"
#include "coin.h"
#include "crypto.h"
#include "key.h"
#include "nvdata.h"
#include "parser.h"
#include "tx.h"
#include "view.h"
#include "view_internal.h"
#include "zxmacros.h"

static bool tx_initialized = false;

__Z_INLINE bool process_chunk(__Z_UNUSED volatile uint32_t *tx, uint32_t rx) {
    // FIXME: correct/improve this. Move to common?
    const uint8_t payloadType = G_io_apdu_buffer[OFFSET_PAYLOAD_TYPE];

    if (rx < OFFSET_DATA) {
        THROW(APDU_CODE_WRONG_LENGTH);
    }

    uint32_t added = 0;
    switch (payloadType) {
        case P1_INIT: {
            ZEMU_LOGF(100, "CHUNK: Reset\n");
            tx_initialize();
            tx_reset();
            tx_initialized = true;
            return false;
        }
        case P1_ADD: {
            if (!tx_initialized) {
                THROW(APDU_CODE_TX_NOT_INITIALIZED);
            }
            ZEMU_LOGF(100, "CHUNK: Add %d\n", rx - OFFSET_DATA);
            added = tx_append(&(G_io_apdu_buffer[OFFSET_DATA]), rx - OFFSET_DATA);
            if (added != rx - OFFSET_DATA) {
                tx_initialized = false;
                THROW(APDU_CODE_OUTPUT_BUFFER_TOO_SMALL);
            }
            return false;
        }
        case P1_LAST: {
            if (!tx_initialized) {
                THROW(APDU_CODE_TX_NOT_INITIALIZED);
            }
            ZEMU_LOGF(100, "CHUNK: Last %d\n", rx - OFFSET_DATA);
            added = tx_append(&(G_io_apdu_buffer[OFFSET_DATA]), rx - OFFSET_DATA);
            tx_initialized = false;
            if (added != rx - OFFSET_DATA) {
                THROW(APDU_CODE_OUTPUT_BUFFER_TOO_SMALL);
            }
            return true;
        }
    }
    THROW(APDU_CODE_INVALIDP1P2);
    // NOLINTNEXTLINE: we don't need to return a value after throwing
}

__Z_INLINE void handleExtractSpendSignature(volatile uint32_t *tx, uint32_t rx) {
    zemu_log("----[handleExtractSpendSignature]\n");

    *tx = 0;
    if (rx != APDU_MIN_LENGTH || G_io_apdu_buffer[OFFSET_DATA_LEN] != 0) {
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

__Z_INLINE void handleExtractTransparentSignature(volatile uint32_t *tx, uint32_t rx) {
    zemu_log("----[handleExtractTransparentSignature]\n");

    *tx = 0;
    if (rx != APDU_MIN_LENGTH || G_io_apdu_buffer[OFFSET_DATA_LEN] != 0) {
        THROW(APDU_CODE_COMMAND_NOT_ALLOWED);
    }

    zxerr_t err = crypto_extract_transparent_signature(G_io_apdu_buffer, IO_APDU_BUFFER_SIZE - 2);

    if (err == zxerr_ok) {
        *tx = 64;
        THROW(APDU_CODE_OK);
    } else {
        view_idle_show(0, NULL);
        *tx = 0;
        THROW(APDU_CODE_DATA_INVALID);
    }
}

__Z_INLINE void handleExtractSpendData(volatile uint32_t *tx, uint32_t rx) {
    zemu_log("----[handleExtractSpendData]\n");

    *tx = 0;
    if (rx != APDU_MIN_LENGTH || G_io_apdu_buffer[OFFSET_DATA_LEN] != 0) {
        THROW(APDU_CODE_COMMAND_NOT_ALLOWED);
    }

    zxerr_t err = crypto_extract_spend_proofkeyandrnd(G_io_apdu_buffer, IO_APDU_BUFFER_SIZE - 2);
    view_tx_state();
    if (err == zxerr_ok) {
        *tx = 128;  // SPEND_EXTRACT_LEN
        THROW(APDU_CODE_OK);
    } else {
        *tx = 0;
        THROW(APDU_CODE_DATA_INVALID);
    }
}

__Z_INLINE void handleExtractOutputData(volatile uint32_t *tx, uint32_t rx) {
    zemu_log("----[handleExtractOutputData]\n");

    *tx = 0;
    if (rx != APDU_MIN_LENGTH || G_io_apdu_buffer[OFFSET_DATA_LEN] != 0) {
        THROW(APDU_CODE_COMMAND_NOT_ALLOWED);
    }

    uint16_t replyLen = 0;
    zxerr_t err = crypto_extract_output_rnd(G_io_apdu_buffer, IO_APDU_BUFFER_SIZE - 2, &replyLen);
    view_tx_state();
    if (err == zxerr_ok) {
        *tx = replyLen;
        THROW(APDU_CODE_OK);
    } else {
        *tx = 0;
        THROW(APDU_CODE_DATA_INVALID);
    }
}

__Z_INLINE void handleInitTX(volatile uint32_t *flags, volatile uint32_t *tx, uint32_t rx) {
    if (!process_chunk(tx, rx)) {
        THROW(APDU_CODE_OK);
    }

    zemu_log("----[handleInitTX]\n");

    *tx = 0;
    const uint8_t *message = tx_get_buffer();
    const uint16_t messageLength = tx_get_buffer_length();

    zxerr_t err = crypto_extracttx_sapling(G_io_apdu_buffer, IO_APDU_BUFFER_SIZE - 3, message, messageLength);
    if (err != zxerr_ok) {
        transaction_reset();
        MEMZERO(G_io_apdu_buffer, IO_APDU_BUFFER_SIZE);
        G_io_apdu_buffer[0] = err;
        *tx = 1;
        THROW(APDU_CODE_EXTRACT_TRANSACTION_FAIL);
    }

    err = crypto_hash_messagebuffer(G_io_apdu_buffer, IO_APDU_BUFFER_SIZE - 3, message, messageLength);
    if (err != zxerr_ok) {
        transaction_reset();
        MEMZERO(G_io_apdu_buffer, IO_APDU_BUFFER_SIZE);
        G_io_apdu_buffer[0] = err;
        *tx = 1;
        THROW(APDU_CODE_HASH_MSG_BUF_FAIL);
    }

    ////////////

    view_review_init(tx_getItem, tx_getNumItems, app_reply_hash);

    view_review_show(REVIEW_TXN);
    *flags |= IO_ASYNCH_REPLY;
}

__Z_INLINE void handleCheckandSign(volatile uint32_t *tx, uint32_t rx) {
    if (!process_chunk(tx, rx)) {
        THROW(APDU_CODE_OK);
    }
    *tx = 0;

    zemu_log("----[handleCheckandSign]\n");

    const uint8_t *message = tx_get_buffer();
    const uint16_t messageLength = tx_get_buffer_length();

    const uint8_t txVersion = G_io_apdu_buffer[OFFSET_P2];

    char buffer[20];
    snprintf(buffer, sizeof(buffer), "Tx Version is %d", txVersion);
    zemu_log_stack(buffer);

    if (!((txVersion == TX_VERSION_SAPLING) || (txVersion == TX_VERSION_NU5))) {
        zemu_log("Unhandled tx version\n");
        MEMZERO(G_io_apdu_buffer, IO_APDU_BUFFER_SIZE);
        view_idle_show(0, NULL);
        transaction_reset();
        THROW(APDU_CODE_UNHANDLED_TX_VERSION);
    }

    if (get_state() != STATE_PROCESSED_ALL_EXTRACTIONS) {
        zemu_log("[handleCheckandSign] not STATE_PROCESSED_ALL_EXTRACTIONS\n");
        MEMZERO(G_io_apdu_buffer, IO_APDU_BUFFER_SIZE);
        view_idle_show(0, NULL);
        transaction_reset();
        THROW(APDU_CODE_UNPROCESSED_TX);
    }

    set_state(STATE_CHECKING_ALL_TXDATA);
    view_tx_state();

    zxerr_t err = crypto_check_prevouts(G_io_apdu_buffer, IO_APDU_BUFFER_SIZE - 3, message, txVersion);
    if (err != zxerr_ok) {
        MEMZERO(G_io_apdu_buffer, IO_APDU_BUFFER_SIZE);
        view_idle_show(0, NULL);
        transaction_reset();
        THROW(APDU_CODE_PREVOUT_INVALID);
    }

    err = crypto_check_sequence(G_io_apdu_buffer, IO_APDU_BUFFER_SIZE - 3, message, txVersion);
    if (err != zxerr_ok) {
        MEMZERO(G_io_apdu_buffer, IO_APDU_BUFFER_SIZE);
        view_idle_show(0, NULL);
        transaction_reset();
        THROW(APDU_CODE_SEQUENCE_INVALID);
    }

    err = crypto_check_outputs(G_io_apdu_buffer, IO_APDU_BUFFER_SIZE - 3, message, messageLength, txVersion);
    if (err != zxerr_ok) {
        MEMZERO(G_io_apdu_buffer, IO_APDU_BUFFER_SIZE);
        view_idle_show(0, NULL);
        transaction_reset();
        THROW(APDU_CODE_OUTPUTS_INVALID);
    }

    err = crypto_check_joinsplits(G_io_apdu_buffer, IO_APDU_BUFFER_SIZE - 3, message, txVersion);
    if (err != zxerr_ok) {
        MEMZERO(G_io_apdu_buffer, IO_APDU_BUFFER_SIZE);
        view_idle_show(0, NULL);
        transaction_reset();
        THROW(APDU_CODE_JOINSPLIT_INVALID);
    }

    // /!\ the valuebalance is different to the total value
    err = crypto_check_valuebalance(G_io_apdu_buffer, IO_APDU_BUFFER_SIZE - 3, message, txVersion);
    if (err != zxerr_ok) {
        MEMZERO(G_io_apdu_buffer, IO_APDU_BUFFER_SIZE);
        view_idle_show(0, NULL);
        transaction_reset();
        THROW(APDU_CODE_BAD_VALUEBALANCE);
    }

    err = crypto_checkspend_sapling(G_io_apdu_buffer, IO_APDU_BUFFER_SIZE - 3, message, messageLength, txVersion);
    if (err != zxerr_ok) {
        MEMZERO(G_io_apdu_buffer, IO_APDU_BUFFER_SIZE);
        view_idle_show(0, NULL);
        transaction_reset();
        THROW(APDU_CODE_SPEND_INVALID);
    }

    err = crypto_checkoutput_sapling(G_io_apdu_buffer, IO_APDU_BUFFER_SIZE - 3, message, messageLength, txVersion);
    if (err != zxerr_ok) {
        zemu_log("----[crypto_checkoutput_sapling failed]\n");
        MEMZERO(G_io_apdu_buffer, IO_APDU_BUFFER_SIZE);
        view_idle_show(0, NULL);
        transaction_reset();
        THROW(APDU_CODE_OUTPUT_CONTENT_INVALID);
    }

    err = crypto_checkencryptions_sapling(G_io_apdu_buffer, IO_APDU_BUFFER_SIZE - 3, message);
    if (err != zxerr_ok) {
        MEMZERO(G_io_apdu_buffer, IO_APDU_BUFFER_SIZE);
        view_idle_show(0, NULL);
        transaction_reset();
        THROW(APDU_CODE_ENCRYPTION_INVALID);
    }

    set_state(STATE_VERIFIED_ALL_TXDATA);
    view_tx_state();

    err = crypto_sign_and_check_transparent(G_io_apdu_buffer, IO_APDU_BUFFER_SIZE - 3, message, messageLength, txVersion);
    if (err != zxerr_ok) {
        MEMZERO(G_io_apdu_buffer, IO_APDU_BUFFER_SIZE);
        view_idle_show(0, NULL);
        transaction_reset();
        THROW(APDU_CODE_CHECK_SIGN_TR_FAIL);
    }

    err = crypto_signspends_sapling(G_io_apdu_buffer, IO_APDU_BUFFER_SIZE - 3, message, messageLength, txVersion);
    if (err != zxerr_ok) {
        MEMZERO(G_io_apdu_buffer, IO_APDU_BUFFER_SIZE);
        view_idle_show(0, NULL);
        transaction_reset();
        THROW(APDU_SIGN_SPEND_FAIL);
    }

    err = crypto_hash_messagebuffer(G_io_apdu_buffer, IO_APDU_BUFFER_SIZE - 3, message, messageLength);
    if (err != zxerr_ok) {
        MEMZERO(G_io_apdu_buffer, IO_APDU_BUFFER_SIZE);
        view_idle_show(0, NULL);
        transaction_reset();
        THROW(APDU_CODE_HASH_MSG_BUF_FAIL);
    }

    set_state(STATE_SIGNED_TX);
    view_tx_state();

    *tx = 32;
    THROW(APDU_CODE_OK);
}
