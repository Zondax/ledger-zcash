/*******************************************************************************
 *   (c) 2018 -2022 Zondax AG
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

__Z_INLINE void handle_getversion(volatile uint32_t *tx) {
#ifdef DEBUG
    G_io_apdu_buffer[0] = 0xFF;
#else
    G_io_apdu_buffer[0] = 0;
#endif
    G_io_apdu_buffer[1] = LEDGER_MAJOR_VERSION;
    G_io_apdu_buffer[2] = LEDGER_MINOR_VERSION;
    G_io_apdu_buffer[3] = LEDGER_PATCH_VERSION;
    // SDK won't reply any APDU message if the device is locked --> Set
    // device_locked = false
    G_io_apdu_buffer[4] = 0;

    G_io_apdu_buffer[5] = (TARGET_ID >> 24) & 0xFF;
    G_io_apdu_buffer[6] = (TARGET_ID >> 16) & 0xFF;
    G_io_apdu_buffer[7] = (TARGET_ID >> 8) & 0xFF;
    G_io_apdu_buffer[8] = (TARGET_ID >> 0) & 0xFF;

    *tx += 9;
    THROW(APDU_CODE_OK);
}

__Z_INLINE void extractHDPath(uint32_t rx, uint32_t offset) {
    if ((rx - offset) < sizeof(uint32_t) * HDPATH_LEN_DEFAULT) {
        THROW(APDU_CODE_WRONG_LENGTH);
    }

    MEMCPY(hdPath, G_io_apdu_buffer + offset, sizeof(uint32_t) * HDPATH_LEN_DEFAULT);

    const bool mainnet = hdPath[0] == HDPATH_0_DEFAULT && hdPath[1] == HDPATH_1_DEFAULT;

    const bool testnet = hdPath[0] == HDPATH_0_TESTNET && hdPath[1] == HDPATH_1_TESTNET;

    if (!mainnet && !testnet) {
        THROW(APDU_CODE_DATA_INVALID);
    }
}

__Z_INLINE bool process_chunk(__Z_UNUSED volatile uint32_t *tx, uint32_t rx) {
    // FIXME: correct/improve this. Move to common?
    const uint8_t payloadType = G_io_apdu_buffer[OFFSET_PAYLOAD_TYPE];

    if (rx < OFFSET_DATA) {
        THROW(APDU_CODE_WRONG_LENGTH);
    }

    uint32_t added;
    switch (payloadType) {
        case 0:
            tx_initialize();
            tx_reset();
            return false;
        case 1:
            added = tx_append(&(G_io_apdu_buffer[OFFSET_DATA]), rx - OFFSET_DATA);
            if (added != rx - OFFSET_DATA) {
                THROW(APDU_CODE_OUTPUT_BUFFER_TOO_SMALL);
            }
            return false;
        case 2:
            added = tx_append(&(G_io_apdu_buffer[OFFSET_DATA]), rx - OFFSET_DATA);
            if (added != rx - OFFSET_DATA) {
                THROW(APDU_CODE_OUTPUT_BUFFER_TOO_SMALL);
            }
            return true;
    }
    THROW(APDU_CODE_INVALIDP1P2);
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

// Transmitted notes are stored on the blockchain in encrypted form.
// If the note was sent to Alice, she uses her incoming viewing key (IVK)
// to decrypt the note (so that she can subsequently send it).
// This function also returns the default diversifier to reduce interactions
// between host and device
__Z_INLINE void handleGetKeyIVK(volatile uint32_t *flags, volatile uint32_t *tx, uint32_t rx) {
    zemu_log("----[handleGetKeyIVK]\n");

    *tx = 0;
    if (rx < APDU_MIN_LENGTH || rx - APDU_MIN_LENGTH != DATA_LENGTH_GET_IVK ||
        G_io_apdu_buffer[OFFSET_DATA_LEN] != DATA_LENGTH_GET_IVK || G_io_apdu_buffer[OFFSET_P1] == 0) {
        zemu_log("Wrong length!\n");
        THROW(APDU_CODE_COMMAND_NOT_ALLOWED);
    }

    uint32_t zip32path = 0;
    parser_error_t prserr = parser_sapling_path(G_io_apdu_buffer + OFFSET_DATA, DATA_LENGTH_GET_IVK, &zip32path);
    MEMZERO(G_io_apdu_buffer, IO_APDU_BUFFER_SIZE);
    if (prserr != parser_ok) {
        *tx = 0;
        THROW(APDU_CODE_DATA_INVALID);
    }
    key_state.kind = key_ivk;
    uint16_t replyLen = 0;

    zxerr_t err = crypto_ivk_sapling(G_io_apdu_buffer, IO_APDU_BUFFER_SIZE - 2, zip32path, &replyLen);
    if (err != zxerr_ok) {
        *tx = 0;
        THROW(APDU_CODE_DATA_INVALID);
    }
    key_state.len = (uint8_t)replyLen;

    view_review_init(key_getItem, key_getNumItems, app_reply_key);
    view_review_show(REVIEW_TXN);
    *flags |= IO_ASYNCH_REPLY;
}

// If Bob sends a note to Alice (stored on the blockchain in encrypted form),
// he can decrypt using his outgoing viewing key (OVK).
__Z_INLINE void handleGetKeyOVK(volatile uint32_t *flags, volatile uint32_t *tx, uint32_t rx) {
    zemu_log("----[handleGetKeyOVK]\n");

    *tx = 0;
    if (rx < APDU_MIN_LENGTH || rx - APDU_MIN_LENGTH != DATA_LENGTH_GET_OVK ||
        G_io_apdu_buffer[OFFSET_DATA_LEN] != DATA_LENGTH_GET_OVK || G_io_apdu_buffer[OFFSET_P1] == 0) {
        zemu_log("Wrong length!\n");
        THROW(APDU_CODE_COMMAND_NOT_ALLOWED);
    }

    uint32_t zip32path = 0;
    parser_error_t prserr = parser_sapling_path(G_io_apdu_buffer + OFFSET_DATA, DATA_LENGTH_GET_OVK, &zip32path);
    MEMZERO(G_io_apdu_buffer, IO_APDU_BUFFER_SIZE);
    if (prserr != parser_ok) {
        *tx = 0;
        THROW(APDU_CODE_DATA_INVALID);
    }
    key_state.kind = key_ovk;
    uint16_t replyLen = 0;

    zxerr_t err = crypto_ovk_sapling(G_io_apdu_buffer, IO_APDU_BUFFER_SIZE - 2, zip32path, &replyLen);
    if (err != zxerr_ok) {
        *tx = 0;
        THROW(APDU_CODE_DATA_INVALID);
    }
    key_state.len = (uint8_t)replyLen;

    view_review_init(key_getItem, key_getNumItems, app_reply_key);
    view_review_show(REVIEW_TXN);
    *flags |= IO_ASYNCH_REPLY;
}

// Get the sapling full viewing key (ak, nk, ovk)
__Z_INLINE void handleGetKeyFVK(volatile uint32_t *flags, volatile uint32_t *tx, uint32_t rx) {
    zemu_log("----[handleGetKeyFVK]\n");

    *tx = 0;
    if (rx < APDU_MIN_LENGTH || rx - APDU_MIN_LENGTH != DATA_LENGTH_GET_FVK ||
        G_io_apdu_buffer[OFFSET_DATA_LEN] != DATA_LENGTH_GET_FVK || G_io_apdu_buffer[OFFSET_P1] == 0) {
        zemu_log("Wrong length!\n");
        THROW(APDU_CODE_COMMAND_NOT_ALLOWED);
    }

    uint32_t zip32path = 0;
    parser_error_t prserr = parser_sapling_path(G_io_apdu_buffer + OFFSET_DATA, DATA_LENGTH_GET_FVK, &zip32path);
    MEMZERO(G_io_apdu_buffer, IO_APDU_BUFFER_SIZE);
    if (prserr != parser_ok) {
        *tx = 0;
        THROW(APDU_CODE_DATA_INVALID);
    }
    key_state.kind = key_fvk;
    uint16_t replyLen = 0;

    zxerr_t err = crypto_fvk_sapling(G_io_apdu_buffer, IO_APDU_BUFFER_SIZE - 2, zip32path, &replyLen);
    if (err != zxerr_ok) {
        *tx = 0;
        THROW(APDU_CODE_DATA_INVALID);
    }
    key_state.len = (uint8_t)replyLen;

    view_review_init(key_getItem, key_getNumItems, app_reply_key);
    view_review_show(REVIEW_TXN);
    *flags |= IO_ASYNCH_REPLY;
}

// Computing the note nullifier nf is required in order to spend the note.
// Computing nf requires the associated (private) nullifier deriving key nk
// and the note position pos.
// (nk is part of the full viewing key fvk = (ak, nk, ovk) )
__Z_INLINE void handleGetNullifier(volatile uint32_t *flags, volatile uint32_t *tx, uint32_t rx) {
    *tx = 0;
    // TODO: review this.. there is too much copy-paste. Move into a single configurable function

    if (rx < APDU_MIN_LENGTH || rx - APDU_MIN_LENGTH != DATA_LENGTH_GET_NF ||
        G_io_apdu_buffer[OFFSET_DATA_LEN] != DATA_LENGTH_GET_NF || G_io_apdu_buffer[OFFSET_P1] == 0) {
        zemu_log("Wrong length!\n");
        THROW(APDU_CODE_COMMAND_NOT_ALLOWED);
    }

    uint32_t zip32path = 0;
    parser_error_t prserr = parser_sapling_path(G_io_apdu_buffer + OFFSET_DATA, DATA_LENGTH_GET_NF, &zip32path);
    if (prserr != parser_ok) {
        MEMZERO(G_io_apdu_buffer, IO_APDU_BUFFER_SIZE);
        *tx = 0;
        zemu_log("Failed to get seed!\n");
        THROW(APDU_CODE_DATA_INVALID);
    }

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
    zxerr_t err = crypto_nullifier_sapling(G_io_apdu_buffer, IO_APDU_BUFFER_SIZE - 2, notepos, cm, &replyLen);
    if (err != zxerr_ok) {
        zemu_log("Failed to get nullifier!\n");
        *tx = 0;
        THROW(APDU_CODE_DATA_INVALID);
    }
    key_state.len = (uint8_t)replyLen;

    view_review_init(key_getItem, key_getNumItems, app_reply_key);
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

__Z_INLINE void handleGetAddrSecp256K1(volatile uint32_t *flags, volatile uint32_t *tx, uint32_t rx) {
    zemu_log("----[handleGetAddrSecp256K1]\n");

    extractHDPath(rx, OFFSET_DATA);
    *tx = 0;
    uint8_t requireConfirmation = G_io_apdu_buffer[OFFSET_P1];
    uint16_t replyLen = 0;

    zxerr_t err = crypto_fillAddress_secp256k1(G_io_apdu_buffer, IO_APDU_BUFFER_SIZE - 2, &replyLen);
    if (err != zxerr_ok) {
        *tx = 0;
        THROW(APDU_CODE_DATA_INVALID);
    }

    action_addrResponse.kind = addr_secp256k1;
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
    zemu_log("----[handleGetAddrSaplingDiv]\n");

    *tx = 0;
    if (rx < APDU_MIN_LENGTH) {
        THROW(APDU_CODE_COMMAND_NOT_ALLOWED);
    }

    if (rx - APDU_MIN_LENGTH != DATA_LENGTH_GET_ADDR_DIV) {
        THROW(APDU_CODE_COMMAND_NOT_ALLOWED);
    }

    if (G_io_apdu_buffer[OFFSET_DATA_LEN] != DATA_LENGTH_GET_ADDR_DIV) {
        THROW(APDU_CODE_COMMAND_NOT_ALLOWED);
    }

    uint8_t requireConfirmation = G_io_apdu_buffer[OFFSET_P1];

    uint16_t replyLen = 0;

    zemu_log_stack("handleGetAddrSapling_withdiv");

    parser_addr_div_t parser_addr;
    MEMZERO(&parser_addr, sizeof(parser_addr_div_t));

    parser_error_t parseErr =
        parser_sapling_path_with_div(G_io_apdu_buffer + OFFSET_DATA, DATA_LENGTH_GET_ADDR_DIV, &parser_addr);
    MEMZERO(G_io_apdu_buffer, IO_APDU_BUFFER_SIZE);
    if (parseErr != parser_ok) {
        *tx = 0;
        THROW(APDU_CODE_DATA_INVALID);
    }
    zxerr_t err = crypto_fillAddress_with_diversifier_sapling(G_io_apdu_buffer, IO_APDU_BUFFER_SIZE - 3, parser_addr.path,
                                                              parser_addr.div, &replyLen);
    if (err != zxerr_ok) {
        *tx = 0;
        THROW(APDU_CODE_DATA_INVALID);
    }
    action_addrResponse.kind = addr_sapling_div;
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

__Z_INLINE void handleGetDiversifierList(volatile uint32_t *tx, uint32_t rx) {
    zemu_log("----[handleGetDiversifierList]\n");

    *tx = 0;
    if (rx < APDU_MIN_LENGTH) {
        THROW(APDU_CODE_COMMAND_NOT_ALLOWED);
    }

    if (rx - APDU_MIN_LENGTH != DATA_LENGTH_GET_DIV_LIST) {
        THROW(APDU_CODE_COMMAND_NOT_ALLOWED);
    }

    if (G_io_apdu_buffer[OFFSET_DATA_LEN] != DATA_LENGTH_GET_DIV_LIST) {
        THROW(APDU_CODE_COMMAND_NOT_ALLOWED);
    }

    uint16_t replyLen = 0;

    zemu_log_stack("handleGetDiversifierList");

    parser_addr_div_t parser_addr;
    MEMZERO(&parser_addr, sizeof(parser_addr_div_t));

    parser_error_t prserr =
        parser_sapling_path_with_div(G_io_apdu_buffer + OFFSET_DATA, DATA_LENGTH_GET_DIV_LIST, &parser_addr);
    MEMZERO(G_io_apdu_buffer, IO_APDU_BUFFER_SIZE);
    if (prserr != parser_ok) {
        *tx = 0;
        THROW(APDU_CODE_DATA_INVALID);
    }
    zxerr_t err = crypto_diversifier_with_startindex(G_io_apdu_buffer, parser_addr.path, parser_addr.div, &replyLen);

    if (err == zxerr_ok) {
        *tx = replyLen;
        THROW(APDU_CODE_OK);
    } else {
        *tx = 0;
        THROW(APDU_CODE_DATA_INVALID);
    }
}

__Z_INLINE void handleGetAddrSapling(volatile uint32_t *flags, volatile uint32_t *tx, uint32_t rx) {
    zemu_log("----[handleGetAddrSapling]\n");

    *tx = 0;
    if (rx < APDU_MIN_LENGTH) {
        zemu_log("Missing data!\n");
        THROW(APDU_CODE_COMMAND_NOT_ALLOWED);
    }

    if (rx != (uint32_t)(DATA_LENGTH_GET_ADDR_SAPLING + APDU_MIN_LENGTH)) {
        zemu_log("Wrong length!\n");
        THROW(APDU_CODE_COMMAND_NOT_ALLOWED);
    }

    if (G_io_apdu_buffer[OFFSET_DATA_LEN] != DATA_LENGTH_GET_ADDR_SAPLING) {
        zemu_log("Wrong offset data length!\n");
        THROW(APDU_CODE_COMMAND_NOT_ALLOWED);
    }

    uint8_t requireConfirmation = G_io_apdu_buffer[OFFSET_P1];

    uint32_t zip32path = 0;
    parser_error_t prserr = parser_sapling_path(G_io_apdu_buffer + OFFSET_DATA, DATA_LENGTH_GET_ADDR_SAPLING, &zip32path);
    MEMZERO(G_io_apdu_buffer, IO_APDU_BUFFER_SIZE);
    if (prserr != parser_ok) {
        *tx = 0;
        THROW(APDU_CODE_DATA_INVALID);
    }
    uint16_t replyLen = 0;
    zxerr_t err = crypto_fillAddress_sapling(G_io_apdu_buffer, IO_APDU_BUFFER_SIZE - 2, zip32path, &replyLen);
    if (err != zxerr_ok) {
        *tx = 0;
        THROW(APDU_CODE_DATA_INVALID);
    }
    action_addrResponse.kind = addr_sapling;
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

__Z_INLINE void handleSignSapling() {
    THROW(APDU_CODE_COMMAND_NOT_ALLOWED);
}

void handleApdu(volatile uint32_t *flags, volatile uint32_t *tx, uint32_t rx) {
    uint16_t sw = 0;

    BEGIN_TRY {
        TRY {
            if (G_io_apdu_buffer[OFFSET_CLA] != CLA) {
                THROW(APDU_CODE_CLA_NOT_SUPPORTED);
            }

            if (rx < APDU_MIN_LENGTH) {
                THROW(APDU_CODE_WRONG_LENGTH);
            }

            switch (G_io_apdu_buffer[OFFSET_INS]) {
                case INS_GET_VERSION: {
                    handle_getversion(tx);
                    break;
                }

                case INS_GET_ADDR_SECP256K1: {
                    CHECK_PIN_VALIDATED()
                    handleGetAddrSecp256K1(flags, tx, rx);
                    break;
                }

                case INS_GET_IVK: {
                    CHECK_PIN_VALIDATED()
                    handleGetKeyIVK(flags, tx, rx);
                    break;
                }

                case INS_GET_OVK: {
                    CHECK_PIN_VALIDATED()
                    handleGetKeyOVK(flags, tx, rx);
                    break;
                }

                case INS_GET_NF: {
                    CHECK_PIN_VALIDATED()
                    handleGetNullifier(flags, tx, rx);
                    break;
                }

                case INS_GET_FVK: {
                    CHECK_PIN_VALIDATED()
                    handleGetKeyFVK(flags, tx, rx);
                    break;
                }

                case INS_INIT_TX: {
                    CHECK_PIN_VALIDATED()
                    handleInitTX(flags, tx, rx);
                    break;
                }

                case INS_EXTRACT_SPEND: {
                    CHECK_PIN_VALIDATED()
                    handleExtractSpendData(tx, rx);
                    break;
                }

                case INS_EXTRACT_OUTPUT: {
                    CHECK_PIN_VALIDATED()
                    handleExtractOutputData(tx, rx);
                    break;
                }

                case INS_CHECKANDSIGN: {
                    CHECK_PIN_VALIDATED()
                    handleCheckandSign(tx, rx);
                    break;
                }

                case INS_EXTRACT_SPENDSIG: {
                    CHECK_PIN_VALIDATED()
                    handleExtractSpendSignature(tx, rx);
                    break;
                }

                case INS_EXTRACT_TRANSSIG: {
                    CHECK_PIN_VALIDATED()
                    handleExtractTransparentSignature(tx, rx);
                    break;
                }

                case INS_GET_ADDR_SAPLING: {
                    CHECK_PIN_VALIDATED()
                    handleGetAddrSapling(flags, tx, rx);
                    break;
                }

                case INS_GET_DIV_LIST: {
                    CHECK_PIN_VALIDATED()
                    handleGetDiversifierList(tx, rx);
                    break;
                }

                case INS_GET_ADDR_SAPLING_DIV: {
                    CHECK_PIN_VALIDATED()
                    handleGetAddrSaplingDiv(flags, tx, rx);
                    break;
                }

                case INS_SIGN_SAPLING: {
                    CHECK_PIN_VALIDATED()
                    handleSignSapling();
                    break;
                }

                default:
                    THROW(APDU_CODE_INS_NOT_SUPPORTED);
            }
        }
        CATCH(EXCEPTION_IO_RESET) {
            THROW(EXCEPTION_IO_RESET);
        }
        CATCH_OTHER(e) {
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
        FINALLY {
        }
    }
    END_TRY;
}
