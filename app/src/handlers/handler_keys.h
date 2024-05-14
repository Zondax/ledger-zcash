#include <os.h>
#include <os_io_seproxyhal.h>

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

// FIXME: we need to add a paranoid mode, where every request is shown

// Transmitted notes are stored on the blockchain in encrypted form.
// If the note was sent to Alice, she uses her incoming viewing key (IVK)
// to decrypt the note (so that she can subsequently send it).
// This function also returns the default diversifier to reduce interactions
// between host and device
__Z_INLINE void handleGetKeyIVK(volatile uint32_t *flags, volatile uint32_t *tx, uint32_t rx) {
    zemu_log("----[handleGetKeyIVK]\n");

    *tx = 0;
    if (rx < APDU_MIN_LENGTH || rx - APDU_MIN_LENGTH != APDU_DATA_LENGTH_GET_IVK ||
        G_io_apdu_buffer[OFFSET_DATA_LEN] != APDU_DATA_LENGTH_GET_IVK || G_io_apdu_buffer[OFFSET_P1] == 0) {
        zemu_log("Wrong length!\n");
        THROW(APDU_CODE_COMMAND_NOT_ALLOWED);
    }

    uint32_t zip32_account = 0;
    parser_error_t prserr = parser_sapling_path(G_io_apdu_buffer + OFFSET_DATA, APDU_DATA_LENGTH_GET_IVK, &zip32_account);
    MEMZERO(G_io_apdu_buffer, IO_APDU_BUFFER_SIZE);
    if (prserr != parser_ok) {
        *tx = 0;
        THROW(APDU_CODE_DATA_INVALID);
    }
    key_state.kind = key_ivk;
    uint16_t replyLen = 0;

    zxerr_t err = crypto_ivk_sapling(G_io_apdu_buffer, IO_APDU_BUFFER_SIZE - 2, zip32_account, &replyLen);
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
    if (rx < APDU_MIN_LENGTH || rx - APDU_MIN_LENGTH != APDU_DATA_LENGTH_GET_OVK ||
        G_io_apdu_buffer[OFFSET_DATA_LEN] != APDU_DATA_LENGTH_GET_OVK || G_io_apdu_buffer[OFFSET_P1] == 0) {
        zemu_log("Wrong length!\n");
        THROW(APDU_CODE_COMMAND_NOT_ALLOWED);
    }

    uint32_t zip32path = 0;
    parser_error_t prserr = parser_sapling_path(G_io_apdu_buffer + OFFSET_DATA, APDU_DATA_LENGTH_GET_OVK, &zip32path);
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
    if (rx < APDU_MIN_LENGTH || rx - APDU_MIN_LENGTH != APDU_DATA_LENGTH_GET_FVK ||
        G_io_apdu_buffer[OFFSET_DATA_LEN] != APDU_DATA_LENGTH_GET_FVK || G_io_apdu_buffer[OFFSET_P1] == 0) {
        zemu_log("Wrong length!\n");
        THROW(APDU_CODE_COMMAND_NOT_ALLOWED);
    }

    uint32_t zip32path = 0;
    parser_error_t prserr = parser_sapling_path(G_io_apdu_buffer + OFFSET_DATA, APDU_DATA_LENGTH_GET_FVK, &zip32path);
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

    if (rx < APDU_MIN_LENGTH || rx - APDU_MIN_LENGTH != APDU_DATA_LENGTH_GET_NF ||
        G_io_apdu_buffer[OFFSET_DATA_LEN] != APDU_DATA_LENGTH_GET_NF || G_io_apdu_buffer[OFFSET_P1] == 0) {
        zemu_log("Wrong length!\n");
        THROW(APDU_CODE_COMMAND_NOT_ALLOWED);
    }

    uint32_t zip32path = 0;
    parser_error_t prserr = parser_sapling_path(G_io_apdu_buffer + OFFSET_DATA, APDU_DATA_LENGTH_GET_NF, &zip32path);
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
    zxerr_t err = crypto_nullifier_sapling(G_io_apdu_buffer, IO_APDU_BUFFER_SIZE - 2, zip32path, notepos, cm, &replyLen);

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

__Z_INLINE void handleGetDiversifierList(volatile uint32_t *tx, uint32_t rx) {
    zemu_log("----[handleGetDiversifierList]\n");

    *tx = 0;
    if (rx < APDU_MIN_LENGTH) {
        THROW(APDU_CODE_COMMAND_NOT_ALLOWED);
    }

    if (rx - APDU_MIN_LENGTH != APDU_DATA_LENGTH_GET_DIV_LIST) {
        THROW(APDU_CODE_COMMAND_NOT_ALLOWED);
    }

    if (G_io_apdu_buffer[OFFSET_DATA_LEN] != APDU_DATA_LENGTH_GET_DIV_LIST) {
        THROW(APDU_CODE_COMMAND_NOT_ALLOWED);
    }

    uint16_t replyLen = 0;

    zemu_log_stack("handleGetDiversifierList");

    parser_addr_div_t parser_addr;
    MEMZERO(&parser_addr, sizeof(parser_addr_div_t));

    parser_error_t prserr =
        parser_sapling_path_with_div(G_io_apdu_buffer + OFFSET_DATA, APDU_DATA_LENGTH_GET_DIV_LIST, &parser_addr);
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
