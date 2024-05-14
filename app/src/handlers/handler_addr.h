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

__Z_INLINE void handleGetAddrSapling(volatile uint32_t *flags, volatile uint32_t *tx, uint32_t rx) {
    zemu_log("----[handleGetAddrSapling]\n");

    *tx = 0;
    if (rx < APDU_MIN_LENGTH) {
        zemu_log("Missing data!\n");
        THROW(APDU_CODE_COMMAND_NOT_ALLOWED);
    }

    if (rx != (uint32_t)(APDU_DATA_LENGTH_GET_ADDR_SAPLING + APDU_MIN_LENGTH)) {
        zemu_log("Wrong length!\n");
        THROW(APDU_CODE_COMMAND_NOT_ALLOWED);
    }

    if (G_io_apdu_buffer[OFFSET_DATA_LEN] != APDU_DATA_LENGTH_GET_ADDR_SAPLING) {
        zemu_log("Wrong offset data length!\n");
        THROW(APDU_CODE_COMMAND_NOT_ALLOWED);
    }

    uint8_t requireConfirmation = G_io_apdu_buffer[OFFSET_P1];

    uint32_t zip32path = 0;
    parser_error_t prserr =
        parser_sapling_path(G_io_apdu_buffer + OFFSET_DATA, APDU_DATA_LENGTH_GET_ADDR_SAPLING, &zip32path);
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

__Z_INLINE void handleGetAddrSaplingDiv(volatile uint32_t *flags, volatile uint32_t *tx, uint32_t rx) {

    *tx = 0;
    if (rx < APDU_MIN_LENGTH) {
        THROW(APDU_CODE_COMMAND_NOT_ALLOWED);
    }

    if (rx - APDU_MIN_LENGTH != APDU_DATA_LENGTH_GET_ADDR_DIV) {
        THROW(APDU_CODE_COMMAND_NOT_ALLOWED);
    }

    if (G_io_apdu_buffer[OFFSET_DATA_LEN] != APDU_DATA_LENGTH_GET_ADDR_DIV) {
        THROW(APDU_CODE_COMMAND_NOT_ALLOWED);
    }

    uint8_t requireConfirmation = G_io_apdu_buffer[OFFSET_P1];

    uint16_t replyLen = 0;

    zemu_log_stack("handleGetAddrSapling_withdiv");

    parser_addr_div_t parser_addr;
    MEMZERO(&parser_addr, sizeof(parser_addr_div_t));

    parser_error_t parseErr =
        parser_sapling_path_with_div(G_io_apdu_buffer + OFFSET_DATA, APDU_DATA_LENGTH_GET_ADDR_DIV, &parser_addr);
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
