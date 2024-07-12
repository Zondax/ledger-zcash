#include <os.h>
#include <os_io_seproxyhal.h>

#include "apdu_errors.h"
#include "app_main.h"
#include "app_mode.h"
#include "coin.h"
#include "crypto.h"
#include "key.h"
#include "nvdata.h"
#include "parser.h"
#include "parser_impl.h"
#include "tx.h"
#include "view.h"
#include "view_internal.h"
#include "zxmacros.h"

__Z_INLINE void extractHDPathTransparent(uint32_t rx, uint32_t offset) {
    if ((rx - offset) < sizeof(uint32_t) * HDPATH_LEN_BIP44) {
        THROW(APDU_CODE_WRONG_LENGTH);
    }
    hdPath.addressKind = addr_not_set;

    MEMCPY(hdPath.secp256k1_path, G_io_apdu_buffer + offset, sizeof(uint32_t) * HDPATH_LEN_BIP44);

    const bool mainnet = hdPath.secp256k1_path[0] == HDPATH_0_DEFAULT && hdPath.secp256k1_path[1] == HDPATH_1_DEFAULT;
    const bool testnet = hdPath.secp256k1_path[0] == HDPATH_0_TESTNET && hdPath.secp256k1_path[1] == HDPATH_1_TESTNET;

    if (!mainnet && !testnet) {
        THROW(APDU_CODE_DATA_INVALID);
    }

    hdPath.addressKind = addr_secp256k1;
}

__Z_INLINE void extractHDPathSapling(uint32_t rx, uint32_t offset) {
    if ((rx - offset) < 4) {
        THROW(APDU_CODE_WRONG_LENGTH);
    }
    hdPath.addressKind = addr_not_set;

    ZEMU_LOGF(100, "extractHDPathSapling\n");

    parser_context_t ctx;
    ctx.buffer = G_io_apdu_buffer;
    ctx.bufferLen = rx;
    ctx.offset = offset;

    hdPath.saplingdiv_path[0] = HDPATH_0_ZIP32;
    hdPath.saplingdiv_path[1] = HDPATH_1_ZIP32;

    ZEMU_LOGF(100, "offset: %d\n", ctx.offset);
    ZEMU_LOGF(100, "bufferLen: %d\n", ctx.bufferLen);

    parser_error_t err = _readUInt32(&ctx, &hdPath.sapling_path[2]);
    if (err != parser_ok) {
        ZEMU_LOGF(100, "error reading u32\n");
        THROW(APDU_CODE_DATA_INVALID);
    }

    // Validate data
    if ((hdPath.sapling_path[2] & MASK_HARDENED) == 0) {
        ZEMU_LOGF(100, "error validating hardening\n");
        THROW(APDU_CODE_DATA_INVALID);
    }

    ZEMU_LOGF(100, "Account %d\n", hdPath.sapling_path[2]);

    hdPath.addressKind = addr_sapling;
}

__Z_INLINE void extractHDPathSaplingDiv(uint32_t rx, uint32_t offset) {
    if ((rx - offset) < 4 + DIV_SIZE) {
        THROW(APDU_CODE_WRONG_LENGTH);
    }
    hdPath.addressKind = addr_not_set;

    parser_context_t ctx;
    ctx.offset = offset;
    ctx.buffer = G_io_apdu_buffer;
    ctx.bufferLen = rx;

    hdPath.saplingdiv_path[0] = HDPATH_0_ZIP32;
    hdPath.saplingdiv_path[1] = HDPATH_1_ZIP32;
    parser_error_t err = _readUInt32(&ctx, &hdPath.saplingdiv_path[2]);
    if (err != parser_ok) {
        THROW(APDU_CODE_DATA_INVALID);
    }

    MEMCPY(hdPath.saplingdiv_div, ctx.buffer + ctx.offset, DIV_SIZE);

    // Validate data
    if ((hdPath.saplingdiv_path[2] & MASK_HARDENED) == 0) {
        THROW(APDU_CODE_DATA_INVALID);
    }

    hdPath.addressKind = addr_sapling_div;
}
