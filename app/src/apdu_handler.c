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

#include "app_main.h"

#include <string.h>
#include <os_io_seproxyhal.h>
#include <os.h>

#include "view.h"
#include "actions.h"
#include "tx.h"
#include "crypto.h"
#include "coin.h"
#include "zxmacros.h"

__Z_INLINE void handleGetAddrSecp256K1(volatile uint32_t *flags, volatile uint32_t *tx, uint32_t rx) {
    extractHDPath(rx, OFFSET_DATA);

    zemu_log_stack("handleGetAddrSecp256K1");

    uint8_t requireConfirmation = G_io_apdu_buffer[OFFSET_P1];

    if (requireConfirmation) {
        app_fill_address(addr_secp256k1);
        view_address_show(addr_secp256k1);
        *flags |= IO_ASYNCH_REPLY;
        return;
    }

    *tx = app_fill_address(addr_secp256k1);
    THROW(APDU_CODE_OK);
}

__Z_INLINE void handleSignSecp256K1(volatile uint32_t *flags, volatile uint32_t *tx, uint32_t rx) {
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

    view_sign_show();
    *flags |= IO_ASYNCH_REPLY;
}

__Z_INLINE void handleGetAddrSapling(volatile uint32_t *flags, volatile uint32_t *tx, uint32_t rx) {
    extractHDPath(rx, OFFSET_DATA);
    uint8_t requireConfirmation = G_io_apdu_buffer[OFFSET_P1];

    zemu_log_stack("handleGetAddrSapling");

    if (requireConfirmation) {
        app_fill_address(addr_sapling);
        view_address_show(addr_sapling);
        *flags |= IO_ASYNCH_REPLY;
        return;
    }

    *tx = app_fill_address(addr_sapling);
    THROW(APDU_CODE_OK);
}

__Z_INLINE void handleSignSapling(volatile uint32_t *flags, volatile uint32_t *tx, uint32_t rx) {
    THROW(APDU_CODE_COMMAND_NOT_ALLOWED);
}

#if defined(APP_TESTING)
#include "rslib.h"

__Z_INLINE void handleTest(volatile uint32_t *flags, volatile uint32_t *tx, uint32_t rx) {
    uint8_t input = G_io_apdu_buffer[OFFSET_DATA+0];

    // You can add anything that helps testing here.
    zemu_log_stack("handleTest");

    uint8_t sk[32];
    uint8_t diversifier[11];
    uint8_t pkd[32];

    crypto_fillSaplingSeed(sk);
    CHECK_APP_CANARY();

    memcpy(diversifier, sk, 11);
    CHECK_APP_CANARY();

    do_pedersen_hash(sk, pkd);
    CHECK_APP_CANARY();

    G_io_apdu_buffer[0] = 0xCA;
    G_io_apdu_buffer[1] = 0xFE;
    G_io_apdu_buffer[2] = input+1;

    *tx = 3;
    THROW(APDU_CODE_OK);
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

                case INS_SIGN_SECP256K1: {
                    handleSignSecp256K1(flags, tx, rx);
                    break;
                }

                case INS_GET_ADDR_SAPLING: {
                    handleGetAddrSapling(flags, tx, rx);
                    break;
                }

                case INS_SIGN_SAPLING: {
                    handleSignSapling(flags, tx, rx);
                    break;
                }

#if defined(APP_TESTING)
                case INS_TEST: {
                    handleTest(flags, tx, rx);
                    break;
                }
#endif
                default:
                    THROW(APDU_CODE_INS_NOT_SUPPORTED);
            }
        }
        CATCH(EXCEPTION_IO_RESET)
        {
            THROW(EXCEPTION_IO_RESET);
        }
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
        {
        }
    }
    END_TRY;
}
