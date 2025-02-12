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
#include "handlers/handler_addr.h"
#include "handlers/handler_keys.h"
#include "handlers/handler_path.h"
#include "handlers/handler_signing.h"
#include "handlers/handler_version.h"
#include "key.h"
#include "nvdata.h"
#include "parser.h"
#include "tx.h"
#include "view.h"
#include "view_internal.h"
#include "zxmacros.h"

hdPath_t hdPath;

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

                case INS_GET_EXT_PK_SECP256K1: {
                    CHECK_PIN_VALIDATED()
                    handleGetExtendedPkSecp256K1(flags, tx, rx);
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
