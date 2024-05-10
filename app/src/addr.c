/*******************************************************************************
 *   (c) 2018 - 2022 Zondax AG
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

#include <stdio.h>

#include "actions.h"
#include "app_mode.h"
#include "coin.h"
#include "crypto.h"
#include "zxerror.h"
#include "zxformat.h"
#include "zxmacros.h"

zxerr_t addr_getNumItems(uint8_t *num_items) {
    zemu_log_stack("addr_getNumItems");
    *num_items = 1;
    if (app_mode_expert()) {
        *num_items = 2;
    }
    return zxerr_ok;
}

zxerr_t addr_getItem(int8_t displayIdx,
                     char *outKey,
                     uint16_t outKeyLen,
                     char *outVal,
                     uint16_t outValLen,
                     uint8_t pageIdx,
                     uint8_t *pageCount) {
    ZEMU_LOGF(200, "[addr_getItem] %d/%d\n", displayIdx, pageIdx)

    switch (displayIdx) {
        case 0:
            switch (action_addrResponse.kind) {
                case addr_secp256k1:
                    snprintf(outKey, outKeyLen, "Unshielded");
                    pageString(outVal, outValLen, (char *)(G_io_apdu_buffer + VIEW_ADDRESS_OFFSET_SECP256K1), pageIdx,
                               pageCount);
                    return zxerr_ok;

                case addr_sapling:
                    snprintf(outKey, outKeyLen, "Shielded");
                    pageString(outVal, outValLen, (char *)(G_io_apdu_buffer + VIEW_ADDRESS_OFFSET_SAPLING), pageIdx,
                               pageCount);
                    return zxerr_ok;

                case addr_sapling_div:
                    snprintf(outKey, outKeyLen, "Shielded with div");
                    pageString(outVal, outValLen, (char *)(G_io_apdu_buffer + VIEW_ADDRESS_OFFSET_SAPLING), pageIdx,
                               pageCount);
                    return zxerr_ok;

                default:
                    return zxerr_no_data;
            }
        case 1: {
            if (!app_mode_expert()) {
                return zxerr_no_data;
            }

            snprintf(outKey, outKeyLen, "Your Path");
            char buffer[300];
            bip32_to_str(buffer, sizeof(buffer), hdPath, HDPATH_LEN_DEFAULT);
            pageString(outVal, outValLen, buffer, pageIdx, pageCount);
            return zxerr_ok;
        }
        default:
            return zxerr_no_data;
    }
}
