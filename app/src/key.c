/*******************************************************************************
 *   (c) 2020 Zondax AG
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

zxerr_t key_getNumItems(uint8_t *num_items) {
    zemu_log_stack("key_getNumItems");
    *num_items = 1;
    if (app_mode_expert()) {
        *num_items = 2;
    }
    return zxerr_ok;
}

zxerr_t key_getItem(int8_t displayIdx,
                    char *outKey,
                    uint16_t outKeyLen,
                    char *outVal,
                    uint16_t outValLen,
                    uint8_t pageIdx,
                    uint8_t *pageCount) {
    snprintf(outKey, outKeyLen, "?");
    snprintf(outVal, outValLen, "?");

    if (hdPath.addressKind == addr_not_set || hdPath.addressKind == addr_secp256k1) {
        // This should not be possible
        return zxerr_unknown;
    }

    zemu_log_stack("key_getItem");
    char tmpBuffer[200];

    switch (displayIdx) {
        case 0: {
            zemu_log_stack("case 0");
            MEMZERO(tmpBuffer, sizeof(tmpBuffer));
            switch (key_state.kind) {
                case key_ovk:
                    snprintf(outKey, outKeyLen, "Send OVK?");
                    array_to_hexstr(tmpBuffer, sizeof(tmpBuffer), G_io_apdu_buffer, 32);
                    pageString(outVal, outValLen, tmpBuffer, pageIdx, pageCount);
                    return zxerr_ok;
                case key_ivk:
                    snprintf(outKey, outKeyLen, "Send IVK?");
                    array_to_hexstr(tmpBuffer, sizeof(tmpBuffer), G_io_apdu_buffer, 32);
                    pageString(outVal, outValLen, tmpBuffer, pageIdx, pageCount);
                    return zxerr_ok;
                case key_fvk:
                    snprintf(outKey, outKeyLen, "Send FVK?\n");
                    array_to_hexstr(tmpBuffer, sizeof(tmpBuffer), G_io_apdu_buffer, 32);
                    pageString(outVal, outValLen, tmpBuffer, pageIdx, pageCount);
                    return zxerr_ok;
                case nf:
                    zemu_log_stack("Send NF?");
                    snprintf(outKey, outKeyLen, "Send NF?");
                    array_to_hexstr(tmpBuffer, sizeof(tmpBuffer), G_io_apdu_buffer, 32);
                    pageString(outVal, outValLen, tmpBuffer, pageIdx, pageCount);
                    return zxerr_ok;
                default:
                    return zxerr_unknown;
            }
        }
        case 1: {
            if (!app_mode_expert()) {
                return zxerr_no_data;
            }

            switch (hdPath.addressKind) {
                case addr_sapling: {
                    snprintf(outKey, outKeyLen, "ZIP32 Path");

                    bip32_to_str(tmpBuffer, sizeof(tmpBuffer), hdPath.sapling_path, HDPATH_LEN_SAPLING);
                    pageString(outVal, outValLen, tmpBuffer, pageIdx, pageCount);

                    return zxerr_ok;
                }

                case addr_sapling_div: {
                    snprintf(outKey, outKeyLen, "ZIP32 Path");

                    bip32_to_str(tmpBuffer, sizeof(tmpBuffer), hdPath.sapling_path, HDPATH_LEN_SAPLING);
                    pageString(outVal, outValLen, tmpBuffer, pageIdx, pageCount);

                    return zxerr_ok;                    
                } 

                default:
                    return zxerr_no_data;
            }
        }        default:
            return zxerr_no_data;
    }
}
