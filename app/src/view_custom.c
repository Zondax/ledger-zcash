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

#include "view.h"
#include "coin.h"
#include "crypto.h"
#include "view_internal.h"
#include <os_io_seproxyhal.h>

#include <string.h>
#include <stdio.h>

view_error_t view_printAddr() {
#if !defined(HAVE_UX_FLOW)
    if (viewdata.addrKind != addr_secp256k1 &&
        viewdata.addrKind != addr_sapling) {
        return view_error_detected;
    }

    char *p = NULL;
    switch (viewdata.addrKind) {
        case addr_secp256k1: {
            h_paging_set_page_count(1);
            snprintf(viewdata.key, MAX_CHARS_PER_KEY_LINE, "unshielded");
            p = (char *) (G_io_apdu_buffer + VIEW_ADDRESS_OFFSET_SECP256K1);
            p += MAX_CHARS_PER_VALUE1_LINE * viewdata.pageIdx;
            snprintf(viewdata.value, MAX_CHARS_PER_VALUE1_LINE, "%s", (char *) (G_io_apdu_buffer + VIEW_ADDRESS_OFFSET_SECP256K1));
            break;
        }
        case addr_sapling: {
            h_paging_set_page_count(3);
            snprintf(viewdata.key, MAX_CHARS_PER_KEY_LINE, "shielded [%d/%d]", viewdata.pageIdx + 1, viewdata.pageCount);
            p = (char *) (G_io_apdu_buffer + VIEW_ADDRESS_OFFSET_SAPLING);
            p += MAX_CHARS_PER_VALUE1_LINE * viewdata.pageIdx;
            snprintf(viewdata.value, MAX_CHARS_PER_VALUE1_LINE, "%s", p);
            break;
        }
        default:
            return view_error_detected;
    }
#else
    snprintf(viewdata.addr, MAX_CHARS_ADDR, "%s", (char *) (G_io_apdu_buffer + VIEW_ADDRESS_BUFFER_OFFSET));
#endif
    splitValueField();
    return view_no_error;
}

view_error_t view_printPath() {
#if !defined(HAVE_UX_FLOW)
    h_paging_set_page_count(2);
    snprintf(viewdata.key, MAX_CHARS_PER_KEY_LINE, "path [%d/%d]", viewdata.pageIdx + 1, viewdata.pageCount);
    snprintf(viewdata.value, MAX_CHARS_PER_VALUE1_LINE, "SOME_PATH %d", viewdata.pageIdx + 1);
#else
    bip32_to_str(viewdata.addr, MAX_CHARS_ADDR, hdPath, HDPATH_LEN_DEFAULT);
#endif
    splitValueField();
    return view_no_error;
}
