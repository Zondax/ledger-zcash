/*******************************************************************************
*  (c) 2019 Zondax GmbH
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

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stddef.h>

#define HDPATH_0_DEFAULT     (0x80000000u | 0x2cu)
#define HDPATH_1_DEFAULT     (0x80000000u | 0x85)
#define HDPATH_2_DEFAULT     (0x80000000u | 0u)
#define HDPATH_3_DEFAULT     (0u)
#define HDPATH_4_DEFAULT     (0u)

#define HDPATH_0_TESTNET     (0x80000000u | 0x2cu)
#define HDPATH_1_TESTNET     (0x80000000u | 0x1u)

#define COIN_AMOUNT_DECIMAL_PLACES 18

typedef enum {
    addr_secp256k1 = 0,
    addr_sapling   = 1
} address_kind_e;

// compressed key
#define SECP256K1_PK_LEN            33u

// sapling address [11+32]
#define SAPLING_PK_LEN              43u

#define VIEW_ADDRESS_OFFSET_SECP256K1       33
#define VIEW_ADDRESS_OFFSET_SAPLING         43
#define VIEW_ADDRESS_ITEM_COUNT 2

#define MENU_MAIN_APP_LINE1 "Zcash"
#ifdef TESTING_ENABLED
#define MENU_MAIN_APP_LINE2 "DO NOT USE!"
#else
#define MENU_MAIN_APP_LINE2 "DO NOT USE!"
#endif
#define APPVERSION_LINE2 ""

#define VIEW_ADDRESS_PRINT_FUNC  \
    case addr_secp256k1: { \
    h_paging_set_page_count(1); \
    snprintf(viewdata.key, MAX_CHARS_PER_KEY_LINE, "unshielded"); \
    p = (char *) (G_io_apdu_buffer + VIEW_ADDRESS_OFFSET_SECP256K1); \
    p += MAX_CHARS_PER_VALUE1_LINE * viewdata.pageIdx; \
    snprintf(viewdata.value, MAX_CHARS_PER_VALUE1_LINE, "%s", (char *) (G_io_apdu_buffer + VIEW_ADDRESS_OFFSET_SECP256K1)); \
    break; \
    } \
    case addr_sapling: { \
    h_paging_set_page_count(3); \
    snprintf(viewdata.key, MAX_CHARS_PER_KEY_LINE, "shielded [%d/%d]", viewdata.pageIdx + 1, viewdata.pageCount); \
    p = (char *) (G_io_apdu_buffer + VIEW_ADDRESS_OFFSET_SAPLING); \
    p += MAX_CHARS_PER_VALUE1_LINE * viewdata.pageIdx; \
    snprintf(viewdata.value, MAX_CHARS_PER_VALUE1_LINE, "%s", p); \
    break; \
    }

#ifdef __cplusplus
}
#endif
