/*******************************************************************************
*   (c) 2016 Ledger
*   (c) 2018 -2022 Zondax AG
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

#include <stdbool.h>
#include "apdu_codes.h"

#define OFFSET_CLA                      0
#define OFFSET_INS                      1  //< Instruction offset
#define OFFSET_P1                       2  //< P1
#define OFFSET_P2                       3  //< P2
#define OFFSET_DATA_LEN                 4  //< Data Length
#define OFFSET_DATA                     5  //< Data offset

#define APDU_MIN_LENGTH                 5

#define P1_INIT                         0  //< P1
#define P1_ADD                          1  //< P1
#define P1_LAST                         2  //< P1

#define DATA_LENGTH_GET_IVK             4   //ZIP32-path
#define DATA_LENGTH_GET_OVK             4   //ZIP32-path
#define DATA_LENGTH_GET_FVK             4   //ZIP32-path
#define DATA_LENGTH_GET_NF              44  // ZIP32-path + 8-byte note position + 32-byte note commitment
#define DATA_LENGTH_GET_ADDR_SAPLING    4   //ZIP32-path
#define DATA_LENGTH_GET_DIV_LIST        15   //ZIP32-path + 11-byte index
#define DATA_LENGTH_GET_ADDR_DIV        15   //ZIP32-path + 11-byte div

#define OFFSET_PAYLOAD_TYPE             OFFSET_P1

#define INS_GET_VERSION                 0x00
#define INS_GET_ADDR_SECP256K1          0x01
#define INS_SIGN_SECP256K1              0x02
#define INS_GET_DIV_LIST                0x09
#define INS_GET_ADDR_SAPLING_DIV        0x10
#define INS_GET_ADDR_SAPLING            0x11
#define INS_SIGN_SAPLING                0x12

#define INS_INIT_TX                     0xa0
#define INS_KEY_EXCHANGE                0xaa
#define INS_EXTRACT_SPEND               0xa1
#define INS_EXTRACT_OUTPUT              0xa2
#define INS_CHECKANDSIGN                0xa3
#define INS_EXTRACT_SPENDSIG            0xa4
#define INS_EXTRACT_TRANSSIG            0xa5

#define INS_GET_IVK                     0xf0
#define INS_GET_OVK                     0xf1
#define INS_GET_NF                      0xf2
#define INS_GET_FVK                     0xf3
#define INS_CRASH_TEST                  0xff

#if defined(APP_TESTING)
#define INS_TEST                        0xFF
#endif

void app_init();

void app_main();

void extractHDPath(uint32_t rx, uint32_t offset);

bool process_chunk(volatile uint32_t *tx, uint32_t rx);

void handleApdu(volatile uint32_t *flags, volatile uint32_t *tx, uint32_t rx);

__Z_INLINE void handle_getversion(volatile uint32_t *tx) {
#ifdef DEBUG
    G_io_apdu_buffer[0] = 0xFF;
#else
    G_io_apdu_buffer[0] = 0;
#endif
    G_io_apdu_buffer[1] = LEDGER_MAJOR_VERSION;
    G_io_apdu_buffer[2] = LEDGER_MINOR_VERSION;
    G_io_apdu_buffer[3] = LEDGER_PATCH_VERSION;
    G_io_apdu_buffer[4] = !IS_UX_ALLOWED;

    G_io_apdu_buffer[5] = (TARGET_ID >> 24) & 0xFF;
    G_io_apdu_buffer[6] = (TARGET_ID >> 16) & 0xFF;
    G_io_apdu_buffer[7] = (TARGET_ID >> 8) & 0xFF;
    G_io_apdu_buffer[8] = (TARGET_ID >> 0) & 0xFF;

    *tx += 9;
    THROW(APDU_CODE_OK);
}
