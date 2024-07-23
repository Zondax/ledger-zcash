/*******************************************************************************
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

#include <os_io_seproxyhal.h>
#include <stdint.h>

#include "apdu_codes.h"
#include "apdu_errors.h"
#include "app_main.h"
#include "coin.h"
#include "crypto.h"
#include "nvdata.h"
#include "parser.h"
#include "tx.h"

typedef struct {
    address_kind_e kind;
    uint8_t len;
} address_state_t;

typedef struct {
    key_type_e kind;
    uint8_t len;
} key_state_t;

extern address_state_t action_addrResponse;
extern key_state_t key_state;

__Z_INLINE void app_reject() {
    transaction_reset();
    MEMZERO(G_io_apdu_buffer, IO_APDU_BUFFER_SIZE);
    view_tx_state();
    set_code(G_io_apdu_buffer, 0, APDU_CODE_COMMAND_NOT_ALLOWED);
    io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, 2);
}

__Z_INLINE void app_reply_key() {
    set_code(G_io_apdu_buffer, key_state.len, APDU_CODE_OK);
    io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, key_state.len + 2);
}

__Z_INLINE void app_reply_address() {
    set_code(G_io_apdu_buffer, action_addrResponse.len, APDU_CODE_OK);
    io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, action_addrResponse.len + 2);
}

__Z_INLINE void app_reply_error() {
    MEMZERO(G_io_apdu_buffer, IO_APDU_BUFFER_SIZE);
    set_code(G_io_apdu_buffer, 0, APDU_CODE_DATA_INVALID);
    io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, 2);
}

__Z_INLINE void app_reply_hash() {
    view_tx_state();
    set_code(G_io_apdu_buffer, 32, APDU_CODE_OK);
    io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, 32 + 2);
}
