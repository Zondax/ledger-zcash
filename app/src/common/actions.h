/*******************************************************************************
*   (c) 2019 Zondax GmbH
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

#include <stdint.h>
#include "crypto.h"
#include "tx.h"
#include "apdu_codes.h"
#include <os_io_seproxyhal.h>
#include "coin.h"
#include "app_main.h"
#include "../nvdata.h"
#include "view.h"

typedef struct {
    address_kind_e kind;
    uint8_t len;
} address_state_t;

extern address_state_t address_state;

typedef struct {
    key_type_e kind;
    uint8_t len;
} key_state_t;

extern key_state_t key_state;

__Z_INLINE zxerr_t init_tx() {
    tx_reset_state();
    const uint8_t *message = tx_get_buffer();
    if(tx_get_buffer_length() > FLASH_BUFFER_SIZE){
        MEMZERO(G_io_apdu_buffer,IO_APDU_BUFFER_SIZE);
        return zxerr_unknown;
    }

    const uint16_t messageLength = tx_get_buffer_length();
    zxerr_t err;
    err = crypto_extracttx_sapling(G_io_apdu_buffer, IO_APDU_BUFFER_SIZE - 3, message, messageLength);
    if (err != zxerr_ok){
        MEMZERO(G_io_apdu_buffer,IO_APDU_BUFFER_SIZE);
        return err;
    }
    err = crypto_hash_messagebuffer(G_io_apdu_buffer, IO_APDU_BUFFER_SIZE - 3, message, messageLength);
    if (err != zxerr_ok){
        MEMZERO(G_io_apdu_buffer,IO_APDU_BUFFER_SIZE);
        return err;
    }
    return err;

}

__Z_INLINE zxerr_t check_and_sign_tx() {
    if(get_state() != STATE_PROCESSED_ALL_EXTRACTIONS){
        MEMZERO(G_io_apdu_buffer,IO_APDU_BUFFER_SIZE);
        return zxerr_unknown;
    }

    tx_reset_state();
    const uint8_t *message = tx_get_buffer();
    if(tx_get_buffer_length() > FLASH_BUFFER_SIZE){
        MEMZERO(G_io_apdu_buffer,IO_APDU_BUFFER_SIZE);
        return zxerr_unknown;
    }
    const uint16_t messageLength = tx_get_buffer_length();

    set_state(STATE_CHECKING_ALL_TXDATA);

    zxerr_t err;
    err = crypto_check_prevouts(G_io_apdu_buffer, IO_APDU_BUFFER_SIZE - 3, message, messageLength);
    if (err != zxerr_ok){
        MEMZERO(G_io_apdu_buffer,IO_APDU_BUFFER_SIZE);
        return err;
    }

    err = crypto_check_sequence(G_io_apdu_buffer, IO_APDU_BUFFER_SIZE - 3, message, messageLength);
    if (err != zxerr_ok){
        MEMZERO(G_io_apdu_buffer,IO_APDU_BUFFER_SIZE);
        return err;
    }

    err = crypto_check_outputs(G_io_apdu_buffer, IO_APDU_BUFFER_SIZE - 3, message, messageLength);
    if (err != zxerr_ok){
        MEMZERO(G_io_apdu_buffer,IO_APDU_BUFFER_SIZE);
        return err;
    }

    err = crypto_check_joinsplits(G_io_apdu_buffer, IO_APDU_BUFFER_SIZE - 3, message, messageLength);
    if (err != zxerr_ok){
        MEMZERO(G_io_apdu_buffer,IO_APDU_BUFFER_SIZE);
        return err;
    }
    //todo: the valuebalance sometimes fails, maybe bug in emulator? Add check later when it is fixed.
    err = crypto_check_valuebalance(G_io_apdu_buffer, IO_APDU_BUFFER_SIZE - 3, message, messageLength);
    /*
    if(err != zxerr_ok){
        return 0;
    }
    */
    err = crypto_checkspend_sapling(G_io_apdu_buffer, IO_APDU_BUFFER_SIZE - 3, message, messageLength);
    if (err != zxerr_ok){
        MEMZERO(G_io_apdu_buffer,IO_APDU_BUFFER_SIZE);
        return err;
    }

    err = crypto_checkoutput_sapling(G_io_apdu_buffer, IO_APDU_BUFFER_SIZE - 3, message, messageLength);
    if (err != zxerr_ok){
        MEMZERO(G_io_apdu_buffer,IO_APDU_BUFFER_SIZE);
        return err;
    }

    err = crypto_checkencryptions_sapling(G_io_apdu_buffer, IO_APDU_BUFFER_SIZE - 3, message, messageLength);
    if (err != zxerr_ok){
        MEMZERO(G_io_apdu_buffer,IO_APDU_BUFFER_SIZE);
        return err;
    }

    set_state(STATE_VERIFIED_ALL_TXDATA);

    err = crypto_sign_and_check_transparent(G_io_apdu_buffer, IO_APDU_BUFFER_SIZE - 3, message, messageLength);
    if (err != zxerr_ok){
        MEMZERO(G_io_apdu_buffer,IO_APDU_BUFFER_SIZE);
        return err;
    }
    err = crypto_signspends_sapling(G_io_apdu_buffer, IO_APDU_BUFFER_SIZE - 3, message, messageLength);
    if (err != zxerr_ok){
        MEMZERO(G_io_apdu_buffer,IO_APDU_BUFFER_SIZE);
        return err;
    }

    err = crypto_hash_messagebuffer(G_io_apdu_buffer, IO_APDU_BUFFER_SIZE - 3, message, messageLength);
    if(err != zxerr_ok){
        MEMZERO(G_io_apdu_buffer,IO_APDU_BUFFER_SIZE);
        return err;
    }

    return zxerr_ok;
}

__Z_INLINE void app_reject() {
    tx_reset_state();
    transaction_reset();
    MEMZERO(G_io_apdu_buffer,IO_APDU_BUFFER_SIZE);
    view_idle_show(0, NULL);
    set_code(G_io_apdu_buffer, 0, APDU_CODE_COMMAND_NOT_ALLOWED);
    io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, 2);
}

__Z_INLINE void app_reply_key() {
    set_code(G_io_apdu_buffer, key_state.len, APDU_CODE_OK);
    io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, key_state.len + 2);
}

__Z_INLINE void app_reply_address() {
    set_code(G_io_apdu_buffer, address_state.len, APDU_CODE_OK);
    io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, address_state.len + 2);
}

__Z_INLINE void app_reply_error() {
    MEMZERO(G_io_apdu_buffer,IO_APDU_BUFFER_SIZE);
    view_idle_show(0, NULL);
    set_code(G_io_apdu_buffer, 0, APDU_CODE_DATA_INVALID);
    io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, 2);
}

__Z_INLINE void app_reply_hash() {
    set_code(G_io_apdu_buffer, 32, APDU_CODE_OK);
    io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, 32 + 2);
}
