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
#include "swap.h"
#include "crypto.h"
#include "bignum.h"
#include "zxformat.h"

static zxerr_t extractHDPath(uint8_t* params, uint8_t paramsSize);
static zxerr_t readU32BE(uint8_t* input, uint32_t *output);
static zxerr_t readU64BE(uint8_t* input, uint64_t *output);

static void handle_check_address(check_address_parameters_t* params);
static void handle_get_printable_amount(get_printable_amount_parameters_t* params);

static bool copy_transaction_parameters(create_transaction_parameters_t* sign_transaction_params);

swap_globals_t G_swap_state;

void swap_handle_command(libargs_s *args) {
    check_api_level(CX_COMPAT_APILEVEL);
    PRINTF("Inside a library \n");
    switch (args->command) {

        case CHECK_ADDRESS:
            handle_check_address(args->check_address);
            break;

        case SIGN_TRANSACTION:
            if (copy_transaction_parameters(args->create_transaction)) {
                G_swap_state.called_from_swap = 1;
            }
            break;

        case GET_PRINTABLE_AMOUNT:
            handle_get_printable_amount(args->get_printable_amount);
            break;

        case RUN_APPLICATION:
        default:
            break;
    }
}

void handle_check_address(check_address_parameters_t* params) {
    params->result = 0;
    uint8_t buffer[100] = {0};
    uint16_t replyLen = 0;

    zxerr_t err = extractHDPath((uint8_t*) params->address_parameters, (uint8_t) params->address_parameters_length);
    if (params->address_to_check == 0 || err != zxerr_ok) {
        return;
    }

    err = crypto_fillAddress_secp256k1(buffer, sizeof(buffer), &replyLen);

    if (err != zxerr_ok || replyLen <= PK_LEN_SECP256K1) {
        MEMZERO(buffer, sizeof(buffer));
        return;
    }

    const uint8_t *address = buffer + PK_LEN_SECP256K1;
    const uint8_t addressLen = replyLen - PK_LEN_SECP256K1;
    const uint8_t addressToCheckLen = strlen(params->address_to_check);

    if (addressLen == addressToCheckLen &&
        memcmp(address, params->address_to_check, addressLen) == 0) {
        params->result = 1;
    }
}

void handle_get_printable_amount( get_printable_amount_parameters_t* params) {
    MEMZERO(params->printable_amount, sizeof(params->printable_amount));

    // Convert to BCD
    bignumBigEndian_to_bcd((uint8_t*) params->printable_amount, sizeof(params->printable_amount),
                           params->amount, params->amount_length);

    // Format number.
    if (!intstr_to_fpstr_inplace(params->printable_amount, sizeof(params->printable_amount), COIN_AMOUNT_DECIMAL_PLACES)) {
        return;
    }

    // Add ticker prefix.
    if (z_str3join(params->printable_amount, sizeof(params->printable_amount), COIN_TICKER, "") != zxerr_ok) {
        return;
    }

    number_inplace_trimming(params->printable_amount, 1);
}

bool copy_transaction_parameters(create_transaction_parameters_t* sign_transaction_params) {
    MEMZERO(&G_swap_state, sizeof(G_swap_state));

    strncpy(G_swap_state.destination_address,
            sign_transaction_params->destination_address,
            sizeof(G_swap_state.destination_address) - 1);

    if ((G_swap_state.destination_address[sizeof(G_swap_state.destination_address) - 1] != '\0') ||
        (sign_transaction_params->amount_length > 8) ||
        (sign_transaction_params->fee_amount_length > 8)) {
        return false;
    }

    // store amount as big endian in 8 bytes, so the passed data should be alligned to right
    // input {0xEE, 0x00, 0xFF} should be stored like {0x00, 0x00, 0x00, 0x00, 0x00, 0xEE, 0x00, 0xFF}
    memcpy(G_swap_state.amount + 8 - sign_transaction_params->amount_length, sign_transaction_params->amount, sign_transaction_params->amount_length);

    uint8_t tmpFees[8] = {0};
    memcpy(tmpFees + 8 - sign_transaction_params->fee_amount_length, sign_transaction_params->fee_amount, sign_transaction_params->fee_amount_length);
    readU64BE(tmpFees, &G_swap_state.fees);
    return true;
}


////////////////////////////////////////////////////////////////
zxerr_t extractHDPath(uint8_t* params, uint8_t paramsSize) {
    if (paramsSize != (sizeof(uint32_t) * HDPATH_LEN_DEFAULT)) {
        return zxerr_invalid_crypto_settings;
    }

    for (uint32_t i = 0; i < paramsSize; i+= 4) {
        if (readU32BE(params + i, &hdPath[i]) != zxerr_ok) {
            return zxerr_unknown;
        }
    }

    return zxerr_ok;
}

zxerr_t readU32BE(uint8_t* input, uint32_t *output) {
    if (input == NULL || output == NULL) {
        return zxerr_no_data;
    }

    *output = 0;
    for(uint8_t i = 0; i < 4; i++) {
        *output += (uint32_t) *(input + i) << (8*i);
    }
    return zxerr_ok;
}

zxerr_t readU64BE(uint8_t* input, uint64_t *output) {
    if (input == NULL || output == NULL) {
        return zxerr_no_data;
    }

    *output = 0;
    for(uint8_t i = 0; i < 8; i++) {
        *output += (uint64_t) *(input + i) << (8*i);
    }
    return zxerr_ok;
}
