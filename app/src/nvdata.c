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

#include "nvdata.h"

#include "app_main.h"
#include "coin.h"
#include "constants.h"
#include "cx.h"
#include "os.h"
#include "view.h"

t_inlist_t NV_CONST N_t_inlist_impl __attribute__((aligned(64)));
#define N_t_inlist (*(NV_VOLATILE t_inlist_t *)PIC(&N_t_inlist_impl))

t_outlist_t NV_CONST N_t_outlist_impl __attribute__((aligned(64)));
#define N_t_outlist (*(NV_VOLATILE t_outlist_t *)PIC(&N_t_outlist_impl))

spendlist_t NV_CONST N_spendlist_impl __attribute__((aligned(64)));
#define N_spendlist (*(NV_VOLATILE spendlist_t *)PIC(&N_spendlist_impl))

outputlist_t NV_CONST N_outputlist_impl __attribute__((aligned(64)));
#define N_outputlist (*(NV_VOLATILE outputlist_t *)PIC(&N_outputlist_impl))

transaction_info_t NV_CONST N_transaction_info_impl __attribute__((aligned(64)));
#define N_transactioninfo (*(NV_VOLATILE transaction_info_t *)PIC(&N_transaction_info_impl))

transaction_header_t transaction_header;

//////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////

zxerr_t t_inlist_append_item(uint32_t *p, uint8_t *script, uint64_t v) {
    zemu_log_stack("let's append");
    if (transaction_header.t_in_len >= T_IN_LIST_SIZE) {
        return zxerr_unknown;
    }

    transaction_header.total_value += v;

    t_input_item_t newitem;
    MEMCPY(newitem.path, (uint8_t *)p, PATH_SIZE * sizeof(uint32_t));
    MEMCPY(newitem.script, script, SCRIPT_SIZE);
    newitem.value = v;

    MEMCPY_NV((void *)&N_t_inlist.items[transaction_header.t_in_len], &newitem, sizeof(t_input_item_t));

    transaction_header.t_in_len += 1;
    zemu_log_stack("appended");
    return zxerr_ok;
}

t_input_item_t *t_inlist_retrieve_item(uint8_t i) {
    if (transaction_header.t_in_len < i) {
        return NULL;
    } else {
        return (t_input_item_t *)&N_t_inlist.items[i];
    }
}

zxerr_t t_outlist_append_item(uint8_t *addr, uint64_t v) {
    if (transaction_header.t_out_len >= T_OUT_LIST_SIZE) {
        return zxerr_unknown;
    }

    transaction_header.total_value -= v;

    t_output_item_t newitem = {0};
    MEMCPY(newitem.address, addr, SCRIPT_SIZE);
    newitem.value = v;

    MEMCPY_NV((void *)&N_t_outlist.items[transaction_header.t_out_len], &newitem, sizeof(t_output_item_t));

    transaction_header.t_out_len += 1;
    return zxerr_ok;
}

t_output_item_t *t_outlist_retrieve_item(uint8_t i) {
    if (transaction_header.t_out_len < i) {
        return NULL;
    } else {
        return (t_output_item_t *)&N_t_outlist.items[i];
    }
}

uint8_t t_inlist_len() {
    return transaction_header.t_in_len;
}

// Returns the list of all transparent input amounts.
uint64_t t_inlist_retrieve_item_amount(uint8_t i) {
    return N_t_inlist.items[i].value;
}

void t_inlist_retrieve_item_script(uint8_t i, uint8_t *output) {
    MEMCPY(output, (const void *)N_t_inlist.items[i].script, SCRIPT_SIZE);
}

uint8_t t_outlist_len() {
    return transaction_header.t_out_len;
}

bool transparent_signatures_more_extract() {
    return transaction_header.t_sign_index > 0;
}

zxerr_t transparent_signatures_append(uint8_t *signature) {
    if (transaction_header.t_sign_index >= transaction_header.t_in_len) {
        return zxerr_unknown;
    }
    MEMCPY_NV((void *)&N_transactioninfo.transparent_signatures[transaction_header.t_sign_index], signature, SIGNATURE_SIZE);
    transaction_header.t_sign_index++;
    return zxerr_ok;
}

zxerr_t get_next_transparent_signature(uint8_t *result) {
    const uint8_t index = transaction_header.t_in_len - transaction_header.t_sign_index;
    if (index >= transaction_header.t_in_len) {
        return zxerr_unknown;
    }
    MEMCPY(result, (void *)&N_transactioninfo.transparent_signatures[index], SIGNATURE_SIZE);
    transaction_header.t_sign_index--;
    if (!transparent_signatures_more_extract() && !spend_signatures_more_extract()) {
        transaction_reset();
        view_idle_show(0, NULL);
    }
    return zxerr_ok;
}

bool spend_signatures_more_extract() {
    return transaction_header.spends_sign_index > 0;
}

zxerr_t spend_signatures_append(uint8_t *signature) {
    if (transaction_header.spends_sign_index >= transaction_header.spendlist_len) {
        return zxerr_unknown;
    }

    MEMCPY_NV((void *)&N_transactioninfo.spend_signatures[transaction_header.spends_sign_index], signature, SIGNATURE_SIZE);
    transaction_header.spends_sign_index++;
    return zxerr_ok;
}

zxerr_t get_next_spend_signature(uint8_t *result) {
    const uint8_t index = transaction_header.spendlist_len - transaction_header.spends_sign_index;
    if (index >= transaction_header.spendlist_len) {
        return zxerr_unknown;
    }
    MEMCPY(result, (void *)&N_transactioninfo.spend_signatures[index], SIGNATURE_SIZE);
    transaction_header.spends_sign_index--;
    if (!transparent_signatures_more_extract() && !spend_signatures_more_extract()) {
        transaction_reset();
        view_idle_show(0, NULL);
    }
    return zxerr_ok;
}

void transaction_reset() {
    MEMZERO(&transaction_header, sizeof(transaction_header_t));
    zeroize_flashstorage();
}

bool spendlist_is_active() {
    return transaction_header.spendlist_len > 0;
}

zxerr_t spendlist_append_item(uint32_t p, uint64_t v, uint8_t *div, uint8_t *pkd, uint8_t *rcm, uint8_t *alpha) {
    if (transaction_header.spendlist_len >= SPEND_LIST_SIZE) {
        return zxerr_unknown;
    }

    transaction_header.sapling_value += v;
    transaction_header.total_value += v;
    uint32_t path = p | 0x80000000;

    spend_item_t newitem;
    newitem.path = path;
    newitem.value = v;
    MEMCPY(newitem.div, div, DIV_SIZE);
    MEMCPY(newitem.pkd, pkd, PKD_SIZE);
    MEMCPY(newitem.rcmvalue, rcm, RCM_SIZE);
    MEMCPY(newitem.alpha, alpha, ALPHA_SIZE);

    MEMCPY_NV((void *)&N_spendlist.items[transaction_header.spendlist_len], &newitem, sizeof(spend_item_t));

    transaction_header.spendlist_len += 1;
    return zxerr_ok;
}

spend_item_t *spendlist_retrieve_item(uint8_t i) {
    if (transaction_header.spendlist_len < i) {
        return NULL;
    } else {
        return (spend_item_t *)&N_spendlist.items[i];
    }
}

spend_item_t *spendlist_extract_next() {
    if (transaction_header.spendlist_len <= transaction_header.spenddata_extract_index) {
        return NULL;
    } else {
        spend_item_t *result = (spend_item_t *)&N_spendlist.items[transaction_header.spenddata_extract_index];
        transaction_header.spenddata_extract_index += 1;
        return result;
    }
}

bool spendlist_more_extract() {
    return transaction_header.spendlist_len > transaction_header.spenddata_extract_index;
}

uint8_t spendlist_len() {
    return transaction_header.spendlist_len;
}

bool outputlist_is_active() {
    return transaction_header.outputlist_len > 0;
}

zxerr_t outputlist_append_item(uint8_t *d, uint8_t *pkd, uint64_t v, uint8_t memotype, uint8_t *ovk, uint8_t *rcmv,
                               uint8_t *rseed) {
    if (transaction_header.outputlist_len >= OUTPUT_LIST_SIZE) {
        return zxerr_unknown;
    }
    transaction_header.sapling_value -= v;
    transaction_header.total_value -= v;

    output_item_t newitem = {0};
    newitem.value = v;
    MEMCPY(newitem.rcmvalue, rcmv, RCM_V_SIZE);
    MEMCPY(newitem.rseed, rseed, RSEED_SIZE);
    MEMCPY(newitem.div, d, DIV_SIZE);
    MEMCPY(newitem.pkd, pkd, PKD_SIZE);
    MEMCPY(newitem.ovk, ovk, OVK_SET_SIZE);
    newitem.memotype = memotype;
    MEMCPY_NV((void *)&N_outputlist.items[transaction_header.outputlist_len], &newitem, sizeof(output_item_t));

    transaction_header.outputlist_len += 1;
    return zxerr_ok;
}

output_item_t *outputlist_retrieve_item(uint8_t i) {
    if (transaction_header.outputlist_len <= i) {
        return NULL;
    } else {
        return (output_item_t *)&N_outputlist.items[i];
    }
}

output_item_t *outputlist_extract_next() {
    if (transaction_header.outputlist_len <= transaction_header.outputdata_extract_index) {
        return NULL;
    } else {
        output_item_t *result = (output_item_t *)&N_outputlist.items[transaction_header.outputdata_extract_index];
        transaction_header.outputdata_extract_index += 1;
        return result;
    }
}

bool outputlist_more_extract() {
    return transaction_header.outputlist_len > transaction_header.outputdata_extract_index;
}

uint8_t outputlist_len() {
    return transaction_header.outputlist_len;
}

// valueBalance is not the total value, but the
// net value of Sapling Spend transfers minus Output transfers.
// i.e. the contents of the Sapling value pool
int64_t get_valuebalance() {
    return transaction_header.sapling_value;
}
uint64_t get_totalvalue() {
    return transaction_header.total_value;
}
uint8_t get_state() {
    return transaction_header.state;
}

void set_state(uint8_t state) {
    transaction_header.state = state;
}

void state_reset() {
    transaction_header.state = STATE_INITIAL;
}

void zeroize_tin_data() {
    uint32_t p[PATH_SIZE];
    uint8_t s[SCRIPT_SIZE];
    uint64_t v = 0;
    MEMZERO(p, sizeof(p));
    MEMZERO(s, sizeof(s));
    transaction_header.t_in_len = 0;
    for (int i = 0; i < T_IN_LIST_SIZE; i++) {
        t_inlist_append_item(p, s, v);
    }
    transaction_header.t_in_len = 0;
}

void zeroize_tout_data() {
    uint8_t s[SCRIPT_SIZE];
    uint64_t v = 0;
    MEMZERO(s, sizeof(s));
    transaction_header.t_out_len = 0;
    for (int i = 0; i < T_OUT_LIST_SIZE; i++) {
        t_outlist_append_item(s, v);
    }
    transaction_header.t_out_len = 0;
}

void zeroize_spend_data() {
    uint32_t p = 0;
    uint64_t v = 0;
    uint8_t div[DIV_SIZE] = {0};
    uint8_t pkd[PKD_SIZE] = {0};
    uint8_t rcm[RCM_SIZE] = {0};
    uint8_t alpha[ALPHA_SIZE] = {0};
    transaction_header.spendlist_len = 0;
    for (int i = 0; i < SPEND_LIST_SIZE; i++) {
        spendlist_append_item(p, v, div, pkd, rcm, alpha);
    }
    transaction_header.spendlist_len = 0;
}

void zeroize_output_data() {
    uint64_t v = 0;
    uint8_t div[DIV_SIZE] = {0};
    uint8_t pkd[PKD_SIZE] = {0};
    uint8_t ovk[OVK_SIZE] = {0};
    uint8_t rcmv[RCM_V_SIZE] = {0};
    uint8_t rseed[RSEED_SIZE] = {0};
    uint8_t memotype = 0x00;
    transaction_header.outputlist_len = 0;
    for (int i = 0; i < OUTPUT_LIST_SIZE; i++) {
        outputlist_append_item(div, pkd, v, memotype, ovk, rcmv, rseed);
    }
    transaction_header.outputlist_len = 0;
}

void zeroize_signatures() {
    uint8_t sig[SIGNATURE_SIZE] = {0};

    transaction_header.t_sign_index = 0;
    for (int i = 0; i < T_IN_LIST_SIZE; i++) {
        transparent_signatures_append(sig);
    }
    transaction_header.t_sign_index = 0;

    transaction_header.spends_sign_index = 0;
    for (int i = 0; i < T_IN_LIST_SIZE; i++) {
        spend_signatures_append(sig);
    }
    transaction_header.spends_sign_index = 0;
}

void zeroize_flashstorage() {
    zeroize_tin_data();
    zeroize_tout_data();
    zeroize_spend_data();
    zeroize_output_data();
    zeroize_signatures();
}
