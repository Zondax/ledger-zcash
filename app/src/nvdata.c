/*******************************************************************************
*   (c) 2020 Zondax GmbH
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

#include "os.h"
#include "cx.h"
#include "coin.h"
#include "app_main.h"
#include "nvdata.h"
#include "constants.h"
#include "view.h"

t_inlist_t NV_CONST
N_t_inlist_impl __attribute__ ((aligned(64)));
#define N_t_inlist (*(NV_VOLATILE t_inlist_t *)PIC(&N_t_inlist_impl))

t_outlist_t NV_CONST
N_t_outlist_impl __attribute__ ((aligned(64)));
#define N_t_outlist (*(NV_VOLATILE t_outlist_t *)PIC(&N_t_outlist_impl))

spendlist_t NV_CONST
N_spendlist_impl __attribute__ ((aligned(64)));
#define N_spendlist (*(NV_VOLATILE spendlist_t *)PIC(&N_spendlist_impl))

outputlist_t NV_CONST
N_outputlist_impl __attribute__ ((aligned(64)));
#define N_outputlist (*(NV_VOLATILE outputlist_t *)PIC(&N_outputlist_impl))

transaction_info_t NV_CONST
N_transaction_info_impl __attribute__ ((aligned(64)));
#define N_transactioninfo (*(NV_VOLATILE transaction_info_t *)PIC(&N_transaction_info_impl))

transaction_header_t transaction_header;

//////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////

void set_session_key(uint8_t *key) {
    MEMCPY_NV(
            &N_transactioninfo.session_key,
            key, 32);
    transaction_header.session_key_set = 1;
};

bool session_key_set() {
    return transaction_header.session_key_set == 1;
}

uint8_t *get_session_key() {
    return (uint8_t * ) & N_transactioninfo.session_key;
};

zxerr_t t_inlist_append_item(uint32_t *p, uint8_t *script, uint64_t v) {
    if (transaction_header.t_in_len >= T_IN_LIST_SIZE) {
        return zxerr_unknown;
    }

    transaction_header.total_value += v;

    t_input_item_t newitem;
    MEMCPY(newitem.path, p, PATH_SIZE * sizeof(uint32_t));
    MEMCPY(newitem.script, script, SCRIPT_SIZE);
    newitem.value = v;

    MEMCPY_NV(
            &N_t_inlist.items[transaction_header.t_in_len],
            &newitem, sizeof(t_input_item_t));

    transaction_header.t_in_len += 1;
    return zxerr_ok;
}

t_input_item_t *t_inlist_retrieve_item(uint8_t i) {
    if (transaction_header.t_in_len < i) {
        return NULL;
    } else {
        return &N_t_inlist.items[i];
    }
}

zxerr_t t_outlist_append_item(uint8_t *addr, uint64_t v) {
    if (transaction_header.t_out_len >= T_OUT_LIST_SIZE) {
        return zxerr_unknown;
    }

    transaction_header.total_value -= v;

    t_output_item_t newitem;
    MEMCPY(newitem.address, addr, SCRIPT_SIZE);
    newitem.value = v;

    MEMCPY_NV(
            &N_t_outlist.items[transaction_header.t_out_len],
            &newitem, sizeof(t_output_item_t));

    transaction_header.t_out_len += 1;
    return zxerr_ok;
}

t_output_item_t *t_outlist_retrieve_item(uint8_t i) {
    if (transaction_header.t_out_len < i) {
        return NULL;
    } else {
        return &N_t_outlist.items[i];
    }
}

uint8_t t_inlist_len() {
    return transaction_header.t_in_len;
}

uint8_t t_outlist_len() {
    return transaction_header.t_out_len;
}

bool transparent_signatures_more_extract() {
    return transaction_header.t_sign_index > transaction_header.t_sign_extract_index;
}


void transparent_signatures_append(uint8_t *signature) {
    MEMCPY_NV(
            &N_transactioninfo.transparent_signatures[transaction_header.t_sign_index],
            signature, SIGNATURE_SIZE);
    transaction_header.t_sign_index++;
}

zxerr_t get_next_transparent_signature(uint8_t *result) {
    if (transaction_header.t_in_len <= transaction_header.t_sign_extract_index) {
        return zxerr_unknown;
    }
    MEMCPY(result, &N_transactioninfo.transparent_signatures[transaction_header.t_sign_extract_index], SIGNATURE_SIZE);
    transaction_header.t_sign_extract_index++;
    if(!transparent_signatures_more_extract() && !spend_signatures_more_extract()){
        transaction_reset();
        view_idle_show(0, NULL);
    }
    return zxerr_ok;
}

bool spend_signatures_more_extract() {
    return transaction_header.spendlist_len > transaction_header.spends_sign_extract_index;
}

void spend_signatures_append(uint8_t *signature) {
    MEMCPY_NV(
            &N_transactioninfo.spend_signatures[transaction_header.spends_sign_index],
            signature, SIGNATURE_SIZE);
    transaction_header.spends_sign_index++;
}

zxerr_t get_next_spend_signature(uint8_t *result) {
    if (transaction_header.spendlist_len <= transaction_header.spends_sign_extract_index) {
        return zxerr_unknown;
    }
    MEMCPY(result, & N_transactioninfo.spend_signatures[transaction_header.spends_sign_extract_index], SIGNATURE_SIZE);
    transaction_header.spends_sign_extract_index++;
    if(!transparent_signatures_more_extract() && !spend_signatures_more_extract()){
        transaction_reset();
        view_idle_show(0, NULL);
    }
    return zxerr_ok;
}

void transaction_reset() {
    transaction_header.t_in_len = 0;
    transaction_header.t_out_len = 0;
    transaction_header.t_sign_index = 0;
    transaction_header.t_sign_extract_index = 0;
    transaction_header.total_value = 0;
    transaction_header.state = 0;
    transaction_header.spendlist_extract_index = 0;
    transaction_header.spendlist_len = 0;
    transaction_header.spends_sign_index = 0;
    transaction_header.outputlist_len = 0;
    transaction_header.outputlist_extract_index = 0;
    transaction_header.spends_sign_extract_index = 0;
    zeroize_flashstorage();
}

bool spendlist_is_active() {
    return transaction_header.spendlist_len > 0;
}

zxerr_t spendlist_append_item(uint32_t p, uint64_t v, uint8_t *div, uint8_t *pkd, uint8_t *rcm, uint8_t *alpha) {
    if (transaction_header.spendlist_len >= SPEND_LIST_SIZE) {
        return zxerr_unknown;
    }

    transaction_header.total_value += v;
    uint32_t path = p | 0x80000000;

    spend_item_t newitem;
    newitem.path = path;
    newitem.value = v;
    MEMCPY(newitem.div, div, DIV_SIZE);
    MEMCPY(newitem.pkd, pkd, PKD_SIZE);
    MEMCPY(newitem.rcm, rcm, RCM_SIZE);
    MEMCPY(newitem.alpha, alpha, ALPHA_SIZE);

    MEMCPY_NV(
            &N_spendlist.items[transaction_header.spendlist_len],
            &newitem, sizeof(spend_item_t));

    transaction_header.spendlist_len += 1;
    return zxerr_ok;
}

spend_item_t *spendlist_retrieve_item(uint8_t i) {
    if (transaction_header.spendlist_len < i) {
        return NULL;
    } else {
        return &N_spendlist.items[i];
    }
}

spend_item_t *spendlist_extract_next() {
    if (transaction_header.spendlist_len <= transaction_header.spendlist_extract_index) {
        return NULL;
    } else {
        spend_item_t *result = &N_spendlist.items[transaction_header.spendlist_extract_index];
        transaction_header.spendlist_extract_index += 1;
        return result;
    }
}

bool spendlist_more_extract() {
    return transaction_header.spendlist_len > transaction_header.spendlist_extract_index;
}

uint8_t spendlist_len() {
    return transaction_header.spendlist_len;
}

bool spendlist_first_sign() {
    return transaction_header.spends_sign_index == 0;
}

bool spendlist_more_sign() {
    return transaction_header.spendlist_len > transaction_header.spends_sign_index;
}

spend_item_t *spendlist_sign_next() {
    if (transaction_header.spendlist_len <= transaction_header.spends_sign_index) {
        return NULL;
    } else {
        spend_item_t *result = &N_spendlist.items[transaction_header.spends_sign_index];
        transaction_header.spends_sign_index += 1;
        return result;
    }
}

bool outputlist_is_active() {
    return transaction_header.outputlist_len > 0;
}

zxerr_t outputlist_append_item(uint8_t *d, uint8_t *pkd, uint64_t v, uint8_t memotype, uint8_t *ovk, uint8_t *rcmv,
                               uint8_t *rseed) {
    if (transaction_header.outputlist_len >= OUTPUT_LIST_SIZE) {
        return zxerr_unknown;
    }

    transaction_header.total_value -= v;

    output_item_t newitem;
    newitem.value = v;
    MEMCPY(newitem.rcmvalue, rcmv, RCM_V_SIZE);
    MEMCPY(newitem.rseed, rseed, RSEED_SIZE);
    MEMCPY(newitem.div, d, DIV_SIZE);
    MEMCPY(newitem.pkd, pkd, PKD_SIZE);
    MEMCPY(newitem.ovk, ovk, OVK_SIZE);
    newitem.memotype = memotype;
    MEMCPY_NV(
            &N_outputlist.items[transaction_header.outputlist_len],
            &newitem, sizeof(output_item_t));

    transaction_header.outputlist_len += 1;
    return zxerr_ok;
}

output_item_t *outputlist_retrieve_item(uint8_t i) {
    if (transaction_header.outputlist_len < i) {
        return NULL;
    } else {
        return &N_outputlist.items[i];
    }
}

output_item_t *outputlist_extract_next() {
    if (transaction_header.outputlist_len <= transaction_header.outputlist_extract_index) {
        return NULL;
    } else {
        output_item_t *result = &N_outputlist.items[transaction_header.outputlist_extract_index];
        transaction_header.outputlist_extract_index += 1;
        return result;
    }
}

bool outputlist_more_extract() {
    return transaction_header.outputlist_len > transaction_header.outputlist_extract_index;
}

uint8_t outputlist_len() {
    return transaction_header.outputlist_len;
}

uint64_t get_valuebalance() {
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

void zeroize_tin_data(){
    uint32_t p[PATH_SIZE];
    uint8_t s[SCRIPT_SIZE];
    uint64_t v = 0;
    MEMZERO(p, sizeof(p));
    MEMZERO(s,sizeof(s));
    transaction_header.t_in_len = 0;
    for(int i = 0; i < T_IN_LIST_SIZE; i++) {
        t_inlist_append_item(p, s, v);
    }
    transaction_header.t_in_len = 0;
}

void zeroize_tout_data(){
    uint8_t s[SCRIPT_SIZE];
    uint64_t v = 0;
    MEMZERO(s,sizeof(s));
    transaction_header.t_out_len = 0;
    for(int i = 0; i < T_OUT_LIST_SIZE; i++) {
        t_outlist_append_item(s, v);
    }
    transaction_header.t_out_len = 0;
}

void zeroize_spend_data(){
    uint32_t p = 0;
    uint64_t v = 0;
    uint8_t div[DIV_SIZE];
    uint8_t pkd[PKD_SIZE];
    uint8_t rcm[RCM_SIZE];
    uint8_t alpha[ALPHA_SIZE];
    MEMZERO(div,sizeof(div));
    MEMZERO(pkd,sizeof(pkd));
    MEMZERO(rcm,sizeof(rcm));
    MEMZERO(alpha,sizeof(alpha));
    transaction_header.spendlist_len = 0;
    for(int i = 0; i < SPEND_LIST_SIZE; i++) {
        spendlist_append_item(p,v,div,pkd,rcm,alpha);
    }
    transaction_header.spendlist_len = 0;
}

void zeroize_output_data(){
    uint64_t v = 0;
    uint8_t div[DIV_SIZE];
    uint8_t pkd[PKD_SIZE];
    uint8_t ovk[OVK_SIZE];
    uint8_t rcmv[RCM_V_SIZE];
    uint8_t rseed[RSEED_SIZE];
    uint8_t memotype = 0x00;
    MEMZERO(div,sizeof(div));
    MEMZERO(pkd,sizeof(pkd));
    MEMZERO(ovk,sizeof(ovk));
    MEMZERO(rcmv,sizeof(rcmv));
    MEMZERO(rseed,sizeof(rseed));
    transaction_header.outputlist_len = 0;
    for(int i = 0; i < OUTPUT_LIST_SIZE; i++) {
        outputlist_append_item(div,pkd,v,memotype,ovk,rcmv,rseed);
    }
    transaction_header.outputlist_len = 0;
}

void zeroize_signatures(){
    uint8_t sig[SIGNATURE_SIZE];
    MEMZERO(sig, SIGNATURE_SIZE);

    transaction_header.t_sign_index = 0;
    for(int i = 0; i < T_IN_LIST_SIZE; i++) {
        transparent_signatures_append(sig);
    }
    transaction_header.t_sign_index = 0;

    transaction_header.spends_sign_index = 0;
    for(int i = 0; i < T_IN_LIST_SIZE; i++) {
        spend_signatures_append(sig);
    }
    transaction_header.spends_sign_index = 0;
}

void zeroize_flashstorage(){
    zeroize_tin_data();
    zeroize_tout_data();
    zeroize_spend_data();
    zeroize_output_data();
    zeroize_signatures();
}
