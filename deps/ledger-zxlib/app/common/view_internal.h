/*******************************************************************************
*   (c) 2019 Zondax GmbH
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
#pragma once

#include <stdint.h>
#include <stdbool.h>
#include "coin.h"
#include "zxerror.h"
#include "view.h"

#define CUR_FLOW G_ux.flow_stack[G_ux.stack_count-1]

#if defined(TARGET_NANOX) || defined(TARGET_NANOS2)
#define MAX_CHARS_PER_KEY_LINE      64
#define MAX_CHARS_PER_VALUE1_LINE   4096
#define MAX_CHARS_HEXMESSAGE        160
#else
#ifndef MAX_CHARS_PER_VALUE_LINE
#define MAX_CHARS_PER_VALUE_LINE    (17)
#endif
#define MAX_CHARS_PER_KEY_LINE      (MAX_CHARS_PER_VALUE_LINE+1)
#define MAX_CHARS_PER_VALUE1_LINE   (2*MAX_CHARS_PER_VALUE_LINE+1)
#define MAX_CHARS_PER_VALUE2_LINE   (MAX_CHARS_PER_VALUE_LINE+1)
#define MAX_CHARS_HEXMESSAGE        40
#endif

// This takes data from G_io_apdu_buffer that is prefilled with the address

#define APPROVE_LABEL "APPROVE"
#define REJECT_LABEL "REJECT"

#define SHORTCUT_TITLE "Skip"
#define SHORTCUT_VALUE "fields"
#define SHORTCUT_STR "Skip fields"

//Review string can be customizable in each app
#if !defined(REVIEW_SCREEN_TITLE) && !defined(REVIEW_SCREEN_TX_VALUE) && !defined(REVIEW_SCREEN_ADDR_VALUE)
    #define REVIEW_SCREEN_TITLE "Please"
    #define REVIEW_SCREEN_TXN_VALUE "review"
    #define REVIEW_SCREEN_ADDR_VALUE "review"
#endif

static const char* review_key = REVIEW_SCREEN_TITLE;
static const char* review_txvalue = REVIEW_SCREEN_TXN_VALUE;
static const char* review_addrvalue = REVIEW_SCREEN_ADDR_VALUE;
static const char* review_keyconfig = "Review";
static const char* review_configvalue = "configuration";

static const char* shortcut_key = SHORTCUT_TITLE;
static const char* shortcut_value = SHORTCUT_VALUE;

#if defined(TARGET_NANOS)
    #if defined(REVIEW_SCREEN_ENABLED) && defined(SHORTCUT_MODE_ENABLED)
        #define INTRO_PAGES 2
    #elif defined(REVIEW_SCREEN_ENABLED) || defined(SHORTCUT_MODE_ENABLED)
        #define INTRO_PAGES 1
    #else
        #define INTRO_PAGES 0
    #endif
#else
    #define INTRO_PAGES 0
#endif

typedef enum {
  REVIEW_UI = 0,
  REVIEW_ADDRESS,
  REVIEW_TXN,
} review_type_e;


#if defined(TARGET_NANOS)
#define INCLUDE_ACTIONS_AS_ITEMS 2
#define INCLUDE_ACTIONS_COUNT (INCLUDE_ACTIONS_AS_ITEMS-1)
typedef uint8_t max_char_display;
#else
#define INCLUDE_ACTIONS_COUNT 0
typedef int max_char_display;
#endif

typedef struct {
    struct {
        char key[MAX_CHARS_PER_KEY_LINE];
        char value[MAX_CHARS_PER_VALUE1_LINE];
#if defined(TARGET_NANOS)
        char value2[MAX_CHARS_PER_VALUE2_LINE];
#endif
    };
    viewfunc_getItem_t viewfuncGetItem;
    viewfunc_getNumItems_t viewfuncGetNumItems;
    viewfunc_accept_t viewfuncAccept;

#ifdef APP_SECRET_MODE_ENABLED
    uint8_t secret_click_count;
#endif
    uint8_t itemIdx;
    uint8_t itemCount;
    uint8_t pageIdx;
    uint8_t pageCount;
} view_t;

typedef enum {
    view_action_unknown,
    view_action_accept,
    view_action_reject,
} view_action_t;

extern view_t viewdata;

#define print_title(...) snprintf(viewdata.title, sizeof(viewdata.title), __VA_ARGS__)
#define print_key(...) snprintf(viewdata.key, sizeof(viewdata.key), __VA_ARGS__);
#define print_value(...) snprintf(viewdata.value, sizeof(viewdata.value), __VA_ARGS__);

#if defined(TARGET_NANOS)
#define print_value2(...) snprintf(viewdata.value2, sizeof(viewdata.value2), __VA_ARGS__);
#endif

void splitValueField();
void splitValueAddress();
max_char_display get_max_char_per_line();

///////////////////////////////////////////////
///////////////////////////////////////////////
///////////////////////////////////////////////
///////////////////////////////////////////////
///////////////////////////////////////////////
///////////////////////////////////////////////
///////////////////////////////////////////////
///////////////////////////////////////////////

void view_initialize_show_impl(uint8_t item_idx, char *statusString);

void view_idle_show_impl(uint8_t item_idx, char *statusString);

void view_message_impl(char *title, char *message);

void view_error_show_impl();

void h_paging_init();

bool h_paging_can_increase();

void h_paging_increase();

bool h_paging_can_decrease();

void h_paging_decrease();

bool h_paging_intro_screen();

void view_review_show_impl(unsigned int requireReply);

void h_approve(unsigned int _);

void h_reject(unsigned int requireReply);

void h_review_action(unsigned int requireReply);

void h_review_update();

void h_error_accept(unsigned int _);

zxerr_t h_review_update_data();
