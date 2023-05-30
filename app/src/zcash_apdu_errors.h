/*******************************************************************************
*   (c) 2018 - 2022 Zondax AG
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

// Specific APDU error codes for ZCash
#define APDU_CODE_DATA_TOO_LONG             0x6988
#define APDU_CODE_EXTRACT_TRANSACTION_FAIL  0x6989
#define APDU_CODE_HASH_MSG_BUF_FAIL         0x6990
#define APDU_CODE_UNPROCESSED_TX            0x6991
#define APDU_CODE_PREVOUT_INVALID           0x6992
#define APDU_CODE_SEQUENCE_INVALID          0x6993
#define APDU_CODE_OUTPUTS_INVALID           0x6994
#define APDU_CODE_JOINSPLIT_INVALID         0x6995
#define APDU_CODE_SPEND_INVALID             0x6996
#define APDU_CODE_OUTPUT_CONTENT_INVALID    0x6997
#define APDU_CODE_ENCRYPTION_INVALID        0x6998
#define APDU_CODE_CHECK_SIGN_TR_FAIL        0x6999
#define APDU_SIGN_SPEND_FAIL                0x69A0
#define APDU_CODE_BAD_VALUEBALANCE          0x69A1
#define APDU_CODE_UNHANDLED_TX_VERSION      0x69A2
