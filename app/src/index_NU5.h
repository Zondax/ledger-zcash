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

#include <stdint.h>

#define NU5_LENGTH_HASH_DATA               220

#define NU5_INDEX_HASH_VERSION             0
#define NU5_INDEX_HASH_VERSION_GROUP_ID    4
#define NU5_INDEX_HASH_CONSENSUS_BRANCH_ID 8
#define NU5_INDEX_HASH_LOCK_TIME           12
#define NU5_INDEX_EXPIRY_HEIGHT            16

#define NU5_INDEX_HASH_PREVOUTSHASH        20   // 32 bytes
#define NU5_INDEX_HASH_SEQUENCEHASH        52   // 32 bytes
#define NU5_INDEX_HASH_OUTPUTSHASH         84   // 32 bytes
#define NU5_INDEX_HASH_SHIELDEDSPENDHASH   116  // 32 bytes
#define NU5_INDEX_HASH_SHIELDEDOUTPUTHASH  148  // 32 bytes
#define NU5_INDEX_HASH_VALUEBALANCE        180  // 64 bit
#define NU5_INDEX_HASH_ORCHARDHASH         188  // of length 32

#define NU5_VALUEBALANCE_SIZE              8  // 64 bit
