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

typedef enum {
    transparent = 0,
    shielded = 1,
} signable_input;

void sapling_transparent_prevouts_hash(const uint8_t *input, uint8_t *output);

void sapling_transparent_sequence_hash(const uint8_t *input, uint8_t *output);

void v4_transparent_outputs_hash(uint8_t *output);

void shielded_output_hash(const uint8_t *input, uint16_t inputlen, uint8_t *output);

void shielded_spend_hash(const uint8_t *input, uint16_t inputlen, uint8_t *output);

void signature_hash(const uint8_t *txdata, uint8_t *start_signdata, uint16_t inputlen, const uint8_t tx_version, uint8_t *output);

void signature_script_hash(const uint8_t *input, uint8_t *start_signdata, uint16_t inputlen, uint8_t *script, uint16_t scriptlen, uint8_t index, const uint8_t tx_version, uint8_t *output);
