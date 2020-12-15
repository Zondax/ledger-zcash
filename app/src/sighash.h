/*******************************************************************************
*   (c) 2018 Zondax GmbH
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

#define HASH_SIZE 32

void prevouts_hash(const uint8_t *input, uint8_t *output);

void sequence_hash(const uint8_t *input, uint8_t *output);

void outputs_hash(uint8_t *output);

void joinsplits_hash(uint8_t *input, uint16_t inputlen, uint8_t *output);

void shielded_output_hash(uint8_t *input, uint16_t inputlen, uint8_t *output);

void shielded_spend_hash(uint8_t *input, uint16_t inputlen, uint8_t *output);

void signature_hash(uint8_t *input, uint16_t inputlen, uint8_t *output);

void signature_script_hash(uint8_t *input, uint16_t inputlen, uint8_t *script, uint16_t scriptlen, uint8_t *output);
