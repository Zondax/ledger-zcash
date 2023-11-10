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

void nu5_transparent_prevouts_hash(const uint8_t *input, uint8_t *output);

void nu5_transparent_sequence_hash(const uint8_t *input, uint8_t *output);

void nu5_transparent_outputs_hash(uint8_t *output);

void nu5_hash_sapling_spends(const uint8_t *input, uint8_t *output);

void nu5_hash_sapling_outputs(const uint8_t *input, uint8_t *output);

void hash_header_txid_data(const uint8_t *input, uint8_t *output);

void hash_transparent_txid_data(const uint8_t *input, uint8_t *output);

void transparent_sig_digest(const uint8_t *input, uint8_t *start_signdata,
                            uint8_t index, signable_input type,
                            uint8_t *output);

void hash_sapling_txid_data(const uint8_t *input, uint8_t *output);

void hash_empty_orchard_txid_data(uint8_t *output);
