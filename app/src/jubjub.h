/*******************************************************************************
*   (c) 2021 Zondax GmbH
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

#define JUBJUB_SCALAR_BYTES         32
#define JUBJUB_FIELD_BYTES          32

typedef unsigned char jubjub_fr[JUBJUB_SCALAR_BYTES];
typedef unsigned char jubjub_fq[JUBJUB_FIELD_BYTES];

typedef struct {
    jubjub_fq U;
    jubjub_fq V;
    jubjub_fq Z;
    jubjub_fq T1;
    jubjub_fq T2;
} jubjub_extendedpoint;

typedef struct {
    jubjub_fq U;
    jubjub_fq V;
    jubjub_fq Z;
    jubjub_fq T1;
    jubjub_fq T2;
} jubjub_extendednielspoint;

unsigned char const JUBJUB_FR_MODULUS_BYTES[JUBJUB_SCALAR_BYTES] =  {14, 125, 180, 234, 101, 51, 175, 169, 6, 103, 59, 1,
                                                    1, 52, 59, 0, 166, 104, 32, 147, 204, 200, 16, 130,
                                                    208, 151, 14, 94, 214, 247, 44, 183};

unsigned char const JUBJUB_FQ_MODULUS_BYTES[JUBJUB_FIELD_BYTES] =  {0x73, 0xed, 0xa7, 0x53, 0x29, 0x9d, 0x7d, 0x48, 0x33,
                                                    0x39, 0xd8, 0x08, 0x09, 0xa1, 0xd8, 0x05, 0x53, 0xbd,
                                                    0xa4, 0x02, 0xff, 0xfe, 0x5b, 0xfe, 0xff, 0xff, 0xff,
                                                    0xff, 0x00, 0x00, 0x00, 0x01};
unsigned char JUBJUB_FQ_ONE[JUBJUB_FIELD_BYTES] = {    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};

const jubjub_fq JUBJUB_FQ_EDWARDS_2D = {85, 38, 49, 206, 151, 244, 86, 145, 235, 251, 36, 15, 205,
                          122, 255, 168, 82, 90, 254, 218, 110, 175, 58, 76, 2, 12,
                          191, 173, 172, 104, 125, 98};

jubjub_extendedpoint const JUBJUB_GEN = {
        .U = {9, 38, 212, 243, 32, 89, 199, 18, 212, 24, 167, 255, 38, 117, 59, 106, 213, 185, 167, 211, 239, 142, 40, 39, 71, 191, 70, 146, 10, 149, 167, 83},
        .V = {87, 161, 1, 158, 109, 233, 182, 117, 83, 187, 55, 208, 194, 28, 253, 5, 109, 101, 103, 77, 206, 219, 221, 188, 48, 86, 50, 173, 170, 242, 181, 48},
        .Z = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
              0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
              0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
              0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
        .T1 = {9, 38, 212, 243, 32, 89, 199, 18, 212, 24, 167, 255, 38, 117, 59, 106, 213, 185, 167, 211, 239, 142, 40, 39, 71, 191, 70, 146, 10, 149, 167, 83},
        .T2 = {87, 161, 1, 158, 109, 233, 182, 117, 83, 187, 55, 208, 194, 28, 253, 5, 109, 101, 103, 77, 206, 219, 221, 188, 48, 86, 50, 173, 170, 242, 181, 48},
};

#define SWAP_BYTES(x, y, tmp) { \
                   tmp = x;     \
                   x = y;       \
                   y = tmp;\
}

#define SWAP_ENDIAN_U64(x, tmp) { \
                 SWAP_BYTES(*x, *(x + 7), tmp); \
SWAP_BYTES(*(x+1), *(x + 6), tmp);         \
SWAP_BYTES(*(x+2), *(x + 5), tmp);         \
SWAP_BYTES(*(x+3), *(x + 4), tmp);         \
}

#define SWAP_ENDIAN_BYTES(x) { \
                 uint8_t tmp = 0;              \
                 for (int i = 0; i < 32/2; i++){ \
                          SWAP_BYTES(*(x + i), *(x + (32-1-i)), tmp); \
                 }          \
}

void jubjub_extendedpoint_tobytes(uint8_t *s, jubjub_extendedpoint p);
void jubjub_extendedpoint_double(jubjub_extendedpoint *r, jubjub_extendedpoint p);
void jubjub_extendedpoint_add(jubjub_extendedpoint *r, jubjub_extendedpoint p);