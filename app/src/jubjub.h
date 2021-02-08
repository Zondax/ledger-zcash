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
#include <zxerror.h>

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

extern const jubjub_extendedpoint JUBJUB_GEN;

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
void jubjub_extendedpoint_scalarmult(jubjub_extendedpoint *r, jubjub_fr scalar);
void jubjub_field_frombytes(jubjub_fq r, const uint8_t *s);
zxerr_t jubjub_extendedpoint_frombytes(jubjub_extendedpoint *p, uint8_t *s);