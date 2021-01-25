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

#include <zxmacros.h>
#include "jubjub.h"
#include "cx.h"

//jubjub_scalar_
//jubjub_field_

void jubjub_field_mult(jubjub_fq r, jubjub_fq a, jubjub_fq b){
    cx_math_multm(r, a, b, JUBJUB_FQ_MODULUS_BYTES, JUBJUB_FIELD_BYTES);
}

void jubjub_field_inv(jubjub_fq r, jubjub_fq a){
    cx_math_invprimem(r, a, JUBJUB_FQ_MODULUS_BYTES, JUBJUB_FIELD_BYTES);
}

void jubjub_extendedpoint_tobytes(uint8_t *s, jubjub_extendedpoint p){

    jubjub_fq x, y, zinv;
    jubjub_field_inv(zinv, p.Z);
    jubjub_field_mult(x, p.X, zinv);
    jubjub_field_mult(y, p.Y, zinv);

    MEMCPY(s, y, sizeof(jubjub_fq));
    s[0] |= x[31] << 7;
    SWAP_ENDIAN_BYTES(&s[0]);

}