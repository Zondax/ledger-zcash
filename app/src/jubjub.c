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

void jubjub_field_copy(jubjub_fq r, jubjub_fq a){
    MEMZERO(r, sizeof(jubjub_fq));
    MEMCPY(r,a, sizeof(jubjub_fq));
}

void jubjub_field_mult(jubjub_fq r, jubjub_fq a, jubjub_fq b){
    cx_math_multm(r, a, b, JUBJUB_FQ_MODULUS_BYTES, JUBJUB_FIELD_BYTES);
}

void jubjub_field_add(jubjub_fq r, jubjub_fq a, jubjub_fq b){
    cx_math_addm(r, a, b, JUBJUB_FQ_MODULUS_BYTES, JUBJUB_FIELD_BYTES);
}

void jubjub_field_sub(jubjub_fq r, jubjub_fq a, jubjub_fq b){
    cx_math_subm(r, a, b, JUBJUB_FQ_MODULUS_BYTES, JUBJUB_FIELD_BYTES);
}

void jubjub_field_inverse(jubjub_fq r, jubjub_fq a){
    cx_math_invprimem(r, a, JUBJUB_FQ_MODULUS_BYTES, JUBJUB_FIELD_BYTES);
}

void jubjub_field_square(jubjub_fq r, jubjub_fq a){
    cx_math_multm(r, a, a, JUBJUB_FQ_MODULUS_BYTES, JUBJUB_FIELD_BYTES);
}

void jubjub_field_double(jubjub_fq r, jubjub_fq a){
    cx_math_addm(r, a, a, JUBJUB_FQ_MODULUS_BYTES, JUBJUB_FIELD_BYTES);
}

void jubjub_extendedpoint_double(jubjub_extendedpoint *r, jubjub_extendedpoint p){
    jubjub_fq uu, vv;
    jubjub_fq zz2, uv2;
    jubjub_fq vv_plus_uu, vv_minus_uu;

    jubjub_field_square(uu, p.U);
    jubjub_field_square(vv, p.V);

    jubjub_field_square(zz2, p.Z);
    jubjub_field_double(zz2,zz2);

    jubjub_field_add(uv2,p.U, p.V);
    jubjub_field_square(uv2,uv2);

    jubjub_field_add(vv_plus_uu,vv, uu);
    jubjub_field_sub(vv_minus_uu,vv, uu);

    //completed point
    jubjub_fq u,v,z,t;
    jubjub_field_sub(u,uv2,vv_plus_uu);
    jubjub_field_copy(v, vv_plus_uu);
    jubjub_field_copy(z, vv_minus_uu);
    jubjub_field_sub(t, zz2,vv_minus_uu);


    //completed point to extended
    jubjub_field_mult(r->U, u,t);
    jubjub_field_mult(r->V, v,z);
    jubjub_field_mult(r->Z, t,z);
    jubjub_field_copy(r->T1, u);
    jubjub_field_copy(r->T2, v);

}

void jubjub_extendedpoint_tobytes(uint8_t *s, jubjub_extendedpoint p){

    jubjub_fq x, y, zinv;
    jubjub_field_inverse(zinv, p.Z);
    jubjub_field_mult(x, p.U, zinv);
    jubjub_field_mult(y, p.V, zinv);

    MEMCPY(s, y, sizeof(jubjub_fq));
    s[0] |= x[31] << 7;
    SWAP_ENDIAN_BYTES(&s[0]);

}