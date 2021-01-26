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

void jubjub_field_one(jubjub_fq r){
    MEMZERO(r, sizeof(jubjub_fq));
    MEMCPY(r,JUBJUB_FQ_ONE, sizeof(jubjub_fq));
}

void jubjub_field_copy(jubjub_fq r, jubjub_fq a){
    MEMZERO(r, sizeof(jubjub_fq));
    MEMCPY(r,a, sizeof(jubjub_fq));
}

void jubjub_field_mult(jubjub_fq r, const jubjub_fq a, const jubjub_fq b){
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

void jubjub_extendedpoint_normalize(jubjub_extendedpoint *r, jubjub_extendedpoint p){
    jubjub_fq zinv;
    jubjub_field_inverse(zinv, r->Z);
    jubjub_field_one(r->Z);
    jubjub_field_mult(r->U, p.U, zinv);
    jubjub_field_mult(r->V, p.V, zinv);
    jubjub_field_copy(r->T1, p.U);
    jubjub_field_copy(r->T2, p.V);
}

void jubjub_extendedpoint_add(jubjub_extendedpoint *r, jubjub_extendedpoint p){
    //jubjub_extendedpoint np;
    //jubjub_extendedpoint_normalize(&np, p);
    //extendednielspoint
    jubjub_fq v_minus_u, v_plus_u, t2d;

    jubjub_field_add(v_plus_u, p.V, p.U);
    jubjub_field_sub(v_minus_u, p.V, p.U);
    jubjub_field_mult(t2d, p.T1, p.T2);
    jubjub_field_mult(t2d, t2d, JUBJUB_FQ_EDWARDS_2D);

    jubjub_fq a,b,c,d;

    jubjub_field_sub(a, r->V, r->U);
    jubjub_field_mult(a,a,v_minus_u);

    jubjub_field_add(b, r->V, r->U);
    jubjub_field_mult(b, b, v_plus_u);

    jubjub_field_mult(c, r->T1, r->T2);
    jubjub_field_mult(c,c,t2d);

    jubjub_field_mult(d, r->Z, p.Z);
    jubjub_field_double(d,d);

    //completed point
    jubjub_fq u,v,z,t;
    jubjub_field_sub(u,b,a);
    jubjub_field_add(v,b,a);
    jubjub_field_add(z, d, c);
    jubjub_field_sub(t,d,c);

    //completed point to extended
    jubjub_field_mult(r->U, u,t);
    jubjub_field_mult(r->V, v,z);
    jubjub_field_mult(r->Z, t,z);
    jubjub_field_copy(r->T1, u);
    jubjub_field_copy(r->T2, v);

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

void jubjub_extendedpoint_scalarmult(jubjub_extendedpoint *r, jubjub_fr scalar){
    jubjub_extendedpoint p, q;
    MEMCPY(&p, &JUBJUB_ID, sizeof(jubjub_extendedpoint));
    MEMCPY(&q, r, sizeof(jubjub_extendedpoint));
    for(int i = 0; i < 256; i++) {
        uint8_t di = (scalar[i / 8] >> (7 - (i % 8))) & 0x01;
        jubjub_extendedpoint_double(&p,p);
        if (di){
            jubjub_extendedpoint_add(&p, q);
        }
    }
    MEMCPY(r, &p, sizeof(jubjub_extendedpoint));
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