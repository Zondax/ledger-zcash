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
#include <zxmacros.h>
#include "jubjub.h"
#include "cx.h"

//jubjub_scalar_
//jubjub_field_

void u8_cmov(uint8_t r, uint8_t a, unsigned int bit){
    uint8_t mask = (uint8_t) (-(int8_t) bit);
    uint8_t h,x;
    h = r;
    x = h ^ a;
    x ^= mask;
    r = r ^ x;
}

void jubjub_field_frombytes(jubjub_fq r, uint8_t *s){
    MEMZERO(r, sizeof(jubjub_fq));
    MEMCPY(r,s, sizeof(jubjub_fq));
    cx_math_modm(r, JUBJUB_FIELD_BYTES, JUBJUB_FQ_MODULUS_BYTES, JUBJUB_FIELD_BYTES);
}

int jubjub_field_iszero(const jubjub_fq r){
    return cx_math_is_zero(r,JUBJUB_FIELD_BYTES);
}

int jubjub_field_is_equal(const jubjub_fq a, const jubjub_fq b){
    return MEMCMP(a,b,sizeof(jubjub_fq)) == 0;
}

void jubjub_field_one(jubjub_fq r){
    MEMZERO(r, sizeof(jubjub_fq));
    MEMCPY(r,JUBJUB_FQ_ONE, sizeof(jubjub_fq));
}

void jubjub_field_copy(jubjub_fq r, const jubjub_fq a){
    MEMZERO(r, sizeof(jubjub_fq));
    MEMCPY(r,a, sizeof(jubjub_fq));
}

void jubjub_field_mult(jubjub_fq r, const jubjub_fq a, const jubjub_fq b){
    cx_math_multm(r, a, b, JUBJUB_FQ_MODULUS_BYTES, JUBJUB_FIELD_BYTES);
}

void jubjub_field_add(jubjub_fq r, const jubjub_fq a, const jubjub_fq b){
    cx_math_addm(r, a, b, JUBJUB_FQ_MODULUS_BYTES, JUBJUB_FIELD_BYTES);
}

void jubjub_field_sub(jubjub_fq r, const jubjub_fq a, const jubjub_fq b){
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

void jubjub_field_pow_t(jubjub_fq r, const jubjub_fq a){
    cx_math_powm(r, a, JUBJUB_FQ_SQRT_T, JUBJUB_FIELD_BYTES, JUBJUB_FQ_MODULUS_BYTES, JUBJUB_FIELD_BYTES);
}

void jubjub_field_negate(jubjub_fq r, const jubjub_fq a){
    cx_math_subm(r, JUBJUB_FQ_ZERO, a, JUBJUB_FQ_MODULUS_BYTES, JUBJUB_FIELD_BYTES);
}

void jubjub_field_cmov(jubjub_fq r, const jubjub_fq a, unsigned int bit){
    uint8_t mask = (uint8_t) (-(int8_t) bit);
    jubjub_fq h, x;
    for(int i = 0; i < JUBJUB_FIELD_BYTES; i++){
        h[i] = r[i];
        x[i] = h[i] ^ a[i];
        x[i] &= mask;
        r[i] = r[i] ^ x[i];
    }
}

zxerr_t jubjub_field_sqrt(jubjub_fq r, const jubjub_fq a){
    jubjub_fq w,x,b,z;
    jubjub_field_pow_t(w,a);
    uint8_t v = 32;
    jubjub_field_mult(x,a,w);
    jubjub_field_mult(b,x,w);
    jubjub_field_copy(z,JUBJUB_FQ_ROOT_OF_UNITY);
    jubjub_fq tmp;
    for(uint8_t max_v = 32; max_v >= 1; max_v--){
        uint8_t k = 1;
        jubjub_field_square(tmp,b);
        uint8_t j_less_than_v = 1;

        for(uint8_t j = 2; j < max_v; j++){
            uint8_t tmp_is_one = jubjub_field_is_equal(tmp,JUBJUB_FQ_ONE);
            jubjub_fq squared;
            jubjub_field_copy(squared,tmp);
            jubjub_field_cmov(squared, z, tmp_is_one);
            jubjub_field_square(squared,squared);
            jubjub_field_cmov(tmp,squared,tmp_is_one);
            jubjub_fq new_z;
            jubjub_field_copy(new_z, squared);
            jubjub_field_cmov(new_z, z, tmp_is_one);
            j_less_than_v &= !(j == v);
            u8_cmov(k,j,tmp_is_one);
            jubjub_field_cmov(z,new_z,j_less_than_v);
        }

        jubjub_fq result;
        jubjub_field_mult(result, x, z);
        uint8_t b_is_one = jubjub_field_is_equal(b, JUBJUB_FQ_ONE);

        jubjub_field_cmov(x,result,b_is_one);
        jubjub_field_square(z,z);
        jubjub_field_mult(b,b,z);
        v = k;
    }

    jubjub_field_square(w,x);
    uint8_t correct = jubjub_field_is_equal(w,a);
    if(!correct){
        return zxerr_unknown;
    }
    jubjub_field_copy(r,x);
    return zxerr_ok;
}

void jubjub_extendedpoint_cmov(jubjub_extendedpoint *r, jubjub_extendedpoint p, unsigned int bit){
    jubjub_field_cmov(r->U, p.U, bit);
    jubjub_field_cmov(r->V, p.V, bit);
    jubjub_field_cmov(r->Z, p.Z, bit);
    jubjub_field_cmov(r->T1, p.T1, bit);
    jubjub_field_cmov(r->T1, p.T2, bit);
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
    jubjub_extendedpoint p, dummy;
    MEMCPY(&p, &JUBJUB_ID, sizeof(jubjub_extendedpoint));
    for(int i = 0; i < 256; i++) {
        uint8_t di = (scalar[i / 8] >> (7 - (i % 8))) & 0x01;
        jubjub_extendedpoint_double(&p,p);
        MEMCPY(&dummy, &p, sizeof(jubjub_extendedpoint));
        jubjub_extendedpoint_add(&dummy, *r);
        jubjub_extendedpoint_cmov(&p, dummy, di);
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

zxerr_t jubjub_extendedpoint_frombytes(jubjub_extendedpoint *p, uint8_t *s){
    uint8_t b[JUBJUB_FIELD_BYTES];
    MEMCPY(b, s, JUBJUB_FIELD_BYTES);
    SWAP_ENDIAN_BYTES(&b[0]);

    uint8_t sign = b[0] >> 7;
    b[0] &= 0x01111111;

    jubjub_fq v, v2, v3, u;

    jubjub_field_frombytes(v, b);
    jubjub_field_square(v2,v);
    jubjub_field_copy(v3,v2);
    jubjub_field_mult(v2,v2, JUBJUB_FQ_EDWARDS_D);
    jubjub_field_add(v2,v2,JUBJUB_FQ_ONE);

    if (jubjub_field_iszero(v2)){
        zemu_log_stack("iszero fails");
        return zxerr_unknown;
    }

    jubjub_field_inverse(v2,v2);
    jubjub_field_sub(v3,v3,JUBJUB_FQ_ONE);
    jubjub_field_mult(v3,v3,v2);
    if (jubjub_field_sqrt(u,v3) != zxerr_ok){
        zemu_log_stack("sqrt fails");
        return zxerr_unknown;
    }


    uint8_t flip_sign = (u[JUBJUB_FIELD_BYTES - 1] ^ sign) & 1;
    jubjub_fq u_neg;
    jubjub_field_negate(u_neg, u);

    jubjub_field_cmov(u,u_neg, flip_sign);

    jubjub_field_copy(p->U, u);
    jubjub_field_copy(p->V, v);
    jubjub_field_copy(p->Z, JUBJUB_FQ_ONE);
    jubjub_field_copy(p->T1, u);
    jubjub_field_copy(p->T2, v);
    return zxerr_ok;
}