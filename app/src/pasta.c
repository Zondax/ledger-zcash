// Zcash curve parameters and elliptic curve arithmetic
//
//     * Curve details
//         Pasta.Pallas (https://github.com/zcash/pasta)
//         E1/Fp : y^2 = x^3 + 5
//         GROUP_ORDER   = 28948022309329048855892746252171976963363056481941647379679742748393362948097 (Fq, 0x94)
//         FIELD_MODULUS = 28948022309329048855892746252171976963363056481941560715954676764349967630337 (Fp, 0x4c)
//

#if defined(TARGET_NANOS) || defined(TARGET_NANOX)

#include <os.h>

#include "pasta.h"

// Base field Fp
static const Field FIELD_MODULUS = {
    0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x22, 0x46, 0x98, 0xfc, 0x09, 0x4c, 0xf9, 0x1b,
    0x99, 0x2d, 0x30, 0xed, 0x00, 0x00, 0x00, 0x01
};

// Scalar field Fq
static const Scalar GROUP_ORDER = {
    0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x22, 0x46, 0x98, 0xfc, 0x09, 0x94, 0xa8, 0xdd,
    0x8c, 0x46, 0xeb, 0x21, 0x00, 0x00, 0x00, 0x01
};

// a = 0, b = 5
static const Field GROUP_COEFF_B = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05
};

static const Field FIELD_ONE = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01
};

static const Field FIELD_THREE = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03
};

static const Field FIELD_FOUR = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04
};

static const Field FIELD_EIGHT = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08
};

static const Field FIELD_ZERO = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

static const Scalar SCALAR_ZERO = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

// (X : Y : Z) = (0 : 1 : 0)
static const Group GROUP_ZERO = {
    {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    },
    {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01
    },
    {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    }
};

// g_generator = (1 : 12418654782883325593414442427049395787963493412651469444558597405572177144507)
static const Affine AFFINE_ONE = {
    {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01
    },
    {
        0x1b, 0x74, 0xb5, 0xa3, 0x0a, 0x12, 0x93, 0x7c,
        0x53, 0xdf, 0xa9, 0xf0, 0x63, 0x78, 0xee, 0x54,
        0x8f, 0x65, 0x5b, 0xd4, 0x33, 0x3d, 0x47, 0x71,
        0x19, 0xcf, 0x7a, 0x23, 0xca, 0xed, 0x2a, 0xbb
    }
};

void field_copy(Field a, const Field b)
{
    for (size_t i = 0; i < sizeof(Field); i++) {
        a[i] = b[i];
    }
}

void field_add(Field c, const Field a, const Field b)
{
    cx_math_addm(c, a, b, FIELD_MODULUS, FIELD_BYTES);
}

void field_sub(Field c, const Field a, const Field b)
{
    cx_math_subm(c, a, b, FIELD_MODULUS, FIELD_BYTES);
}

void field_mul(Field c, const Field a, const Field b)
{
    cx_math_multm(c, a, b, FIELD_MODULUS, FIELD_BYTES);
}

void field_sq(Field c, const Field a)
{
    cx_math_multm(c, a, a, FIELD_MODULUS, FIELD_BYTES);
}

void field_inv(Field c, const Field a)
{
    cx_math_invprimem(c, a, FIELD_MODULUS, FIELD_BYTES);
}

void field_negate(Field c, const Field a)
{
    // Ledger API expects inputs to be in range [0, FIELD_MODULUS)
    cx_math_subm(c, FIELD_ZERO, a, FIELD_MODULUS, FIELD_BYTES);
}

// c = a^e mod m
void field_pow(Field c, const Field a, const Field e)
{
    cx_math_powm(c, a, e, FIELD_BYTES, FIELD_MODULUS, FIELD_BYTES);
}

unsigned int field_eq(const Field a, const Field b)
{
    return (os_memcmp(a, b, FIELD_BYTES) == 0);
}

void scalar_copy(Scalar a, const Scalar b)
{
    for (size_t i = 0; i < sizeof(Scalar); i++) {
        a[i] = b[i];
    }
}

void scalar_add(Scalar c, const Scalar a, const Scalar b)
{
    cx_math_addm(c, a, b, GROUP_ORDER, SCALAR_BYTES);
}

void scalar_sub(Scalar c, const Scalar a, const Scalar b)
{
    cx_math_subm(c, a, b, GROUP_ORDER, SCALAR_BYTES);
}

void scalar_mul(Scalar c, const Scalar a, const Scalar b)
{
    cx_math_multm(c, a, b, GROUP_ORDER, SCALAR_BYTES);
}

void scalar_sq(Scalar c, const Scalar a)
{
    cx_math_multm(c, a, a, GROUP_ORDER, SCALAR_BYTES);
}

void scalar_negate(Field c, const Field a)
{
    // Ledger API expects inputs to be in range [0, GROUP_ORDER)
    cx_math_subm(c, SCALAR_ZERO, a, GROUP_ORDER, SCALAR_BYTES);
}

// c = a^e mod m
void scalar_pow(Scalar c, const Scalar a, const Scalar e)
{
    cx_math_powm(c, a, e, SCALAR_BYTES, GROUP_ORDER, SCALAR_BYTES);
}

unsigned int scalar_eq(const Scalar a, const Scalar b)
{
    return (os_memcmp(a, b, SCALAR_BYTES) == 0);
}

// zero is the only point with Z = 0 in jacobian coordinates
unsigned int is_zero(const Group *p)
{
    return field_eq(p->Z, FIELD_ZERO);
}

unsigned int affine_is_zero(const Affine *p)
{
    return (field_eq(p->x, FIELD_ZERO) && field_eq(p->y, FIELD_ZERO));
}

unsigned int is_on_curve(const Group *p)
{
    if (is_zero(p)) {
        return 1;
    }

    Field lhs, rhs;
    if (field_eq(p->Z, FIELD_ONE)) {
        // we can check y^2 == x^3 + ax + b
        field_sq(lhs, p->Y);                // y^2
        field_sq(rhs, p->X);                // x^2
        field_mul(rhs, rhs, p->X);          // x^3
        field_add(rhs, rhs, GROUP_COEFF_B); // x^3 + b
    }
    else {
        // we check (y/z^3)^2 == (x/z^2)^3 + b
        // => y^2 == x^3 + bz^6
        Field x3, z6;
        field_sq(x3, p->X);                 // x^2
        field_mul(x3, x3, p->X);            // x^3
        field_sq(lhs, p->Y);                // y^2
        field_sq(z6, p->Z);                 // z^2
        field_sq(z6, z6);                   // z^4
        field_mul(z6, z6, p->Z);            // z^5
        field_mul(z6, z6, p->Z);            // z^6

        field_mul(rhs, z6, GROUP_COEFF_B);  // bz^6
        field_add(rhs, x3, rhs);            // x^3 + bz^6
    }

    return field_eq(lhs, rhs);
}

void affine_to_projective(Group *r, const Affine *p)
{
    if (field_eq(p->x, FIELD_ZERO) && field_eq(p->y, FIELD_ZERO)) {
        os_memcpy(r->X, FIELD_ZERO, FIELD_BYTES);
        os_memcpy(r->Y, FIELD_ONE, FIELD_BYTES);
        os_memcpy(r->Z, FIELD_ZERO, FIELD_BYTES);
        return;
    }

    os_memcpy(r->X, p->x, FIELD_BYTES);
    os_memcpy(r->Y, p->y, FIELD_BYTES);
    os_memcpy(r->Z, FIELD_ONE, FIELD_BYTES);
}

void projective_to_affine(Affine *r, const Group *p)
{
    if (field_eq(p->Z, FIELD_ZERO)) {
        os_memcpy(r->x, FIELD_ZERO, FIELD_BYTES);
        os_memcpy(r->y, FIELD_ZERO, FIELD_BYTES);
        return;
    }

    Field zi, zi2, zi3;
    field_inv(zi, p->Z);        // 1/Z
    field_mul(zi2, zi, zi);     // 1/Z^2
    field_mul(zi3, zi2, zi);    // 1/Z^3
    field_mul(r->x, p->X, zi2); // X/Z^2
    field_mul(r->y, p->Y, zi3); // Y/Z^3
}

// https://www.hyperelliptic.org/EFD/g1p/auto-code/shortw/jacobian-0/doubling/dbl-2009-l.op3
// cost 2M + 5S + 6add + 3*2 + 1*3 + 1*8
void group_dbl(Group *r, const Group *p)
{
    if (is_zero(p)) {
        *r = *p;
        return;
    }

    Field a, b, c;
    field_sq(a, p->X);            // a = X1^2
    field_sq(b, p->Y);            // b = Y1^2
    field_sq(c, b);               // c = b^2

    Field d, e, f;
    field_add(r->X, p->X, b);     // t0 = X1 + b
    field_sq(r->Y, r->X);         // t1 = t0^2
    field_sub(r->Z, r->Y, a);     // t2 = t1 - a
    field_sub(r->X, r->Z, c);     // t3 = t2 - c
    field_add(d, r->X, r->X);     // d = 2 * t3
    field_mul(e, FIELD_THREE, a); // e = 3 * a
    field_sq(f, e);               // f = e^2

    field_add(r->Y, d, d);        // t4 = 2 * d
    field_sub(r->X, f, r->Y);     // X = f - t4

    field_sub(r->Y, d, r->X);     // t5 = d - X
    field_mul(f, FIELD_EIGHT, c); // t6 = 8 * c
    field_mul(r->Z, e, r->Y);     // t7 = e * t5
    field_sub(r->Y, r->Z, f);     // Y = t7 - t6

    field_mul(f, p->Y, p->Z);     // t8 = Y1 * Z1
    field_add(r->Z, f, f);        // Z = 2 * t8
}

// https://www.hyperelliptic.org/EFD/g1p/auto-code/shortw/jacobian-0/addition/add-2007-bl.op3
// cost 11M + 5S + 9add + 4*2
void group_add(Group *r, const Group *p, const Group *q)
{
    if (is_zero(p)) {
        *r = *q;
        return;
    }

    if (is_zero(q)) {
        *r = *p;
        return;
    }

    if (field_eq(p->X, q->X) && field_eq(p->Y, q->Y) && field_eq(p->Z, q->Z)) {
        return group_dbl(r, p);
    }

    Field z1z1, z2z2;
    field_sq(z1z1, p->Z);         // Z1Z1 = Z1^2
    field_sq(z2z2, q->Z);         // Z2Z2 = Z2^2

    Field u1, u2, s1, s2;
    field_mul(u1, p->X, z2z2);    // u1 = x1 * z2z2
    field_mul(u2, q->X, z1z1);    // u2 = x2 * z1z1
    field_mul(r->X, q->Z, z2z2);  // t0 = z2 * z2z2
    field_mul(s1, p->Y, r->X);    // s1 = y1 * t0
    field_mul(r->Y, p->Z, z1z1);  // t1 = z1 * z1z1
    field_mul(s2, q->Y, r->Y);    // s2 = y2 * t1

    Field h, i, j, w, v;
    field_sub(h, u2, u1);         // h = u2 - u1
    field_add(r->Z, h, h);        // t2 = 2 * h
    field_sq(i, r->Z);            // i = t2^2
    field_mul(j, h, i);           // j = h * i
    field_sub(r->X, s2, s1);      // t3 = s2 - s1
    field_add(w, r->X, r->X);     // w = 2 * t3
    field_mul(v, u1, i);          // v = u1 * i

    // X3 = w^2 - j - 2*v
    field_sq(r->X, w);            // t4 = w^2
    field_add(r->Y, v, v);        // t5 = 2 * v
    field_sub(r->Z, r->X, j);     // t6 = t4 - j
    field_sub(r->X, r->Z, r->Y);  // t6 - t5

    // Y3 = w * (v - X3) - 2*s1*j
    field_sub(r->Y, v, r->X);     // t7 = v - X3
    field_mul(r->Z, s1, j);       // t8 = s1 * j
    field_add(s1, r->Z, r->Z);    // t9 = 2 * t8
    field_mul(r->Z, w, r->Y);     // t10 = w * t7
    field_sub(r->Y, r->Z, s1);    // w * (v - X3) - 2*s1*j

    // Z3 = ((Z1 + Z2)^2 - Z1Z1 - Z2Z2) * h
    field_add(r->Z, p->Z, q->Z);  // t11 = z1 + z2
    field_sq(s1, r->Z);           // t12 = (z1 + z2)^2
    field_sub(r->Z, s1, z1z1);    // t13 = (z1 + z2)^2 - z1z1
    field_sub(j, r->Z, z2z2);     // t14 = (z1 + z2)^2 - z1z1 - z2z2
    field_mul(r->Z, j, h);        // ((z1 + z2)^2 - z1z1 - z2z2) * h
}

// Montgomery ladder scalar multiplication (this could be optimized further)
void group_scalar_mul(Group *r, const Scalar k, const Group *p)
{
    *r = GROUP_ZERO;
    if (is_zero(p)) {
        return;
    }
    if (scalar_eq(k, SCALAR_ZERO)) {
        return;
    }

    Group r1 = *p;
    for (size_t i = SCALAR_OFFSET; i < SCALAR_BITS; i++) {
        uint8_t di = k[i / 8] & (1 << (7 - (i % 8)));
        Group q0;
        if (!di) {
            group_add(&q0, r, &r1); // r1 = r0 + r1
            r1 = q0;
            group_dbl(&q0, r);      // r0 = r0 + r0
            *r = q0;
        }
        else {
            group_add(&q0, r, &r1); // r0 = r0 + r1
            *r = q0;
            group_dbl(&q0, &r1);    // r1 = r1 + r1
            r1 = q0;
        }
    }
}

void affine_scalar_mul(Affine *r, const Scalar k, const Affine *p)
{
    Group pp, pr;
    affine_to_projective(&pp, p);
    group_scalar_mul(&pr, k, &pp);
    projective_to_affine(r, &pr);
}

inline unsigned int is_odd(const Field y)
{
    return y[FIELD_BYTES - 1] & 0x01;
}

#endif // #if defined(TARGET_NANOS) || defined(TARGET_NANOX)
