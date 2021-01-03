#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stddef.h>

#define FIELD_BYTES    32
#define SCALAR_BYTES   32
#define SCALAR_BITS    256

typedef uint8_t Field[FIELD_BYTES];
typedef uint8_t Scalar[SCALAR_BYTES];

typedef struct group {
    Field X;
    Field Y;
    Field Z;
} Group;

typedef struct affine {
    Field x;
    Field y;
} Affine;

void field_copy(Field a, const Field b);
void field_add(Field c, const Field a, const Field b);
void field_mul(Field c, const Field a, const Field b);
void field_sq(Field c, const Field a);
void field_pow(Field c, const Field a, const Field e);
void group_add(Group *c, const Group *a, const Group *b);
void group_dbl(Group *c, const Group *a);
void group_scalar_mul(Group *r, const Scalar k, const Group *p);
void affine_scalar_mul(Affine *r, const Scalar k, const Affine *p);
void projective_to_affine(Affine *p, const Group *r);

#ifdef __cplusplus
}
#endif
