#ifndef __GFP_CURVE_ALGEBRA_H__
#define __GFP_CURVE_ALGEBRA_H__

#include "cosigner_export.h"

#include "crypto/elliptic_curve_algebra/elliptic_curve256_algebra.h"
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif //__cplusplus


// This module is an abstraction for elliptic curves defined in standard Weierstrass form (y^2 = x^3 + a*x + b) over GFp (Galois prime field of order p)

COSIGNER_EXPORT extern const uint8_t SECP256K1_FIELD[];
COSIGNER_EXPORT extern const uint8_t SECP256R1_FIELD[];

typedef struct GFp_curve_algebra_ctx GFp_curve_algebra_ctx_t;

COSIGNER_EXPORT GFp_curve_algebra_ctx_t *secp256k1_algebra_ctx_new();
COSIGNER_EXPORT GFp_curve_algebra_ctx_t *secp256r1_algebra_ctx_new();
COSIGNER_EXPORT void GFp_curve_algebra_ctx_free(GFp_curve_algebra_ctx_t *ctx);

/* Generates elliptic curve point point = g^data where g is the generator of the group and data is reduced modulo the group order */
COSIGNER_EXPORT elliptic_curve_algebra_status GFp_curve_algebra_generator_mul_data(const GFp_curve_algebra_ctx_t *ctx, const uint8_t *data, uint32_t data_len, elliptic_curve256_point_t *point);
/* Verifies that point == g^data on the curve */
COSIGNER_EXPORT elliptic_curve_algebra_status GFp_curve_algebra_verify(const GFp_curve_algebra_ctx_t *ctx, const uint8_t *data, uint32_t data_len, const elliptic_curve256_point_t *point, uint8_t *result);
/* Verifies that sum_point == sum(proof_points) over the curve */
COSIGNER_EXPORT elliptic_curve_algebra_status GFp_curve_algebra_verify_sum(const GFp_curve_algebra_ctx_t *ctx, const elliptic_curve256_point_t *sum_point, const elliptic_curve256_point_t *proof_points, uint32_t points_count, uint8_t *result);
/* Verifies that sum_point == sum(proof_point[i]*coef[i]) over the curve */
COSIGNER_EXPORT elliptic_curve_algebra_status GFp_curve_algebra_verify_linear_combination(const GFp_curve_algebra_ctx_t *ctx, const elliptic_curve256_point_t *sum_point, const elliptic_curve256_point_t *proof_points, const elliptic_curve256_scalar_t *coefficients, 
    uint32_t points_count, uint8_t *result);
/* Returns g^exp on the curve, exp must be smaller than the group order */
COSIGNER_EXPORT elliptic_curve_algebra_status GFp_curve_algebra_generator_mul(const GFp_curve_algebra_ctx_t *ctx, elliptic_curve256_point_t *res, const elliptic_curve256_scalar_t *exp);
/* Adds p1 and p2 points on the curve */
COSIGNER_EXPORT elliptic_curve_algebra_status GFp_curve_algebra_add_points(const GFp_curve_algebra_ctx_t *ctx, elliptic_curve256_point_t *res, const elliptic_curve256_point_t *p1, const elliptic_curve256_point_t *p2);
/* Computes p^exp on the curve where p is an arbitrary point in the curve */
COSIGNER_EXPORT elliptic_curve_algebra_status GFp_curve_algebra_point_mul(const GFp_curve_algebra_ctx_t *ctx, elliptic_curve256_point_t *res, const elliptic_curve256_point_t *p, const elliptic_curve256_scalar_t *exp);
/* Returns the normalized projection of p on the X axis, the optional parameter overflow returns whether x coordinate exceeds the order */
COSIGNER_EXPORT elliptic_curve_algebra_status GFp_curve_algebra_get_point_projection(const GFp_curve_algebra_ctx_t *ctx, elliptic_curve256_scalar_t *res, const elliptic_curve256_point_t *p, uint8_t* overflow);
/* Adds a and b modulo the group order */
COSIGNER_EXPORT elliptic_curve_algebra_status GFp_curve_algebra_add_scalars(GFp_curve_algebra_ctx_t *ctx, elliptic_curve256_scalar_t *res, const uint8_t *a, uint32_t a_len, const uint8_t *b, uint32_t b_len);
/* Subs b from a modulo the group order */
COSIGNER_EXPORT elliptic_curve_algebra_status GFp_curve_algebra_sub_scalars(GFp_curve_algebra_ctx_t *ctx, elliptic_curve256_scalar_t *res, const uint8_t *a, uint32_t a_len, const uint8_t *b, uint32_t b_len);
/* Multiplies a and b modulo the group order */
COSIGNER_EXPORT elliptic_curve_algebra_status GFp_curve_algebra_mul_scalars(GFp_curve_algebra_ctx_t *ctx, elliptic_curve256_scalar_t *res, const uint8_t *a, uint32_t a_len, const uint8_t *b, uint32_t b_len);
/* Calculates val ^ -1 modulo the group order */
COSIGNER_EXPORT elliptic_curve_algebra_status GFp_curve_algebra_inverse(GFp_curve_algebra_ctx_t *ctx, elliptic_curve256_scalar_t *res, const elliptic_curve256_scalar_t *val);
/* Returns the positive (unsigned) value of val modulo the group order, e.g. if val > field/2 return -val */
COSIGNER_EXPORT elliptic_curve_algebra_status GFp_curve_algebra_abs(GFp_curve_algebra_ctx_t *ctx, elliptic_curve256_scalar_t *res, const elliptic_curve256_scalar_t *val);
/* Returns a random number modulo the group order */
COSIGNER_EXPORT elliptic_curve_algebra_status GFp_curve_algebra_rand(GFp_curve_algebra_ctx_t *ctx, elliptic_curve256_scalar_t *res);
/* Verifies that the signature (sig_r, sig_s) using public_key */
COSIGNER_EXPORT elliptic_curve_algebra_status GFp_curve_algebra_verify_signature(const GFp_curve_algebra_ctx_t *ctx, const elliptic_curve256_point_t *public_key, const elliptic_curve256_scalar_t *message, 
    const elliptic_curve256_scalar_t *sig_r, const elliptic_curve256_scalar_t *sig_s);

#ifdef __cplusplus
}
#endif //__cplusplus

#endif //#ifndef __GFP_CURVE_ALGEBRA_H__