#ifndef __ELLIPTIC_CURVE256_ALGEBRA_H__
#define __ELLIPTIC_CURVE256_ALGEBRA_H__

#include "cosigner_export.h"

#include "crypto/elliptic_curve_algebra/elliptic_curve_algebra_status.h"
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif //__cplusplus

#define ELLIPTIC_CURVE_FIELD_SIZE 32
#define ELLIPTIC_CURVE_COMPRESSED_POINT_LEN 33

// In case the point serialization is shorter than ELLIPTIC_CURVE_COMPRESSED_POINT_LEN (like for curve25519) the remaining bytes should be set to 0 by the concrete implementation
typedef uint8_t elliptic_curve256_point_t[ELLIPTIC_CURVE_COMPRESSED_POINT_LEN];
// Encodes the scalar in big endian format
typedef uint8_t elliptic_curve256_scalar_t[ELLIPTIC_CURVE_FIELD_SIZE];

typedef enum
{
    ELLIPTIC_CURVE_SECP256K1    = 0,
    ELLIPTIC_CURVE_SECP256R1    = 1,
    ELLIPTIC_CURVE_ED25519      = 2,
    ELLIPTIC_CURVE_STARK        = 3,
} elliptic_curve256_type_t;

typedef struct elliptic_curve256_algebra_ctx elliptic_curve256_algebra_ctx_t;

typedef elliptic_curve_algebra_status (*elliptic_curve256_generator_mul_data)(const struct elliptic_curve256_algebra_ctx *ctx, const uint8_t *data, uint32_t data_len, elliptic_curve256_point_t *point);
typedef elliptic_curve_algebra_status (*elliptic_curve256_verify)(const struct elliptic_curve256_algebra_ctx *ctx, const uint8_t *data, uint32_t data_len, const elliptic_curve256_point_t *point, uint8_t *result);
typedef elliptic_curve_algebra_status (*elliptic_curve256_verify_linear_combination)(const struct elliptic_curve256_algebra_ctx *ctx, const elliptic_curve256_point_t *sum_point, const elliptic_curve256_point_t *points, 
    const elliptic_curve256_scalar_t *coefficients, uint32_t points_count, uint8_t *result);

typedef elliptic_curve_algebra_status (*elliptic_curve256_generator_mul)(const struct elliptic_curve256_algebra_ctx *ctx, elliptic_curve256_point_t *res, const elliptic_curve256_scalar_t *exp);
typedef elliptic_curve_algebra_status (*elliptic_curve256_add_points)(const struct elliptic_curve256_algebra_ctx *ctx, elliptic_curve256_point_t *res, const elliptic_curve256_point_t *p1, const elliptic_curve256_point_t *p2);
typedef elliptic_curve_algebra_status (*elliptic_curve256_point_mul)(const struct elliptic_curve256_algebra_ctx *ctx, elliptic_curve256_point_t *res, const elliptic_curve256_point_t *p, const elliptic_curve256_scalar_t *exp);
typedef elliptic_curve_algebra_status (*elliptic_curve256_add_scalars)(const struct elliptic_curve256_algebra_ctx *ctx, elliptic_curve256_scalar_t *res, const uint8_t *a, uint32_t a_len, const uint8_t *b, uint32_t b_len);
typedef elliptic_curve_algebra_status (*elliptic_curve256_sub_scalars)(const struct elliptic_curve256_algebra_ctx *ctx, elliptic_curve256_scalar_t *res, const uint8_t *a, uint32_t a_len, const uint8_t *b, uint32_t b_len);
typedef elliptic_curve_algebra_status (*elliptic_curve256_mul_scalars)(const struct elliptic_curve256_algebra_ctx *ctx, elliptic_curve256_scalar_t *res, const uint8_t *a, uint32_t a_len, const uint8_t *b, uint32_t b_len);
typedef elliptic_curve_algebra_status (*elliptic_curve256_inverse)(const struct elliptic_curve256_algebra_ctx *ctx, elliptic_curve256_scalar_t *res, const elliptic_curve256_scalar_t *val);
typedef elliptic_curve_algebra_status (*elliptic_curve256_rand)(const struct elliptic_curve256_algebra_ctx *ctx, elliptic_curve256_scalar_t *res);
typedef elliptic_curve_algebra_status (*elliptic_curve256_reduce)(const struct elliptic_curve256_algebra_ctx *ctx, elliptic_curve256_scalar_t *res, const elliptic_curve256_scalar_t *val);

typedef struct elliptic_curve256_algebra_ctx
{
    void *ctx;
    elliptic_curve256_type_t type;

    int (*release)(struct elliptic_curve256_algebra_ctx *ctx);

    /* Returns the gruop order, this is a const vaule 256bit long */
    const uint8_t *(*order)(const struct elliptic_curve256_algebra_ctx *ctx);
    /* Returns the size (in bytes) needed to represent a point on the curve, size must be <= ELLIPTIC_CURVE_COMPRESSED_POINT_LEN */
    uint8_t (*point_size)(const struct elliptic_curve256_algebra_ctx *ctx);
    /* Returns the infinity point of the curve, this is a const vaule */
    const elliptic_curve256_point_t *(*infinity_point)(const struct elliptic_curve256_algebra_ctx *ctx);

    elliptic_curve256_generator_mul_data generator_mul_data;
    elliptic_curve256_verify verify;
    elliptic_curve256_verify_linear_combination verify_linear_combination;
    elliptic_curve256_generator_mul generator_mul;
    elliptic_curve256_add_points add_points;
    elliptic_curve256_point_mul point_mul;
    elliptic_curve256_add_scalars add_scalars;
    elliptic_curve256_sub_scalars sub_scalars;
    elliptic_curve256_mul_scalars mul_scalars;
    elliptic_curve256_inverse inverse;
    elliptic_curve256_rand rand;
    elliptic_curve256_reduce reduce;

    /* Returns the internal represantation of group order */
    const struct bignum_st *(*order_internal)(const struct elliptic_curve256_algebra_ctx *ctx);
} elliptic_curve256_algebra_ctx_t;

COSIGNER_EXPORT elliptic_curve256_algebra_ctx_t *elliptic_curve256_new_secp256k1_algebra();
COSIGNER_EXPORT elliptic_curve256_algebra_ctx_t *elliptic_curve256_new_secp256r1_algebra();
COSIGNER_EXPORT elliptic_curve256_algebra_ctx_t *elliptic_curve256_new_ed25519_algebra();
COSIGNER_EXPORT elliptic_curve256_algebra_ctx_t *elliptic_curve256_new_stark_algebra();

inline void elliptic_curve256_algebra_ctx_free(elliptic_curve256_algebra_ctx_t* ctx) 
{
    if (ctx)
        ctx->release(ctx);
}

#ifdef __cplusplus
}
#endif //__cplusplus

#endif //#ifndef __ELLIPTIC_CURVE256_ALGEBRA_H__