#ifndef __ED25519_ALGEBRA_H__
#define __ED25519_ALGEBRA_H__

#include "cosigner_export.h"

#include "crypto/elliptic_curve_algebra/elliptic_curve_algebra_status.h"
#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif //__cplusplus

#define ED25519_FIELD_SIZE 32
#define ED25519_COMPRESSED_POINT_LEN 32

COSIGNER_EXPORT extern const uint8_t ED25519_FIELD[];

COSIGNER_EXPORT int ED25519_verify(const uint8_t *message, size_t message_len, const uint8_t signature[64], const uint8_t public_key[32]);

typedef struct ed25519_algebra_ctx ed25519_algebra_ctx_t;
typedef uint8_t ed25519_point_t[ED25519_COMPRESSED_POINT_LEN];
typedef uint8_t ed25519_scalar_t[ED25519_FIELD_SIZE];
typedef uint8_t ed25519_le_scalar_t[ED25519_FIELD_SIZE];
typedef uint8_t ed25519_le_large_scalar_t[ED25519_FIELD_SIZE * 2];

COSIGNER_EXPORT ed25519_algebra_ctx_t *ed25519_algebra_ctx_new();
COSIGNER_EXPORT void ed25519_algebra_ctx_free(ed25519_algebra_ctx_t *ctx);


/* Generates point = g^data over the ed25519 curve, data will be moduled to ED25519_FIELD */
COSIGNER_EXPORT elliptic_curve_algebra_status ed25519_algebra_is_point_on_curve(const ed25519_algebra_ctx_t *ctx, const ed25519_point_t *point);
/* Generates point g^data over the ed25519 curve, data will be moduled to ED25519_FIELD */
COSIGNER_EXPORT elliptic_curve_algebra_status ed25519_algebra_generator_mul_data(const ed25519_algebra_ctx_t *ctx, const uint8_t *data, uint32_t data_len, ed25519_point_t *point);
/* Verifies that point == g^data over the ed25519 curve */
COSIGNER_EXPORT elliptic_curve_algebra_status ed25519_algebra_verify(const ed25519_algebra_ctx_t *ctx, const uint8_t *data, uint32_t data_len, const ed25519_point_t *point, uint8_t *result);
/* Verifies that sum_point == sum(proof_point[i]*coef[i]) over the ed25519 curve */
COSIGNER_EXPORT elliptic_curve_algebra_status ed25519_algebra_verify_linear_combination(const ed25519_algebra_ctx_t *ctx, const ed25519_point_t *sum_point, const ed25519_point_t *proof_points, const ed25519_scalar_t *coefficients, 
    uint32_t points_count, uint8_t *result);
/* Returns g^exp over the ed25519 curve, exp must be inside ED25519_FIELD */
COSIGNER_EXPORT elliptic_curve_algebra_status ed25519_algebra_generator_mul(const ed25519_algebra_ctx_t *ctx, ed25519_point_t *res, const ed25519_scalar_t *exp);
/* Adds p1 and p2 points over the ed25519 curve */
COSIGNER_EXPORT elliptic_curve_algebra_status ed25519_algebra_add_points(const ed25519_algebra_ctx_t *ctx, ed25519_point_t *res, const ed25519_point_t *p1, const ed25519_point_t *p2);
/* Computes p^exp over the ed25519 curve */
COSIGNER_EXPORT elliptic_curve_algebra_status ed25519_algebra_point_mul(const ed25519_algebra_ctx_t *ctx, ed25519_point_t *res, const ed25519_point_t *p, const ed25519_scalar_t *exp);
/* Adds a and b over the ed25519 order */
COSIGNER_EXPORT elliptic_curve_algebra_status ed25519_algebra_add_scalars(const ed25519_algebra_ctx_t *ctx, ed25519_scalar_t *res, const uint8_t *a, uint32_t a_len, const uint8_t *b, uint32_t b_len);
/* Subs b from a over the ed25519 order */
COSIGNER_EXPORT elliptic_curve_algebra_status ed25519_algebra_sub_scalars(const ed25519_algebra_ctx_t *ctx, ed25519_scalar_t *res, const uint8_t *a, uint32_t a_len, const uint8_t *b, uint32_t b_len);
/* Multiplies a and b over the ed25519 order */
COSIGNER_EXPORT elliptic_curve_algebra_status ed25519_algebra_mul_scalars(const ed25519_algebra_ctx_t *ctx, ed25519_scalar_t *res, const uint8_t *a, uint32_t a_len, const uint8_t *b, uint32_t b_len);
/* Adds a and b as little endian over the ed25519 order */
COSIGNER_EXPORT elliptic_curve_algebra_status ed25519_algebra_add_le_scalars(const ed25519_algebra_ctx_t *ctx, ed25519_le_scalar_t *res, const ed25519_le_scalar_t *a, const ed25519_le_scalar_t *b);
/* Calculates val ^ -1 over the ed25519 order */
COSIGNER_EXPORT elliptic_curve_algebra_status ed25519_algebra_inverse(const ed25519_algebra_ctx_t *ctx, ed25519_scalar_t *res, const ed25519_scalar_t *val);
/* Returns a random number over the ed25519 order */
COSIGNER_EXPORT elliptic_curve_algebra_status ed25519_algebra_rand(const ed25519_algebra_ctx_t *ctx, ed25519_scalar_t *res);
/* Computes s % ED25519_FIELD */
COSIGNER_EXPORT elliptic_curve_algebra_status ed25519_algebra_reduce(const ed25519_algebra_ctx_t *ctx, ed25519_le_scalar_t *res, const ed25519_le_large_scalar_t *s);
/* Computes a * b + c over the ed25519 curve order */
COSIGNER_EXPORT elliptic_curve_algebra_status ed25519_algebra_mul_add(const ed25519_algebra_ctx_t *ctx, ed25519_le_scalar_t *res, const ed25519_le_scalar_t *a, const ed25519_le_scalar_t *b, const ed25519_le_scalar_t *c);
/* Convert scalar from little endian to big endian */
COSIGNER_EXPORT elliptic_curve_algebra_status ed25519_algebra_le_to_be(ed25519_scalar_t *res, const ed25519_le_scalar_t *n);
/* Convert scalar from big endian to little endian */
COSIGNER_EXPORT elliptic_curve_algebra_status ed25519_algebra_be_to_le(ed25519_le_scalar_t *res, const ed25519_scalar_t *n);
/* Calculates H(RAM) the hash of R || public key || message and reduces the result to ed25519 field */
COSIGNER_EXPORT elliptic_curve_algebra_status ed25519_calc_hram(const ed25519_algebra_ctx_t *ctx, ed25519_le_scalar_t *hram, const ed25519_point_t *R, const ed25519_point_t *public_key, const uint8_t *message, uint32_t message_size, uint8_t use_keccak);
/* Signs the message using the private key directly (without diriving the private key from the private seed) */
COSIGNER_EXPORT elliptic_curve_algebra_status ed25519_algebra_sign(const ed25519_algebra_ctx_t *ctx, const ed25519_scalar_t *private_key, const uint8_t *message, uint32_t message_size, uint8_t use_keccak, uint8_t signature[64]);
/* Verifies the signature using the message and public_key key */
COSIGNER_EXPORT int ed25519_verify(const ed25519_algebra_ctx_t *ctx, const uint8_t *message, size_t message_len, const uint8_t signature[64], const uint8_t public_key[32], uint8_t use_keccak);
#ifdef __cplusplus
}
#endif //__cplusplus

#endif //#ifndef __ED25519_ALGEBRA_H__