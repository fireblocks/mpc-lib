#include "crypto/ed25519_algebra/ed25519_algebra.h"
#include "crypto/elliptic_curve_algebra/elliptic_curve256_algebra.h"
#include "crypto/keccak1600/keccak1600.h"

#include "curve25519.c"

#include "crypto/common/byteswap.h"

#include <openssl/bn.h>
#include <openssl/sha.h>

// this is big endian value of 0x1000000000000000000000000000000013E974E72F8A692C2FB98D0599FD6765
const uint8_t ED25519_FIELD[] =
{
    0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x14, 0xde, 0xf9, 0xde, 0xa2, 0xf7, 0x9c, 0xd6, 0x58, 0x12, 0x63, 0x1a, 0x5c, 0xf5, 0xd3, 0xed
};

static const uint8_t ED25519_FIELD_LITTLE_ENDIAN[] =
{
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10
};



struct ed25519_algebra_ctx
{
    BIGNUM *L; //order of the curve
    BIGNUM *P; //order of the field of each coordinate
};

ed25519_algebra_ctx_t *ed25519_algebra_ctx_new()
{
    ed25519_algebra_ctx_t *ctx = malloc(sizeof(ed25519_algebra_ctx_t));

    if (ctx)
    {
        ctx->P = BN_new();
        ctx->L = BN_bin2bn(ED25519_FIELD, sizeof(ED25519_FIELD), NULL);
        if (!ctx->L || !ctx->P)
        {
            ed25519_algebra_ctx_free(ctx);
            return NULL;
        }
        BN_set_flags(ctx->L, BN_FLG_CONSTTIME);

        if (!BN_set_bit(ctx->P, 255) ||
            !BN_sub_word(ctx->P, 19))
        {
            ed25519_algebra_ctx_free(ctx);
            return NULL;
        }
        BN_set_flags(ctx->P, BN_FLG_CONSTTIME);

    }
    return ctx;
}

void ed25519_algebra_ctx_free(ed25519_algebra_ctx_t *ctx)
{
    if (ctx)
    {
        BN_free(ctx->L);
        BN_free(ctx->P);
        free(ctx);
    }
}

static inline void bswap_256(const ed25519_scalar_t in, ed25519_scalar_t out)
{
    uint64_t *inptr = (uint64_t*)in;
    uint64_t *outptr = (uint64_t*)out;
    outptr[0] = bswap_64(inptr[3]);
    outptr[1] = bswap_64(inptr[2]);
    outptr[2] = bswap_64(inptr[1]);
    outptr[3] = bswap_64(inptr[0]);
}

static inline int ed25519_to_scalar(const ed25519_scalar_t in, ed25519_scalar_t out)
{
    OPENSSL_cleanse(out, sizeof(ed25519_scalar_t));
    if (in[0] & 0x80)
        return 0;

    bswap_256(in, out);
    return 1;
}

static inline int ed25519_scalar_mult(ed25519_point_t res, const ed25519_scalar_t exp, const ed25519_point_t point)
{
    static const ed25519_scalar_t ZERO = {0};
    ge_p3 P;
    ge_p2 r;
    if (ge_frombytes_vartime(&P, point))
        return 0;
    ge_double_scalarmult_vartime(&r, exp, &P, ZERO);
    ge_tobytes(res, &r);
    return 1;
}

static inline int ed25519_is_valid_point(const ed25519_point_t point)
{
    ed25519_point_t p1;
    ed25519_point_t p2;
    const uint8_t EIGHT[32] = {8, 0};
    const uint8_t EIGHT_INVERSE[32] = {0x79, 0x2f, 0xdc, 0xe2, 0x29, 0xe5, 0x06, 0x61, 0xd0, 0xda, 0x1c, 0x7d, 0xb3, 0x9d, 0xd3, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06};

    if (!ed25519_scalar_mult(p1, EIGHT_INVERSE, point))
        return 0;
    if (!ed25519_scalar_mult(p2, EIGHT, p1))
        return 0;
    return memcmp(point, p2, sizeof(ed25519_point_t)) == 0 ? 1 : 0;
}

static inline int ed25519_is_point_on_curve(const ed25519_point_t point)
{
    ge_p3 P;
    return ge_frombytes_vartime(&P, point) == 0;
}

elliptic_curve_algebra_status ed25519_algebra_is_point_on_curve(const ed25519_algebra_ctx_t *ctx, const ed25519_point_t *point)
{
    if (!ctx || !point)
        return ELLIPTIC_CURVE_ALGEBRA_INVALID_PARAMETER;
    return ed25519_is_point_on_curve(*point) ? ELLIPTIC_CURVE_ALGEBRA_SUCCESS : ELLIPTIC_CURVE_ALGEBRA_INVALID_POINT;
}

static inline void ed25519_algebra_generator_mul_internal(ed25519_point_t *res, const ed25519_le_scalar_t *exp)
{
    ge_p3 point;
    ge_scalarmult_base(&point, *exp);
    ge_p3_tobytes(*res, &point);
}

static elliptic_curve_algebra_status to_ed25519_scalar(const ed25519_algebra_ctx_t *ctx, ed25519_le_scalar_t *res, const uint8_t *num, uint32_t num_size)
{
    BN_CTX *bn_ctx = NULL;
    BIGNUM *bn_n = NULL;
    elliptic_curve_algebra_status ret = ELLIPTIC_CURVE_ALGEBRA_UNKNOWN_ERROR;

    bn_ctx = BN_CTX_new();
    if (!bn_ctx)
    {
        return ELLIPTIC_CURVE_ALGEBRA_OUT_OF_MEMORY;
    }

    BN_CTX_start(bn_ctx);

    bn_n = BN_CTX_get(bn_ctx);
    if (!bn_n || !BN_bin2bn(num, num_size, bn_n))
    {
        ret = ELLIPTIC_CURVE_ALGEBRA_OUT_OF_MEMORY;
        goto cleanup;
    }

    BN_set_flags(bn_n, BN_FLG_CONSTTIME);

    if (BN_mod(bn_n, bn_n, ctx->L, bn_ctx))
    {
        ret = BN_bn2lebinpad(bn_n, *res, sizeof(ed25519_le_scalar_t)) > 0 ? ELLIPTIC_CURVE_ALGEBRA_SUCCESS : ELLIPTIC_CURVE_ALGEBRA_UNKNOWN_ERROR;
    }

cleanup:
    if (bn_n)
        BN_clear(bn_n);
    BN_CTX_end(bn_ctx);
    BN_CTX_free(bn_ctx);
    return ret;
}

elliptic_curve_algebra_status ed25519_algebra_generator_mul_data(const ed25519_algebra_ctx_t *ctx, const uint8_t *data, uint32_t data_len, ed25519_point_t *point)
{
    ed25519_le_scalar_t exp;
    elliptic_curve_algebra_status ret = ELLIPTIC_CURVE_ALGEBRA_OUT_OF_MEMORY;

    if (!ctx || !data || !point || !data_len)
        return ELLIPTIC_CURVE_ALGEBRA_INVALID_PARAMETER;

    OPENSSL_cleanse(*point, sizeof(ed25519_point_t));
    ret = to_ed25519_scalar(ctx, &exp, data, data_len);

    if (ret == ELLIPTIC_CURVE_ALGEBRA_SUCCESS)
    {
        ed25519_algebra_generator_mul_internal(point, &exp);
        OPENSSL_cleanse(exp, sizeof(ed25519_scalar_t));
    }
    return ret;
}

elliptic_curve_algebra_status ed25519_algebra_verify(const ed25519_algebra_ctx_t *ctx, const uint8_t *data, uint32_t data_len, const ed25519_point_t *point, uint8_t *result)
{
    ed25519_point_t local_proof;
    elliptic_curve_algebra_status ret;

    if (!result || !point)
        return ELLIPTIC_CURVE_ALGEBRA_INVALID_PARAMETER;

    *result = 0;

    ret = ed25519_algebra_generator_mul_data(ctx, data, data_len, &local_proof);
    if (ret == ELLIPTIC_CURVE_ALGEBRA_SUCCESS)
        *result = CRYPTO_memcmp(local_proof, point, sizeof(ed25519_point_t)) ? 0 : 1;
    return ret;
}

elliptic_curve_algebra_status ed25519_algebra_verify_linear_combination(const ed25519_algebra_ctx_t *ctx,
                                                                        const ed25519_point_t *sum_point,
                                                                        const ed25519_point_t *proof_points,
                                                                        const ed25519_scalar_t *coefficients,
                                                                        uint32_t points_count,
                                                                        uint8_t *result)
{
    ge_p3 sum;
    ed25519_point_t ecpoint;

    if (!ctx || !sum_point || !proof_points || !coefficients || !points_count || !result)
        return ELLIPTIC_CURVE_ALGEBRA_INVALID_PARAMETER;
    *result = 0;

    if (!ed25519_is_valid_point(*sum_point))
        return ELLIPTIC_CURVE_ALGEBRA_INVALID_POINT;

    for (uint32_t i = 0; i < points_count; ++i)
    {
        ed25519_scalar_t exp;
        ed25519_point_t p;
        if (!ed25519_is_valid_point(proof_points[i]))
            return ELLIPTIC_CURVE_ALGEBRA_INVALID_POINT;

        if (!ed25519_to_scalar(coefficients[i], exp))
            return ELLIPTIC_CURVE_ALGEBRA_INVALID_SCALAR;

        if (!ed25519_scalar_mult(p, exp, proof_points[i]))
            return ELLIPTIC_CURVE_ALGEBRA_INVALID_POINT;

        if (i == 0)
        {
            if (ge_frombytes_vartime(&sum, p))
                return ELLIPTIC_CURVE_ALGEBRA_UNKNOWN_ERROR;
        }
        else
        {
            ge_p3 P;
            ge_p1p1 tmp;
            ge_cached cache_p;
            if (ge_frombytes_vartime(&P, p))
                return ELLIPTIC_CURVE_ALGEBRA_UNKNOWN_ERROR;

            ge_p3_to_cached(&cache_p, &P);
            ge_add(&tmp, &sum, &cache_p);
            ge_p1p1_to_p3(&sum, &tmp);
        }
    }

    ge_p3_tobytes(ecpoint, &sum);
    *result = CRYPTO_memcmp(ecpoint, *sum_point, sizeof(ed25519_point_t)) == 0 ? 1 : 0;
    return ELLIPTIC_CURVE_ALGEBRA_SUCCESS;
}

elliptic_curve_algebra_status ed25519_algebra_generator_mul(const ed25519_algebra_ctx_t *ctx, ed25519_point_t *res, const ed25519_scalar_t *exp)
{
    ed25519_le_scalar_t local_exp;

    if (!ctx || !res || !exp)
        return ELLIPTIC_CURVE_ALGEBRA_INVALID_PARAMETER;

    OPENSSL_cleanse(*res, sizeof(ed25519_point_t));

    if (!ed25519_to_scalar(*exp, local_exp))
        return ELLIPTIC_CURVE_ALGEBRA_INVALID_SCALAR;
    ed25519_algebra_generator_mul_internal(res, &local_exp);
    OPENSSL_cleanse(local_exp, sizeof(local_exp));
    return ELLIPTIC_CURVE_ALGEBRA_SUCCESS;
}

elliptic_curve_algebra_status ed25519_algebra_add_points(const ed25519_algebra_ctx_t *ctx, ed25519_point_t *res, const ed25519_point_t *p1, const ed25519_point_t *p2)
{
    ge_p3 P1, P2;
    ge_p1p1 tmp;
    ge_cached cache_p;
    ge_p3 sum;

    if (!ctx || !res || !p1 || !p2)
        return ELLIPTIC_CURVE_ALGEBRA_INVALID_PARAMETER;

    if (!ed25519_is_valid_point(*p1) || ge_frombytes_vartime(&P1, *p1))
        return ELLIPTIC_CURVE_ALGEBRA_INVALID_POINT;
    if (!ed25519_is_valid_point(*p2) || ge_frombytes_vartime(&P2, *p2))
        return ELLIPTIC_CURVE_ALGEBRA_INVALID_POINT;

    ge_p3_to_cached(&cache_p, &P2);
    ge_add(&tmp, &P1, &cache_p);
    ge_p1p1_to_p3(&sum, &tmp);
    ge_p3_tobytes(*res, &sum);
    return ELLIPTIC_CURVE_ALGEBRA_SUCCESS;
}

elliptic_curve_algebra_status ed25519_algebra_point_mul(const ed25519_algebra_ctx_t *ctx, ed25519_point_t *res, const ed25519_point_t *p, const ed25519_scalar_t *exp)
{
    ed25519_scalar_t local_exp;
    
    if (!ctx || !res || !p || !exp)
        return ELLIPTIC_CURVE_ALGEBRA_INVALID_PARAMETER;

    if (!ed25519_is_valid_point(*p))
        return ELLIPTIC_CURVE_ALGEBRA_INVALID_POINT;

    if (!ed25519_to_scalar(*exp, local_exp))
        return ELLIPTIC_CURVE_ALGEBRA_INVALID_SCALAR;

    elliptic_curve_algebra_status ret = ed25519_scalar_mult(*res, local_exp, *p) ? ELLIPTIC_CURVE_ALGEBRA_SUCCESS : ELLIPTIC_CURVE_ALGEBRA_INVALID_POINT;

    OPENSSL_cleanse(local_exp, sizeof(ed25519_scalar_t));

    return ret;
}

elliptic_curve_algebra_status ed25519_algebra_add_scalars(const ed25519_algebra_ctx_t *ctx, ed25519_scalar_t *res, const uint8_t *a, uint32_t a_len, const uint8_t *b, uint32_t b_len)
{
    BN_CTX *bn_ctx = NULL;
    BIGNUM *bn_a = NULL;
    BIGNUM *bn_b = NULL;
    elliptic_curve_algebra_status ret = ELLIPTIC_CURVE_ALGEBRA_OUT_OF_MEMORY;

    if (!ctx || !res || !a || !a_len || !b || !b_len)
        return ELLIPTIC_CURVE_ALGEBRA_INVALID_PARAMETER;

    bn_ctx = BN_CTX_new();
    if (!bn_ctx)
        return ELLIPTIC_CURVE_ALGEBRA_OUT_OF_MEMORY;

    BN_CTX_start(bn_ctx);

    bn_a = BN_CTX_get(bn_ctx);
    if (!bn_a || !BN_bin2bn(a, a_len, bn_a))
        goto cleanup;
    bn_b = BN_CTX_get(bn_ctx);
    if (!bn_b || !BN_bin2bn(b, b_len, bn_b))
        goto cleanup;

    BN_set_flags(bn_a, BN_FLG_CONSTTIME);
    BN_set_flags(bn_b, BN_FLG_CONSTTIME);

    if (BN_mod_add(bn_a, bn_a, bn_b, ctx->L, bn_ctx))
    {
        ret = BN_bn2binpad(bn_a, *res, sizeof(ed25519_scalar_t)) > 0 ? ELLIPTIC_CURVE_ALGEBRA_SUCCESS : ELLIPTIC_CURVE_ALGEBRA_UNKNOWN_ERROR;
    }
    else
    {
        ret = ELLIPTIC_CURVE_ALGEBRA_UNKNOWN_ERROR;
    }

cleanup:
    if (bn_a)
        BN_clear(bn_a);
    if (bn_b)
        BN_clear(bn_b);
    BN_CTX_end(bn_ctx);
    BN_CTX_free(bn_ctx);
    return ret;
}

elliptic_curve_algebra_status ed25519_algebra_sub_scalars(const ed25519_algebra_ctx_t *ctx, ed25519_scalar_t *res, const uint8_t *a, uint32_t a_len, const uint8_t *b, uint32_t b_len)
{
    BN_CTX *bn_ctx = NULL;
    BIGNUM *bn_a = NULL;
    BIGNUM *bn_b = NULL;
    elliptic_curve_algebra_status ret = ELLIPTIC_CURVE_ALGEBRA_OUT_OF_MEMORY;

    if (!ctx || !res || !a || !a_len || !b || !b_len)
        return ELLIPTIC_CURVE_ALGEBRA_INVALID_PARAMETER;

    bn_ctx = BN_CTX_new();
    if (!bn_ctx)
        return ELLIPTIC_CURVE_ALGEBRA_OUT_OF_MEMORY;

    BN_CTX_start(bn_ctx);

    bn_a = BN_CTX_get(bn_ctx);
    if (!bn_a || !BN_bin2bn(a, a_len, bn_a))
        goto cleanup;
    bn_b = BN_CTX_get(bn_ctx);
    if (!bn_b || !BN_bin2bn(b, b_len, bn_b))
        goto cleanup;

    BN_set_flags(bn_a, BN_FLG_CONSTTIME);
    BN_set_flags(bn_b, BN_FLG_CONSTTIME);

    if (BN_mod_sub(bn_a, bn_a, bn_b, ctx->L, bn_ctx))
    {
        ret = BN_bn2binpad(bn_a, *res, sizeof(ed25519_scalar_t)) > 0 ? ELLIPTIC_CURVE_ALGEBRA_SUCCESS : ELLIPTIC_CURVE_ALGEBRA_UNKNOWN_ERROR;
    }
    else
    {
        ret = ELLIPTIC_CURVE_ALGEBRA_UNKNOWN_ERROR;
    }

cleanup:
    if (bn_a)
        BN_clear(bn_a);
    if (bn_b)
        BN_clear(bn_b);
    BN_CTX_end(bn_ctx);
    BN_CTX_free(bn_ctx);
    return ret;
}

elliptic_curve_algebra_status ed25519_algebra_mul_scalars(const ed25519_algebra_ctx_t *ctx, ed25519_scalar_t *res, const uint8_t *a, uint32_t a_len, const uint8_t *b, uint32_t b_len)
{
    BN_CTX *bn_ctx = NULL;
    BIGNUM *bn_a = NULL;
    BIGNUM *bn_b = NULL;
    elliptic_curve_algebra_status ret = ELLIPTIC_CURVE_ALGEBRA_OUT_OF_MEMORY;

    if (!ctx || !res || !a || !a_len || !b || !b_len)
        return ELLIPTIC_CURVE_ALGEBRA_INVALID_PARAMETER;

    bn_ctx = BN_CTX_new();
    if (!bn_ctx)
        return ELLIPTIC_CURVE_ALGEBRA_OUT_OF_MEMORY;

    BN_CTX_start(bn_ctx);

    bn_a = BN_CTX_get(bn_ctx);
    if (!bn_a || !BN_bin2bn(a, a_len, bn_a))
        goto cleanup;
    bn_b = BN_CTX_get(bn_ctx);
    if (!bn_b || !BN_bin2bn(b, b_len, bn_b))
        goto cleanup;

    BN_set_flags(bn_a, BN_FLG_CONSTTIME);
    BN_set_flags(bn_b, BN_FLG_CONSTTIME);

    if (BN_mod_mul(bn_a, bn_a, bn_b, ctx->L, bn_ctx))
    {
        ret = BN_bn2binpad(bn_a, *res, sizeof(ed25519_scalar_t)) > 0 ? ELLIPTIC_CURVE_ALGEBRA_SUCCESS : ELLIPTIC_CURVE_ALGEBRA_UNKNOWN_ERROR;
    }
    else
    {
        ret = ELLIPTIC_CURVE_ALGEBRA_UNKNOWN_ERROR;
    }

cleanup:
    if (bn_a)
        BN_clear(bn_a);
    if (bn_b)
        BN_clear(bn_b);
    BN_CTX_end(bn_ctx);
    BN_CTX_free(bn_ctx);
    return ret;
}

elliptic_curve_algebra_status ed25519_algebra_add_le_scalars(const ed25519_algebra_ctx_t *ctx, ed25519_le_scalar_t *res, const ed25519_le_scalar_t *a, const ed25519_le_scalar_t *b)
{
    BN_CTX *bn_ctx = NULL;
    BIGNUM *bn_a = NULL;
    BIGNUM *bn_b = NULL;
    elliptic_curve_algebra_status ret = ELLIPTIC_CURVE_ALGEBRA_OUT_OF_MEMORY;

    if (!ctx || !res || !a || !b)
        return ELLIPTIC_CURVE_ALGEBRA_INVALID_PARAMETER;

    bn_ctx = BN_CTX_new();
    if (!bn_ctx)
        return ELLIPTIC_CURVE_ALGEBRA_OUT_OF_MEMORY;

    BN_CTX_start(bn_ctx);

    bn_a = BN_CTX_get(bn_ctx);
    if (!bn_a || !BN_lebin2bn(*a, sizeof(ed25519_le_scalar_t), bn_a))
        goto cleanup;
    bn_b = BN_CTX_get(bn_ctx);
    if (!bn_b || !BN_lebin2bn(*b, sizeof(ed25519_le_scalar_t), bn_b))
        goto cleanup;

    if (BN_cmp(bn_a, ctx->L) >= 0 || BN_cmp(bn_b, ctx->L) >= 0)
    {
        ret = ELLIPTIC_CURVE_ALGEBRA_INVALID_PARAMETER;
        goto cleanup;
    }

    BN_set_flags(bn_a, BN_FLG_CONSTTIME);
    BN_set_flags(bn_b, BN_FLG_CONSTTIME);

    if (BN_mod_add_quick(bn_a, bn_a, bn_b, ctx->L))
    {
        ret = BN_bn2lebinpad(bn_a, *res, sizeof(ed25519_scalar_t)) > 0 ? ELLIPTIC_CURVE_ALGEBRA_SUCCESS : ELLIPTIC_CURVE_ALGEBRA_UNKNOWN_ERROR;
    }
    else
    {
        ret = ELLIPTIC_CURVE_ALGEBRA_UNKNOWN_ERROR;
    }

cleanup:
    if (bn_a)
        BN_clear(bn_a);
    if (bn_b)
        BN_clear(bn_b);
    BN_CTX_end(bn_ctx);
    BN_CTX_free(bn_ctx);
    return ret;
}

elliptic_curve_algebra_status ed25519_algebra_inverse(const ed25519_algebra_ctx_t *ctx, ed25519_scalar_t *res, const ed25519_scalar_t *val)
{
    BN_CTX *bn_ctx = NULL;
    BIGNUM *bn_val = NULL;
    elliptic_curve_algebra_status ret = ELLIPTIC_CURVE_ALGEBRA_OUT_OF_MEMORY;

    if (!ctx || !res || !val)
        return ELLIPTIC_CURVE_ALGEBRA_INVALID_PARAMETER;

    bn_ctx = BN_CTX_new();
    if (!bn_ctx)
        return ELLIPTIC_CURVE_ALGEBRA_OUT_OF_MEMORY;

    BN_CTX_start(bn_ctx);

    bn_val = BN_CTX_get(bn_ctx);
    if (!bn_val || !BN_bin2bn(*val, sizeof(ed25519_scalar_t), bn_val))
        goto cleanup;

    BN_set_flags(bn_val, BN_FLG_CONSTTIME);

    if (BN_mod_inverse(bn_val, bn_val, ctx->L, bn_ctx))
    {
        ret = BN_bn2binpad(bn_val, *res, sizeof(ed25519_scalar_t)) > 0 ? ELLIPTIC_CURVE_ALGEBRA_SUCCESS : ELLIPTIC_CURVE_ALGEBRA_UNKNOWN_ERROR;
    }
    else
        ret = ELLIPTIC_CURVE_ALGEBRA_UNKNOWN_ERROR;

cleanup:
    if (bn_val)
        BN_clear(bn_val);
    BN_CTX_end(bn_ctx);
    BN_CTX_free(bn_ctx);
    return ret;
}

elliptic_curve_algebra_status ed25519_algebra_rand(const ed25519_algebra_ctx_t *ctx, ed25519_scalar_t *res)
{
    BIGNUM *tmp = NULL;
    elliptic_curve_algebra_status ret = ELLIPTIC_CURVE_ALGEBRA_OUT_OF_MEMORY;

    if (!ctx || !res)
        return ELLIPTIC_CURVE_ALGEBRA_INVALID_PARAMETER;

    tmp = BN_new();
    if (!tmp)
        goto cleanup;
    if (!BN_rand_range(tmp, ctx->L))
    {
        ret = ELLIPTIC_CURVE_ALGEBRA_UNKNOWN_ERROR;
        goto cleanup;
    }

    ret = BN_bn2binpad(tmp, *res, sizeof(ed25519_scalar_t)) > 0 ? ELLIPTIC_CURVE_ALGEBRA_SUCCESS : ELLIPTIC_CURVE_ALGEBRA_UNKNOWN_ERROR;

cleanup:
    BN_clear_free(tmp);
    return ret;
}

elliptic_curve_algebra_status ed25519_algebra_reduce(const ed25519_algebra_ctx_t *ctx, ed25519_le_scalar_t *res, const ed25519_le_large_scalar_t *s)
{
    ed25519_le_large_scalar_t value;
    if (!ctx || !res || !s)
        return ELLIPTIC_CURVE_ALGEBRA_INVALID_PARAMETER;

    memcpy(value, *s, sizeof(ed25519_le_large_scalar_t));
    x25519_sc_reduce(value);
    memcpy(*res, value, sizeof(ed25519_le_scalar_t));
    OPENSSL_cleanse(value,sizeof(ed25519_le_large_scalar_t));
    return ELLIPTIC_CURVE_ALGEBRA_SUCCESS;
}

elliptic_curve_algebra_status ed25519_algebra_mul_add(const ed25519_algebra_ctx_t *ctx,
                                                      ed25519_le_scalar_t *res,
                                                      const ed25519_le_scalar_t *a,
                                                      const ed25519_le_scalar_t *b,
                                                      const ed25519_le_scalar_t *c)
{
    if (!ctx || !res || !a || !b || !c)
        return ELLIPTIC_CURVE_ALGEBRA_INVALID_PARAMETER;

    sc_muladd(*res, *a, *b, *c);
    return ELLIPTIC_CURVE_ALGEBRA_SUCCESS;
}

elliptic_curve_algebra_status ed25519_calc_hram(const ed25519_algebra_ctx_t *ctx,
                                                ed25519_le_scalar_t *hram,
                                                const ed25519_point_t *R,
                                                const ed25519_point_t *public_key,
                                                const uint8_t *message,
                                                uint32_t message_size,
                                                uint8_t use_keccak)
{
    if (!ctx || !hram || !R || !public_key || !message || !message_size)
        return ELLIPTIC_CURVE_ALGEBRA_INVALID_PARAMETER;

    uint8_t hash[SHA512_DIGEST_LENGTH];
    if (use_keccak)
    {
        KECCAK1600_CTX hash_ctx;
        keccak1600_init(&hash_ctx, 512, KECCAK256_PAD);
        keccak1600_update(&hash_ctx, *R, 32);
        keccak1600_update(&hash_ctx, *public_key, 32);
        keccak1600_update(&hash_ctx, message, message_size);
        keccak1600_final(&hash_ctx, hash);
    }
    else
    {
        SHA512_CTX hash_ctx;
        SHA512_Init(&hash_ctx);
        SHA512_Update(&hash_ctx, *R, 32);
        SHA512_Update(&hash_ctx, *public_key, 32);
        SHA512_Update(&hash_ctx, message, message_size);
        SHA512_Final(hash, &hash_ctx);
    }
    return ed25519_algebra_reduce(ctx, hram, &hash);
}

elliptic_curve_algebra_status ed25519_algebra_sign(const ed25519_algebra_ctx_t *ctx,
                                                   const ed25519_scalar_t *private_key,
                                                   const uint8_t *message,
                                                   uint32_t message_size,
                                                   uint8_t use_keccak,
                                                   uint8_t signature[64])
{
    elliptic_curve_algebra_status status;
    SHA512_CTX hash_ctx;
    ed25519_le_scalar_t k;
    ed25519_le_large_scalar_t hash;
    ed25519_le_scalar_t hram;
    ed25519_le_scalar_t s;
    ed25519_le_scalar_t priv;
    ed25519_point_t A;
    ed25519_point_t R;

    if (!ctx || !private_key || !message || !message_size || !signature)
        return ELLIPTIC_CURVE_ALGEBRA_INVALID_PARAMETER;

    // deterministic k
    SHA512_Init(&hash_ctx);
    SHA512_Update(&hash_ctx, *private_key, sizeof(ed25519_scalar_t));
    SHA512_Update(&hash_ctx, message, message_size);
    SHA512_Final(hash, &hash_ctx);
    ed25519_algebra_reduce(ctx, &k, &hash);
    ed25519_algebra_generator_mul_internal(&R, &k);

    status = ed25519_algebra_generator_mul(ctx, &A, private_key);
    if (status != ELLIPTIC_CURVE_ALGEBRA_SUCCESS)
        return status;

    status = ed25519_calc_hram(ctx, &hram, &R, &A, message, message_size, use_keccak);
    if (status != ELLIPTIC_CURVE_ALGEBRA_SUCCESS)
        return status;

    ed25519_algebra_be_to_le(&priv, private_key);
    ed25519_algebra_mul_add(ctx, &s, &hram, &priv, &k);
    memcpy(signature, R, 32);
    memcpy(signature + 32, s, 32);

    OPENSSL_cleanse(k, sizeof(ed25519_le_scalar_t));
    OPENSSL_cleanse(priv, sizeof(ed25519_le_scalar_t));

    return ELLIPTIC_CURVE_ALGEBRA_SUCCESS;
}

int ed25519_verify(const ed25519_algebra_ctx_t *ctx,
                   const uint8_t *message,
                   size_t message_len,
                   const uint8_t signature[64],
                   const uint8_t public_key[32],
                   uint8_t use_keccak)
{
    if (!ctx || !signature || !message || !message_len || !public_key)
        return 0;

    if (!use_keccak)
        return ED25519_verify(message, message_len, signature, public_key);
    int i;
    ge_p3 A;
    const uint8_t *r, *s;
    KECCAK1600_CTX hash_ctx;
    ge_p2 R;
    uint8_t rcheck[32];
    uint8_t h[SHA512_DIGEST_LENGTH];
    /* 27742317777372353535851937790883648493 in little endian format */
    const uint8_t l_low[16] =
    {
        0xED, 0xD3, 0xF5, 0x5C, 0x1A, 0x63, 0x12, 0x58, 0xD6, 0x9C, 0xF7, 0xA2,
        0xDE, 0xF9, 0xDE, 0x14
    };

    r = signature;
    s = signature + 32;

    /*
     * Check 0 <= s < L where L = 2^252 + 27742317777372353535851937790883648493
     *
     * If not the signature is publicly invalid. Since it's public we can do the
     * check in variable time.
     *
     * First check the most significant byte
     */
    if (s[31] > 0x10)
        return 0;
    if (s[31] == 0x10)
    {
        /*
         * Most significant byte indicates a value close to 2^252 so check the
         * rest
         */
        if (memcmp(s + 16, allzeroes, sizeof(allzeroes)) != 0)
            return 0;
        for (i = 15; i >= 0; i--)
        {
            if (s[i] < l_low[i])
                break;
            if (s[i] > l_low[i])
                return 0;
        }
        if (i < 0)
            return 0;
    }

    if (ge_frombytes_vartime(&A, public_key) != 0)
    {
        return 0;
    }

    fe_neg(A.X, A.X);
    fe_neg(A.T, A.T);

    keccak1600_init(&hash_ctx, 512, KECCAK256_PAD);
    keccak1600_update(&hash_ctx, r, 32);
    keccak1600_update(&hash_ctx, public_key, 32);
    keccak1600_update(&hash_ctx, message, message_len);
    keccak1600_final(&hash_ctx, h);

    x25519_sc_reduce(h);

    ge_double_scalarmult_vartime(&R, h, &A, s);

    ge_tobytes(rcheck, &R);

    return CRYPTO_memcmp(rcheck, r, sizeof(rcheck)) == 0;
}

elliptic_curve_algebra_status ed25519_algebra_le_to_be(ed25519_scalar_t *res, const ed25519_le_scalar_t *n)
{
    ed25519_le_scalar_t tmp;
    if (!res || !n)
        return ELLIPTIC_CURVE_ALGEBRA_INVALID_PARAMETER;
    memcpy(&tmp, *n, (sizeof(ed25519_le_scalar_t)));
    bswap_256(tmp, *res);

    OPENSSL_cleanse(tmp, sizeof(ed25519_le_scalar_t));

    return ELLIPTIC_CURVE_ALGEBRA_SUCCESS;
}

elliptic_curve_algebra_status ed25519_algebra_be_to_le(ed25519_le_scalar_t *res, const ed25519_scalar_t *n)
{
    ed25519_scalar_t tmp;
    if (!res || !n)
        return ELLIPTIC_CURVE_ALGEBRA_INVALID_PARAMETER;
    memcpy(&tmp, *n, (sizeof(ed25519_scalar_t)));
    bswap_256(tmp, *res);

    OPENSSL_cleanse(tmp, sizeof(ed25519_scalar_t));

    return ELLIPTIC_CURVE_ALGEBRA_SUCCESS;
}

// elliptic_curve256_algebra_ctx_t interface implementation needed as ed25519_point_t is smaller than elliptic_curve256_point_t
static int release(elliptic_curve256_algebra_ctx_t *ctx)
{
    if (ctx)
    {
        if (ctx->type != ELLIPTIC_CURVE_ED25519)
            return 0;
        ed25519_algebra_ctx_free((ed25519_algebra_ctx_t*)ctx->ctx);
        free(ctx);
    }
    return 1;
}

static const uint8_t *ed25519_order(const elliptic_curve256_algebra_ctx_t *ctx)
{
    (void)(ctx);

    return ED25519_FIELD;
}

static uint8_t ed25519_point_size(const elliptic_curve256_algebra_ctx_t *ctx)
{
    (void)(ctx);

    return ED25519_COMPRESSED_POINT_LEN;
}

static const elliptic_curve256_point_t *infinity_point(const struct elliptic_curve256_algebra_ctx *ctx)
{
    (void)(ctx);
    static const elliptic_curve256_point_t INFINITY = {1, 0};
    return &INFINITY;
}

static inline int ed25519_is_infinity_compat(const elliptic_curve256_point_t *p)
{
    /*
     * Ed25519 identity (neutral element) in compressed form is:
     *   y = 1, x sign bit = 0  =>  0x01 followed by 31 zero bytes.
     *
     * Note: `elliptic_curve256_point_t` is 33 bytes, while Ed25519 point
     * serialization is 32 bytes. All Ed25519 operations in this file ignore
     * the 33rd byte (tail) by passing only the first 32 bytes to the ref10
     * parser. Therefore we must treat any value in the tail byte as still
     * representing infinity as long as the first 32 bytes encode the identity.
     */
    /* We intentionally do NOT reuse the 33-byte `elliptic_curve256_point_t INFINITY = {1,0}` here:
     * comparing 33 bytes would incorrectly reject valid "infinity" encodings where the tail byte is non-zero,
     * which are still treated as infinity by all Ed25519 operations in this file (they ignore the tail byte). */
    static const uint8_t ED25519_INFINITY_COMPRESSED[ED25519_COMPRESSED_POINT_LEN] = {1, 0};
    return CRYPTO_memcmp(*p, ED25519_INFINITY_COMPRESSED, ED25519_COMPRESSED_POINT_LEN) == 0;
}

static elliptic_curve_algebra_status validate_non_infinity_point(const struct elliptic_curve256_algebra_ctx *ctx, const elliptic_curve256_point_t *p)
{
    if (!ctx || !p || ctx->type != ELLIPTIC_CURVE_ED25519)
    {
        return ELLIPTIC_CURVE_ALGEBRA_INVALID_PARAMETER;
    }

    /* Must be a valid encoding in the correct subgroup, and must not be infinity. */
    if (!ed25519_is_valid_point(*p))
    {
        return ELLIPTIC_CURVE_ALGEBRA_INVALID_POINT;
    }
    if (ed25519_is_infinity_compat(p))
    {
        return ELLIPTIC_CURVE_ALGEBRA_INVALID_POINT;
    }
    return ELLIPTIC_CURVE_ALGEBRA_SUCCESS;
}


static elliptic_curve_algebra_status generator_mul_data(const elliptic_curve256_algebra_ctx_t *ctx, const uint8_t *data, uint32_t data_len, elliptic_curve256_point_t *proof)
{
    if (!ctx || !proof || ctx->type != ELLIPTIC_CURVE_ED25519)
        return ELLIPTIC_CURVE_ALGEBRA_INVALID_PARAMETER;

    (*proof)[sizeof(ed25519_point_t)] = 0;
    return ed25519_algebra_generator_mul_data(ctx->ctx, data, data_len, (ed25519_point_t*)proof);
}

static elliptic_curve_algebra_status verify(const elliptic_curve256_algebra_ctx_t *ctx, const uint8_t *data, uint32_t data_len, const elliptic_curve256_point_t *proof, uint8_t *result)
{
    if (!ctx || ctx->type != ELLIPTIC_CURVE_ED25519)
        return ELLIPTIC_CURVE_ALGEBRA_INVALID_PARAMETER;
    return ed25519_algebra_verify(ctx->ctx, data, data_len, (const ed25519_point_t*)proof, result);
}

static elliptic_curve_algebra_status verify_linear_combination(const elliptic_curve256_algebra_ctx_t *ctx, const elliptic_curve256_point_t *proof, const elliptic_curve256_point_t *proof_points,
    const elliptic_curve256_scalar_t *coefficients, uint32_t points_count, uint8_t *result)
{
    ed25519_point_t *points;
    elliptic_curve_algebra_status status;
    if (!ctx || !proof_points || !points_count || ctx->type != ELLIPTIC_CURVE_ED25519)
        return ELLIPTIC_CURVE_ALGEBRA_INVALID_PARAMETER;

    points = calloc(points_count, sizeof(ed25519_point_t));
    if (!points)
        return ELLIPTIC_CURVE_ALGEBRA_OUT_OF_MEMORY;

    for (uint32_t i = 0; i < points_count; ++i)
        memcpy(points[i], proof_points[i], sizeof(ed25519_point_t));
    status = ed25519_algebra_verify_linear_combination(ctx->ctx, (const ed25519_point_t*)proof, points, coefficients, points_count, result);
    free(points);
    return status;
}

static elliptic_curve_algebra_status generator_mul(const elliptic_curve256_algebra_ctx_t *ctx, elliptic_curve256_point_t *res, const elliptic_curve256_scalar_t *exp)
{
    if (!ctx || !res || ctx->type != ELLIPTIC_CURVE_ED25519)
        return ELLIPTIC_CURVE_ALGEBRA_INVALID_PARAMETER;

    (*res)[sizeof(ed25519_point_t)] = 0;
    return ed25519_algebra_generator_mul_data(ctx->ctx, *exp, sizeof(elliptic_curve256_scalar_t), (ed25519_point_t*)res);
}

static elliptic_curve_algebra_status add_points(const elliptic_curve256_algebra_ctx_t *ctx,
                                                elliptic_curve256_point_t *res,
                                                const elliptic_curve256_point_t *p1,
                                                const elliptic_curve256_point_t *p2)
{
    if (!ctx || !res || ctx->type != ELLIPTIC_CURVE_ED25519)
        return ELLIPTIC_CURVE_ALGEBRA_INVALID_PARAMETER;

    (*res)[sizeof(ed25519_point_t)] = 0;
    return ed25519_algebra_add_points(ctx->ctx, (ed25519_point_t*)res, (const ed25519_point_t*)p1, (const ed25519_point_t*)p2);
}

static elliptic_curve_algebra_status point_mul(const elliptic_curve256_algebra_ctx_t *ctx, elliptic_curve256_point_t *res, const elliptic_curve256_point_t *p, const elliptic_curve256_scalar_t *exp)
{
    elliptic_curve_algebra_status ret;
    ed25519_le_scalar_t le_exp;
    if (!ctx || !res || ctx->type != ELLIPTIC_CURVE_ED25519)
        return ELLIPTIC_CURVE_ALGEBRA_INVALID_PARAMETER;
    if (!ed25519_is_valid_point(*p))
        return ELLIPTIC_CURVE_ALGEBRA_INVALID_POINT;

    (*res)[sizeof(ed25519_point_t)] = 0;
    ret = to_ed25519_scalar(ctx->ctx, &le_exp, *exp, sizeof(elliptic_curve256_scalar_t));

    if (ret == ELLIPTIC_CURVE_ALGEBRA_SUCCESS)
    {
        if (ed25519_scalar_mult(*res, le_exp, *p))
            return ELLIPTIC_CURVE_ALGEBRA_SUCCESS;
        else
            return ELLIPTIC_CURVE_ALGEBRA_INVALID_POINT;
    }
    return ret;
}

static elliptic_curve_algebra_status add_scalars(const struct elliptic_curve256_algebra_ctx *ctx, elliptic_curve256_scalar_t *res, const uint8_t *a, uint32_t a_len, const uint8_t *b, uint32_t b_len)
{
    if (!ctx || ctx->type != ELLIPTIC_CURVE_ED25519)
        return ELLIPTIC_CURVE_ALGEBRA_INVALID_PARAMETER;
    return ed25519_algebra_add_scalars(ctx->ctx, res, a, a_len, b, b_len);
}

static elliptic_curve_algebra_status sub_scalars(const struct elliptic_curve256_algebra_ctx *ctx, elliptic_curve256_scalar_t *res, const uint8_t *a, uint32_t a_len, const uint8_t *b, uint32_t b_len)
{
    if (!ctx || ctx->type != ELLIPTIC_CURVE_ED25519)
        return ELLIPTIC_CURVE_ALGEBRA_INVALID_PARAMETER;
    return ed25519_algebra_sub_scalars(ctx->ctx, res, a, a_len, b, b_len);
}

static elliptic_curve_algebra_status mul_scalars(const struct elliptic_curve256_algebra_ctx *ctx, elliptic_curve256_scalar_t *res, const uint8_t *a, uint32_t a_len, const uint8_t *b, uint32_t b_len)
{
    if (!ctx || ctx->type != ELLIPTIC_CURVE_ED25519)
        return ELLIPTIC_CURVE_ALGEBRA_INVALID_PARAMETER;
    return ed25519_algebra_mul_scalars(ctx->ctx, res, a, a_len, b, b_len);
}

static elliptic_curve_algebra_status inverse(const struct elliptic_curve256_algebra_ctx *ctx, elliptic_curve256_scalar_t *res, const elliptic_curve256_scalar_t *val)
{
    if (!ctx || ctx->type != ELLIPTIC_CURVE_ED25519)
        return ELLIPTIC_CURVE_ALGEBRA_INVALID_PARAMETER;
    return ed25519_algebra_inverse(ctx->ctx, res, val);
}

static elliptic_curve_algebra_status ec_rand(const struct elliptic_curve256_algebra_ctx *ctx, elliptic_curve256_scalar_t *res)
{
    if (!ctx || ctx->type != ELLIPTIC_CURVE_ED25519)
        return ELLIPTIC_CURVE_ALGEBRA_INVALID_PARAMETER;
    return ed25519_algebra_rand(ctx->ctx, res);
}

/**
 * @brief Checks if a given scalar value is within the Ed25519 field order.
 *
 * This function determines whether the given scalar `val` is strictly less
 * than the Ed25519 field order by performing a big-endian comparison.
 * It processes the 256-bit value in 32-bit chunks and propagates a borrow bit
 * to detect whether an underflow occurs.
 *
 * The function operates as follows:
 * - The scalar `val` is interpreted as an array of 32-bit words.
 * - `ED25519_FIELD_LITTLE_ENDIAN` is the reference field order in little-endian format.
 * - Each 32-bit word in `val` is byte-swapped to convert from big-endian to little-endian.
 * - The function performs a subtraction of `val` from `ED25519_FIELD_LITTLE_ENDIAN`
 *   while tracking borrow propagation.
 * - If an underflow occurs (borrow is set), it means that `val` is greater than or equal
 *   to the field order, and the function returns 0.
 * - If no underflow occurs (borrow remains 0 at the end), `val` is within the valid range,
 *   and the function returns 1.
 *
 * This function runs in constant time to prevent timing-based side-channel attacks.
 *
 * @param val   The scalar value to check, represented as a 256-bit integer.
 * @return      1 if `val` is strictly less than the field order, 0 otherwise.
 */
static uint8_t in_field(const elliptic_curve256_scalar_t val)
{
    uint8_t borrow = 0; // Tracks underflow during subtraction
    const uint32_t *ptr1 = (const uint32_t*)val; // Scalar value as 32-bit words
    const uint32_t *ptr2 = (const uint32_t*)ED25519_FIELD_LITTLE_ENDIAN; // Field order in little-endian

    // Iterate over 32-bit segments, processing from least significant to most significant
    for (size_t i = 0; i < sizeof(elliptic_curve256_scalar_t) / sizeof(uint32_t); ++i)
    {
        uint64_t v1 = bswap_32(ptr1[sizeof(elliptic_curve256_scalar_t) / sizeof(uint32_t) - 1 - i]); // Convert to little-endian
        uint64_t v2 = ptr2[i];

        // Perform subtraction with borrow tracking
        borrow = ((v1 - v2 - borrow) >> 32) & 0x1;
    }

    return borrow; // 1 if `val` is less than the field order, 0 otherwise
}

static elliptic_curve_algebra_status reduce(const struct elliptic_curve256_algebra_ctx *ctx, elliptic_curve256_scalar_t *res, const elliptic_curve256_scalar_t *val)
{
    elliptic_curve256_scalar_t tmp;
    elliptic_curve_algebra_status ret = ELLIPTIC_CURVE_ALGEBRA_INVALID_SCALAR;

    if (!ctx || !res || !val || ctx->type != ELLIPTIC_CURVE_ED25519)
        return ELLIPTIC_CURVE_ALGEBRA_INVALID_PARAMETER;
    memcpy(tmp, *val, sizeof(elliptic_curve256_scalar_t));
    tmp[0] &= 0x1f; // ed25519 curve order is 253 bit
    if (in_field(tmp))
    {
        memcpy(*res, tmp, sizeof(elliptic_curve256_scalar_t));
        ret = ELLIPTIC_CURVE_ALGEBRA_SUCCESS;
    }
    else
        OPENSSL_cleanse(*res, sizeof(elliptic_curve256_scalar_t));

    OPENSSL_cleanse(tmp, sizeof(elliptic_curve256_scalar_t));
    return ret;
}

static const struct bignum_st *order_internal(const elliptic_curve256_algebra_ctx_t *ctx)
{
    if (ctx && ctx->type == ELLIPTIC_CURVE_ED25519)
    {
        ed25519_algebra_ctx_t *ctx_ = (ed25519_algebra_ctx_t*)ctx->ctx;
        return ctx_->L;
    }
    return NULL;
}

/**
 * @brief Maps a message to a valid Ed25519 elliptic curve point using a simple hash function.
 *
 * This function attempts to map an arbitrary message to a point on the Ed25519 curve
 * by using a hashing approach. It performs the following steps:
 *
 * 1. Computes a SHA-512 hash of the input message.
 * 2. Interprets the hash as a candidate point and checks if it is a valid Ed25519 point.
 * 3. If the point is invalid, it re-hashes the previous hash and repeats.
 * 4. If a valid point is found within a maximum number of attempts (`max_retries`),
 *    the function returns the point.
 * 5. If no valid point is found after `max_retries`, the function returns an error.
 *
 * This approach is commonly used in hash-to-curve operations where a message is mapped
 * deterministically to an elliptic curve point.
 *
 * @param algebra  The elliptic curve algebra context (must be of type `ELLIPTIC_CURVE_ED25519`).
 * @param res      The output buffer to store the computed elliptic curve point.
 * @param msg      The input message to be hashed and mapped to the curve.
 * @param msg_len  The length of the input message.
 * @return         `ELLIPTIC_CURVE_ALGEBRA_SUCCESS` if a valid point is found,
 *                 `ELLIPTIC_CURVE_ALGEBRA_INVALID_POINT` if no valid point is found within the retry limit,
 *                 or `ELLIPTIC_CURVE_ALGEBRA_INVALID_PARAMETER` if inputs are null or incorrect.
 */
static elliptic_curve_algebra_status simple_hash_to_curve(const struct elliptic_curve256_algebra_ctx *algebra,
                                                          elliptic_curve256_point_t *res,
                                                          const uint8_t* msg,
                                                          uint32_t msg_len)
{
    uint8_t hash[SHA512_DIGEST_LENGTH];  // Buffer to store the SHA-512 hash
    uint32_t max_retries = 1024;         // Maximum number of retries to find a valid point
    SHA512_CTX hash_ctx;                 // SHA-512 context
    elliptic_curve_algebra_status status = ELLIPTIC_CURVE_ALGEBRA_INVALID_POINT;

    // Validate input parameters
    if (!algebra || !res || (msg_len && !msg) || algebra->type != ELLIPTIC_CURVE_ED25519)
    {
        return ELLIPTIC_CURVE_ALGEBRA_INVALID_PARAMETER;
    }

    // Clear the result buffer
    OPENSSL_cleanse(*res, sizeof(elliptic_curve256_point_t));

    // Compute initial SHA-512 hash of the input message
    SHA512_Init(&hash_ctx);
    SHA512_Update(&hash_ctx, msg, msg_len);
    SHA512_Final(hash, &hash_ctx);

    // Try to map the hash to a valid Ed25519 point
    while (0 != --max_retries)
    {
        // Check if the hashed value is a valid Ed25519 point
        if (ed25519_is_valid_point(hash))
        {
            memcpy(res, hash, sizeof(ed25519_point_t));
            status = ELLIPTIC_CURVE_ALGEBRA_SUCCESS;
            break;
        }

        // If invalid, re-hash and try again
        SHA512_Init(&hash_ctx);
        SHA512_Update(&hash_ctx, hash, sizeof(hash));
        SHA512_Final(hash, &hash_ctx);
    }

    return status;
}

elliptic_curve256_algebra_ctx_t* elliptic_curve256_new_ed25519_algebra()
{
    elliptic_curve256_algebra_ctx_t *ctx = malloc(sizeof(elliptic_curve256_algebra_ctx_t));
    if (!ctx)
        return ctx;

    ctx->ctx = ed25519_algebra_ctx_new();
    ctx->type = ELLIPTIC_CURVE_ED25519;
    ctx->release = release;
    ctx->order = ed25519_order;
    ctx->point_size = ed25519_point_size;
    ctx->infinity_point = infinity_point;
    ctx->validate_non_infinity_point = validate_non_infinity_point;
    ctx->generator_mul_data = generator_mul_data;
    ctx->verify = verify;
    ctx->verify_linear_combination = verify_linear_combination;
    ctx->generator_mul = generator_mul;
    ctx->add_points = add_points;
    ctx->point_mul = point_mul;
    ctx->add_scalars = add_scalars;
    ctx->sub_scalars = sub_scalars;
    ctx->mul_scalars = mul_scalars;
    ctx->inverse = inverse;
    ctx->rand = ec_rand;
    ctx->order_internal = order_internal;
    ctx->reduce = reduce;
    ctx->hash_on_curve = simple_hash_to_curve;

    return ctx;
}
