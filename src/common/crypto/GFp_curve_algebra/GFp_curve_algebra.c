#include "crypto/GFp_curve_algebra/GFp_curve_algebra.h"

#include <string.h>
#include <assert.h>
#include "crypto/common/byteswap.h"

#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/ec.h>
#include <openssl/objects.h>

const uint8_t SECP256K1_FIELD[] = {
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 
    0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41};

const uint8_t SECP256R1_FIELD[] = {
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51};

const uint8_t STARK_FIELD[] = {
    0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 
    0xb7, 0x81, 0x12, 0x6d, 0xca, 0xe7, 0xb2, 0x32, 0x1e, 0x66, 0xa2, 0x41, 0xad, 0xc6, 0x4d, 0x2f};

static const uint8_t STARK_P[] = {
    0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};

static const uint8_t STARK_B[] = {
    0x06, 0xf2, 0x14, 0x13, 0xef, 0xbe, 0x40, 0xde, 0x15, 0x0e, 0x59, 0x6d, 0x72, 0xf7, 0xa8, 0xc5, 
    0x60, 0x9a, 0xd2, 0x6c, 0x15, 0xc9, 0x15, 0xc1, 0xf4, 0xcd, 0xfc, 0xb9, 0x9c, 0xee, 0x9e, 0x89};

static const uint8_t STARK_GX[] = {
    0x01, 0xef, 0x15, 0xc1, 0x85, 0x99, 0x97, 0x1b, 0x7b, 0xec, 0xed, 0x41, 0x5a, 0x40, 0xf0, 0xc7, 
    0xde, 0xac, 0xfd, 0x9b, 0x0d, 0x18, 0x19, 0xe0, 0x3d, 0x72, 0x3d, 0x8b, 0xc9, 0x43, 0xcf, 0xca};
static const uint8_t STARK_GY[] = {
    0x00, 0x56, 0x68, 0x06, 0x0a, 0xa4, 0x97, 0x30, 0xb7, 0xbe, 0x48, 0x01, 0xdf, 0x46, 0xec, 0x62, 
    0xde, 0x53, 0xec, 0xd1, 0x1a, 0xbe, 0x43, 0xa3, 0x28, 0x73, 0x00, 0x0c, 0x36, 0xe8, 0xdc, 0x1f};
    
struct GFp_curve_algebra_ctx 
{
    EC_GROUP *curve;
};

GFp_curve_algebra_ctx_t *secp256k1_algebra_ctx_new()
{
    GFp_curve_algebra_ctx_t *ctx = malloc(sizeof(GFp_curve_algebra_ctx_t));

    if (ctx)
    {
        ctx->curve = EC_GROUP_new_by_curve_name(NID_secp256k1);
        if (!ctx->curve)
        {
            free(ctx);
            return NULL;
        }
    }
    return ctx;
}

GFp_curve_algebra_ctx_t *secp256r1_algebra_ctx_new()
{
    GFp_curve_algebra_ctx_t *ctx = malloc(sizeof(GFp_curve_algebra_ctx_t));

    if (ctx)
    {
        ctx->curve = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
        if (!ctx->curve)
        {
            free(ctx);
            return NULL;
        }
    }
    return ctx;
}

GFp_curve_algebra_ctx_t *stark_algebra_ctx_new()
{
    int ret = 0;
    BN_CTX *ctx = NULL;
    BIGNUM *p = NULL, *q = NULL, *b = NULL, *x = NULL, *y = NULL;
    EC_POINT *g = NULL;

    GFp_curve_algebra_ctx_t *algebra = malloc(sizeof(GFp_curve_algebra_ctx_t));
    if (!algebra)
        return NULL;
    algebra->curve = NULL;
    
    ctx = BN_CTX_new();
    if (!ctx)
        goto cleanup;
    BN_CTX_start(ctx);
    p = BN_CTX_get(ctx);
    q = BN_CTX_get(ctx);
    b = BN_CTX_get(ctx);
    x = BN_CTX_get(ctx);
    y = BN_CTX_get(ctx);
    if (!p || !q || !b || !x || !y)
        goto cleanup;
    
    if (!BN_bin2bn(STARK_P, sizeof(STARK_P), p))
        goto cleanup;
    if (!BN_bin2bn(STARK_FIELD, sizeof(STARK_FIELD), q))
        goto cleanup;
    if (!BN_bin2bn(STARK_B, sizeof(STARK_B), b))
        goto cleanup;
    if (!BN_bin2bn(STARK_GX, sizeof(STARK_GX), x))
        goto cleanup;
    if (!BN_bin2bn(STARK_GY, sizeof(STARK_GY), y))
        goto cleanup;

    algebra->curve = EC_GROUP_new_curve_GFp(p, BN_value_one(), b, ctx);
    if (!algebra->curve)
        goto cleanup;

    g = EC_POINT_new(algebra->curve);
    if (!g)
        goto cleanup;
    if (!EC_POINT_set_affine_coordinates(algebra->curve, g, x, y, ctx))
        goto cleanup;
    if (!EC_GROUP_set_generator(algebra->curve, g, q, BN_value_one()))
        goto cleanup;
    ret = 1;

cleanup:
    EC_POINT_free(g);
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);

    if (!ret)
    {
        GFp_curve_algebra_ctx_free(algebra);
        algebra = NULL;
    }
    return algebra;
}

void GFp_curve_algebra_ctx_free(GFp_curve_algebra_ctx_t *ctx)
{
    if (ctx)
    {
        EC_GROUP_free(ctx->curve);
        free(ctx);
    }
}

#define SIZEOF_POINT(p) (*(p) ? sizeof(elliptic_curve256_point_t) : 1)

static elliptic_curve_algebra_status from_openssl_error(long err)
{
    if (ERR_GET_LIB(err) == ERR_LIB_EC && (ERR_GET_REASON(err) == EC_R_INVALID_ENCODING || ERR_GET_REASON(err) == EC_R_INVALID_COMPRESSED_POINT))
        return ELLIPTIC_CURVE_ALGEBRA_INVALID_POINT;
    if (ERR_GET_REASON(err) == ERR_R_MALLOC_FAILURE)
        return ELLIPTIC_CURVE_ALGEBRA_OUT_OF_MEMORY;
    return ELLIPTIC_CURVE_ALGEBRA_UNKNOWN_ERROR;
}

elliptic_curve_algebra_status GFp_curve_algebra_generator_mul_data(const GFp_curve_algebra_ctx_t *ctx, const uint8_t *data, uint32_t data_len, elliptic_curve256_point_t *point)
{
    BN_CTX *bn_ctx = NULL;
    EC_POINT *ecpoint = NULL;
    BIGNUM *exp = NULL;
    elliptic_curve_algebra_status ret = ELLIPTIC_CURVE_ALGEBRA_UNKNOWN_ERROR;

    if (!ctx || !data || !point || !data_len)
        return ELLIPTIC_CURVE_ALGEBRA_INVALID_PARAMETER;
    
    memset(*point, 0, sizeof(elliptic_curve256_point_t));
    ecpoint = EC_POINT_new(ctx->curve);
    if (!ecpoint)
        return ELLIPTIC_CURVE_ALGEBRA_OUT_OF_MEMORY;
    bn_ctx = BN_CTX_new();
    if (!bn_ctx)
    {
        EC_POINT_free(ecpoint);
        return ELLIPTIC_CURVE_ALGEBRA_OUT_OF_MEMORY;
    }
    BN_CTX_start(bn_ctx);
    exp = BN_CTX_get(bn_ctx);
    if (!exp || !BN_bin2bn(data, data_len, exp))
    {
        ret = ELLIPTIC_CURVE_ALGEBRA_OUT_OF_MEMORY;
        goto cleanup;
    }
    if (EC_POINT_mul(ctx->curve, ecpoint, exp, NULL, NULL, bn_ctx))
    {
        if (EC_POINT_point2oct(ctx->curve, ecpoint, POINT_CONVERSION_COMPRESSED, *point, sizeof(elliptic_curve256_point_t), bn_ctx) > 0)
            ret = ELLIPTIC_CURVE_ALGEBRA_SUCCESS;          
    }

cleanup:
    BN_clear(exp);
    BN_CTX_end(bn_ctx);
    BN_CTX_free(bn_ctx);
    EC_POINT_free(ecpoint);
    return ret;
}

elliptic_curve_algebra_status GFp_curve_algebra_verify(const GFp_curve_algebra_ctx_t *ctx, const uint8_t *data, uint32_t data_len, const elliptic_curve256_point_t *point, uint8_t *result)
{
    elliptic_curve256_point_t local_point;
    elliptic_curve_algebra_status ret;

    if (!result || !point)
        return ELLIPTIC_CURVE_ALGEBRA_INVALID_PARAMETER;
    
    *result = 0;
    
    ret = GFp_curve_algebra_generator_mul_data(ctx, data, data_len, &local_point);
    if (ret == ELLIPTIC_CURVE_ALGEBRA_SUCCESS)
        *result = CRYPTO_memcmp(local_point, point, sizeof(elliptic_curve256_point_t)) ? 0 : 1;
    return ret;
}

elliptic_curve_algebra_status GFp_curve_algebra_verify_sum(const GFp_curve_algebra_ctx_t *ctx, const elliptic_curve256_point_t *sum_point, const elliptic_curve256_point_t *proof_points, uint32_t points_count, uint8_t *result)
{
    BN_CTX *bn_ctx = NULL;
    EC_POINT *p_proof = NULL;
    EC_POINT *point = NULL;
    EC_POINT *tmp = NULL;
    int ret;
    elliptic_curve_algebra_status status = ELLIPTIC_CURVE_ALGEBRA_UNKNOWN_ERROR;

    if (!ctx || !sum_point || !proof_points || !points_count || !result)
        return ELLIPTIC_CURVE_ALGEBRA_INVALID_PARAMETER;
    
    *result = 0;

    p_proof = EC_POINT_new(ctx->curve);
    if (!p_proof)
        return ELLIPTIC_CURVE_ALGEBRA_OUT_OF_MEMORY;

    point = EC_POINT_new(ctx->curve);
    if (!point)
    {
        status = ELLIPTIC_CURVE_ALGEBRA_OUT_OF_MEMORY;
        goto cleanup;
    }

    tmp = EC_POINT_new(ctx->curve);
    if (!tmp)
    {
        status = ELLIPTIC_CURVE_ALGEBRA_OUT_OF_MEMORY;
        goto cleanup;
    }

    bn_ctx = BN_CTX_new();
    if (!bn_ctx)
    {
        status = ELLIPTIC_CURVE_ALGEBRA_OUT_OF_MEMORY;
        goto cleanup;
    }
    BN_CTX_start(bn_ctx);
    
    if (!EC_POINT_oct2point(ctx->curve, p_proof, *sum_point, SIZEOF_POINT(*sum_point), bn_ctx))
    {
        status = from_openssl_error(ERR_get_error());
        goto cleanup;
    }

    for (uint32_t i = 0; i < points_count; ++i)
    {
        if (!EC_POINT_oct2point(ctx->curve, tmp, proof_points[i], SIZEOF_POINT(proof_points[i]), bn_ctx))
        {
            status = from_openssl_error(ERR_get_error());
            goto cleanup;
        }
        if (!EC_POINT_add(ctx->curve, point, point, tmp, bn_ctx))
            goto cleanup;
    }
    
    ret = EC_POINT_cmp(ctx->curve, point, p_proof, bn_ctx);
    if (ret >= 0)
    {
        *result = (ret == 0);
        status = ELLIPTIC_CURVE_ALGEBRA_SUCCESS;
    }
    
cleanup:
    BN_CTX_end(bn_ctx);
    BN_CTX_free(bn_ctx);
    EC_POINT_free(p_proof);
    EC_POINT_free(point);
    EC_POINT_free(tmp);
    return status;
}

elliptic_curve_algebra_status GFp_curve_algebra_verify_linear_combination(const GFp_curve_algebra_ctx_t *ctx, const elliptic_curve256_point_t *sum_point, const elliptic_curve256_point_t *proof_points, const elliptic_curve256_scalar_t *coefficients, 
    uint32_t points_count, uint8_t *result)
{
    BN_CTX *bn_ctx = NULL;
    EC_POINT *p_proof = NULL;
    EC_POINT **points = NULL;
    BIGNUM **coeff = NULL;
    EC_POINT *tmp = NULL;
    BIGNUM *zero = NULL;
    int ret;
    elliptic_curve_algebra_status status = ELLIPTIC_CURVE_ALGEBRA_OUT_OF_MEMORY;

    if (!ctx || !sum_point || !proof_points || !coefficients || !points_count || !result)
        return ELLIPTIC_CURVE_ALGEBRA_INVALID_PARAMETER;
    
    *result = 0;

    bn_ctx = BN_CTX_new();
    if (!bn_ctx)
        return ELLIPTIC_CURVE_ALGEBRA_OUT_OF_MEMORY;
    BN_CTX_start(bn_ctx);
    
    p_proof = EC_POINT_new(ctx->curve);
    if (!p_proof)
        goto cleanup;
    if (!EC_POINT_oct2point(ctx->curve, p_proof, *sum_point, SIZEOF_POINT(*sum_point), bn_ctx))
    {
        status = from_openssl_error(ERR_get_error());
        goto cleanup;
    }

    points = (EC_POINT**)calloc(points_count, sizeof(EC_POINT*));
    if (!points)
        goto cleanup;
    
    for (size_t i = 0; i < points_count; ++i)
    {
        points[i] = EC_POINT_new(ctx->curve);
        if (!points[i])
            goto cleanup;
        if (!EC_POINT_oct2point(ctx->curve, points[i], proof_points[i], SIZEOF_POINT(proof_points[i]), bn_ctx))
        {
            status = from_openssl_error(ERR_get_error());
            goto cleanup;
        }
    }

    coeff = (BIGNUM**)calloc(points_count, sizeof(BIGNUM*));
    if (!coeff)
        goto cleanup;
    
    for (size_t i = 0; i < points_count; ++i)
    {
        coeff[i] = BN_CTX_get(bn_ctx);
        if (!coeff[i] || !BN_bin2bn(coefficients[i], sizeof(elliptic_curve256_scalar_t), coeff[i]))
            goto cleanup;
    }

    zero = BN_CTX_get(bn_ctx);
    tmp = EC_POINT_new(ctx->curve);
    if (!zero || !tmp)
        goto cleanup;
    BN_zero(zero);
    if (!EC_POINTs_mul(ctx->curve, tmp, zero, points_count, (const EC_POINT**)points, (const BIGNUM**)coeff, bn_ctx))
    {
        status = ELLIPTIC_CURVE_ALGEBRA_UNKNOWN_ERROR;
        goto cleanup;
    }
    
    ret = EC_POINT_cmp(ctx->curve, tmp, p_proof, bn_ctx);
    if (ret >= 0)
    {
        *result = (ret == 0);
        status = ELLIPTIC_CURVE_ALGEBRA_SUCCESS;
    }
    
cleanup:
    if (coeff)
    {
        for (size_t i = 0; i < points_count; ++i)
        {
            if (coeff[i])
                BN_clear(coeff[i]);
        }
        free(coeff);
    }

    BN_CTX_end(bn_ctx);
    BN_CTX_free(bn_ctx);

    if (points)
    {
        for (size_t i = 0; i < points_count; ++i)
            EC_POINT_free(points[i]);
        free(points);
    }
    EC_POINT_free(p_proof);
    EC_POINT_free(tmp);
    return status;
}

elliptic_curve_algebra_status GFp_curve_algebra_generator_mul(const GFp_curve_algebra_ctx_t *ctx, elliptic_curve256_point_t *res, const elliptic_curve256_scalar_t *exp)
{
    if (!exp)
        return ELLIPTIC_CURVE_ALGEBRA_INVALID_PARAMETER;
    return GFp_curve_algebra_generator_mul_data(ctx, *exp, sizeof(elliptic_curve256_scalar_t), res);
}

elliptic_curve_algebra_status GFp_curve_algebra_add_points(const GFp_curve_algebra_ctx_t *ctx, elliptic_curve256_point_t *res, const elliptic_curve256_point_t *p1, const elliptic_curve256_point_t *p2)
{
    BN_CTX *bn_ctx = NULL;
    EC_POINT *p_p1 = NULL;
    EC_POINT *p_p2 = NULL;
    elliptic_curve_algebra_status status = ELLIPTIC_CURVE_ALGEBRA_UNKNOWN_ERROR;

    if (!ctx || !res || !p1 || !p2)
        return ELLIPTIC_CURVE_ALGEBRA_INVALID_PARAMETER;
    
    p_p1 = EC_POINT_new(ctx->curve);
    if (!p_p1)
        return ELLIPTIC_CURVE_ALGEBRA_OUT_OF_MEMORY;

    p_p2 = EC_POINT_new(ctx->curve);
    if (!p_p2)
    {
        status = ELLIPTIC_CURVE_ALGEBRA_OUT_OF_MEMORY;
        goto cleanup;
    }

    bn_ctx = BN_CTX_new();
    if (!bn_ctx)
    {
        status = ELLIPTIC_CURVE_ALGEBRA_OUT_OF_MEMORY;
        goto cleanup;
    }
    BN_CTX_start(bn_ctx);
    
    if (!EC_POINT_oct2point(ctx->curve, p_p1, *p1, SIZEOF_POINT(*p1), bn_ctx))
    {
        status = from_openssl_error(ERR_get_error());
        goto cleanup;
    }
    if (!EC_POINT_oct2point(ctx->curve, p_p2, *p2, SIZEOF_POINT(*p2), bn_ctx))
    {
        status = from_openssl_error(ERR_get_error());
        goto cleanup;
    }

    if (!EC_POINT_add(ctx->curve, p_p1, p_p1, p_p2, bn_ctx))
        goto cleanup;
    
    memset(*res, 0, sizeof(elliptic_curve256_point_t));
    if (EC_POINT_point2oct(ctx->curve, p_p1, POINT_CONVERSION_COMPRESSED, *res, sizeof(elliptic_curve256_point_t), bn_ctx) > 0)
        status = ELLIPTIC_CURVE_ALGEBRA_SUCCESS;
    
cleanup:
    BN_CTX_end(bn_ctx);
    BN_CTX_free(bn_ctx);
    EC_POINT_free(p_p1);
    EC_POINT_free(p_p2);
    return status;
}

elliptic_curve_algebra_status GFp_curve_algebra_point_mul(const GFp_curve_algebra_ctx_t *ctx, elliptic_curve256_point_t *res, const elliptic_curve256_point_t *p, const elliptic_curve256_scalar_t *exp)
{
    BN_CTX *bn_ctx = NULL;
    EC_POINT *p_p = NULL;
    BIGNUM *bn_exp = NULL;
    elliptic_curve_algebra_status status = ELLIPTIC_CURVE_ALGEBRA_UNKNOWN_ERROR;

    if (!ctx || !res || !p || !exp)
        return ELLIPTIC_CURVE_ALGEBRA_INVALID_PARAMETER;
    
    p_p = EC_POINT_new(ctx->curve);
    if (!p_p)
        return ELLIPTIC_CURVE_ALGEBRA_OUT_OF_MEMORY;

    bn_ctx = BN_CTX_new();
    if (!bn_ctx)
    {
        status = ELLIPTIC_CURVE_ALGEBRA_OUT_OF_MEMORY;
        goto cleanup;
    }
    BN_CTX_start(bn_ctx);
    
    bn_exp = BN_CTX_get(bn_ctx);
    if (!bn_exp || !BN_bin2bn(*exp, sizeof(elliptic_curve256_scalar_t), bn_exp))
    {
        status = ELLIPTIC_CURVE_ALGEBRA_OUT_OF_MEMORY;
        goto cleanup;
    }

    if (!EC_POINT_oct2point(ctx->curve, p_p, *p, SIZEOF_POINT(*p), bn_ctx))
    {
        status = from_openssl_error(ERR_get_error());
        goto cleanup;
    }

    if (!EC_POINT_mul(ctx->curve, p_p, NULL, p_p, bn_exp, bn_ctx))
        goto cleanup;
    
    memset(*res, 0, sizeof(elliptic_curve256_point_t));
    if (EC_POINT_point2oct(ctx->curve, p_p, POINT_CONVERSION_COMPRESSED, *res, sizeof(elliptic_curve256_point_t), bn_ctx) > 0)
        status = ELLIPTIC_CURVE_ALGEBRA_SUCCESS;
    
cleanup:
    if (bn_exp)
        BN_clear(bn_exp);
    BN_CTX_end(bn_ctx);
    BN_CTX_free(bn_ctx);
    EC_POINT_free(p_p);
    return status;
}

elliptic_curve_algebra_status GFp_curve_algebra_get_point_projection(const GFp_curve_algebra_ctx_t *ctx, elliptic_curve256_scalar_t *res, const elliptic_curve256_point_t *p, uint8_t* overflow)
{
    BN_CTX *bn_ctx = NULL;
    EC_POINT *p_p = NULL;
    BIGNUM *X = NULL;
    int cmp;
    elliptic_curve_algebra_status status = ELLIPTIC_CURVE_ALGEBRA_UNKNOWN_ERROR;

    if (!ctx || !res || !p)
        return ELLIPTIC_CURVE_ALGEBRA_INVALID_PARAMETER;
    
    memset(*res, 0, sizeof(elliptic_curve256_scalar_t));
    p_p = EC_POINT_new(ctx->curve);
    if (!p_p)
        return ELLIPTIC_CURVE_ALGEBRA_OUT_OF_MEMORY;

    bn_ctx = BN_CTX_new();
    if (!bn_ctx)
    {
        status = ELLIPTIC_CURVE_ALGEBRA_OUT_OF_MEMORY;
        goto cleanup;
    }

    BN_CTX_start(bn_ctx);
    
    X = BN_CTX_get(bn_ctx);
    if (!X)
    {
        status = ELLIPTIC_CURVE_ALGEBRA_OUT_OF_MEMORY;
        goto cleanup;
    }

    if (!EC_POINT_oct2point(ctx->curve, p_p, *p, SIZEOF_POINT(*p), bn_ctx))
    {
        status = from_openssl_error(ERR_get_error());
        goto cleanup;
    }

    if (!EC_POINT_get_affine_coordinates_GFp(ctx->curve, p_p, X, NULL, bn_ctx))
        goto cleanup;
    
    cmp = BN_cmp(X, EC_GROUP_get0_order(ctx->curve));
    if (overflow)
        *overflow = cmp >= 0;

    // This code works because in all supported curves curve.p - curve.q < curve.q, so X - curve.q == X % curve.q
    // See https://en.wikipedia.org/wiki/Hasse%27s_theorem_on_elliptic_curves
    if (cmp >= 0 && !BN_sub(X, X, EC_GROUP_get0_order(ctx->curve)))
        goto cleanup;
    
    status = BN_bn2binpad(X, *res, sizeof(elliptic_curve256_scalar_t)) > 0 ? ELLIPTIC_CURVE_ALGEBRA_SUCCESS : ELLIPTIC_CURVE_ALGEBRA_UNKNOWN_ERROR;
    
cleanup:
    BN_CTX_end(bn_ctx);
    BN_CTX_free(bn_ctx);
    EC_POINT_free(p_p);
    return status;
}

elliptic_curve_algebra_status GFp_curve_algebra_add_scalars(GFp_curve_algebra_ctx_t *ctx, elliptic_curve256_scalar_t *res, const uint8_t *a, uint32_t a_len, const uint8_t *b, uint32_t b_len)
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
    
    if (BN_mod_add(bn_a, bn_a, bn_b, EC_GROUP_get0_order(ctx->curve), bn_ctx))
    {
        ret = BN_bn2binpad(bn_a, *res, sizeof(elliptic_curve256_scalar_t)) > 0 ? ELLIPTIC_CURVE_ALGEBRA_SUCCESS : ELLIPTIC_CURVE_ALGEBRA_UNKNOWN_ERROR;
    }
    else
        ret = ELLIPTIC_CURVE_ALGEBRA_UNKNOWN_ERROR;
    
cleanup:
    if (bn_a)
        BN_clear(bn_a);
    if (bn_b)
        BN_clear(bn_b);
    BN_CTX_end(bn_ctx);
    BN_CTX_free(bn_ctx);
    return ret;
}

elliptic_curve_algebra_status GFp_curve_algebra_sub_scalars(GFp_curve_algebra_ctx_t *ctx, elliptic_curve256_scalar_t *res, const uint8_t *a, uint32_t a_len, const uint8_t *b, uint32_t b_len)
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

    if (BN_mod_sub(bn_a, bn_a, bn_b, EC_GROUP_get0_order(ctx->curve), bn_ctx))
    {
        ret = BN_bn2binpad(bn_a, *res, sizeof(elliptic_curve256_scalar_t)) > 0 ? ELLIPTIC_CURVE_ALGEBRA_SUCCESS : ELLIPTIC_CURVE_ALGEBRA_UNKNOWN_ERROR;
    }
    else
        ret = ELLIPTIC_CURVE_ALGEBRA_UNKNOWN_ERROR;
    
cleanup:
    if (bn_a)
        BN_clear(bn_a);
    if (bn_b)
        BN_clear(bn_b);
    BN_CTX_end(bn_ctx);
    BN_CTX_free(bn_ctx);
    return ret;
}

elliptic_curve_algebra_status GFp_curve_algebra_mul_scalars(GFp_curve_algebra_ctx_t *ctx, elliptic_curve256_scalar_t *res, const uint8_t *a, uint32_t a_len, const uint8_t *b, uint32_t b_len)
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

    if (BN_mod_mul(bn_a, bn_a, bn_b, EC_GROUP_get0_order(ctx->curve), bn_ctx))
    {
        ret = BN_bn2binpad(bn_a, *res, sizeof(elliptic_curve256_scalar_t)) > 0 ? ELLIPTIC_CURVE_ALGEBRA_SUCCESS : ELLIPTIC_CURVE_ALGEBRA_UNKNOWN_ERROR;
    }
    else
        ret = ELLIPTIC_CURVE_ALGEBRA_UNKNOWN_ERROR;

cleanup:
    if (bn_a)
        BN_clear(bn_a);
    if (bn_b)
        BN_clear(bn_b);
    BN_CTX_end(bn_ctx);
    BN_CTX_free(bn_ctx);
    return ret;
}

elliptic_curve_algebra_status GFp_curve_algebra_inverse(GFp_curve_algebra_ctx_t *ctx, elliptic_curve256_scalar_t *res, const elliptic_curve256_scalar_t *val)
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
    if (!bn_val || !BN_bin2bn(*val, sizeof(elliptic_curve256_scalar_t), bn_val))
        goto cleanup;
    
    BN_set_flags(bn_val, BN_FLG_CONSTTIME);
    
    if (BN_mod_inverse(bn_val, bn_val, EC_GROUP_get0_order(ctx->curve), bn_ctx))
    {
        ret = BN_bn2binpad(bn_val, *res, sizeof(elliptic_curve256_scalar_t)) > 0 ? ELLIPTIC_CURVE_ALGEBRA_SUCCESS : ELLIPTIC_CURVE_ALGEBRA_UNKNOWN_ERROR;
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

elliptic_curve_algebra_status GFp_curve_algebra_abs(GFp_curve_algebra_ctx_t *ctx, elliptic_curve256_scalar_t *res, const elliptic_curve256_scalar_t *val)
{
    BIGNUM *bn_val = NULL;
    BIGNUM *bn_neg_val = NULL;
    BIGNUM *tmp = NULL;
    const BIGNUM *field = NULL;
    elliptic_curve_algebra_status ret = ELLIPTIC_CURVE_ALGEBRA_OUT_OF_MEMORY;

    if (!ctx || !res || !val)
        return ELLIPTIC_CURVE_ALGEBRA_INVALID_PARAMETER;
    
    field = EC_GROUP_get0_order(ctx->curve);

    bn_val = BN_new();
    if (!bn_val || !BN_bin2bn(*val, sizeof(elliptic_curve256_scalar_t), bn_val))
        goto cleanup;
    tmp = BN_new();
    if (!tmp || !BN_rshift1(tmp, field))
        goto cleanup;
    bn_neg_val = BN_new();
    if (!bn_neg_val)
        goto cleanup;

    // The sub operation is always done, so that the function will run in constant time
    if (!BN_sub(bn_neg_val, field, bn_val))
    {
        ret = ELLIPTIC_CURVE_ALGEBRA_UNKNOWN_ERROR;
        goto cleanup;
    }

    if (BN_cmp(bn_val, tmp) > 0 && !BN_is_negative(bn_neg_val))
        ret = BN_bn2binpad(bn_neg_val, *res, sizeof(elliptic_curve256_scalar_t)) > 0 ? ELLIPTIC_CURVE_ALGEBRA_SUCCESS : ELLIPTIC_CURVE_ALGEBRA_UNKNOWN_ERROR;
    else
        ret = BN_bn2binpad(bn_val, *res, sizeof(elliptic_curve256_scalar_t)) > 0 ? ELLIPTIC_CURVE_ALGEBRA_SUCCESS : ELLIPTIC_CURVE_ALGEBRA_UNKNOWN_ERROR;

cleanup:
    if (bn_val)
        BN_clear_free(bn_val);
    if (bn_neg_val)
        BN_clear_free(bn_neg_val);
    if (tmp)
        BN_free(tmp);
    return ret;
}

elliptic_curve_algebra_status GFp_curve_algebra_rand(GFp_curve_algebra_ctx_t *ctx, elliptic_curve256_scalar_t *res)
{
    BIGNUM *tmp = NULL;
    elliptic_curve_algebra_status ret = ELLIPTIC_CURVE_ALGEBRA_OUT_OF_MEMORY;

    if (!ctx || !res)
        return ELLIPTIC_CURVE_ALGEBRA_INVALID_PARAMETER;
    
    tmp = BN_new();
    if (!tmp)
        goto cleanup;
    if (!BN_rand_range(tmp, EC_GROUP_get0_order(ctx->curve)))
    {
        ret = ELLIPTIC_CURVE_ALGEBRA_UNKNOWN_ERROR;
        goto cleanup;
    }

    ret = BN_bn2binpad(tmp, *res, sizeof(elliptic_curve256_scalar_t)) > 0 ? ELLIPTIC_CURVE_ALGEBRA_SUCCESS : ELLIPTIC_CURVE_ALGEBRA_UNKNOWN_ERROR;

cleanup:
    BN_clear_free(tmp);
    return ret;
}

elliptic_curve_algebra_status GFp_curve_algebra_verify_signature(const GFp_curve_algebra_ctx_t *ctx, const elliptic_curve256_point_t *public_key, const elliptic_curve256_scalar_t *message, 
    const elliptic_curve256_scalar_t *sig_r, const elliptic_curve256_scalar_t *sig_s)
{
    elliptic_curve_algebra_status ret = ELLIPTIC_CURVE_ALGEBRA_OUT_OF_MEMORY;
    BN_CTX *bn_ctx = NULL;
    const BIGNUM *order;
    BIGNUM *r = NULL, *s = NULL, *u1 = NULL, *u2 = NULL, *m = NULL;
    EC_POINT *pubkey = NULL, *point = NULL;
    int cmp;

    if (!ctx || !public_key || !message || !sig_r || !sig_s)
        return ELLIPTIC_CURVE_ALGEBRA_INVALID_PARAMETER;

    order = EC_GROUP_get0_order(ctx->curve);

    bn_ctx = BN_CTX_new();
    if (!bn_ctx)
        return ELLIPTIC_CURVE_ALGEBRA_OUT_OF_MEMORY;
    BN_CTX_start(bn_ctx);

    r = BN_CTX_get(bn_ctx);
    s = BN_CTX_get(bn_ctx);
    u1 = BN_CTX_get(bn_ctx);
    u2 = BN_CTX_get(bn_ctx);
    m = BN_CTX_get(bn_ctx);
    if (!r || !s || !u1 || !u2 || !m)
        goto cleanup;

    if (!BN_bin2bn(*sig_r, sizeof(elliptic_curve256_scalar_t), r) || !BN_bin2bn(*sig_s, sizeof(elliptic_curve256_scalar_t), s) || !BN_bin2bn(*message, sizeof(elliptic_curve256_scalar_t), m))
        goto cleanup;

    if (BN_is_zero(r) || BN_ucmp(r, order) >= 0 || BN_is_zero(s) || BN_ucmp(s, order) >= 0)
    {
        ret = ELLIPTIC_CURVE_ALGEBRA_INVALID_SIGNATURE;
        goto cleanup;
    }

    pubkey = EC_POINT_new(ctx->curve);
    point = EC_POINT_new(ctx->curve);
    if (!pubkey || !point)
        goto cleanup;
    if (!EC_POINT_oct2point(ctx->curve, pubkey, *public_key, sizeof(elliptic_curve256_point_t), NULL))
    {
        ret = ELLIPTIC_CURVE_ALGEBRA_INVALID_POINT;
        goto cleanup;
    }

    ret = ELLIPTIC_CURVE_ALGEBRA_UNKNOWN_ERROR;

    if (!BN_mod_inverse(u2, s, order, bn_ctx))
        goto cleanup;

    /* u1 = m * s_inv mod order */
    if (!BN_mod_mul(u1, m, u2, order, bn_ctx))
        goto cleanup;
    
    /* u2 = r * s_inv mod order */
    if (!BN_mod_mul(u2, r, u2, order, bn_ctx))
        goto cleanup;
    
    if (!EC_POINT_mul(ctx->curve, point, u1, pubkey, u2, bn_ctx))
        goto cleanup;
    
    if (!EC_POINT_get_affine_coordinates(ctx->curve, point, u1, NULL, bn_ctx))
        goto cleanup;

    cmp = BN_cmp(u1, order);

    if (cmp >= 0 && !BN_usub(u1, order, u1))
        goto cleanup;
    
    /*  if the signature is correct u1 is equal to sig_r */
    cmp = BN_ucmp(u1, r);
    
    // verify that s is positive
    if (!BN_lshift1(s, s))
        goto cleanup;

    ret = (cmp == 0 && BN_ucmp(s, order) < 0) ? ELLIPTIC_CURVE_ALGEBRA_SUCCESS : ELLIPTIC_CURVE_ALGEBRA_INVALID_SIGNATURE;

cleanup:
    EC_POINT_free(pubkey);
    EC_POINT_free(point);
    BN_CTX_end(bn_ctx);
    BN_CTX_free(bn_ctx);
    return ret;
}

static int release(elliptic_curve256_algebra_ctx_t *ctx)
{
    if (ctx)
    {
        if (ctx->type != ELLIPTIC_CURVE_SECP256K1 && ctx->type != ELLIPTIC_CURVE_SECP256R1 && ctx->type != ELLIPTIC_CURVE_STARK)
            return 0;
        GFp_curve_algebra_ctx_free((GFp_curve_algebra_ctx_t*)ctx->ctx);
        free(ctx);
    }
    return 1;
}

static uint8_t point_size(const elliptic_curve256_algebra_ctx_t *ctx)
{
    (void)(ctx);
    return ELLIPTIC_CURVE_COMPRESSED_POINT_LEN;
}

static const elliptic_curve256_point_t *infinity_point(const struct elliptic_curve256_algebra_ctx *ctx)
{
    (void)(ctx);
    static const elliptic_curve256_point_t INFINITY = {0};
    return &INFINITY;
}

static const uint8_t *secp256k1_order(const elliptic_curve256_algebra_ctx_t *ctx)
{
    (void)(ctx);
    return SECP256K1_FIELD;
}

static const uint8_t *secp256r1_order(const elliptic_curve256_algebra_ctx_t *ctx)
{
    (void)(ctx);
    return SECP256R1_FIELD;
}

static const uint8_t *stark_order(const elliptic_curve256_algebra_ctx_t *ctx)
{
    (void)(ctx);
    return STARK_FIELD;
}

static elliptic_curve_algebra_status generate_proof_for_data(const elliptic_curve256_algebra_ctx_t *ctx, const uint8_t *data, uint32_t data_len, elliptic_curve256_point_t *proof)
{
    if (!ctx || (ctx->type != ELLIPTIC_CURVE_SECP256K1 && ctx->type != ELLIPTIC_CURVE_SECP256R1 && ctx->type != ELLIPTIC_CURVE_STARK))
        return ELLIPTIC_CURVE_ALGEBRA_INVALID_PARAMETER;
    return GFp_curve_algebra_generator_mul_data(ctx->ctx, data, data_len, proof);
}

static elliptic_curve_algebra_status verify(const elliptic_curve256_algebra_ctx_t *ctx, const uint8_t *data, uint32_t data_len, const elliptic_curve256_point_t *proof, uint8_t *result)
{
    if (!ctx || (ctx->type != ELLIPTIC_CURVE_SECP256K1 && ctx->type != ELLIPTIC_CURVE_SECP256R1 && ctx->type != ELLIPTIC_CURVE_STARK))
        return ELLIPTIC_CURVE_ALGEBRA_INVALID_PARAMETER;
    return GFp_curve_algebra_verify(ctx->ctx, data, data_len, proof, result);
}

static elliptic_curve_algebra_status verify_linear_combination(const elliptic_curve256_algebra_ctx_t *ctx, const elliptic_curve256_point_t *proof, const elliptic_curve256_point_t *proof_points, 
    const elliptic_curve256_scalar_t *coefficients, uint32_t points_count, uint8_t *result)
{
    if (!ctx || (ctx->type != ELLIPTIC_CURVE_SECP256K1 && ctx->type != ELLIPTIC_CURVE_SECP256R1 && ctx->type != ELLIPTIC_CURVE_STARK))
        return ELLIPTIC_CURVE_ALGEBRA_INVALID_PARAMETER;
    return GFp_curve_algebra_verify_linear_combination(ctx->ctx, proof, proof_points, coefficients, points_count, result);
}

static elliptic_curve_algebra_status generator_mul(const elliptic_curve256_algebra_ctx_t *ctx, elliptic_curve256_point_t *res, const elliptic_curve256_scalar_t *exp)
{
    if (!ctx || (ctx->type != ELLIPTIC_CURVE_SECP256K1 && ctx->type != ELLIPTIC_CURVE_SECP256R1 && ctx->type != ELLIPTIC_CURVE_STARK))
        return ELLIPTIC_CURVE_ALGEBRA_INVALID_PARAMETER;

    return GFp_curve_algebra_generator_mul(ctx->ctx, res, exp);
}

static elliptic_curve_algebra_status add_points(const elliptic_curve256_algebra_ctx_t *ctx, elliptic_curve256_point_t *res, const elliptic_curve256_point_t *p1, const elliptic_curve256_point_t *p2)
{
    if (!ctx || (ctx->type != ELLIPTIC_CURVE_SECP256K1 && ctx->type != ELLIPTIC_CURVE_SECP256R1 && ctx->type != ELLIPTIC_CURVE_STARK))
        return ELLIPTIC_CURVE_ALGEBRA_INVALID_PARAMETER;

    return GFp_curve_algebra_add_points(ctx->ctx, res, p1, p2);
}

static elliptic_curve_algebra_status point_mul(const elliptic_curve256_algebra_ctx_t *ctx, elliptic_curve256_point_t *res, const elliptic_curve256_point_t *p, const elliptic_curve256_scalar_t *exp)
{
    if (!ctx || (ctx->type != ELLIPTIC_CURVE_SECP256K1 && ctx->type != ELLIPTIC_CURVE_SECP256R1 && ctx->type != ELLIPTIC_CURVE_STARK))
        return ELLIPTIC_CURVE_ALGEBRA_INVALID_PARAMETER;
    return GFp_curve_algebra_point_mul(ctx->ctx, res, p, exp);
}

static elliptic_curve_algebra_status add_scalars(const struct elliptic_curve256_algebra_ctx *ctx, elliptic_curve256_scalar_t *res, const uint8_t *a, uint32_t a_len, const uint8_t *b, uint32_t b_len)
{
    if (!ctx || (ctx->type != ELLIPTIC_CURVE_SECP256K1 && ctx->type != ELLIPTIC_CURVE_SECP256R1 && ctx->type != ELLIPTIC_CURVE_STARK))
        return ELLIPTIC_CURVE_ALGEBRA_INVALID_PARAMETER;
    return GFp_curve_algebra_add_scalars(ctx->ctx, res, a, a_len, b, b_len);
}

static elliptic_curve_algebra_status sub_scalars(const struct elliptic_curve256_algebra_ctx *ctx, elliptic_curve256_scalar_t *res, const uint8_t *a, uint32_t a_len, const uint8_t *b, uint32_t b_len)
{
    if (!ctx || (ctx->type != ELLIPTIC_CURVE_SECP256K1 && ctx->type != ELLIPTIC_CURVE_SECP256R1 && ctx->type != ELLIPTIC_CURVE_STARK))
        return ELLIPTIC_CURVE_ALGEBRA_INVALID_PARAMETER;
    return GFp_curve_algebra_sub_scalars(ctx->ctx, res, a, a_len, b, b_len);
}

static elliptic_curve_algebra_status mul_scalars(const struct elliptic_curve256_algebra_ctx *ctx, elliptic_curve256_scalar_t *res, const uint8_t *a, uint32_t a_len, const uint8_t *b, uint32_t b_len)
{
    if (!ctx || (ctx->type != ELLIPTIC_CURVE_SECP256K1 && ctx->type != ELLIPTIC_CURVE_SECP256R1 && ctx->type != ELLIPTIC_CURVE_STARK))
        return ELLIPTIC_CURVE_ALGEBRA_INVALID_PARAMETER;
    return GFp_curve_algebra_mul_scalars(ctx->ctx, res, a, a_len, b, b_len);
}

static elliptic_curve_algebra_status inverse(const struct elliptic_curve256_algebra_ctx *ctx, elliptic_curve256_scalar_t *res, const elliptic_curve256_scalar_t *val)
{
    if (!ctx || (ctx->type != ELLIPTIC_CURVE_SECP256K1 && ctx->type != ELLIPTIC_CURVE_SECP256R1 && ctx->type != ELLIPTIC_CURVE_STARK))
        return ELLIPTIC_CURVE_ALGEBRA_INVALID_PARAMETER;
    return GFp_curve_algebra_inverse(ctx->ctx, res, val);
}

static elliptic_curve_algebra_status ec_rand(const struct elliptic_curve256_algebra_ctx *ctx, elliptic_curve256_scalar_t *res)
{
    if (!ctx || (ctx->type != ELLIPTIC_CURVE_SECP256K1 && ctx->type != ELLIPTIC_CURVE_SECP256R1 && ctx->type != ELLIPTIC_CURVE_STARK))
        return ELLIPTIC_CURVE_ALGEBRA_INVALID_PARAMETER;
    return GFp_curve_algebra_rand(ctx->ctx, res);
}

static const struct bignum_st *order_internal(const elliptic_curve256_algebra_ctx_t *ctx)
{
    if (ctx && (ctx->type == ELLIPTIC_CURVE_SECP256K1 || ctx->type == ELLIPTIC_CURVE_SECP256R1 || ctx->type == ELLIPTIC_CURVE_STARK))
    {
        GFp_curve_algebra_ctx_t *ctx_ = (GFp_curve_algebra_ctx_t*)ctx->ctx;
        return EC_GROUP_get0_order(ctx_->curve);
    }
    return NULL;
}

static uint8_t in_field(const elliptic_curve256_scalar_t val, const uint8_t *field)
{
    uint64_t cc = 0;
    const uint32_t *ptr1 = (const uint32_t*)val;
    const uint32_t *ptr2 = (const uint32_t*)field;
    for (size_t i = sizeof(elliptic_curve256_scalar_t) / sizeof(uint32_t); i > 0; i --)
    {
        uint64_t v1 = bswap_32(ptr1[i - 1]);
        uint64_t v2 = bswap_32(ptr2[i - 1]);
        cc = ((v1 - v2 - cc) >> 32) & 1;
    }
    return cc;
}

static elliptic_curve_algebra_status ec_reduce(const struct elliptic_curve256_algebra_ctx *ctx, elliptic_curve256_scalar_t *res, const elliptic_curve256_scalar_t *val)
{
    if (!ctx || !res || !val || (ctx->type != ELLIPTIC_CURVE_SECP256K1 && ctx->type != ELLIPTIC_CURVE_SECP256R1))
        return ELLIPTIC_CURVE_ALGEBRA_INVALID_PARAMETER;
    if (!in_field(*val, ctx->type == ELLIPTIC_CURVE_SECP256K1 ? SECP256K1_FIELD : SECP256R1_FIELD))
        return ELLIPTIC_CURVE_ALGEBRA_INVALID_SCALAR;
    if (res != val)
        memcpy(*res, *val, sizeof(elliptic_curve256_scalar_t));
    return ELLIPTIC_CURVE_ALGEBRA_SUCCESS;
}

static elliptic_curve_algebra_status ec_reduce_stark(const struct elliptic_curve256_algebra_ctx *ctx, elliptic_curve256_scalar_t *res, const elliptic_curve256_scalar_t *val)
{
    elliptic_curve_algebra_status ret;
    elliptic_curve256_scalar_t tmp;
    if (!ctx || !res || !val || ctx->type != ELLIPTIC_CURVE_STARK)
        return ELLIPTIC_CURVE_ALGEBRA_INVALID_PARAMETER;
    memcpy(tmp, *val, sizeof(elliptic_curve256_scalar_t));
    tmp[0] &= 0x0f; // stack curve order is 252 bit
    if (in_field(tmp, STARK_FIELD))
    {
        memcpy(*res, tmp, sizeof(elliptic_curve256_scalar_t));
        ret = ELLIPTIC_CURVE_ALGEBRA_SUCCESS;
    }
    else
        ret = ELLIPTIC_CURVE_ALGEBRA_INVALID_SCALAR;
    OPENSSL_cleanse(tmp, sizeof(elliptic_curve256_scalar_t));
    return ret;
}

elliptic_curve256_algebra_ctx_t* elliptic_curve256_new_secp256k1_algebra()
{
    elliptic_curve256_algebra_ctx_t *ctx = malloc(sizeof(elliptic_curve256_algebra_ctx_t));
    if (!ctx)
        return ctx;

    ctx->ctx = secp256k1_algebra_ctx_new();
    ctx->type = ELLIPTIC_CURVE_SECP256K1;
    ctx->release = release;
    ctx->order = secp256k1_order;
    ctx->point_size = point_size;
    ctx->infinity_point = infinity_point;
    ctx->generator_mul_data = generate_proof_for_data;
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
    ctx->reduce = ec_reduce;
    ctx->order_internal = order_internal;
    return ctx;
}

elliptic_curve256_algebra_ctx_t* elliptic_curve256_new_secp256r1_algebra()
{
    elliptic_curve256_algebra_ctx_t *ctx = malloc(sizeof(elliptic_curve256_algebra_ctx_t));
    if (!ctx)
        return ctx;

    ctx->ctx = secp256r1_algebra_ctx_new();
    ctx->type = ELLIPTIC_CURVE_SECP256R1;
    ctx->release = release;
    ctx->order = secp256r1_order;
    ctx->point_size = point_size;
    ctx->infinity_point = infinity_point;
    ctx->generator_mul_data = generate_proof_for_data;
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
    ctx->reduce = ec_reduce;
    ctx->order_internal = order_internal;
    return ctx;
}

elliptic_curve256_algebra_ctx_t* elliptic_curve256_new_stark_algebra()
{
    elliptic_curve256_algebra_ctx_t *ctx = malloc(sizeof(elliptic_curve256_algebra_ctx_t));
    if (!ctx)
        return ctx;

    ctx->ctx = stark_algebra_ctx_new();
    ctx->type = ELLIPTIC_CURVE_STARK;
    ctx->release = release;
    ctx->order = stark_order;
    ctx->point_size = point_size;
    ctx->infinity_point = infinity_point;
    ctx->generator_mul_data = generate_proof_for_data;
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
    ctx->reduce = ec_reduce_stark;
    ctx->order_internal = order_internal;
    return ctx;
}
