#include "crypto/shamir_secret_sharing/verifiable_secret_sharing.h"

#include <string.h>
#include <assert.h>

#include <openssl/bn.h>

struct verifiable_secret_sharing 
{
    const elliptic_curve256_algebra_ctx_t *algebra;
    uint64_t *ids;
    shamir_secret_sharing_scalar_t *shares;
    elliptic_curve256_point_t *proofs;
    elliptic_curve256_point_t *coefficient_proofs;
    uint8_t num_shares;
    uint8_t threshold;
};

static verifiable_secret_sharing_status from_commitments_status(commitments_status status)
{
    switch (status)
    {
        case COMMITMENTS_SUCCESS: return VERIFIABLE_SECRET_SHARING_SUCCESS;
        case COMMITMENTS_INTERNAL_ERROR: return VERIFIABLE_SECRET_SHARING_UNKNOWN_ERROR;
        case COMMITMENTS_INVALID_PARAMETER: return VERIFIABLE_SECRET_SHARING_INVALID_PARAMETER;
        case COMMITMENTS_INVALID_CONTEXT: return VERIFIABLE_SECRET_SHARING_INVALID_PARAMETER;
        case COMMITMENTS_OUT_OF_MEMORY: return VERIFIABLE_SECRET_SHARING_OUT_OF_MEMORY;
        case COMMITMENTS_INVALID_COMMITMENT: return VERIFIABLE_SECRET_SHARING_INVALID_SHARE;
        default: return VERIFIABLE_SECRET_SHARING_UNKNOWN_ERROR;
    }
}

static verifiable_secret_sharing_status create_shares(const elliptic_curve256_algebra_ctx_t *algebra, const BIGNUM *secret, uint8_t t, uint8_t n, const BIGNUM **mat, verifiable_secret_sharing_t *shares, BN_CTX *ctx, const BIGNUM *prime)
{
    verifiable_secret_sharing_status ret = VERIFIABLE_SECRET_SHARING_OUT_OF_MEMORY;
    elliptic_curve256_scalar_t coefficient;
    BIGNUM *tmp = NULL;
    BIGNUM *share = NULL;
    BIGNUM **polynom = (BIGNUM**)calloc(t, sizeof(BIGNUM*));
    
    if (!polynom)
        return VERIFIABLE_SECRET_SHARING_OUT_OF_MEMORY;
    polynom[0] = (BIGNUM*)secret;

    BN_CTX_start(ctx);

    // define the polynom
    for (size_t i = 1; i < t; ++i)
    {
        polynom[i] = BN_CTX_get(ctx);

        if (!polynom[i])
            goto cleanup;
        
        do
        {
            if (!BN_rand_range(polynom[i], prime))
                goto cleanup;
        } while (BN_is_zero(polynom[i])); // generating random zero is most likely a bug in the RNG (RDRAND instruction) so we ignore this value
    }

    shares->algebra = algebra;
    shares->num_shares = n;
    shares->threshold = t;
    shares->shares = calloc(n, sizeof(shamir_secret_sharing_scalar_t));
    if (!shares->shares)
        goto cleanup;
    shares->proofs = calloc(n, sizeof(elliptic_curve256_point_t));
    if (!shares->proofs)
        goto cleanup;
    shares->coefficient_proofs = calloc(t, sizeof(elliptic_curve256_point_t));
    if (!shares->coefficient_proofs)
        goto cleanup;
    
    for (size_t i = 0; i < t; ++i)
    {
        elliptic_curve_algebra_status status;
        if (BN_bn2binpad(polynom[i], coefficient, sizeof(elliptic_curve256_scalar_t)) <= 0)
            goto cleanup;
        status = shares->algebra->generator_mul(shares->algebra, &shares->coefficient_proofs[i], &coefficient);
        if (status != ELLIPTIC_CURVE_ALGEBRA_SUCCESS)
        {
            ret = (status == ELLIPTIC_CURVE_ALGEBRA_OUT_OF_MEMORY) ? VERIFIABLE_SECRET_SHARING_OUT_OF_MEMORY : VERIFIABLE_SECRET_SHARING_UNKNOWN_ERROR;
            goto cleanup;
        }
    }
    OPENSSL_cleanse(coefficient, sizeof(elliptic_curve256_scalar_t));
    
    tmp = BN_CTX_get(ctx);
    if (!tmp)
        goto cleanup;

    share = BN_CTX_get(ctx);
    if (!share)
        goto cleanup;


    // multiply the access matrix and the coefficient vector to get the sharws
    for (size_t i = 0; i < n; ++i)
    {
        elliptic_curve_algebra_status status;
        
        if (!share)
            goto cleanup;
        BN_zero_ex(share);

        for (size_t j = 0; j < t; j++)
        {
            if (!BN_mod_mul(tmp, mat[i * t + j], polynom[j], prime, ctx))
                goto cleanup;
            if (!BN_mod_add_quick(share, share, tmp, prime))
                goto cleanup;
        }
        if (BN_bn2binpad(share, shares->shares[i], sizeof(shamir_secret_sharing_scalar_t)) <= 0)
            goto cleanup;
        status = shares->algebra->generator_mul(shares->algebra, &shares->proofs[i], &shares->shares[i]);
        if (status != ELLIPTIC_CURVE_ALGEBRA_SUCCESS)
        {
            ret = (status == ELLIPTIC_CURVE_ALGEBRA_OUT_OF_MEMORY) ? VERIFIABLE_SECRET_SHARING_OUT_OF_MEMORY : VERIFIABLE_SECRET_SHARING_UNKNOWN_ERROR;
            goto cleanup;
        }
    }
    ret = VERIFIABLE_SECRET_SHARING_SUCCESS;

cleanup:
    BN_CTX_end(ctx);
    free(polynom);
    return ret;
}

static verifiable_secret_sharing_status verifiable_secret_sharing_split_impl(const elliptic_curve256_algebra_ctx_t *algebra, const uint8_t *secret, uint32_t secret_len, uint8_t t, uint8_t n, BIGNUM **access_mat, 
    verifiable_secret_sharing_t **shares, uint64_t *ids, BN_CTX *ctx)
{
    BIGNUM *bn_secret = NULL;
    BIGNUM *bn_prime = NULL;
    verifiable_secret_sharing_status ret = VERIFIABLE_SECRET_SHARING_OUT_OF_MEMORY;
    verifiable_secret_sharing_t *shares_local = NULL;

    shares_local = (verifiable_secret_sharing_t*)calloc(1, sizeof(verifiable_secret_sharing_t));
    if (!shares_local)
        return VERIFIABLE_SECRET_SHARING_OUT_OF_MEMORY;
    BN_CTX_start(ctx);
    if (!(bn_secret = BN_bin2bn(secret, secret_len, NULL)))
        goto cleanup;
    if (!(bn_prime = BN_bin2bn(algebra->order(algebra), ELLIPTIC_CURVE_FIELD_SIZE, NULL)))
        goto cleanup;
    
    assert(BN_is_prime_ex(bn_prime, 1000, ctx, NULL));
    BN_set_flags(bn_prime, BN_FLG_CONSTTIME);

    if (BN_cmp(bn_secret, bn_prime) >= 0)
    {
        ret = VERIFIABLE_SECRET_SHARING_INVALID_SECRET;
        goto cleanup;
    }

    for (size_t i = 0; i < t*n; ++i)
        BN_mod(access_mat[i], access_mat[i], bn_prime, ctx);
    
    shares_local->ids = ids;
    
    if (create_shares(algebra, bn_secret, t, n, (const BIGNUM**)access_mat, shares_local, ctx, bn_prime) == 0)
    {
        *shares = shares_local;
        ret = VERIFIABLE_SECRET_SHARING_SUCCESS;
    }
    else
    {
        // NULL shares_local->ids so it want be freed by verifiable_secret_sharing_free_shares, as we didn't take ownership over it
        shares_local->ids = NULL;
    }

cleanup:
    if (bn_prime)
        BN_free(bn_prime);
    if (bn_secret)
        BN_clear_free(bn_secret);
    BN_CTX_end(ctx);
    if (ret != VERIFIABLE_SECRET_SHARING_SUCCESS)
        verifiable_secret_sharing_free_shares(shares_local);

    return ret;
}

verifiable_secret_sharing_status verifiable_secret_sharing_split(const elliptic_curve256_algebra_ctx_t *algebra, const uint8_t *secret, uint32_t secret_len, uint8_t t, uint8_t n, verifiable_secret_sharing_t **shares)
{
    BN_CTX *ctx = NULL;
    BIGNUM **mat = NULL;
    BIGNUM *one = NULL;
    uint64_t *ids = NULL;
    verifiable_secret_sharing_status ret = VERIFIABLE_SECRET_SHARING_OUT_OF_MEMORY;
    
    if (!algebra || !secret || !secret_len || !shares || t < 1 || t > n)
        return VERIFIABLE_SECRET_SHARING_INVALID_PARAMETER;
    ctx = BN_CTX_new();
    if (!ctx)
    {
        return VERIFIABLE_SECRET_SHARING_OUT_OF_MEMORY;
    }
    BN_CTX_start(ctx);
    
    mat = (BIGNUM**)calloc(n * t, sizeof(BIGNUM*));
    if (!mat)
        goto cleanup;   
    one = BN_CTX_get(ctx);
    if (!one)
        goto cleanup;
    BN_one(one);

    ids = (uint64_t*)calloc(n, sizeof(uint64_t));
    if (!ids)
        goto cleanup;
    ids[0] = 1;

    // init first row to one
    for (size_t i = 0; i < t; ++i)
        mat[i] = one;

    for (size_t i = 1; i < n; ++i)
    {
        BIGNUM *prev = one;
        ids[i] = i + 1;

        // init first cal to one
        mat[i * t] = one;
        for (size_t j = 1; j < t; ++j)
        {
            BIGNUM *cur = BN_CTX_get(ctx);
            if (!cur)
                goto cleanup;
            if (!BN_copy(cur, prev))
                goto cleanup;
            if (!BN_mul_word(cur, i + 1))
                goto cleanup;
            mat[i * t + j] = cur;
            prev = cur;
        }
    }
    ret = verifiable_secret_sharing_split_impl(algebra, secret, secret_len, t, n, mat, shares, ids, ctx);

cleanup:
    if (ctx)
    {
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
    }
    if (mat)
        free(mat);
    if (ret != VERIFIABLE_SECRET_SHARING_SUCCESS)
        free(ids);
    return ret;
}

verifiable_secret_sharing_status verifiable_secret_sharing_split_with_custom_ids(const elliptic_curve256_algebra_ctx_t *algebra, const uint8_t *secret, uint32_t secret_len, uint8_t t, uint8_t n, uint64_t *ids, 
    verifiable_secret_sharing_t **shares)
{
    BN_CTX *ctx = NULL;
    BIGNUM **mat = NULL;
    BIGNUM *one = NULL;
    uint64_t *local_ids = NULL;
    verifiable_secret_sharing_status ret = VERIFIABLE_SECRET_SHARING_OUT_OF_MEMORY;
    
    if (!algebra || !secret || !secret_len || !shares || t < 1 || t > n || !ids)
        return VERIFIABLE_SECRET_SHARING_INVALID_PARAMETER;

    ctx = BN_CTX_new();
    if (!ctx)
    {
        return VERIFIABLE_SECRET_SHARING_OUT_OF_MEMORY;
    }
    BN_CTX_start(ctx);
    
    mat = (BIGNUM**)calloc(n * t, sizeof(BIGNUM*));
    if (!mat)
        goto cleanup;   
    one = BN_CTX_get(ctx);
    if (!one)
        goto cleanup;
    BN_one(one);

    local_ids = (uint64_t*)calloc(n, sizeof(uint64_t));
    if (!local_ids)
        goto cleanup;
    memcpy(local_ids, ids, n * sizeof(uint64_t));

    for (size_t i = 0; i < n; ++i)
    {
        if (!local_ids[i])
        {
            ret = VERIFIABLE_SECRET_SHARING_INVALID_SHARE_ID;
            goto cleanup;
        }
        for (size_t j = i + 1; j < n; ++j)
        {
            if (local_ids[i] == local_ids[j])
            {
                ret = VERIFIABLE_SECRET_SHARING_INVALID_SHARE_ID;
                goto cleanup;
            }
        }
    }
    
    for (size_t i = 0; i < n; ++i)
    {
        BIGNUM *prev = one;

        // init first cal to one
        mat[i * t] = one;
        for (size_t j = 1; j < t; ++j)
        {
            BIGNUM *cur = BN_CTX_get(ctx);
            if (!cur)
                goto cleanup;
            if (!BN_copy(cur, prev))
                goto cleanup;
            if (!BN_mul_word(cur, local_ids[i]))
                goto cleanup;
            mat[i * t + j] = cur;
            prev = cur;
        }
    }
    ret = verifiable_secret_sharing_split_impl(algebra, secret, secret_len, t, n, mat, shares, local_ids, ctx);

cleanup:
    if (ctx)
    {
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
    }
    if (mat)
        free(mat);
    if (ret != VERIFIABLE_SECRET_SHARING_SUCCESS)
        free(local_ids);
    return ret;
}

verifiable_secret_sharing_status verifiable_secret_sharing_get_share(const verifiable_secret_sharing_t *shares, uint8_t index, shamir_secret_share_t *share)
{
    if (!shares || !share)
        return VERIFIABLE_SECRET_SHARING_INVALID_PARAMETER;
    if (index >= shares->num_shares)
        return VERIFIABLE_SECRET_SHARING_INVALID_INDEX;
    if (!shares->shares || !shares->shares[index])
        return VERIFIABLE_SECRET_SHARING_UNKNOWN_ERROR;
    share->id = shares->ids[index];
    memcpy(share->data, shares->shares[index], sizeof(shamir_secret_sharing_scalar_t));
    return VERIFIABLE_SECRET_SHARING_SUCCESS;
}

verifiable_secret_sharing_status verifiable_secret_sharing_get_share_and_proof(const verifiable_secret_sharing_t *shares, uint8_t index, shamir_secret_share_t *share, elliptic_curve256_point_t *proof)
{
    verifiable_secret_sharing_status ret;
    if (!proof)
        return VERIFIABLE_SECRET_SHARING_INVALID_PARAMETER;
    ret = verifiable_secret_sharing_get_share(shares, index, share);
    if (ret == VERIFIABLE_SECRET_SHARING_SUCCESS)
        memcpy(proof, shares->proofs[index], sizeof(elliptic_curve256_point_t));
    return ret;
}

verifiable_secret_sharing_status verifiable_secret_sharing_get_shares_commitment(const verifiable_secret_sharing_t *shares, commitments_commitment_t *commitment)
{
    elliptic_curve256_point_t *proofs = NULL;
    verifiable_secret_sharing_status status;
    if (!shares || !commitment)
        return VERIFIABLE_SECRET_SHARING_INVALID_PARAMETER;
    
    proofs = (elliptic_curve256_point_t*)malloc(shares->num_shares * sizeof(elliptic_curve256_point_t));
    if (!proofs)
        return VERIFIABLE_SECRET_SHARING_OUT_OF_MEMORY;
    
    for (size_t i = 0; i < shares->num_shares; ++i)
        memcpy(proofs[i], shares->proofs[i], sizeof(elliptic_curve256_point_t));
    status = from_commitments_status(commitments_create_commitment_for_data((uint8_t*)proofs, shares->num_shares * sizeof(elliptic_curve256_point_t), commitment));
    free(proofs);
    return status;
}


int verifiable_secret_sharing_get_number_of_players(const verifiable_secret_sharing_t *shares)
{
    if (!shares)
        return -1;
    return shares->num_shares;
}

int verifiable_secret_sharing_get_threshold(const verifiable_secret_sharing_t *shares)
{
    if (!shares)
        return -1;
    return shares->threshold;
}

verifiable_secret_sharing_status verifiable_secret_sharing_get_polynom_proofs(const verifiable_secret_sharing_t *shares, elliptic_curve256_point_t *proofs, uint8_t proofs_count)
{
    if (!shares || !proofs || proofs_count < shares->threshold)
        return VERIFIABLE_SECRET_SHARING_INVALID_PARAMETER;
    memcpy(proofs, shares->coefficient_proofs, sizeof(elliptic_curve256_point_t) * shares->threshold);
    return VERIFIABLE_SECRET_SHARING_SUCCESS;
}

verifiable_secret_sharing_status verifiable_secret_sharing_get_polynom_commitment(const verifiable_secret_sharing_t *shares, commitments_commitment_t *commitment)
{
    elliptic_curve256_point_t *proofs = NULL;
    verifiable_secret_sharing_status status;
    if (!shares || !commitment)
        return VERIFIABLE_SECRET_SHARING_INVALID_PARAMETER;
    
    proofs = (elliptic_curve256_point_t*)malloc(shares->threshold * sizeof(elliptic_curve256_point_t));
    if (!proofs)
        return VERIFIABLE_SECRET_SHARING_OUT_OF_MEMORY;
    
    for (size_t i = 0; i < shares->threshold; ++i)
        memcpy(proofs[i], shares->coefficient_proofs[i], sizeof(elliptic_curve256_point_t));
    status = from_commitments_status(commitments_create_commitment_for_data((uint8_t*)proofs, shares->threshold * sizeof(elliptic_curve256_point_t), commitment));
    free(proofs);
    return status;
}

static int lagrange_interpolate(const shamir_secret_share_t *shares, uint8_t shares_count, uint8_t index, BIGNUM *p, const BIGNUM *field, BN_CTX *ctx)
{
    int ret = 0;
    BIGNUM *x = NULL;
    BIGNUM *other_x = NULL;
    BIGNUM *tmp = NULL;

    BN_CTX_start(ctx);
    x = BN_CTX_get(ctx);
    other_x = BN_CTX_get(ctx);
    tmp = BN_CTX_get(ctx);

    if (!x || !other_x || !tmp)
        goto cleanup;
    
    if (!BN_set_word(x, shares[index].id))
        goto cleanup;
    if (!BN_one(p))
        goto cleanup;

    for (uint8_t i = 0; i < shares_count; ++i)
    {
        if (i == index)
            continue;
        if (!BN_set_word(other_x, shares[i].id))
            goto cleanup;
        if (!BN_mod_sub_quick(tmp, other_x, x, field))
            goto cleanup;
        if (!BN_mod_inverse(tmp, tmp, field, ctx))
            goto cleanup;
        if (!BN_mod_mul(tmp, tmp, other_x, field, ctx))
            goto cleanup;
        if (!BN_mod_mul(p, p, tmp, field, ctx))
            goto cleanup;
    }
    ret = 1;

cleanup:
    BN_CTX_end(ctx);
    return ret;
}

verifiable_secret_sharing_status verifiable_secret_sharing_reconstruct(const elliptic_curve256_algebra_ctx_t *algebra, const shamir_secret_share_t *shares, uint8_t shares_count, uint8_t *secret, uint32_t secret_len, 
    uint32_t *out_secret_len)
{
    BN_CTX *ctx = NULL;
    BIGNUM *sum = NULL;
    BIGNUM *tmp = NULL;
    BIGNUM *y_value = NULL;
    const BIGNUM *bn_prime = NULL;
    int ret = VERIFIABLE_SECRET_SHARING_OUT_OF_MEMORY;

    if (!algebra || !shares || !shares_count || (!secret && secret_len))
        return VERIFIABLE_SECRET_SHARING_INVALID_PARAMETER;

    for (uint8_t i = 0; i < shares_count; ++i)
    {
        if (!shares[i].id)
            return VERIFIABLE_SECRET_SHARING_INVALID_PARAMETER;
        for (uint8_t j = i + 1; j < shares_count; ++j)
            if (shares[i].id == shares[j].id)
                return VERIFIABLE_SECRET_SHARING_INVALID_PARAMETER;
    }

    ctx = BN_CTX_new();
    if (!ctx)
        return ret;
    BN_CTX_start(ctx);
    
    bn_prime = algebra->order_internal(algebra);
    if (!bn_prime)
        goto cleanup;

    sum = BN_CTX_get(ctx);
    if (!sum)
        goto cleanup;
    
    tmp = BN_CTX_get(ctx);
    if (!tmp)
        goto cleanup;

    y_value = BN_CTX_get(ctx);
    if (!y_value)
        goto cleanup;
    
    for (uint8_t i = 0; i < shares_count; ++i)
    {
        if (!BN_bin2bn(shares[i].data, sizeof(shamir_secret_sharing_scalar_t), y_value))
            goto cleanup;
        if (!lagrange_interpolate(shares, shares_count, i, tmp, bn_prime, ctx))
            goto cleanup;
        if (!BN_mod_mul(tmp, y_value, tmp, bn_prime, ctx))
            goto cleanup;
        if (!BN_mod_add_quick(sum, sum, tmp, bn_prime))
            goto cleanup;
    }

    if (out_secret_len)
        *out_secret_len = BN_num_bytes(sum);
    ret = secret_len >= (uint32_t)BN_num_bytes(sum) ? VERIFIABLE_SECRET_SHARING_SUCCESS : VERIFIABLE_SECRET_SHARING_INSUFFICIENT_BUFFER;

    if (ret == VERIFIABLE_SECRET_SHARING_SUCCESS && secret)
        ret = BN_bn2bin(sum, secret) > 0 ? VERIFIABLE_SECRET_SHARING_SUCCESS : VERIFIABLE_SECRET_SHARING_UNKNOWN_ERROR;

cleanup:
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    return ret;
}

verifiable_secret_sharing_status verifiable_secret_sharing_verify_share(const elliptic_curve256_algebra_ctx_t *algebra, uint64_t id, const elliptic_curve256_point_t *share_proof, uint8_t threshold, 
    const elliptic_curve256_point_t *coefficient_proofs)
{
    elliptic_curve256_scalar_t *x_vals = NULL;
    BIGNUM *x = NULL;
    BIGNUM *tmp = NULL;
    const BIGNUM *field = NULL;
    BN_CTX *ctx = NULL;
    uint8_t res = 0;
    verifiable_secret_sharing_status status = VERIFIABLE_SECRET_SHARING_OUT_OF_MEMORY;
    
    if (!algebra || !share_proof || !threshold || !coefficient_proofs)
        return VERIFIABLE_SECRET_SHARING_INVALID_PARAMETER;
    
    ctx = BN_CTX_new();
    if (!ctx)
        return VERIFIABLE_SECRET_SHARING_OUT_OF_MEMORY;
    BN_CTX_start(ctx);
    
    x = BN_CTX_get(ctx);
    if (!x || !BN_set_word(x, id))
        goto cleanup;
    tmp = BN_CTX_get(ctx);
    if (!tmp || !BN_one(tmp))
        goto cleanup;
    field = algebra->order_internal(algebra);
    if (!field)
        goto cleanup;
    x_vals = calloc(threshold, sizeof(elliptic_curve256_scalar_t));
    if (!x_vals)
        goto cleanup;

    if (BN_bn2binpad(tmp, x_vals[0], sizeof(elliptic_curve256_scalar_t)) < 0)
    {
        status = VERIFIABLE_SECRET_SHARING_UNKNOWN_ERROR;
        goto cleanup;
    }
    for (uint8_t i = 0; i < threshold - 1; ++i)
    {
        if (!BN_mod_mul(tmp, tmp, x, field, ctx))
            goto cleanup;
        if (BN_bn2binpad(tmp, x_vals[i + 1], sizeof(elliptic_curve256_scalar_t)) < 0)
        {
            status = VERIFIABLE_SECRET_SHARING_UNKNOWN_ERROR;
            goto cleanup;
        }
    }
    
    if (algebra->verify_linear_combination(algebra, share_proof, coefficient_proofs, x_vals, threshold, &res) != ELLIPTIC_CURVE_ALGEBRA_SUCCESS)
    {
        status = VERIFIABLE_SECRET_SHARING_UNKNOWN_ERROR;
        goto cleanup;
    }

    status = res ? VERIFIABLE_SECRET_SHARING_SUCCESS : VERIFIABLE_SECRET_SHARING_INVALID_SHARE;

cleanup:
    if (ctx)
    {
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
    }
    free(x_vals);

    return status;
}

verifiable_secret_sharing_status verifiable_secret_sharing_verify_commitment(const elliptic_curve256_point_t *proofs, uint8_t proofs_count, const commitments_commitment_t *commitment)
{
    return from_commitments_status(commitments_verify_commitment((uint8_t*)proofs, proofs_count * sizeof(elliptic_curve256_point_t), commitment));
}

void verifiable_secret_sharing_free_shares(verifiable_secret_sharing_t *shares)
{
    if (shares)
    {
        free(shares->ids);
        if (shares->shares)
        {
            OPENSSL_cleanse(shares->shares, shares->num_shares * sizeof(shamir_secret_sharing_scalar_t));
            free(shares->shares);
        }
        free(shares->proofs);
        free(shares->coefficient_proofs);
        free(shares);
    }
}
