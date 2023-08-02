#include "crypto/zero_knowledge_proof/schnorr.h"
#include <string.h>
#include <openssl/bn.h>
#include <openssl/sha.h>

#ifndef ENCLAVE
#define memset_s(dest, destsz, ch, count) memset(dest, ch, count)
#endif

static zero_knowledge_proof_status from_elliptic_curve_algebra_status(elliptic_curve_algebra_status status)
{
    switch (status)
    {
        case ELLIPTIC_CURVE_ALGEBRA_SUCCESS: return ZKP_SUCCESS;
        case ELLIPTIC_CURVE_ALGEBRA_INVALID_PARAMETER: return ZKP_INVALID_PARAMETER;
        case ELLIPTIC_CURVE_ALGEBRA_INVALID_POINT: return ZKP_INVALID_PARAMETER;
        case ELLIPTIC_CURVE_ALGEBRA_INVALID_SCALAR: return ZKP_INVALID_PARAMETER;
        case ELLIPTIC_CURVE_ALGEBRA_OUT_OF_MEMORY: return ZKP_OUT_OF_MEMORY;
        case ELLIPTIC_CURVE_ALGEBRA_INVALID_SIGNATURE: return ZKP_VERIFICATION_FAILED;
        case ELLIPTIC_CURVE_ALGEBRA_INSUFFICIENT_BUFFER:
        case ELLIPTIC_CURVE_ALGEBRA_UNKNOWN_ERROR:
        default: return ZKP_UNKNOWN_ERROR;
    }
}

static zero_knowledge_proof_status schnorr_zkp_generate_impl(const elliptic_curve256_algebra_ctx_t *algebra, const uint8_t *prover_id, uint32_t id_len, const uint8_t *secret, uint32_t secret_size, const elliptic_curve256_point_t *public_data, 
    const elliptic_curve256_scalar_t *randomness, schnorr_zkp_t *proof)
{
    elliptic_curve_algebra_status status = ELLIPTIC_CURVE_ALGEBRA_UNKNOWN_ERROR;
    elliptic_curve256_scalar_t k;
    elliptic_curve256_scalar_t c;
    SHA256_CTX sha_ctx;

    if (randomness)
    {
        memcpy(k, *randomness, sizeof(elliptic_curve256_scalar_t));
    }
    else
    {
        status = algebra->rand(algebra, &k);
        if (status != ELLIPTIC_CURVE_ALGEBRA_SUCCESS)
            return from_elliptic_curve_algebra_status(status);        
    }

    status = algebra->generator_mul(algebra, &proof->R, &k);
    if (status != ELLIPTIC_CURVE_ALGEBRA_SUCCESS)
        return from_elliptic_curve_algebra_status(status);
    
    SHA256_Init(&sha_ctx);
    SHA256_Update(&sha_ctx, prover_id, id_len);
    SHA256_Update(&sha_ctx, proof->R, sizeof(proof->R));
    SHA256_Update(&sha_ctx, *public_data, sizeof(elliptic_curve256_point_t));
    SHA256_Final(c, &sha_ctx);

    status = algebra->mul_scalars(algebra, &c, secret, secret_size, c, sizeof(c));
    if (status != ELLIPTIC_CURVE_ALGEBRA_SUCCESS)
        return from_elliptic_curve_algebra_status(status);

    status = algebra->sub_scalars(algebra, &proof->s, k, sizeof(k), c, sizeof(c));
    memset_s(k, sizeof(k), 0, sizeof(k));
    if (status != ELLIPTIC_CURVE_ALGEBRA_SUCCESS)
        return from_elliptic_curve_algebra_status(status);

    return ZKP_SUCCESS;
}

zero_knowledge_proof_status schnorr_zkp_generate(const elliptic_curve256_algebra_ctx_t *algebra, const uint8_t *prover_id, uint32_t id_len, const elliptic_curve256_scalar_t *secret, const elliptic_curve256_point_t *public_data, schnorr_zkp_t *proof)
{
    zero_knowledge_proof_status ret = ZKP_UNKNOWN_ERROR;
    schnorr_zkp_t local_proof;
    
    if (!algebra || !prover_id || !id_len || !secret || !public_data || !proof)
        return ZKP_INVALID_PARAMETER;
    
    ret = schnorr_zkp_generate_impl(algebra, prover_id, id_len, *secret, sizeof(elliptic_curve256_scalar_t), public_data, NULL, &local_proof);
    if (ret == ZKP_SUCCESS)
        memcpy(proof, &local_proof, sizeof(local_proof));
    return ret;
}

zero_knowledge_proof_status schnorr_zkp_generate_for_data(const elliptic_curve256_algebra_ctx_t *algebra, const uint8_t *prover_id, uint32_t id_len, const uint8_t *secret, uint32_t secret_size, elliptic_curve256_point_t *public_data, schnorr_zkp_t *proof)
{
    zero_knowledge_proof_status ret = ZKP_UNKNOWN_ERROR;
    elliptic_curve_algebra_status status = ELLIPTIC_CURVE_ALGEBRA_UNKNOWN_ERROR;
    elliptic_curve256_point_t point;
    schnorr_zkp_t local_proof;
    
    if (!algebra || !prover_id || !id_len || !secret || !secret_size || !public_data || !proof)
        return ZKP_INVALID_PARAMETER;
    
    status = algebra->generator_mul_data(algebra, secret, secret_size, &point);
    if (status != ELLIPTIC_CURVE_ALGEBRA_SUCCESS)
    {
        return from_elliptic_curve_algebra_status(status);
    }
    
    ret = schnorr_zkp_generate_impl(algebra, prover_id, id_len, secret, secret_size, &point, NULL, &local_proof);
    if (ret == ZKP_SUCCESS)
    {
        memcpy(proof, &local_proof, sizeof(local_proof));
        memcpy(*public_data, point, sizeof(point));
    }

    return ret;
}

static inline uint8_t is_zero(const elliptic_curve256_scalar_t randomness)
{
    uint64_t *p = (uint64_t*)randomness;
    for (size_t i = 0; i < sizeof(elliptic_curve256_scalar_t) / sizeof(uint64_t); i++)
    {
        if (*p)
            return 0;
        p++;
    }
    return 1;
}

zero_knowledge_proof_status schnorr_zkp_generate_with_custom_randomness(const elliptic_curve256_algebra_ctx_t *algebra, const uint8_t *prover_id, uint32_t id_len, const elliptic_curve256_scalar_t *secret, const elliptic_curve256_point_t *public_data, 
    const elliptic_curve256_scalar_t *randomness, schnorr_zkp_t *proof)
{
    zero_knowledge_proof_status ret = ZKP_UNKNOWN_ERROR;
    schnorr_zkp_t local_proof;
    
    if (!algebra || !prover_id || !id_len || !secret || !public_data || !randomness || !proof)
        return ZKP_INVALID_PARAMETER;

    if (is_zero(*randomness))
        return ZKP_INVALID_PARAMETER;
    
    ret = schnorr_zkp_generate_impl(algebra, prover_id, id_len, *secret, sizeof(elliptic_curve256_scalar_t), public_data, randomness, &local_proof);
    if (ret == ZKP_SUCCESS)
        memcpy(proof, &local_proof, sizeof(local_proof));
    return ret;
}

zero_knowledge_proof_status schnorr_zkp_verify(const elliptic_curve256_algebra_ctx_t *algebra, const uint8_t *prover_id, uint32_t id_len, const elliptic_curve256_point_t *public_data, const schnorr_zkp_t *proof)
{
    elliptic_curve_algebra_status status = ELLIPTIC_CURVE_ALGEBRA_UNKNOWN_ERROR;
    elliptic_curve256_scalar_t c;
    elliptic_curve256_point_t points[2];
    elliptic_curve256_scalar_t ones[2];
    SHA256_CTX sha_ctx;
    uint8_t res = 0;

    if (!algebra || !prover_id || ! id_len || !public_data || !proof)
        return ZKP_INVALID_PARAMETER;

    SHA256_Init(&sha_ctx);
    SHA256_Update(&sha_ctx, prover_id, id_len);
    SHA256_Update(&sha_ctx, proof->R, sizeof(proof->R));
    SHA256_Update(&sha_ctx, *public_data, sizeof(elliptic_curve256_point_t));
    SHA256_Final(c, &sha_ctx);

    status = algebra->point_mul(algebra, &points[0], public_data, &c);
    if (status != ELLIPTIC_CURVE_ALGEBRA_SUCCESS)
    {
        return from_elliptic_curve_algebra_status(status);
    }
    
    status = algebra->generator_mul(algebra, &points[1], &proof->s);
    if (status != ELLIPTIC_CURVE_ALGEBRA_SUCCESS)
    {
        return from_elliptic_curve_algebra_status(status);
    }

    memset(ones, 0, sizeof(ones));
    ones[0][ELLIPTIC_CURVE_FIELD_SIZE - 1] = 1;
    ones[1][ELLIPTIC_CURVE_FIELD_SIZE - 1] = 1;
    status = algebra->verify_linear_combination(algebra, &proof->R, points, ones, 2, &res);
    if (status != ELLIPTIC_CURVE_ALGEBRA_SUCCESS)
    {
        return from_elliptic_curve_algebra_status(status);
    }
    
    return res ? ZKP_SUCCESS : ZKP_VERIFICATION_FAILED;
}