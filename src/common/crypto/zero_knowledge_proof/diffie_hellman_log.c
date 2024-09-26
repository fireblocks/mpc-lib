#include "crypto/zero_knowledge_proof/diffie_hellman_log.h"
#include "crypto/drng/drng.h"
#include "crypto/common/byteswap.h"
#include <string.h>
#include <openssl/sha.h>

#define LOG_ZKP_SALT "diffie hellman discrete log zkp"

static inline int cmp_uint256(const uint8_t *a, const uint8_t *b)
{
    const uint64_t *aptr = (const uint64_t*)a;
    const uint64_t *bptr = (const uint64_t*)b;

    for (size_t i = 0; i < sizeof(elliptic_curve256_scalar_t) / sizeof(uint64_t); i++)
    {
        uint64_t n1 = bswap_64(*aptr); // elliptic_curve256_scalar_t is represented as big endian number
        uint64_t n2 = bswap_64(*bptr);
        if (n1 > n2)
            return 1;
        else if (n1 < n2)
            return -1;
        aptr++;
        bptr++;
    }
    
    return 0;
}

static zero_knowledge_proof_status diffie_hellman_log_generate_e(const elliptic_curve256_algebra_ctx_t *algebra, const uint8_t *aad, uint32_t aad_len, const elliptic_curve256_point_t *base_point, const diffie_hellman_log_public_data_t *public_data, 
    const diffie_hellman_log_zkp_t *proof, elliptic_curve256_scalar_t *e)
{
    drng_t *rng = NULL;
    SHA256_CTX ctx;
    uint8_t seed[SHA256_DIGEST_LENGTH];
    const uint8_t *q = algebra->order(algebra);
    zero_knowledge_proof_status status = ZKP_UNKNOWN_ERROR;
    
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, LOG_ZKP_SALT, sizeof(LOG_ZKP_SALT));
    if (aad)
        SHA256_Update(&ctx, aad, aad_len);
    SHA256_Update(&ctx, *base_point, sizeof(elliptic_curve256_point_t));
    SHA256_Update(&ctx, public_data->A, sizeof(elliptic_curve256_point_t));
    SHA256_Update(&ctx, public_data->B, sizeof(elliptic_curve256_point_t));
    SHA256_Update(&ctx, public_data->C, sizeof(elliptic_curve256_point_t));
    SHA256_Update(&ctx, public_data->X, sizeof(elliptic_curve256_point_t));
    SHA256_Update(&ctx, proof->D, sizeof(elliptic_curve256_point_t));
    SHA256_Update(&ctx, proof->Y, sizeof(elliptic_curve256_point_t));
    SHA256_Update(&ctx, proof->V, sizeof(elliptic_curve256_point_t));
    SHA256_Final(seed, &ctx);

    if (drng_new(seed, SHA256_DIGEST_LENGTH, &rng) != DRNG_SUCCESS)
        return ZKP_OUT_OF_MEMORY;

    do
    {
        if (drng_read_deterministic_rand(rng, *e, sizeof(elliptic_curve256_scalar_t)) != DRNG_SUCCESS)
            goto cleanup;
    } while (cmp_uint256(*e, q) >= 0);
    status = ZKP_SUCCESS;

cleanup:
    drng_free(rng);
    return status;
}

zero_knowledge_proof_status diffie_hellman_log_zkp_generate(const elliptic_curve256_algebra_ctx_t *algebra, const uint8_t *aad, uint32_t aad_len, const elliptic_curve256_point_t *base_point, const elliptic_curve256_scalar_t *secret, 
    const elliptic_curve256_scalar_t *a, const elliptic_curve256_scalar_t *b, const diffie_hellman_log_public_data_t *public_data, diffie_hellman_log_zkp_t *proof)
{

    zero_knowledge_proof_status status = ZKP_UNKNOWN_ERROR;
    elliptic_curve256_scalar_t d;
    elliptic_curve256_scalar_t y;
    elliptic_curve256_scalar_t e;
    elliptic_curve256_scalar_t tmp;
    diffie_hellman_log_zkp_t local_proof;
    
    if (!algebra || !aad || !aad_len || !base_point || !secret || !a || !b || !public_data || !proof)
        return ZKP_INVALID_PARAMETER;

    if (algebra->rand(algebra, &d) != ELLIPTIC_CURVE_ALGEBRA_SUCCESS)
        return status;
    if (algebra->rand(algebra, &y) != ELLIPTIC_CURVE_ALGEBRA_SUCCESS)
        return status;
    
    if (algebra->generator_mul(algebra, &local_proof.D, &d) != ELLIPTIC_CURVE_ALGEBRA_SUCCESS)
        return status;
    if (algebra->point_mul(algebra, &local_proof.Y, base_point, &y) != ELLIPTIC_CURVE_ALGEBRA_SUCCESS)
        return status;
    if (algebra->mul_scalars(algebra, &tmp, *a, sizeof(elliptic_curve256_scalar_t), d, sizeof(elliptic_curve256_scalar_t)) != ELLIPTIC_CURVE_ALGEBRA_SUCCESS)
        return status;
    if (algebra->add_scalars(algebra, &tmp, tmp, sizeof(elliptic_curve256_scalar_t), y, sizeof(elliptic_curve256_scalar_t)) != ELLIPTIC_CURVE_ALGEBRA_SUCCESS)
        return status;
    if (algebra->generator_mul(algebra, &local_proof.V, &tmp) != ELLIPTIC_CURVE_ALGEBRA_SUCCESS)
        return status;

    status = diffie_hellman_log_generate_e(algebra, aad, aad_len, base_point, public_data, &local_proof, &e);
    if (status != ZKP_SUCCESS)
        return status;

    status = ZKP_UNKNOWN_ERROR;
    if (algebra->mul_scalars(algebra, &local_proof.z, e, sizeof(elliptic_curve256_scalar_t), *b, sizeof(elliptic_curve256_scalar_t)) != ELLIPTIC_CURVE_ALGEBRA_SUCCESS)
        return status;
    if (algebra->add_scalars(algebra, &local_proof.z, local_proof.z, sizeof(elliptic_curve256_scalar_t), d, sizeof(elliptic_curve256_scalar_t)) != ELLIPTIC_CURVE_ALGEBRA_SUCCESS)
        return status;
    if (algebra->mul_scalars(algebra, &local_proof.w, e, sizeof(elliptic_curve256_scalar_t), *secret, sizeof(elliptic_curve256_scalar_t)) != ELLIPTIC_CURVE_ALGEBRA_SUCCESS)
        return status;
    if (algebra->add_scalars(algebra, &local_proof.w, local_proof.w, sizeof(elliptic_curve256_scalar_t), y, sizeof(elliptic_curve256_scalar_t)) != ELLIPTIC_CURVE_ALGEBRA_SUCCESS)
        return status;
    
    memcpy(proof, &local_proof, sizeof(diffie_hellman_log_zkp_t));
    return ZKP_SUCCESS;
}

static inline zero_knowledge_proof_status from_elliptic_curve_status(elliptic_curve_algebra_status status)
{
    switch (status)
    {
    case ELLIPTIC_CURVE_ALGEBRA_SUCCESS:
        return ZKP_SUCCESS;
    case ELLIPTIC_CURVE_ALGEBRA_INVALID_PARAMETER:
    case ELLIPTIC_CURVE_ALGEBRA_INVALID_POINT:
        return ZKP_VERIFICATION_FAILED;
    case ELLIPTIC_CURVE_ALGEBRA_OUT_OF_MEMORY:
        return ZKP_OUT_OF_MEMORY;
    case ELLIPTIC_CURVE_ALGEBRA_INVALID_SIGNATURE: 
        return ZKP_VERIFICATION_FAILED;
    case ELLIPTIC_CURVE_ALGEBRA_INSUFFICIENT_BUFFER:
    case ELLIPTIC_CURVE_ALGEBRA_INVALID_SCALAR:
    case ELLIPTIC_CURVE_ALGEBRA_UNKNOWN_ERROR:
    default:
        return ZKP_UNKNOWN_ERROR;
    }
}

zero_knowledge_proof_status diffie_hellman_log_zkp_verify(const elliptic_curve256_algebra_ctx_t *algebra, const uint8_t *aad, uint32_t aad_len, const elliptic_curve256_point_t *base_point, 
    const diffie_hellman_log_public_data_t *public_data, const diffie_hellman_log_zkp_t *proof)
{
    zero_knowledge_proof_status status;
    elliptic_curve256_scalar_t e;
    elliptic_curve256_point_t p1;
    elliptic_curve256_point_t p2;

    if (!algebra || !aad || !aad_len || !base_point || !public_data || !proof)
        return ZKP_INVALID_PARAMETER;

    status = diffie_hellman_log_generate_e(algebra, aad, aad_len, base_point, public_data, proof, &e);
    if (status != ZKP_SUCCESS)
        return status;

    status = from_elliptic_curve_status(algebra->generator_mul(algebra, &p1, &proof->z));
    if (status != ZKP_SUCCESS)
        return status;
    status = from_elliptic_curve_status(algebra->point_mul(algebra, &p2, &public_data->B, &e));
    if (status != ZKP_SUCCESS)
        return status;
    status = from_elliptic_curve_status(algebra->add_points(algebra, &p2, &p2, &proof->D));
    if (status != ZKP_SUCCESS)
        return status;
    
    if (memcmp(p1, p2, sizeof(elliptic_curve256_point_t)) != 0)
        return ZKP_VERIFICATION_FAILED;
    
    status = from_elliptic_curve_status(algebra->point_mul(algebra, &p1, base_point, &proof->w));
    if (status != ZKP_SUCCESS)
        return status;
    status = from_elliptic_curve_status(algebra->point_mul(algebra, &p2, &public_data->X, &e));
    if (status != ZKP_SUCCESS)
        return status;
    status = from_elliptic_curve_status(algebra->add_points(algebra, &p2, &p2, &proof->Y));
    if (status != ZKP_SUCCESS)
        return status;
    
    if (memcmp(p1, p2, sizeof(elliptic_curve256_point_t)) != 0)
        return ZKP_VERIFICATION_FAILED;

    status = from_elliptic_curve_status(algebra->point_mul(algebra, &p1, &public_data->A, &proof->z));
    if (status != ZKP_SUCCESS)
        return status;
    status = from_elliptic_curve_status(algebra->generator_mul(algebra, &p2, &proof->w));
    if (status != ZKP_SUCCESS)
        return status;
    status = from_elliptic_curve_status(algebra->add_points(algebra, &p1, &p1, &p2));
    if (status != ZKP_SUCCESS)
        return status;
    status = from_elliptic_curve_status(algebra->point_mul(algebra, &p2, &public_data->C, &e));
    if (status != ZKP_SUCCESS)
        return status;
    status = from_elliptic_curve_status(algebra->add_points(algebra, &p2, &p2, &proof->V));
    if (status != ZKP_SUCCESS)
        return status;
    
    if (memcmp(p1, p2, sizeof(elliptic_curve256_point_t)) != 0)
        return ZKP_VERIFICATION_FAILED;
    return ZKP_SUCCESS;
}
