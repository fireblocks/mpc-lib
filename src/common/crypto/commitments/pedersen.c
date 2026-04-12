#include "crypto/commitments/pedersen.h"
#include <string.h>
#include "crypto/drng/drng.h"
#include <openssl/crypto.h>

// We will need to review this function - it is a deterministic commitment 
// derived from AAD. It is not really sent over network. The idea that both 
// parties can calculate it.
// Since they simply need to derive two elliptic curve points based on aad we might 
// use a different method.
// although current implementation is similar to the commonly used one which searches for 
// a legal point by simply adding 1 if a SHA256 point is not legal
commitments_status pedersen_commitment_two_generators_base_generate(pedersen_commitment_two_generators_t* base, 
                                                                    const uint8_t* aad, 
                                                                    const uint32_t aad_len, 
                                                                    const struct elliptic_curve256_algebra_ctx *ctx)
{
    drng_t *rng = NULL;
    uint8_t random_buffer[ELLIPTIC_CURVE_FIELD_SIZE * 2];
    commitments_status status = COMMITMENTS_INTERNAL_ERROR;

    if (!base || !ctx || !aad || !aad_len)
    {
        return COMMITMENTS_INVALID_PARAMETER;
    }

    if (drng_new(aad, aad_len, &rng) != DRNG_SUCCESS)
    {
        return COMMITMENTS_OUT_OF_MEMORY;
    }

    if (drng_read_deterministic_rand(rng, random_buffer, sizeof(random_buffer)) != DRNG_SUCCESS)
    {
        goto cleanup;
    }

    if (ELLIPTIC_CURVE_ALGEBRA_SUCCESS != ctx->hash_on_curve(ctx, &base->f, random_buffer, sizeof(random_buffer)))
    {
        goto cleanup;
    }

    if (drng_read_deterministic_rand(rng, random_buffer, sizeof(random_buffer)) != DRNG_SUCCESS)
    {
        goto cleanup;
    }

    if (ELLIPTIC_CURVE_ALGEBRA_SUCCESS != ctx->hash_on_curve(ctx, &base->h, random_buffer, sizeof(random_buffer)))
    {
        goto cleanup;
    }
    
    status = COMMITMENTS_SUCCESS;

cleanup:
    drng_free(rng);
    return status;
}

commitments_status pedersen_commitment_two_generators_create_commitment(elliptic_curve_commitment_t* commitment, 
                                                                        const pedersen_commitment_two_generators_t* base, 
                                                                        const uint8_t* a, 
                                                                        const uint32_t a_len, 
                                                                        const uint8_t* b, 
                                                                        const uint32_t b_len, 
                                                                        const uint8_t* c, 
                                                                        const uint32_t c_len, 
                                                                        const struct elliptic_curve256_algebra_ctx *ctx) 
{
    if (!commitment || !base || !ctx || !a || (a && !a_len) || !b || (b && !b_len) || !c || (c && !c_len))
    {
        return COMMITMENTS_INVALID_PARAMETER;
    }
        
    elliptic_curve256_point_t tmp;
    elliptic_curve256_scalar_t scalar;
    const uint8_t ZERO = 0;

    if (ctx->generator_mul_data(ctx, a, a_len, commitment) != ELLIPTIC_CURVE_ALGEBRA_SUCCESS)
    {
        goto cleanup;
    }
        
    // trick to "transform" a variable-length scalar into the modular-reduced one.
    // scalar will be (b + 0) in mod n which is b mod n
    if (ctx->add_scalars(ctx, &scalar, b, b_len, &ZERO, 1) != ELLIPTIC_CURVE_ALGEBRA_SUCCESS ||
        ctx->point_mul(ctx, &tmp, &base->h, &scalar) != ELLIPTIC_CURVE_ALGEBRA_SUCCESS)
    {
        goto cleanup;
    }
        

    if (ctx->add_points(ctx, commitment, commitment, &tmp) != ELLIPTIC_CURVE_ALGEBRA_SUCCESS)
    {
        goto cleanup;
    }
        

    if (ctx->add_scalars(ctx, &scalar, c, c_len, &ZERO, 1) != ELLIPTIC_CURVE_ALGEBRA_SUCCESS ||
        ctx->point_mul(ctx, &tmp, &base->f, &scalar) != ELLIPTIC_CURVE_ALGEBRA_SUCCESS)
    {
        goto cleanup;
    }
       
    if (ctx->add_points(ctx, commitment, commitment, &tmp) != ELLIPTIC_CURVE_ALGEBRA_SUCCESS)
    {
        goto cleanup;
    }
        
    return COMMITMENTS_SUCCESS;

cleanup:

    OPENSSL_cleanse(commitment, sizeof(elliptic_curve_commitment_t));
    OPENSSL_cleanse(scalar, sizeof(elliptic_curve256_scalar_t));
    
    return COMMITMENTS_INTERNAL_ERROR;
}

commitments_status pedersen_commitment_two_generators_verify_commitment(const elliptic_curve_commitment_t* commitment, 
                                                                        const pedersen_commitment_two_generators_t* base, 
                                                                        const uint8_t* a, 
                                                                        const uint32_t a_len, 
                                                                        const uint8_t* b, 
                                                                        const uint32_t b_len, 
                                                                        const uint8_t* c, 
                                                                        const uint32_t c_len, 
                                                                        const struct elliptic_curve256_algebra_ctx *ctx)
{
    elliptic_curve_commitment_t generated_commitment;
    commitments_status ret  = pedersen_commitment_two_generators_create_commitment(&generated_commitment, base, a, a_len, b, b_len, c, c_len, ctx);
    if (COMMITMENTS_SUCCESS == ret)
    {
        ret = (0 == CRYPTO_memcmp(&generated_commitment, commitment, sizeof(elliptic_curve_commitment_t))) ?  COMMITMENTS_SUCCESS : COMMITMENTS_INVALID_COMMITMENT;
    }

    return ret;
}