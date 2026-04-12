#include "crypto/zero_knowledge_proof/range_proofs.h"
#include "crypto/paillier_commitment/paillier_commitment.h"
#include "crypto/drng/drng.h"
#include "crypto/algebra_utils/algebra_utils.h"
#include "crypto/algebra_utils/status_convert.h"
#include "../paillier/paillier_internal.h"
#include "../paillier_commitment/paillier_commitment_internal.h"
#include "../commitments/ring_pedersen_internal.h"
#include "../commitments/damgard_fujisaki_internal.h"
#include "../zero_knowledge_proof/zkp_constants_internal.h"

#include <openssl/bn.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <alloca.h>
#include <string.h>
#include <assert.h>

#define ZKPOK_L_SIZE sizeof(elliptic_curve256_scalar_t)
#define ZKPOK_EPSILON_SIZE 2 * sizeof(elliptic_curve256_scalar_t)

#define EXPONENT_ZKPOK_SALT "Exponent vs Paillier Encryption zkpok"
#define DIFFIE_HELLMAN_ZKPOK_SALT "Range Proof with Diffie Hellman Commitment"
#define PAILLIER_LARGE_FACTORS_ZKP_SALT "Range Proof Paillier factors"

#define PAILLER_LARGE_FACTORS_QUADRATIC_ZKP_SEED "Range Proof Pailler Quadratic for G and H"


#define MAX_D_SIZE (4096)

typedef struct
{
    BIGNUM *S;
    BIGNUM *D;
    BIGNUM *T;
    BIGNUM *z1;
    BIGNUM *z2;
    BIGNUM *z3;
    elliptic_curve256_point_t Y;
} range_proof_exponent_zkpok_t;

typedef struct
{
  range_proof_exponent_zkpok_t base; // diffie_hellman is extension to the exponent zkpok where rddh.Z<->log.Y
  elliptic_curve256_scalar_t w;
  elliptic_curve256_point_t Y;
} range_proof_diffie_hellman_zkpok_t;

typedef struct
{
    BIGNUM *P;
    BIGNUM *Q;
    BIGNUM *A;
    BIGNUM *B;
    BIGNUM *T;
    BIGNUM *lambda;
    BIGNUM *z1;
    BIGNUM *z2;
    BIGNUM *w1;
    BIGNUM *w2;
    BIGNUM *v;
} range_proof_paillier_large_factors_zkp_t;

typedef struct
{
    BIGNUM* d;
    BIGNUM* d_minus_1_over_2;
    BIGNUM* P;
    BIGNUM* Q;
    BN_MONT_CTX *d_mont; // to accelerate further exponentiations mod d
} paillier_large_factors_quadratic_setup_t;

typedef struct
{
    paillier_large_factors_quadratic_setup_t setup;
    BIGNUM *A;
    BIGNUM *B;
    BIGNUM *C;

    BIGNUM *z1;
    BIGNUM *z2;
    BIGNUM *lambda1;
    BIGNUM *lambda2;
    BIGNUM *w;
} range_proof_paillier_large_factors_quadratic_zkp_t;

#define MAX(a,b) (((a)>(b))?(a):(b))

static zero_knowledge_proof_status init_exponent_zkpok(range_proof_exponent_zkpok_t *zkpok, BN_CTX *ctx)
{
    zkpok->S = BN_CTX_get(ctx);
    zkpok->D = BN_CTX_get(ctx);
    zkpok->T = BN_CTX_get(ctx);
    zkpok->z1 = BN_CTX_get(ctx);
    zkpok->z2 = BN_CTX_get(ctx);
    zkpok->z3 = BN_CTX_get(ctx);

    if (zkpok->S && zkpok->D && zkpok->T && zkpok->z1 && zkpok->z2 && zkpok->z3)
    {
        return ZKP_SUCCESS;
    }

    return ZKP_OUT_OF_MEMORY;
}

static inline int genarate_zkpok_seed_internal(const uint32_t paillier_n_size,
                                               const uint32_t ring_pedersen_n_size,
                                               const range_proof_exponent_zkpok_t *proof, 
                                               const BIGNUM *ciphertext, 
                                               const elliptic_curve256_point_t *X, 
                                               const uint8_t *aad, 
                                               const uint32_t aad_len, 
                                               const uint8_t use_extended_seed,
                                               SHA256_CTX *ctx)
{
    uint8_t *n = NULL;
    uint32_t max_size;

    SHA256_Update(ctx, EXPONENT_ZKPOK_SALT, sizeof(EXPONENT_ZKPOK_SALT));
    if (aad)
    {
        SHA256_Update(ctx, aad, aad_len);
    }

    assert( (uint32_t)BN_num_bytes(proof->D) <= 2 * paillier_n_size );
    assert( (uint32_t)BN_num_bytes(proof->S) <= ring_pedersen_n_size );
    assert( (uint32_t)BN_num_bytes(ciphertext) <= 2 * paillier_n_size );
    assert( (uint32_t)BN_num_bytes(proof->T) <= ring_pedersen_n_size );
    

    if (use_extended_seed)
    {
        max_size = MAX(ring_pedersen_n_size, 2U * paillier_n_size);
    }
    else
    {
        max_size = MAX((uint32_t)BN_num_bytes(proof->D), (uint32_t)BN_num_bytes(proof->S)); // we assume that the paillier n is larger then ring pedersen n
        max_size = MAX(max_size, (uint32_t)BN_num_bytes(ciphertext));
        max_size = MAX(max_size, (uint32_t)BN_num_bytes(proof->T));
    }    
    n = (uint8_t*)malloc(max_size);
    
    if (!n)
    {
        return 0;
    }

    if (use_extended_seed)
    {
        if (BN_bn2binpad(ciphertext, n, 2U * paillier_n_size) != (int)(2U * paillier_n_size))
        {
            goto cleanup;
        }
        SHA256_Update(ctx, n, 2U * paillier_n_size);
    }
    else
    {
        BN_bn2bin(ciphertext, n);
        SHA256_Update(ctx, n, (size_t)BN_num_bytes(ciphertext));
    }
    
    
    SHA256_Update(ctx, *X, sizeof(elliptic_curve256_point_t));

    if (use_extended_seed)
    {

        if (BN_bn2binpad(proof->S, n, ring_pedersen_n_size) != (int)ring_pedersen_n_size)
        {
            goto cleanup;
        }
        SHA256_Update(ctx, n, ring_pedersen_n_size);
        if (BN_bn2binpad(proof->D, n, 2U * paillier_n_size) != (int)(2U * paillier_n_size))
        {
            goto cleanup;
        }
        SHA256_Update(ctx, n, 2U * paillier_n_size);
    }
    else
    {
        BN_bn2bin(proof->S, n);
        SHA256_Update(ctx, n, BN_num_bytes(proof->S));
        BN_bn2bin(proof->D, n);
        SHA256_Update(ctx, n, BN_num_bytes(proof->D));

    }

    SHA256_Update(ctx, proof->Y, sizeof(elliptic_curve256_point_t));

    if (use_extended_seed)
    {
        if (BN_bn2binpad(proof->T, n, ring_pedersen_n_size) != (int)ring_pedersen_n_size)
        {
            goto cleanup;
        }
        SHA256_Update(ctx, n, ring_pedersen_n_size);
    }
    else
    {
        BN_bn2bin(proof->T, n);
        SHA256_Update(ctx, n, BN_num_bytes(proof->T));
    }
    free(n);
    return 1;

cleanup:
    free(n);
    return 0;
}

static inline int genarate_exponent_zkpok_seed(const uint32_t paillier_n_size,
                                               const uint32_t ring_pedersen_n_size, 
                                               const range_proof_exponent_zkpok_t *proof, 
                                               const BIGNUM *ciphertext, 
                                               const elliptic_curve256_point_t *X, 
                                               const uint8_t *aad, 
                                               uint32_t aad_len, 
                                               const uint8_t use_extended_seed,
                                               uint8_t *seed)
{
    SHA256_CTX ctx;

    SHA256_Init(&ctx);
    if (!genarate_zkpok_seed_internal(paillier_n_size, ring_pedersen_n_size, proof, ciphertext, X, aad, aad_len, use_extended_seed, &ctx))
    {
        return 0;
    }

    SHA256_Final(seed, &ctx);
    return 1;
}

static inline uint32_t exponent_zkpok_serialized_size_internal(const BIGNUM *pedersen_n, const BIGNUM *paillier_n)
{
    const uint32_t ring_pedersen_n_size = (uint32_t)BN_num_bytes(pedersen_n);
    const uint32_t paillier_n_size = (uint32_t)BN_num_bytes(paillier_n);

    return
        sizeof(uint32_t) + // sizeof(ring_pedersen->n)
        sizeof(uint32_t) + // sizeof(paillier->n)
        ring_pedersen_n_size + // sizeof(S)
        2 * paillier_n_size + // sizeof(D)
        sizeof(elliptic_curve256_point_t) + // sizeof(Y)
        ring_pedersen_n_size + // sizeof(T)
        ZKPOK_EPSILON_SIZE + sizeof(elliptic_curve256_scalar_t) + 1 + // sizeof(z1)
        paillier_n_size + // sizeof(z2)
        ZKPOK_EPSILON_SIZE + sizeof(elliptic_curve256_scalar_t) + ring_pedersen_n_size + 1; // sizeof(z3)
}


static inline uint32_t exponent_zkpok_serialized_size(const ring_pedersen_public_t *pub, const paillier_public_key_t *paillier)
{
    return exponent_zkpok_serialized_size_internal(pub->n, paillier->n);
}

static uint8_t* serialize_exponent_zkpok(const range_proof_exponent_zkpok_t* proof,
                                         const BIGNUM* ring_pedersen_n,
                                         const BIGNUM* paillier_n,
                                         uint8_t* serialized_proof)
{
    const uint32_t ring_pedersen_n_size = (uint32_t)BN_num_bytes(ring_pedersen_n);
    const uint32_t paillier_n_size = (uint32_t)BN_num_bytes(paillier_n);
    uint8_t *ptr = serialized_proof;

    *(uint32_t*)ptr = ring_pedersen_n_size;
    ptr += sizeof(uint32_t);

    *(uint32_t*)ptr = paillier_n_size;
    ptr += sizeof(uint32_t);

    if (BN_bn2binpad(proof->S, ptr, ring_pedersen_n_size) <= 0)
    {
        return NULL;
    }
    ptr += ring_pedersen_n_size;

    if (BN_bn2binpad(proof->D, ptr, paillier_n_size * 2) <= 0)
    {
        return NULL;
    }
    ptr += paillier_n_size * 2;

    memcpy(ptr, proof->Y, sizeof(elliptic_curve256_point_t));
    ptr += sizeof(elliptic_curve256_point_t);

    if (BN_bn2binpad(proof->T, ptr, ring_pedersen_n_size) <= 0)
    {
        return NULL;
    }
    ptr += ring_pedersen_n_size;

    if (BN_bn2binpad(proof->z1, ptr, ZKPOK_EPSILON_SIZE + sizeof(elliptic_curve256_scalar_t) + 1) <= 0)
    {
        return NULL;
    }
    ptr += ZKPOK_EPSILON_SIZE + sizeof(elliptic_curve256_scalar_t) + 1;

    if (BN_bn2binpad(proof->z2, ptr, paillier_n_size) <= 0)
    {
        return NULL;
    }
    ptr += paillier_n_size;

    if (BN_bn2binpad(proof->z3, ptr, ZKPOK_EPSILON_SIZE + sizeof(elliptic_curve256_scalar_t) + ring_pedersen_n_size + 1) <= 0)
    {
        return NULL;
    }
    ptr += ZKPOK_EPSILON_SIZE + sizeof(elliptic_curve256_scalar_t) + ring_pedersen_n_size + 1;

    return ptr;
}

static const uint8_t* deserialize_exponent_zkpok(range_proof_exponent_zkpok_t* proof,
                                                 const BIGNUM* ring_pedersen_n,
                                                 const BIGNUM* paillier_n,
                                                 const uint8_t* serialized_proof)
{
    const uint32_t ring_pedersen_n_size = (uint32_t)BN_num_bytes(ring_pedersen_n);
    const uint32_t paillier_n_size = (uint32_t)BN_num_bytes(paillier_n);
    const uint8_t *ptr = serialized_proof;

    if (*(const uint32_t*)ptr != ring_pedersen_n_size)
    {
        return NULL;
    }
    ptr += sizeof(uint32_t);

    if (*(const uint32_t*)ptr != paillier_n_size)
    {
        return NULL;
    }
    ptr += sizeof(uint32_t);

    if (!BN_bin2bn(ptr, ring_pedersen_n_size, proof->S))
    {
        return NULL;
    }
    ptr += ring_pedersen_n_size;

    if (!BN_bin2bn(ptr, paillier_n_size * 2, proof->D))
    {
        return NULL;
    }
    ptr += paillier_n_size * 2;

    memcpy(proof->Y, ptr, sizeof(elliptic_curve256_point_t));
    ptr += sizeof(elliptic_curve256_point_t);

    if (!BN_bin2bn(ptr, ring_pedersen_n_size, proof->T))
    {
        return NULL;
    }
    ptr += ring_pedersen_n_size;

    if (!BN_bin2bn(ptr, ZKPOK_EPSILON_SIZE + sizeof(elliptic_curve256_scalar_t) + 1, proof->z1))
    {
        return NULL;
    }
    ptr += ZKPOK_EPSILON_SIZE + sizeof(elliptic_curve256_scalar_t) + 1;

    if (!BN_bin2bn(ptr, paillier_n_size, proof->z2))
    {
        return NULL;
    }
    ptr += paillier_n_size;

    if (!BN_bin2bn(ptr, ZKPOK_EPSILON_SIZE + sizeof(elliptic_curve256_scalar_t) + ring_pedersen_n_size + 1, proof->z3))
    {
        return NULL;
    }
    ptr += ZKPOK_EPSILON_SIZE + sizeof(elliptic_curve256_scalar_t) + ring_pedersen_n_size + 1;

    return ptr;
}

zero_knowledge_proof_status range_proof_paillier_exponent_zkpok_generate(const ring_pedersen_public_t *ring_pedersen,
                                                                         const paillier_public_key_t *paillier,
                                                                         const elliptic_curve256_algebra_ctx_t *algebra,
                                                                         const uint8_t *aad,
                                                                         uint32_t aad_len,
                                                                         const elliptic_curve256_scalar_t *secret,
                                                                         const paillier_ciphertext_t *ciphertext,
                                                                         const uint8_t use_extended_seed,
                                                                         uint8_t *serialized_proof,
                                                                         uint32_t proof_len,
                                                                         uint32_t *real_proof_len)
{
    BN_CTX *ctx = NULL;
    drng_t *rng = NULL;
    range_proof_exponent_zkpok_t zkpok;
    zero_knowledge_proof_status status = ZKP_OUT_OF_MEMORY;
    BIGNUM *alpha = NULL, *mu = NULL, *r = NULL, *gamma = NULL, *e = NULL, *x = NULL, *tmp = NULL;
    const BIGNUM *q;
    elliptic_curve256_scalar_t alpha_bin;
    uint8_t seed[SHA256_DIGEST_LENGTH];
    long paillier_status = 0;
    uint32_t needed_len;
    elliptic_curve256_point_t public_point;

    if (!ring_pedersen || !paillier || !algebra || !aad || !aad_len || !secret || !ciphertext || (!serialized_proof && proof_len))
        return ZKP_INVALID_PARAMETER;

    if (!ciphertext->r || !ciphertext->ciphertext)
        return ZKP_INVALID_PARAMETER;

    needed_len = exponent_zkpok_serialized_size(ring_pedersen, paillier);
    if (real_proof_len)
        *real_proof_len = needed_len;
    if (proof_len < needed_len)
        return ZKP_INSUFFICIENT_BUFFER;


    ctx = BN_CTX_new();

    if (!ctx)
        return ZKP_OUT_OF_MEMORY;

    if (is_coprime_fast(ciphertext->r, paillier->n, ctx) != 1)
    {
        BN_CTX_free(ctx);
        return ZKP_INVALID_PARAMETER;
    }

    BN_CTX_start(ctx);
    alpha = BN_CTX_get(ctx);
    mu = BN_CTX_get(ctx);
    r = BN_CTX_get(ctx);
    gamma = BN_CTX_get(ctx);
    e = BN_CTX_get(ctx);
    x = BN_CTX_get(ctx);
    tmp = BN_CTX_get(ctx);

    if (!alpha || !mu || !r || !gamma || !e || !x || !tmp)
        goto cleanup;

    status = init_exponent_zkpok(&zkpok, ctx);
    if (status != ZKP_SUCCESS)
        goto cleanup;

    if (!BN_bin2bn(*secret, sizeof(elliptic_curve256_scalar_t), x))
        goto cleanup;

    q = algebra->order_internal(algebra);

    // generate S, D, Y, T
    if (!BN_set_bit(tmp, (sizeof(elliptic_curve256_scalar_t) + ZKPOK_EPSILON_SIZE) * 8))
        goto cleanup;

    status = ZKP_UNKNOWN_ERROR;

    // rand alpha
    if (!BN_rand_range(alpha, tmp))
        goto cleanup;

    // rand mu
    if (!BN_copy(tmp, ring_pedersen->n) || !BN_lshift(tmp, tmp, sizeof(elliptic_curve256_scalar_t) * 8))
    {
        status = ZKP_OUT_OF_MEMORY;
        goto cleanup;
    }

    if (!BN_rand_range(mu, tmp))
        goto cleanup;

    // rand gamma
    if (!BN_lshift(tmp, tmp, ZKPOK_EPSILON_SIZE * 8))
    {
        status = ZKP_OUT_OF_MEMORY;
        goto cleanup;
    }

    if (!BN_rand_range(gamma, tmp))
        goto cleanup;

    do
    {
        if (!BN_rand_range(r, paillier->n))
            goto cleanup;
        paillier_status = paillier_encrypt_openssl_internal(paillier, zkpok.D, r, alpha, ctx);
    } while (paillier_status == PAILLIER_ERROR_INVALID_RANDOMNESS);

    if (paillier_status != PAILLIER_SUCCESS)
        goto cleanup;

    if (ring_pedersen_create_commitment_internal(ring_pedersen, x, mu, zkpok.S, ctx) != RING_PEDERSEN_SUCCESS)
        goto cleanup;
    if (ring_pedersen_create_commitment_internal(ring_pedersen, alpha, gamma, zkpok.T, ctx) != RING_PEDERSEN_SUCCESS)
        goto cleanup;
    if (!BN_mod(tmp, alpha, q, ctx))
        goto cleanup;
    if (BN_bn2binpad(tmp, alpha_bin, sizeof(elliptic_curve256_scalar_t)) <= 0)
        goto cleanup;
    if (algebra->generator_mul(algebra, &zkpok.Y, &alpha_bin) != ELLIPTIC_CURVE_ALGEBRA_SUCCESS)
        goto cleanup;

    if (algebra->generator_mul(algebra, &public_point, secret) != ELLIPTIC_CURVE_ALGEBRA_SUCCESS)
        goto cleanup;

    const uint32_t ring_pedersen_n_size = (uint32_t)BN_num_bytes(ring_pedersen->n);
    const uint32_t paillier_n_size = (uint32_t)BN_num_bytes(paillier->n);

    // sample e
    if (!genarate_exponent_zkpok_seed(paillier_n_size, ring_pedersen_n_size, &zkpok, ciphertext->ciphertext, &public_point, aad, aad_len, use_extended_seed, seed))
        goto cleanup;
    if (drng_new(seed, SHA256_DIGEST_LENGTH, &rng) != DRNG_SUCCESS)
    {
        status = ZKP_OUT_OF_MEMORY;
        goto cleanup;
    }

    do
    {
        elliptic_curve256_scalar_t val;

        if (drng_read_deterministic_rand(rng, val, sizeof(elliptic_curve256_scalar_t)) != DRNG_SUCCESS)
        {
            status = ZKP_UNKNOWN_ERROR;
            goto cleanup;
        }
        if (!BN_bin2bn(val, sizeof(elliptic_curve256_scalar_t), e))
            goto cleanup;
    } while (BN_cmp(e, q) >= 0);

    // calc z1, z2, z3
    if (!BN_mul(zkpok.z1, e, x, ctx))
        goto cleanup;
    if (!BN_add(zkpok.z1, zkpok.z1, alpha))
        goto cleanup;

    if (!BN_mod_exp(zkpok.z2, ciphertext->r, e, paillier->n, ctx))
        goto cleanup;
    if (!BN_mod_mul(zkpok.z2, zkpok.z2, r, paillier->n, ctx))
        goto cleanup;

    if (!BN_mul(zkpok.z3, e, mu, ctx))
        goto cleanup;
    if (!BN_add(zkpok.z3, zkpok.z3, gamma))
        goto cleanup;

    status = serialize_exponent_zkpok(&zkpok, ring_pedersen->n, paillier->n, serialized_proof) != NULL ? ZKP_SUCCESS : ZKP_OUT_OF_MEMORY;

cleanup:

    if (alpha)
    {
        BN_clear(alpha);
    }

    if (mu)
    {
        BN_clear(mu);
    }
    
    if (r)
    {
        BN_clear(r);
    }

    if (gamma)
    {
        BN_clear(gamma);
    }

    if (e)
    {
        BN_clear(e);
    }

    if (x)
    {
        BN_clear(x);
    }
    
    if (tmp)
    {
        BN_clear(tmp);
    }

        
    drng_free(rng);
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    return status;
}

zero_knowledge_proof_status range_proof_paillier_encrypt_with_exponent_zkpok_generate(const ring_pedersen_public_t *ring_pedersen, const paillier_public_key_t *paillier, const elliptic_curve256_algebra_ctx_t *algebra,
    const uint8_t *aad, uint32_t aad_len, const elliptic_curve256_scalar_t *secret, const uint8_t use_extended_seed, paillier_with_range_proof_t **proof)
{
    paillier_ciphertext_t *ciphertext = NULL;
    paillier_with_range_proof_t *local_proof = NULL;
    zero_knowledge_proof_status status = ZKP_OUT_OF_MEMORY;

    if (!paillier || !secret)
        return ZKP_INVALID_PARAMETER;

    if (paillier_encrypt_to_ciphertext(paillier, *secret, sizeof(elliptic_curve256_scalar_t), &ciphertext) != PAILLIER_SUCCESS)
    {
        status = ZKP_UNKNOWN_ERROR;
        goto cleanup;
    }

    local_proof = (paillier_with_range_proof_t*)calloc(1, sizeof(paillier_with_range_proof_t));
    if (!local_proof)
        goto cleanup;

    local_proof->ciphertext_len = BN_num_bytes(paillier->n2);
    local_proof->ciphertext = (uint8_t*)malloc(local_proof->ciphertext_len);
    local_proof->proof_len = exponent_zkpok_serialized_size(ring_pedersen, paillier);
    local_proof->serialized_proof = (uint8_t*)malloc(local_proof->proof_len);

    if (!local_proof->ciphertext || !local_proof->serialized_proof)
    {
        goto cleanup;
    }


    if (BN_bn2binpad(ciphertext->ciphertext, local_proof->ciphertext, local_proof->ciphertext_len) <= 0)
    {
        status = ZKP_UNKNOWN_ERROR;
        goto cleanup;
    }

    status = range_proof_paillier_exponent_zkpok_generate(ring_pedersen, paillier, algebra, aad, aad_len, secret, ciphertext, use_extended_seed, local_proof->serialized_proof, local_proof->proof_len, NULL);

    if (status == ZKP_SUCCESS)
    {
        *proof = local_proof;
        local_proof = NULL;
    }

cleanup:
    range_proof_free_paillier_with_range_proof(local_proof);
    paillier_free_ciphertext(ciphertext);
    return status;
}

zero_knowledge_proof_status range_proof_exponent_zkpok_verify(const ring_pedersen_private_t *ring_pedersen,
                                                              const paillier_public_key_t *paillier,
                                                              const elliptic_curve256_algebra_ctx_t *algebra,
                                                              const uint8_t *aad,
                                                              uint32_t aad_len,
                                                              const elliptic_curve256_point_t *public_point,
                                                              const paillier_with_range_proof_t *proof,
                                                              const uint8_t strict_ciphertext_length,
                                                              const uint8_t use_extended_seed)
{
    BN_CTX *ctx = NULL;
    drng_t *rng = NULL;
    range_proof_exponent_zkpok_t zkpok;
    uint32_t needed_proof_len;
    zero_knowledge_proof_status status = ZKP_OUT_OF_MEMORY;
    BIGNUM *e = NULL, *tmp1 = NULL, *tmp2 = NULL;
    const BIGNUM *q;
    uint8_t seed[SHA256_DIGEST_LENGTH];
    elliptic_curve256_scalar_t val;
    elliptic_curve256_scalar_t z1;
    elliptic_curve256_point_t p1;
    elliptic_curve256_point_t p2;

    if (!ring_pedersen || !paillier || !algebra || !aad || !aad_len || !public_point || !proof || !proof->ciphertext || !proof->ciphertext_len || !proof->serialized_proof || !proof->proof_len)
        return ZKP_INVALID_PARAMETER;

    if (strict_ciphertext_length && proof->ciphertext_len != (uint32_t)BN_num_bytes(paillier->n2))
    {
        return ZKP_INVALID_PARAMETER;
    }

    needed_proof_len = exponent_zkpok_serialized_size(&ring_pedersen->pub, paillier);
    if (proof->proof_len < needed_proof_len)
        return ZKP_INVALID_PARAMETER;

    ctx = BN_CTX_new();

    if (!ctx)
        return ZKP_OUT_OF_MEMORY;

    BN_CTX_start(ctx);

    e = BN_CTX_get(ctx);
    tmp1 = BN_CTX_get(ctx);
    tmp2 = BN_CTX_get(ctx);

    if (!e || !tmp1 || !tmp2)
        goto cleanup;

    status = init_exponent_zkpok(&zkpok, ctx);
    if (status != ZKP_SUCCESS)
        goto cleanup;

    status = ZKP_UNKNOWN_ERROR;
    if (!deserialize_exponent_zkpok(&zkpok, ring_pedersen->pub.n, paillier->n, proof->serialized_proof))
    {
        status = ZKP_VERIFICATION_FAILED;
        goto cleanup;
    }

    if (is_coprime_fast(zkpok.D, paillier->n, ctx) != 1)
    {
        status = ZKP_VERIFICATION_FAILED;
        goto cleanup;
    }

    if (!BN_bin2bn(proof->ciphertext, proof->ciphertext_len, tmp1))
    {
        status = ZKP_OUT_OF_MEMORY;
        goto cleanup;
    }

    if (is_coprime_fast(tmp1, paillier->n, ctx) != 1)
    {
        status = ZKP_VERIFICATION_FAILED;
        goto cleanup;
    }

    if (is_coprime_fast(zkpok.S, ring_pedersen->pub.n, ctx) != 1)
    {
        status = ZKP_VERIFICATION_FAILED;
        goto cleanup;
    }
    if (is_coprime_fast(zkpok.T, ring_pedersen->pub.n, ctx) != 1)
    {
        status = ZKP_VERIFICATION_FAILED;
        goto cleanup;
    }

    const uint32_t ring_pedersen_n_size = (uint32_t)BN_num_bytes(ring_pedersen->pub.n);
    const uint32_t paillier_n_size = (uint32_t)BN_num_bytes(paillier->n);

    // sample e
    if (!genarate_exponent_zkpok_seed(paillier_n_size, ring_pedersen_n_size, &zkpok, tmp1, public_point, aad, aad_len, use_extended_seed, seed))
    {
        status = ZKP_UNKNOWN_ERROR;
        goto cleanup;
    }
    if (drng_new(seed, SHA256_DIGEST_LENGTH, &rng) != DRNG_SUCCESS)
        goto cleanup;

    if ((size_t)BN_num_bytes(zkpok.z1) > sizeof(elliptic_curve256_scalar_t) + ZKPOK_EPSILON_SIZE)
    {
        status = ZKP_VERIFICATION_FAILED;
        goto cleanup;
    }

    q = algebra->order_internal(algebra);

    do
    {
        if (drng_read_deterministic_rand(rng, val, sizeof(elliptic_curve256_scalar_t)) != DRNG_SUCCESS)
        {
            status = ZKP_UNKNOWN_ERROR;
            goto cleanup;
        }
        if (!BN_bin2bn(val, sizeof(elliptic_curve256_scalar_t), e))
            goto cleanup;
    } while (BN_cmp(e, q) >= 0);

    if (paillier_encrypt_openssl_internal(paillier, tmp2, zkpok.z2, zkpok.z1, ctx) != PAILLIER_SUCCESS)
        goto cleanup;
    if (!BN_mod_exp(tmp1, tmp1, e, paillier->n2, ctx))
        goto cleanup;
    if (!BN_mod_mul(tmp1, tmp1, zkpok.D, paillier->n2, ctx))
        goto cleanup;

    if (BN_cmp(tmp1, tmp2) != 0)
    {
        status = ZKP_VERIFICATION_FAILED;
        goto cleanup;
    }

    if (ring_pedersen_create_commitment_internal(&ring_pedersen->pub, zkpok.z1, zkpok.z3, tmp2, ctx) != RING_PEDERSEN_SUCCESS)
        goto cleanup;

    if (!BN_mod_exp(tmp1, zkpok.S, e, ring_pedersen->pub.n, ctx))
        goto cleanup;
    if (!BN_mod_mul(tmp1, tmp1, zkpok.T, ring_pedersen->pub.n, ctx))
        goto cleanup;

    if (BN_cmp(tmp1, tmp2) != 0)
    {
        status = ZKP_VERIFICATION_FAILED;
        goto cleanup;
    }

    if (!BN_mod(zkpok.z1, zkpok.z1, q, ctx))
        goto cleanup;

    if (BN_bn2binpad(zkpok.z1, z1, sizeof(elliptic_curve256_scalar_t)) <= 0)
        goto cleanup;
    if (algebra->point_mul(algebra, &p1, public_point, &val) != ELLIPTIC_CURVE_ALGEBRA_SUCCESS)
        goto cleanup;
    if (algebra->add_points(algebra, &p1, &p1, &zkpok.Y) != ELLIPTIC_CURVE_ALGEBRA_SUCCESS)
        goto cleanup;
    if (algebra->generator_mul(algebra, &p2, &z1) != ELLIPTIC_CURVE_ALGEBRA_SUCCESS)
        goto cleanup;

    status = memcmp(p1, p2, sizeof(elliptic_curve256_point_t)) == 0 ? ZKP_SUCCESS : ZKP_VERIFICATION_FAILED;
cleanup:
    drng_free(rng);
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    return status;
}


static inline zero_knowledge_proof_status init_diffie_hellman_zkpok(range_proof_diffie_hellman_zkpok_t *zkpok, BN_CTX *ctx)
{
    return init_exponent_zkpok(&zkpok->base, ctx);
}

static inline int genarate_diffie_hellman_zkpok_seed(const uint32_t paillier_n_size,
                                                     const uint32_t ring_pedersen_n_size,
                                                     const range_proof_diffie_hellman_zkpok_t *proof, 
                                                     const BIGNUM *ciphertext, 
                                                     const elliptic_curve256_point_t *A, 
                                                     const elliptic_curve256_point_t *B, 
                                                     const elliptic_curve256_point_t *X, 
                                                     const uint8_t *aad, 
                                                     uint32_t aad_len, 
                                                     const uint8_t use_extended_seed,
                                                     uint8_t *seed)
{
    SHA256_CTX ctx;

    SHA256_Init(&ctx);
    if (!genarate_zkpok_seed_internal(paillier_n_size, ring_pedersen_n_size, &proof->base, ciphertext, X, aad, aad_len, use_extended_seed, &ctx))
        return 0;
    SHA256_Update(&ctx, *A, sizeof(elliptic_curve256_point_t));
    SHA256_Update(&ctx, *B, sizeof(elliptic_curve256_point_t));
    SHA256_Update(&ctx, proof->Y, sizeof(elliptic_curve256_point_t));
    SHA256_Final(seed, &ctx);
    return 1;
}

static inline uint32_t diffie_hellman_zkpok_serialized_size(const ring_pedersen_public_t *pub, const paillier_public_key_t *paillier)
{
    return exponent_zkpok_serialized_size(pub, paillier) +
        sizeof(elliptic_curve256_point_t) + // sizeof(Y)
        sizeof(elliptic_curve256_scalar_t); // sizeof(w)
}

static inline uint8_t* serialize_diffie_hellman_zkpok(const range_proof_diffie_hellman_zkpok_t *proof, const BIGNUM *ring_pedersen_n, const BIGNUM *paillier_n, uint8_t *serialized_proof)
{
    uint8_t *ptr = serialize_exponent_zkpok(&proof->base, ring_pedersen_n, paillier_n, serialized_proof);
    if (!ptr)
        return NULL;
    memcpy(ptr, proof->Y, sizeof(elliptic_curve256_point_t));
    memcpy(ptr + sizeof(elliptic_curve256_point_t), proof->w, sizeof(elliptic_curve256_scalar_t));
    return ptr + sizeof(elliptic_curve256_point_t) + sizeof(elliptic_curve256_scalar_t);
}

static inline int deserialize_diffie_hellman_zkpok(range_proof_diffie_hellman_zkpok_t *proof, const BIGNUM *ring_pedersen_n, const BIGNUM *paillier_n, const uint8_t *serialized_proof)
{
    const uint8_t *ptr = deserialize_exponent_zkpok(&proof->base, ring_pedersen_n, paillier_n, serialized_proof);
    if (!ptr)
        return 0;
    memcpy(proof->Y, ptr, sizeof(elliptic_curve256_point_t));
    memcpy(proof->w, ptr + sizeof(elliptic_curve256_point_t), sizeof(elliptic_curve256_scalar_t));
    return 1;
}

zero_knowledge_proof_status range_proof_diffie_hellman_zkpok_generate(const ring_pedersen_public_t *ring_pedersen, 
                                                                      const paillier_public_key_t *paillier, 
                                                                      const elliptic_curve256_algebra_ctx_t *algebra,
                                                                      const uint8_t *aad, 
                                                                      uint32_t aad_len, 
                                                                      const elliptic_curve256_scalar_t *secret, 
                                                                      const elliptic_curve256_scalar_t *a, 
                                                                      const elliptic_curve256_scalar_t *b, const 
                                                                      paillier_ciphertext_t *ciphertext,
                                                                      const uint8_t use_extended_seed,
                                                                      uint8_t *serialized_proof, 
                                                                      uint32_t proof_len, 
                                                                      uint32_t *real_proof_len)
{
    BN_CTX *ctx = NULL;
    drng_t *rng = NULL;
    range_proof_diffie_hellman_zkpok_t zkpok;
    zero_knowledge_proof_status status = ZKP_OUT_OF_MEMORY;
    BIGNUM *alpha = NULL, *mu = NULL, *r = NULL, *gamma = NULL, *e = NULL, *x = NULL, *tmp = NULL;
    elliptic_curve256_scalar_t beta;
    const BIGNUM *q;
    elliptic_curve256_scalar_t alpha_bin;
    elliptic_curve256_scalar_t tmp_scalar;
    elliptic_curve256_scalar_t e_val;
    uint8_t seed[SHA256_DIGEST_LENGTH];
    long paillier_status = 0;
    elliptic_curve256_point_t A, B, X;
    uint32_t needed_len;

    if (!ring_pedersen || !paillier || !algebra || !aad || !aad_len || !secret || !a || !b || !ciphertext || (!serialized_proof && proof_len))
        return ZKP_INVALID_PARAMETER;

    needed_len = diffie_hellman_zkpok_serialized_size(ring_pedersen, paillier);

    if (real_proof_len)
        *real_proof_len = needed_len;
    if (proof_len < needed_len)
        return ZKP_INSUFFICIENT_BUFFER;


    ctx = BN_CTX_new();

    if (!ctx)
        return ZKP_OUT_OF_MEMORY;

    if (is_coprime_fast(ciphertext->r, paillier->n, ctx) != 1)
    {
        BN_CTX_free(ctx);
        return ZKP_INVALID_PARAMETER;
    }

    BN_CTX_start(ctx);
    alpha = BN_CTX_get(ctx);
    mu = BN_CTX_get(ctx);
    r = BN_CTX_get(ctx);
    gamma = BN_CTX_get(ctx);
    e = BN_CTX_get(ctx);
    x = BN_CTX_get(ctx);
    tmp = BN_CTX_get(ctx);

    if (!alpha || !mu || !r || !gamma || !e || !x || !tmp)
        goto cleanup;

    status = init_diffie_hellman_zkpok(&zkpok, ctx);
    if (status != ZKP_SUCCESS)
        goto cleanup;

    if (!BN_bin2bn(*secret, sizeof(elliptic_curve256_scalar_t), x))
        goto cleanup;

    q = algebra->order_internal(algebra);

    // generate S, D, Y, Z, T
    if (!BN_set_bit(tmp, (sizeof(elliptic_curve256_scalar_t) + ZKPOK_EPSILON_SIZE) * 8))
        goto cleanup;

    status = ZKP_UNKNOWN_ERROR;

    // rand alpha
    if (!BN_rand_range(alpha, tmp))
        goto cleanup;

    // rand beta
    if (algebra->rand(algebra, &beta) != ELLIPTIC_CURVE_ALGEBRA_SUCCESS)
        goto cleanup;

    // rand mu
    if (!BN_copy(tmp, ring_pedersen->n) || !BN_lshift(tmp, tmp, sizeof(elliptic_curve256_scalar_t) * 8))
    {
        status = ZKP_OUT_OF_MEMORY;
        goto cleanup;
    }

    if (!BN_rand_range(mu, tmp))
        goto cleanup;

    // rand gamma
    if (!BN_lshift(tmp, tmp, ZKPOK_EPSILON_SIZE * 8))
    {
        status = ZKP_OUT_OF_MEMORY;
        goto cleanup;
    }

    if (!BN_rand_range(gamma, tmp))
        goto cleanup;

    do
    {
        if (!BN_rand_range(r, paillier->n))
            goto cleanup;
        paillier_status = paillier_encrypt_openssl_internal(paillier, zkpok.base.D, r, alpha, ctx);
    } while (paillier_status == PAILLIER_ERROR_INVALID_RANDOMNESS);

    if (paillier_status != PAILLIER_SUCCESS)
        goto cleanup;

    if (ring_pedersen_create_commitment_internal(ring_pedersen, x, mu, zkpok.base.S, ctx) != RING_PEDERSEN_SUCCESS)
        goto cleanup;
    if (ring_pedersen_create_commitment_internal(ring_pedersen, alpha, gamma, zkpok.base.T, ctx) != RING_PEDERSEN_SUCCESS)
        goto cleanup;
    if (algebra->generator_mul(algebra, &zkpok.base.Y, &beta) != ELLIPTIC_CURVE_ALGEBRA_SUCCESS)
        goto cleanup;
    if (!BN_mod(tmp, alpha, q, ctx))
        goto cleanup;
    if (BN_bn2binpad(tmp, alpha_bin, sizeof(elliptic_curve256_scalar_t)) <= 0)
        goto cleanup;

    if (algebra->mul_scalars(algebra, &tmp_scalar, *a, sizeof(elliptic_curve256_scalar_t), beta, sizeof(elliptic_curve256_scalar_t)) != ELLIPTIC_CURVE_ALGEBRA_SUCCESS)
        goto cleanup;
    if (algebra->add_scalars(algebra, &tmp_scalar, alpha_bin, sizeof(elliptic_curve256_scalar_t), tmp_scalar, sizeof(elliptic_curve256_scalar_t)) != ELLIPTIC_CURVE_ALGEBRA_SUCCESS)
        goto cleanup;
    if (algebra->generator_mul(algebra, &zkpok.Y, &tmp_scalar) != ELLIPTIC_CURVE_ALGEBRA_SUCCESS) // Y = A^beta*g^alpha == g^(a*beta+alpha)
        goto cleanup;

    if (algebra->generator_mul(algebra, &A, a) != ELLIPTIC_CURVE_ALGEBRA_SUCCESS)
        goto cleanup;
    if (algebra->generator_mul(algebra, &B, b) != ELLIPTIC_CURVE_ALGEBRA_SUCCESS)
        goto cleanup;
    if (algebra->mul_scalars(algebra, &tmp_scalar, *a, sizeof(elliptic_curve256_scalar_t), *b, sizeof(elliptic_curve256_scalar_t)) != ELLIPTIC_CURVE_ALGEBRA_SUCCESS)
        goto cleanup;
    if (algebra->add_scalars(algebra, &tmp_scalar, tmp_scalar, sizeof(elliptic_curve256_scalar_t), *secret, sizeof(elliptic_curve256_scalar_t)) != ELLIPTIC_CURVE_ALGEBRA_SUCCESS)
        goto cleanup;
    if (algebra->generator_mul(algebra, &X, &tmp_scalar) != ELLIPTIC_CURVE_ALGEBRA_SUCCESS) // Y = A^beta*g^alpha == g^(a*beta+alpha)
        goto cleanup;

    const uint32_t ring_pedersen_n_size = (uint32_t)BN_num_bytes(ring_pedersen->n);
    const uint32_t paillier_n_size = (uint32_t)BN_num_bytes(paillier->n);

    // sample e
    if (!genarate_diffie_hellman_zkpok_seed(paillier_n_size, ring_pedersen_n_size, &zkpok, ciphertext->ciphertext, &A, &B, &X, aad, aad_len, use_extended_seed, seed))
        goto cleanup;
    if (drng_new(seed, SHA256_DIGEST_LENGTH, &rng) != DRNG_SUCCESS)
    {
        status = ZKP_OUT_OF_MEMORY;
        goto cleanup;
    }

    do
    {
        if (drng_read_deterministic_rand(rng, e_val, sizeof(elliptic_curve256_scalar_t)) != DRNG_SUCCESS)
            goto cleanup;
        if (!BN_bin2bn(e_val, sizeof(elliptic_curve256_scalar_t), e))
            goto cleanup;
    } while (BN_cmp(e, q) >= 0);

    // calc z1, z2, z3, w
    if (!BN_mul(zkpok.base.z1, e, x, ctx))
        goto cleanup;
    if (!BN_add(zkpok.base.z1, zkpok.base.z1, alpha))
        goto cleanup;

    if (!BN_mod_exp(zkpok.base.z2, ciphertext->r, e, paillier->n, ctx))
        goto cleanup;
    if (!BN_mod_mul(zkpok.base.z2, zkpok.base.z2, r, paillier->n, ctx))
        goto cleanup;

    if (!BN_mul(zkpok.base.z3, e, mu, ctx))
        goto cleanup;
    if (!BN_add(zkpok.base.z3, zkpok.base.z3, gamma))
        goto cleanup;

    if (algebra->mul_scalars(algebra, &zkpok.w, *b, sizeof(elliptic_curve256_scalar_t), e_val, sizeof(elliptic_curve256_scalar_t)) != ELLIPTIC_CURVE_ALGEBRA_SUCCESS)
        goto cleanup;
    if (algebra->add_scalars(algebra, &zkpok.w, zkpok.w, sizeof(elliptic_curve256_scalar_t), beta, sizeof(elliptic_curve256_scalar_t)) != ELLIPTIC_CURVE_ALGEBRA_SUCCESS)
        goto cleanup;

    status = serialize_diffie_hellman_zkpok(&zkpok, ring_pedersen->n, paillier->n, serialized_proof) != NULL ? ZKP_SUCCESS : ZKP_OUT_OF_MEMORY;

cleanup:
    if (alpha)
    {
        BN_clear(alpha);
    }

    if (mu)
    {
        BN_clear(mu);
    }

    if (r)
    {
        BN_clear(r);
    }

    if (gamma)
    {
        BN_clear(gamma);
    }

    if (e)
    {
        BN_clear(e);
    }

    if (x)
    {
        BN_clear(x);
    }
    
    if (tmp)
    {
        BN_clear(tmp);
    }

    OPENSSL_cleanse(alpha_bin, sizeof(elliptic_curve256_scalar_t));
    OPENSSL_cleanse(tmp_scalar, sizeof(elliptic_curve256_scalar_t));
    drng_free(rng);
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    return status;
}

zero_knowledge_proof_status range_proof_paillier_encrypt_with_diffie_hellman_zkpok_generate(const ring_pedersen_public_t *ring_pedersen, const paillier_public_key_t *paillier, const elliptic_curve256_algebra_ctx_t *algebra,
    const uint8_t *aad, uint32_t aad_len, const elliptic_curve256_scalar_t *secret, const elliptic_curve256_scalar_t *a, const elliptic_curve256_scalar_t *b, const uint8_t use_extended_seed, paillier_with_range_proof_t **proof)
{
    paillier_ciphertext_t *ciphertext = NULL;
    paillier_with_range_proof_t *local_proof = NULL;
    zero_knowledge_proof_status status = ZKP_OUT_OF_MEMORY;

    if (!paillier || !secret)
        return ZKP_INVALID_PARAMETER;

    if (paillier_encrypt_to_ciphertext(paillier, *secret, sizeof(elliptic_curve256_scalar_t), &ciphertext) != PAILLIER_SUCCESS)
    {
        status = ZKP_UNKNOWN_ERROR;
        goto cleanup;
    }

    local_proof = (paillier_with_range_proof_t*)calloc(1, sizeof(paillier_with_range_proof_t));
    if (!local_proof)
        goto cleanup;

    paillier_get_ciphertext(ciphertext, NULL, 0, &local_proof->ciphertext_len);
    local_proof->ciphertext = (uint8_t*)malloc(local_proof->ciphertext_len);

    local_proof->proof_len = diffie_hellman_zkpok_serialized_size(ring_pedersen, paillier);
    local_proof->serialized_proof = (uint8_t*)malloc(local_proof->proof_len);

    if (!local_proof->ciphertext || !local_proof->serialized_proof)
    {
        goto cleanup;
    }

    if (paillier_get_ciphertext(ciphertext, local_proof->ciphertext, local_proof->ciphertext_len, NULL)  != PAILLIER_SUCCESS)
    {
        goto cleanup;
    }

    status = range_proof_diffie_hellman_zkpok_generate(ring_pedersen, paillier, algebra, aad, aad_len, secret, a, b, ciphertext, use_extended_seed, local_proof->serialized_proof, local_proof->proof_len, NULL);

    if (status == ZKP_SUCCESS)
    {
        *proof = local_proof;
        local_proof = NULL;
    }

cleanup:
    range_proof_free_paillier_with_range_proof(local_proof);
    paillier_free_ciphertext(ciphertext);
    return status;
}

zero_knowledge_proof_status range_proof_diffie_hellman_zkpok_verify(const ring_pedersen_private_t *ring_pedersen,
                                                                    const paillier_public_key_t *paillier,
                                                                    const elliptic_curve256_algebra_ctx_t *algebra,
                                                                    const uint8_t *aad,
                                                                    uint32_t aad_len,
                                                                    const elliptic_curve256_point_t *public_point,
                                                                    const elliptic_curve256_point_t *A,
                                                                    const elliptic_curve256_point_t *B,
                                                                    const paillier_with_range_proof_t *proof,
                                                                    const uint8_t strict_ciphertext_length,
                                                                    const uint8_t use_extended_seed)
{
    BN_CTX *ctx = NULL;
    drng_t *rng = NULL;
    range_proof_diffie_hellman_zkpok_t zkpok;
    uint32_t needed_proof_len;
    zero_knowledge_proof_status status = ZKP_OUT_OF_MEMORY;
    BIGNUM *e = NULL, *tmp1 = NULL, *tmp2 = NULL;
    const BIGNUM *q;
    uint8_t seed[SHA256_DIGEST_LENGTH];
    elliptic_curve256_scalar_t val;
    elliptic_curve256_scalar_t z1;
    elliptic_curve256_point_t p1;
    elliptic_curve256_point_t p2;

    if (!ring_pedersen || !paillier || !algebra || !aad || !aad_len || !public_point || !A || !B || !proof || !proof->ciphertext || !proof->ciphertext_len || !proof->serialized_proof || !proof->proof_len)
        return ZKP_INVALID_PARAMETER;


    if (strict_ciphertext_length && proof->ciphertext_len != (uint32_t)BN_num_bytes(paillier->n2))
    {
        return ZKP_INVALID_PARAMETER;
    }

    needed_proof_len = diffie_hellman_zkpok_serialized_size(&ring_pedersen->pub, paillier);
    if (proof->proof_len < needed_proof_len)
        return ZKP_INVALID_PARAMETER;

    ctx = BN_CTX_new();

    if (!ctx)
        return ZKP_OUT_OF_MEMORY;

    BN_CTX_start(ctx);

    e = BN_CTX_get(ctx);
    tmp1 = BN_CTX_get(ctx);
    tmp2 = BN_CTX_get(ctx);

    if (!e || !tmp1 || !tmp2)
        goto cleanup;

    status = init_diffie_hellman_zkpok(&zkpok, ctx);
    if (status != ZKP_SUCCESS)
        goto cleanup;

    status = ZKP_UNKNOWN_ERROR;
    if (!deserialize_diffie_hellman_zkpok(&zkpok, ring_pedersen->pub.n, paillier->n, proof->serialized_proof))
    {
        status = ZKP_VERIFICATION_FAILED;
        goto cleanup;
    }

    if (is_coprime_fast(zkpok.base.D, paillier->n, ctx) != 1)
    {
        status = ZKP_VERIFICATION_FAILED;
        goto cleanup;
    }

    if (!BN_set_bit(tmp1, (sizeof(elliptic_curve256_scalar_t) + ZKPOK_EPSILON_SIZE) * 8))
        goto cleanup;
    if (BN_ucmp(zkpok.base.z1, tmp1) > 0) // range check
    {
        status = ZKP_VERIFICATION_FAILED;
        goto cleanup;
    }

    if (!BN_bin2bn(proof->ciphertext, proof->ciphertext_len, tmp1))
    {
        status = ZKP_OUT_OF_MEMORY;
        goto cleanup;
    }

    if (is_coprime_fast(tmp1, paillier->n, ctx) != 1)
    {
        status = ZKP_VERIFICATION_FAILED;
        goto cleanup;
    }

    if (is_coprime_fast(zkpok.base.S, ring_pedersen->pub.n, ctx) != 1)
    {
        status = ZKP_VERIFICATION_FAILED;
        goto cleanup;
    }

    if (is_coprime_fast(zkpok.base.T, ring_pedersen->pub.n, ctx) != 1)
    {
        status = ZKP_VERIFICATION_FAILED;
        goto cleanup;
    }

    const uint32_t ring_pedersen_n_size = (uint32_t)BN_num_bytes(ring_pedersen->pub.n);
    const uint32_t paillier_n_size = (uint32_t)BN_num_bytes(paillier->n);

    // sample e
    if (!genarate_diffie_hellman_zkpok_seed(paillier_n_size, ring_pedersen_n_size, &zkpok, tmp1, A, B, public_point, aad, aad_len, use_extended_seed, seed))
    {
        status = ZKP_UNKNOWN_ERROR;
        goto cleanup;
    }
    if (drng_new(seed, SHA256_DIGEST_LENGTH, &rng) != DRNG_SUCCESS)
        goto cleanup;

    q = algebra->order_internal(algebra);

    do
    {
        if (drng_read_deterministic_rand(rng, val, sizeof(elliptic_curve256_scalar_t)) != DRNG_SUCCESS)
        {
            status = ZKP_UNKNOWN_ERROR;
            goto cleanup;
        }
        if (!BN_bin2bn(val, sizeof(elliptic_curve256_scalar_t), e))
            goto cleanup;
    } while (BN_cmp(e, q) >= 0);

    if (paillier_encrypt_openssl_internal(paillier, tmp2, zkpok.base.z2, zkpok.base.z1, ctx) != PAILLIER_SUCCESS)
        goto cleanup;
    if (!BN_mod_exp(tmp1, tmp1, e, paillier->n2, ctx))
        goto cleanup;
    if (!BN_mod_mul(tmp1, tmp1, zkpok.base.D, paillier->n2, ctx))
        goto cleanup;

    if (BN_cmp(tmp1, tmp2) != 0)
    {
        status = ZKP_VERIFICATION_FAILED;
        goto cleanup;
    }

    if (ring_pedersen_create_commitment_internal(&ring_pedersen->pub, zkpok.base.z1, zkpok.base.z3, tmp2, ctx) != RING_PEDERSEN_SUCCESS)
        goto cleanup;

    if (!BN_mod_exp(tmp1, zkpok.base.S, e, ring_pedersen->pub.n, ctx))
        goto cleanup;
    if (!BN_mod_mul(tmp1, tmp1, zkpok.base.T, ring_pedersen->pub.n, ctx))
        goto cleanup;

    if (BN_cmp(tmp1, tmp2) != 0)
    {
        status = ZKP_VERIFICATION_FAILED;
        goto cleanup;
    }

    if (!BN_mod(zkpok.base.z1, zkpok.base.z1, q, ctx))
        goto cleanup;

    if (BN_bn2binpad(zkpok.base.z1, z1, sizeof(elliptic_curve256_scalar_t)) <= 0)
        goto cleanup;
    if (algebra->point_mul(algebra, &p1, A, &zkpok.w) != ELLIPTIC_CURVE_ALGEBRA_SUCCESS)
        goto cleanup;
    if (algebra->generator_mul(algebra, &p2, &z1) != ELLIPTIC_CURVE_ALGEBRA_SUCCESS)
        goto cleanup;
    if (algebra->add_points(algebra, &p1, &p1, &p2) != ELLIPTIC_CURVE_ALGEBRA_SUCCESS)
        goto cleanup;
    if (algebra->point_mul(algebra, &p2, public_point, &val) != ELLIPTIC_CURVE_ALGEBRA_SUCCESS)
        goto cleanup;
    if (algebra->add_points(algebra, &p2, &p2, &zkpok.Y) != ELLIPTIC_CURVE_ALGEBRA_SUCCESS)
        goto cleanup;

    if (memcmp(p1, p2, sizeof(elliptic_curve256_point_t)) != 0)
    {
        status = ZKP_VERIFICATION_FAILED;
        goto cleanup;
    }

    if (algebra->point_mul(algebra, &p1, B, &val) != ELLIPTIC_CURVE_ALGEBRA_SUCCESS)
        goto cleanup;
    if (algebra->add_points(algebra, &p1, &p1, &zkpok.base.Y) != ELLIPTIC_CURVE_ALGEBRA_SUCCESS)
        goto cleanup;
    if (algebra->generator_mul(algebra, &p2, &zkpok.w) != ELLIPTIC_CURVE_ALGEBRA_SUCCESS)
        goto cleanup;

    status = memcmp(p1, p2, sizeof(elliptic_curve256_point_t)) == 0 ? ZKP_SUCCESS : ZKP_VERIFICATION_FAILED;
cleanup:
    drng_free(rng);
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    return status;
}

void range_proof_free_paillier_with_range_proof(paillier_with_range_proof_t *proof)
{
    if (proof)
    {
        free(proof->ciphertext);
        free(proof->serialized_proof);
        free(proof);
    }
}

// paillier large factors zkp
static inline uint32_t paillier_large_factors_zkp_serialized_size(const ring_pedersen_public_t *pub, const paillier_public_key_t *paillier)
{
    return
        sizeof(uint32_t) + // sizeof(ring_pedersen->n)
        sizeof(uint32_t) + // sizeof(paillier->n)
        5 * BN_num_bytes(pub->n) + // sizeof(P) + sizeof(Q) + sizeof(A) + sizeof(B) + sizeof(T)
        ZKPOK_L_SIZE + BN_num_bytes(pub->n) + BN_num_bytes(paillier->n) + // sizeof(lambda)
        2 * (ZKPOK_L_SIZE + ZKPOK_EPSILON_SIZE + (BN_num_bytes(paillier->n) / 2)) + // sizeof(z1) + sizeof(z2)
        2 * (ZKPOK_L_SIZE + ZKPOK_EPSILON_SIZE + BN_num_bytes(pub->n)) + // sizeof(w1) + sizeof(w2)
        ZKPOK_L_SIZE + ZKPOK_EPSILON_SIZE + BN_num_bytes(pub->n) + BN_num_bytes(paillier->n); // sizeof(v)
}

// this function doesn't verify serialized_proof size as it's done in range_proof_paillier_large_factors_zkp_generate function
static inline uint8_t* serialize_paillier_large_factors_zkp(const range_proof_paillier_large_factors_zkp_t *proof, const BIGNUM *ring_pedersen_n, const BIGNUM *paillier_n, uint8_t *serialized_proof)
{
    const uint32_t ring_pedersen_n_size = (uint32_t)BN_num_bytes(ring_pedersen_n);
    const uint32_t paillier_n_size = (uint32_t)BN_num_bytes(paillier_n);
    const uint32_t lambda_size = ZKPOK_L_SIZE + ring_pedersen_n_size + paillier_n_size;
    const uint32_t z_size = ZKPOK_L_SIZE + ZKPOK_EPSILON_SIZE + paillier_n_size / 2;
    const uint32_t w_size = ZKPOK_L_SIZE + ZKPOK_EPSILON_SIZE + ring_pedersen_n_size;
    const uint32_t v_size = ZKPOK_L_SIZE + ZKPOK_EPSILON_SIZE + ring_pedersen_n_size + paillier_n_size;
    uint8_t *ptr = serialized_proof;

    if (BN_num_bytes(proof->lambda) > (int)lambda_size)
        return NULL;
    if (BN_num_bytes(proof->z1) > (int)z_size || BN_num_bytes(proof->z2) > (int)z_size)
        return NULL;
    if (BN_num_bytes(proof->w1) > (int)w_size || BN_num_bytes(proof->w2) > (int)w_size)
        return NULL;
    if (BN_num_bytes(proof->v) > (int)v_size)
        return NULL;

    *(uint32_t*)ptr = ring_pedersen_n_size;
    ptr += sizeof(uint32_t);
    *(uint32_t*)ptr = paillier_n_size;
    ptr += sizeof(uint32_t);

    if (BN_bn2binpad(proof->P, ptr, ring_pedersen_n_size) <= 0)
        return NULL;
    ptr += ring_pedersen_n_size;
    if (BN_bn2binpad(proof->Q, ptr, ring_pedersen_n_size) <= 0)
        return NULL;
    ptr += ring_pedersen_n_size;
    if (BN_bn2binpad(proof->A, ptr, ring_pedersen_n_size) <= 0)
        return NULL;
    ptr += ring_pedersen_n_size;
    if (BN_bn2binpad(proof->B, ptr, ring_pedersen_n_size) <= 0)
        return NULL;
    ptr += ring_pedersen_n_size;
    if (BN_bn2binpad(proof->T, ptr, ring_pedersen_n_size) <= 0)
        return NULL;
    ptr += ring_pedersen_n_size;
    if (BN_bn2binpad(proof->lambda, ptr, lambda_size) <= 0)
        return NULL;
    ptr += lambda_size;
    if (BN_bn2binpad(proof->z1, ptr, z_size) <= 0)
        return NULL;
    ptr += z_size;
    if (BN_bn2binpad(proof->z2, ptr, z_size) <= 0)
        return NULL;
    ptr += z_size;
    if (BN_bn2binpad(proof->w1, ptr, w_size) <= 0)
        return NULL;
    ptr += w_size;
    if (BN_bn2binpad(proof->w2, ptr, w_size) <= 0)
        return NULL;
    ptr += w_size;
    if (BN_bn2binpad(proof->v, ptr, v_size) <= 0)
        return NULL;
    ptr += v_size;
    return ptr;
}

static inline const uint8_t* deserialize_paillier_large_factors_zkp(range_proof_paillier_large_factors_zkp_t *proof,
                                                                    const BIGNUM *ring_pedersen_n,
                                                                    const BIGNUM *paillier_n,
                                                                    const uint8_t *serialized_proof)
{
    const uint32_t ring_pedersen_n_size = (uint32_t)BN_num_bytes(ring_pedersen_n);
    const uint32_t paillier_n_size = (uint32_t)BN_num_bytes(paillier_n);
    const uint32_t lambda_size = ZKPOK_L_SIZE + ring_pedersen_n_size + paillier_n_size;
    const uint32_t z_size = ZKPOK_L_SIZE + ZKPOK_EPSILON_SIZE + paillier_n_size / 2;
    const uint32_t w_size = ZKPOK_L_SIZE + ZKPOK_EPSILON_SIZE + ring_pedersen_n_size;
    const uint32_t v_size = ZKPOK_L_SIZE + ZKPOK_EPSILON_SIZE + ring_pedersen_n_size + paillier_n_size;
    const uint8_t *ptr = serialized_proof;

    if (*(uint32_t*)ptr != ring_pedersen_n_size)
        return NULL;
    ptr += sizeof(uint32_t);
    if (*(uint32_t*)ptr != paillier_n_size)
        return NULL;
    ptr += sizeof(uint32_t);
    if (!BN_bin2bn(ptr, ring_pedersen_n_size, proof->P))
        return NULL;
    ptr += ring_pedersen_n_size;
    if (!BN_bin2bn(ptr, ring_pedersen_n_size, proof->Q))
        return NULL;
    ptr += ring_pedersen_n_size;
    if (!BN_bin2bn(ptr, ring_pedersen_n_size, proof->A))
        return NULL;
    ptr += ring_pedersen_n_size;
    if (!BN_bin2bn(ptr, ring_pedersen_n_size, proof->B))
        return NULL;
    ptr += ring_pedersen_n_size;
    if (!BN_bin2bn(ptr, ring_pedersen_n_size, proof->T))
        return NULL;
    ptr += ring_pedersen_n_size;
    if (!BN_bin2bn(ptr, lambda_size, proof->lambda))
        return NULL;
    ptr += lambda_size;
    if (!BN_bin2bn(ptr, z_size, proof->z1))
        return NULL;
    ptr += z_size;
    if (!BN_bin2bn(ptr, z_size, proof->z2))
        return NULL;
    ptr += z_size;
    if (!BN_bin2bn(ptr, w_size, proof->w1))
        return NULL;
    ptr += w_size;
    if (!BN_bin2bn(ptr, w_size, proof->w2))
        return NULL;
    ptr += w_size;
    if (!BN_bin2bn(ptr, v_size, proof->v))
        return NULL;
    ptr += v_size;
    return ptr;
}

static zero_knowledge_proof_status init_paillier_large_factors_zkp(range_proof_paillier_large_factors_zkp_t *zkp, BN_CTX *ctx)
{
    zkp->P = BN_CTX_get(ctx);
    zkp->Q = BN_CTX_get(ctx);
    zkp->A = BN_CTX_get(ctx);
    zkp->B = BN_CTX_get(ctx);
    zkp->T = BN_CTX_get(ctx);
    zkp->lambda = BN_CTX_get(ctx);
    zkp->z1 = BN_CTX_get(ctx);
    zkp->z2 = BN_CTX_get(ctx);
    zkp->w1 = BN_CTX_get(ctx);
    zkp->w2 = BN_CTX_get(ctx);
    zkp->v = BN_CTX_get(ctx);

    if (zkp->P && zkp->Q && zkp->A && zkp->B && zkp->T && zkp->lambda && zkp->z1 && zkp->z2 && zkp->w1 && zkp->w2 && zkp->v)
        return ZKP_SUCCESS;
    return ZKP_OUT_OF_MEMORY;
}


static inline int genarate_paillier_large_factors_zkp_seed_ex(const range_proof_paillier_large_factors_zkp_t *proof,
                                                              const BIGNUM *ring_pedersen_n,
                                                              const BIGNUM *paillier_n,
                                                              const uint8_t *aad,
                                                              uint32_t aad_len,
                                                              uint8_t *seed)
{
    SHA256_CTX ctx;
    const uint32_t ring_pedersen_n_size = (uint32_t)BN_num_bytes(ring_pedersen_n);
    const uint32_t paillier_n_size = (uint32_t)BN_num_bytes(paillier_n);
    const uint32_t lambda_size = ZKPOK_L_SIZE + ring_pedersen_n_size + paillier_n_size;
    uint8_t *n = (uint8_t*)malloc(lambda_size); //lambda has the maximum size in the proof

    if (!n)
    {
        return 0;
    }


    SHA256_Init(&ctx);
    SHA256_Update(&ctx, PAILLIER_LARGE_FACTORS_ZKP_SALT, sizeof(PAILLIER_LARGE_FACTORS_ZKP_SALT));
    if (aad)
    {
        SHA256_Update(&ctx, aad, aad_len);
    }

    if (BN_bn2binpad(paillier_n, n, paillier_n_size) <= 0)
    {
        goto error;
    }
    SHA256_Update(&ctx, n, paillier_n_size);

    // hash P
    assert ((uint32_t)BN_num_bytes(proof->P) <= ring_pedersen_n_size);
    if (BN_bn2binpad(proof->P, n, ring_pedersen_n_size) <= 0)
    {
        goto error;
    }
    SHA256_Update(&ctx, n, ring_pedersen_n_size);

    // hash Q
    assert ((uint32_t)BN_num_bytes(proof->Q) <= ring_pedersen_n_size);
    if (BN_bn2binpad(proof->Q, n, ring_pedersen_n_size) <= 0)
    {
        goto error;
    }
    SHA256_Update(&ctx, n, ring_pedersen_n_size);

    // hash A
    assert ((uint32_t)BN_num_bytes(proof->A) <= ring_pedersen_n_size);
    if (BN_bn2binpad(proof->A, n, ring_pedersen_n_size) <= 0)
    {
        goto error;
    }
    SHA256_Update(&ctx, n, ring_pedersen_n_size);

    // hash B
    assert ((uint32_t)BN_num_bytes(proof->B) <= ring_pedersen_n_size);
    if (BN_bn2binpad(proof->B, n, ring_pedersen_n_size) <= 0)
    {
        goto error;
    }
    SHA256_Update(&ctx, n, ring_pedersen_n_size);

    // hash T
    assert ((uint32_t)BN_num_bytes(proof->T) <= ring_pedersen_n_size);
    if (BN_bn2binpad(proof->T, n, ring_pedersen_n_size) <= 0)
    {
        goto error;
    }
    SHA256_Update(&ctx, n, ring_pedersen_n_size);

    // hash lambda
    assert ((uint32_t)BN_num_bytes(proof->lambda) <= lambda_size);
    if (BN_bn2binpad(proof->lambda, n, lambda_size) <= 0)
    {
        goto error;
    }
    SHA256_Update(&ctx, n, lambda_size);

    free(n);
    SHA256_Final(seed, &ctx);
    return 1;

error:
    free(n);
    return 0;
}

static inline int genarate_paillier_large_factors_zkp_seed(const range_proof_paillier_large_factors_zkp_t *proof,
                                                           const BIGNUM *ring_pedersen_n,
                                                           const BIGNUM *paillier_n,
                                                           const uint8_t *aad,
                                                           uint32_t aad_len,
                                                           uint8_t *seed)
{
    SHA256_CTX ctx;
    const uint32_t ring_pedersen_n_size = (uint32_t)BN_num_bytes(ring_pedersen_n);
    const uint32_t paillier_n_size = (uint32_t)BN_num_bytes(paillier_n);
    const uint32_t lambda_size = ZKPOK_L_SIZE + ring_pedersen_n_size + paillier_n_size;
    uint8_t *n = (uint8_t*)malloc(lambda_size); //lambda has the maximum size in the proof

    if (!n)
        return 0;

    SHA256_Init(&ctx);
    SHA256_Update(&ctx, PAILLIER_LARGE_FACTORS_ZKP_SALT, sizeof(PAILLIER_LARGE_FACTORS_ZKP_SALT));
    if (aad)
        SHA256_Update(&ctx, aad, aad_len);
    BN_bn2bin(paillier_n, n);
    SHA256_Update(&ctx, n, paillier_n_size);
    BN_bn2bin(proof->P, n);
    SHA256_Update(&ctx, n, BN_num_bytes(proof->P));
    BN_bn2bin(proof->Q, n);
    SHA256_Update(&ctx, n, BN_num_bytes(proof->Q));
    BN_bn2bin(proof->A, n);
    SHA256_Update(&ctx, n, BN_num_bytes(proof->A));
    BN_bn2bin(proof->B, n);
    SHA256_Update(&ctx, n, BN_num_bytes(proof->B));
    BN_bn2bin(proof->T, n);
    SHA256_Update(&ctx, n, BN_num_bytes(proof->T));
    BN_bn2bin(proof->lambda, n);
    SHA256_Update(&ctx, n, BN_num_bytes(proof->lambda));
    free(n);
    SHA256_Final(seed, &ctx);
    return 1;
}

zero_knowledge_proof_status range_proof_paillier_large_factors_zkp_generate(const paillier_private_key_t *priv,
                                                                            const ring_pedersen_public_t *ring_pedersen,
                                                                            const uint8_t *aad,
                                                                            uint32_t aad_len,
                                                                            const uint8_t use_extended_seed,
                                                                            uint8_t *serialized_proof,
                                                                            uint32_t proof_len,
                                                                            uint32_t *real_proof_len)
{
    BN_CTX *ctx = NULL;
    range_proof_paillier_large_factors_zkp_t zkp;
    zero_knowledge_proof_status status = ZKP_OUT_OF_MEMORY;
    BIGNUM *alpha = NULL, *beta = NULL, *mu = NULL, *sigma = NULL, *r = NULL, *e = NULL, *x = NULL, *y = NULL, *tmp = NULL;
    elliptic_curve256_scalar_t e_val;
    uint32_t needed_len;
    uint32_t ring_pedersen_n_size;
    uint32_t paillier_n_size;
    uint32_t lambda_size;
    uint32_t z_size;
    uint32_t w_size;
    uint32_t v_size;

    if (!priv || !ring_pedersen || (!aad && aad_len) || (!serialized_proof && proof_len))
        return ZKP_INVALID_PARAMETER;

    ring_pedersen_n_size = BN_num_bytes(ring_pedersen->n);
    paillier_n_size = BN_num_bytes(priv->pub.n);
    lambda_size = ZKPOK_L_SIZE + ring_pedersen_n_size + paillier_n_size;
    z_size = ZKPOK_L_SIZE + ZKPOK_EPSILON_SIZE + paillier_n_size / 2;
    w_size = ZKPOK_L_SIZE + ZKPOK_EPSILON_SIZE + ring_pedersen_n_size;
    v_size = ZKPOK_L_SIZE + ZKPOK_EPSILON_SIZE + ring_pedersen_n_size + paillier_n_size;

    needed_len = paillier_large_factors_zkp_serialized_size(ring_pedersen, &priv->pub);
    if (real_proof_len)
        *real_proof_len = needed_len;
    if (proof_len < needed_len)
        return ZKP_INSUFFICIENT_BUFFER;

    ctx = BN_CTX_new();

    if (!ctx)
        return ZKP_OUT_OF_MEMORY;

    BN_CTX_start(ctx);
    alpha = BN_CTX_get(ctx);
    beta = BN_CTX_get(ctx);
    mu = BN_CTX_get(ctx);
    sigma = BN_CTX_get(ctx);
    r = BN_CTX_get(ctx);
    e = BN_CTX_get(ctx);
    x = BN_CTX_get(ctx);
    y = BN_CTX_get(ctx);
    tmp = BN_CTX_get(ctx);

    if (!alpha || !beta || !mu || !sigma || !r || !e || !x || !y || !tmp)
        goto cleanup;

    status = init_paillier_large_factors_zkp(&zkp, ctx);
    if (status != ZKP_SUCCESS)
        goto cleanup;

    status = ZKP_UNKNOWN_ERROR;
    if (!BN_rand(alpha, z_size * 8, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY))
        goto cleanup;
    if (!BN_rand(beta, z_size * 8, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY))
        goto cleanup;
    if (!BN_rand(mu, (ZKPOK_L_SIZE + ring_pedersen_n_size) * 8, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY))
        goto cleanup;
    if (!BN_rand(sigma, (ZKPOK_L_SIZE + ring_pedersen_n_size) * 8, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY))
        goto cleanup;
    if (!BN_rand(zkp.lambda, lambda_size * 8, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY))
        goto cleanup;
    if (!BN_rand(r, v_size * 8, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY))
        goto cleanup;
    if (!BN_rand(x, w_size * 8, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY))
        goto cleanup;
    if (!BN_rand(y, w_size * 8, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY))
        goto cleanup;

    if (RING_PEDERSEN_SUCCESS != ring_pedersen_create_commitment_internal(ring_pedersen, priv->p, mu, zkp.P, ctx))
        goto cleanup;
    if (RING_PEDERSEN_SUCCESS != ring_pedersen_create_commitment_internal(ring_pedersen, priv->q, sigma, zkp.Q, ctx))
        goto cleanup;
    if (RING_PEDERSEN_SUCCESS != ring_pedersen_create_commitment_internal(ring_pedersen, alpha, x, zkp.A, ctx))
        goto cleanup;
    if (RING_PEDERSEN_SUCCESS != ring_pedersen_create_commitment_internal(ring_pedersen, beta, y, zkp.B, ctx))
        goto cleanup;
    if (!BN_mod_exp2_mont(zkp.T, zkp.Q, alpha, ring_pedersen->t, r, ring_pedersen->n, ctx, ring_pedersen->mont))
        goto cleanup;

    if (use_extended_seed)
    {
        if (!genarate_paillier_large_factors_zkp_seed_ex(&zkp, ring_pedersen->n, priv->pub.n, aad, aad_len, e_val))
        {
            status = ZKP_OUT_OF_MEMORY;
            goto cleanup;
        }
    }
    else
    {
        if (!genarate_paillier_large_factors_zkp_seed(&zkp, ring_pedersen->n, priv->pub.n, aad, aad_len, e_val))
        {
            status = ZKP_OUT_OF_MEMORY;
            goto cleanup;
        }
    }


    if (!BN_bin2bn(e_val, sizeof(elliptic_curve256_scalar_t), e))
        goto cleanup;

    if (!BN_mul(zkp.z1, e, priv->p, ctx) || !BN_add(zkp.z1, zkp.z1, alpha))
        goto cleanup;
    if (!BN_mul(zkp.z2, e, priv->q, ctx) || !BN_add(zkp.z2, zkp.z2, beta))
        goto cleanup;
    if (!BN_mul(zkp.w1, e, mu, ctx) || !BN_add(zkp.w1, zkp.w1, x))
        goto cleanup;
    if (!BN_mul(zkp.w2, e, sigma, ctx) || !BN_add(zkp.w2, zkp.w2, y))
        goto cleanup;

    if (!BN_mul(tmp, sigma, priv->p, ctx) || !BN_sub(tmp, zkp.lambda, tmp)) // calc lambda hat
        goto cleanup;
    if (!BN_mul(zkp.v, e, tmp, ctx) || !BN_add(zkp.v, zkp.v, r))
        goto cleanup;

    status = serialize_paillier_large_factors_zkp(&zkp, ring_pedersen->n, priv->pub.n, serialized_proof) ? ZKP_SUCCESS : ZKP_INVALID_PARAMETER;

cleanup:
    if (alpha)
    {
        BN_clear(alpha);
    }
    if (beta)
    {
        BN_clear(beta);
    }
    if (mu)
    {
        BN_clear(mu);
    }
    if (sigma)
    {
        BN_clear(sigma);
    }
    if (r)
    {
        BN_clear(r);
    }
    if (e)
    {
        BN_clear(e);
    }
    if (x)
    {
        BN_clear(x);
    }
    if (y)
    {
        BN_clear(y);
    }
    if (tmp)
    {
        BN_clear(tmp);
    }
    OPENSSL_cleanse(e_val, sizeof(elliptic_curve256_scalar_t));

    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    return status;
}

zero_knowledge_proof_status range_proof_paillier_large_factors_zkp_verify(const paillier_public_key_t *pub,
                                                                          const ring_pedersen_private_t *ring_pedersen,
                                                                          const uint8_t *aad,
                                                                          uint32_t aad_len,
                                                                          const uint8_t use_extended_seed,
                                                                          const uint8_t *serialized_proof,
                                                                          uint32_t proof_len)
{
    BN_CTX *ctx = NULL;
    range_proof_paillier_large_factors_zkp_t zkp;
    zero_knowledge_proof_status status = ZKP_OUT_OF_MEMORY;
    BIGNUM *e = NULL, *R = NULL, *tmp1 = NULL, *tmp2 = NULL;
    elliptic_curve256_scalar_t e_val;
    uint32_t needed_len;
    int expected_size;

    if (!pub || !ring_pedersen || (!aad && aad_len) || !serialized_proof || !proof_len)
        return ZKP_INVALID_PARAMETER;

    needed_len = paillier_large_factors_zkp_serialized_size(&ring_pedersen->pub, pub);
    if (proof_len < needed_len)
        return ZKP_INVALID_PARAMETER;

    ctx = BN_CTX_new();

    if (!ctx)
        return ZKP_OUT_OF_MEMORY;

    BN_CTX_start(ctx);

    e = BN_CTX_get(ctx);
    R = BN_CTX_get(ctx);
    tmp1 = BN_CTX_get(ctx);
    tmp2 = BN_CTX_get(ctx);

    if (!e || !R || !tmp1 || !tmp2)
        goto cleanup;

    status = init_paillier_large_factors_zkp(&zkp, ctx);
    if (status != ZKP_SUCCESS)
        goto cleanup;

    status = ZKP_UNKNOWN_ERROR;
    if (!deserialize_paillier_large_factors_zkp(&zkp, ring_pedersen->pub.n, pub->n, serialized_proof))
    {
        status = ZKP_VERIFICATION_FAILED;
        goto cleanup;
    }

    // sample e
    if (use_extended_seed)
    {
        if (!genarate_paillier_large_factors_zkp_seed_ex(&zkp, ring_pedersen->pub.n, pub->n, aad, aad_len, e_val))
        {
            status = ZKP_UNKNOWN_ERROR;
            goto cleanup;
        }
    }
    else
    {
        if (!genarate_paillier_large_factors_zkp_seed(&zkp, ring_pedersen->pub.n, pub->n, aad, aad_len, e_val))
        {
            status = ZKP_UNKNOWN_ERROR;
            goto cleanup;
        }
    }
    if (!BN_bin2bn(e_val, sizeof(elliptic_curve256_scalar_t), e))
            goto cleanup;

    if (RING_PEDERSEN_SUCCESS != ring_pedersen_create_commitment_internal(&ring_pedersen->pub, pub->n, zkp.lambda, R, ctx))
        goto cleanup;

    if (RING_PEDERSEN_SUCCESS != ring_pedersen_create_commitment_internal(&ring_pedersen->pub, zkp.z1, zkp.w1, tmp1, ctx))
        goto cleanup;
    if (!BN_mod_exp(tmp2, zkp.P, e, ring_pedersen->pub.n, ctx) || !BN_mod_mul(tmp2, tmp2, zkp.A, ring_pedersen->pub.n, ctx))
        goto cleanup;
    if (BN_cmp(tmp1, tmp2) != 0)
    {
        status = ZKP_VERIFICATION_FAILED;
        goto cleanup;
    }

    if (RING_PEDERSEN_SUCCESS != ring_pedersen_create_commitment_internal(&ring_pedersen->pub, zkp.z2, zkp.w2, tmp1, ctx))
        goto cleanup;
    if (!BN_mod_exp(tmp2, zkp.Q, e, ring_pedersen->pub.n, ctx) || !BN_mod_mul(tmp2, tmp2, zkp.B, ring_pedersen->pub.n, ctx))
        goto cleanup;
    if (BN_cmp(tmp1, tmp2) != 0)
    {
        status = ZKP_VERIFICATION_FAILED;
        goto cleanup;
    }

    if (!BN_mod_exp(tmp1, zkp.Q, zkp.z1, ring_pedersen->pub.n, ctx))
        goto cleanup;
    if (!BN_mod_exp(tmp2, ring_pedersen->pub.t, zkp.v, ring_pedersen->pub.n, ctx))
        goto cleanup;
    if (!BN_mod_mul(tmp1, tmp1, tmp2, ring_pedersen->pub.n, ctx))
        goto cleanup;
    if (!BN_mod_exp(tmp2, R, e, ring_pedersen->pub.n, ctx) || !BN_mod_mul(tmp2, tmp2, zkp.T, ring_pedersen->pub.n, ctx))
        goto cleanup;
    if (BN_cmp(tmp1, tmp2) != 0)
    {
        status = ZKP_VERIFICATION_FAILED;
        goto cleanup;
    }

    expected_size = ZKPOK_L_SIZE + ZKPOK_EPSILON_SIZE + BN_num_bytes(pub->n) / 2;

    if (BN_num_bytes(zkp.z1) <= expected_size && BN_num_bytes(zkp.z2) <= expected_size)
        status = ZKP_SUCCESS;
    else
        status = ZKP_VERIFICATION_FAILED;

cleanup:
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    return status;
}

/*********************************************************
 *
 *    PAILLER RANGE PROOF WITH QUADRATIC MODULAR ELEMENTS
 *
 *********************************************************/

// it is expected that the caller would call BN_CTX_start()
// before calling this function and BN_CTX_end() after calling it
static inline zero_knowledge_proof_status range_proof_paillier_large_factors_quadratic_zkp_initialize(range_proof_paillier_large_factors_quadratic_zkp_t* zkp, BN_CTX *ctx)
{
    if (!zkp || !ctx)
    {
        return ZKP_INVALID_PARAMETER;
    }
    OPENSSL_cleanse(zkp, sizeof(range_proof_paillier_large_factors_quadratic_zkp_t));

    zkp->setup.d_mont = BN_MONT_CTX_new();
    if (!zkp->setup.d_mont)
    {
        return ZKP_OUT_OF_MEMORY;
    }
    zkp->setup.d = BN_CTX_get(ctx);
    zkp->setup.d_minus_1_over_2 = BN_CTX_get(ctx);
    zkp->setup.P = BN_CTX_get(ctx);
    zkp->setup.Q = BN_CTX_get(ctx);
    zkp->A = BN_CTX_get(ctx);
    zkp->B = BN_CTX_get(ctx);
    zkp->C = BN_CTX_get(ctx);
    zkp->lambda1 = BN_CTX_get(ctx);
    zkp->lambda2 = BN_CTX_get(ctx);
    zkp->w = BN_CTX_get(ctx);
    zkp->z1 = BN_CTX_get(ctx);
    zkp->z2 = BN_CTX_get(ctx);

    // only need to check the last allocation was successful
    if (zkp->setup.d &&
        zkp->setup.d_minus_1_over_2 &&
        zkp->setup.P &&
        zkp->setup.Q &&
        zkp->A &&
        zkp->B &&
        zkp->C &&
        zkp->lambda1 &&
        zkp->lambda2 &&
        zkp->w &&
        zkp->z1 &&
        zkp->z2)
    {
        return ZKP_SUCCESS;
    }

    BN_MONT_CTX_free(zkp->setup.d_mont);
    zkp->setup.d_mont = NULL;

    return ZKP_OUT_OF_MEMORY;
}

// "nothing up my sleeve" refers to the principle of transparency
// in the generation of constants or parameters used in cryptographic algorithms.
// The phrase means that the creators of the cryptographic system are not hiding any
// hidden backdoors or weaknesses in the design by using arbitrary or suspicious values.
// generates g and h as nothing-up-my-sleeve based on aad
static inline zero_knowledge_proof_status range_proof_pailler_quadratic_generate_basis(BIGNUM* g,
                                                                                       BIGNUM* h,
                                                                                       const BIGNUM* d,
                                                                                       const uint8_t* aad,
                                                                                       uint32_t aad_len,
                                                                                       BN_CTX *ctx)
{
    drng_t* rng = NULL;
    long ret = -1;

    const uint32_t d_size = (uint32_t)BN_num_bytes(d);
    const uint32_t salted_msg_len = (uint32_t)sizeof(PAILLER_LARGE_FACTORS_QUADRATIC_ZKP_SEED) + aad_len + d_size;

    #define BIAS_PROTECTION_BYTES 16
    #define MAX_AAD_LEN 4096
    if (d_size > MAX_D_SIZE || aad_len > MAX_AAD_LEN)
    {
        goto cleanup; //protect from stack overflow. Normally should be around 3K
    }

    uint8_t* buffer = (uint8_t*)alloca(salted_msg_len + BIAS_PROTECTION_BYTES);

    memcpy(buffer, PAILLER_LARGE_FACTORS_QUADRATIC_ZKP_SEED, sizeof(PAILLER_LARGE_FACTORS_QUADRATIC_ZKP_SEED));
    memcpy(buffer + sizeof(PAILLER_LARGE_FACTORS_QUADRATIC_ZKP_SEED), aad, aad_len);
    BN_bn2bin(d, buffer + sizeof(PAILLER_LARGE_FACTORS_QUADRATIC_ZKP_SEED) + aad_len );

    ret = convert_drng_to_zkp_status(drng_new(buffer, salted_msg_len, &rng));
    if (ret != ZKP_SUCCESS)
    {
        goto cleanup;
    }

    // generate 'g' as nothing-up-my-sleeve
    ret = convert_drng_to_zkp_status(drng_read_deterministic_rand(rng, buffer, d_size  + BIAS_PROTECTION_BYTES));
    if (ret != ZKP_SUCCESS)
    {
        goto cleanup;
    }

    ret = -1; //reset ret to openssl error

    if (!BN_bin2bn(buffer, d_size  + BIAS_PROTECTION_BYTES, g))
    {
        goto cleanup;
    }

    // make sure it's a square mod d
    if (!BN_mod_sqr(g, g, d, ctx))
    {
        goto cleanup;
    }

    // generate 'h' as nothing-up-my-sleeve
    ret = convert_drng_to_zkp_status(drng_read_deterministic_rand(rng, buffer, d_size  + BIAS_PROTECTION_BYTES));
    if (ret != ZKP_SUCCESS)
    {
        goto cleanup;
    }

    ret = -1; //reset ret to openssl error

    if (!BN_bin2bn(buffer, d_size  + BIAS_PROTECTION_BYTES, h))
    {

        goto cleanup;
    }

    // make sure it's a square mod d
    if (!BN_mod_sqr(h, h, d, ctx))
    {
        goto cleanup;
    }

    ret = ZKP_SUCCESS;

cleanup:
    if (-1 == ret)
    {
        ERR_clear_error();
        ret = ZKP_UNKNOWN_ERROR;
    }

    drng_free(rng);

    return ret;
}

uint32_t range_proof_paillier_large_factors_quadratic_zkp_compute_d_bitsize(const paillier_public_key_t* pub)
{
    if (!pub)
    {
        return 0;
    }

    const uint32_t n_bitsize = paillier_public_key_size(pub);
    return n_bitsize + 2 * ZKPOK_OPTIM_L_SIZE(n_bitsize) * 8  + 2 * ZKPOK_OPTIM_NU_SIZE(n_bitsize) * 8  + /*4 extra bit*/ 4;
}

// will generate the group Z/d s.t. d >= n*2^(2*(ZKPOK_OPTIM_L_SIZE*8)), with the 'Pedersen' basis
// generates g and h as nothing-up-my-sleeve based on aad
// Uses predefined or generates a prime d which is large enough to hold the result
// when calculates P = g ^ p * h ^ r in mod d  AND  Q = g ^ q * h ^ s in mod d
// where r and s are random
static inline zero_knowledge_proof_status range_proof_pailler_quadratic_generate_setup(paillier_large_factors_quadratic_setup_t* setup,
                                                                                       BIGNUM* r,
                                                                                       BIGNUM* s,
                                                                                       BIGNUM* g,
                                                                                       BIGNUM* h,
                                                                                       const BIGNUM* d,
                                                                                       const paillier_private_key_t* priv,
                                                                                       const uint8_t* aad,
                                                                                       const uint32_t aad_len,
                                                                                       BN_CTX *ctx)
{
    if (!setup || !r || !s || !g || !h || !priv || (aad && !aad_len) || (!aad && aad_len) || !ctx)
    {
        return ZKP_INVALID_PARAMETER;
    }

    long ret = -1;
    const uint32_t d_bitsize = range_proof_paillier_large_factors_quadratic_zkp_compute_d_bitsize(&priv->pub);


    if (d)
    {
        //verify that d is big enough and it is a prime
        if ((uint32_t)BN_num_bits(d) < d_bitsize || BN_is_prime_ex(d, BN_prime_checks, ctx, NULL) != 1)
        {
            ret = ZKP_INVALID_PARAMETER;
            goto cleanup;
        }
        if (!BN_copy(setup->d, d))
        {
            goto cleanup;
        }
    }
    else
    {
        do
        {
            //generate safe prime - VERY LARGE and slow
            if (!BN_generate_prime_ex(setup->d, d_bitsize, 1, NULL, NULL, NULL))
            {
                goto cleanup;
            }
        } while ((uint32_t)BN_num_bits(setup->d) < d_bitsize);
    }

    // setup->d_minus_1_over_2 = setup->d / 2
    if (!BN_rshift1(setup->d_minus_1_over_2, setup->d))
    {
        goto cleanup;
    }

    // if d was given, verify that it is a strong prime
    if (d && BN_is_prime_ex(setup->d_minus_1_over_2, BN_prime_checks, ctx, NULL) != 1)
    {
        ret = ZKP_INVALID_PARAMETER;
        goto cleanup;
    }

    if (!BN_MONT_CTX_set(setup->d_mont, setup->d, ctx))
    {
        goto cleanup;
    }

    ret = range_proof_pailler_quadratic_generate_basis(g, h, setup->d, aad, aad_len, ctx);
    if (ret != ZKP_SUCCESS)
    {
        goto cleanup;
    }

    ret = -1; //cleanup ret for openssl errors

    // Generate P and Q
    if (!BN_rand(r, 2 * ZKPOK_OPTIM_L_SIZE(BN_num_bits(priv->pub.n)) * 8, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY) ||
        !BN_rand(s, 2 * ZKPOK_OPTIM_L_SIZE(BN_num_bits(priv->pub.n)) * 8, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY) )
    {
        goto cleanup;
    }

    // P = g ^ p * h ^ r in mod d
    if (!BN_mod_exp2_mont(setup->P, g, priv->p, h, r, setup->d, ctx, setup->d_mont))
    {
        goto cleanup;
    }

    // Q = g ^ q * h ^ s in mod d
    if (!BN_mod_exp2_mont(setup->Q, g, priv->q, h, s, setup->d, ctx, setup->d_mont))
    {
        goto cleanup;
    }

    ret = ZKP_SUCCESS;

cleanup:
    if (-1 == ret)
    {
        ERR_clear_error();
        ret = ZKP_UNKNOWN_ERROR;
    }

    return ret;
}

static inline int generate_paillier_large_factors_quadratic_zkp_seed(const range_proof_paillier_large_factors_quadratic_zkp_t *proof,
                                                                     const paillier_public_key_t *pub,
                                                                     const uint8_t *aad,
                                                                     const uint32_t aad_len,
                                                                     uint8_t *seed)
{
    SHA256_CTX ctx;
    const uint32_t d_size = (uint32_t)BN_num_bytes(proof->setup.d);
    const uint32_t n_size = (uint32_t)BN_num_bytes(pub->n);

    if (d_size > MAX_D_SIZE ||
        n_size > d_size)
    {
        return 0; //protect from stack overflow. Normally should be around 3K
    }

    uint8_t *tmp = (uint8_t*)alloca(d_size); //use alloca for fast allocation


    SHA256_Init(&ctx);
    SHA256_Update(&ctx, PAILLIER_LARGE_FACTORS_ZKP_SALT, sizeof(PAILLIER_LARGE_FACTORS_ZKP_SALT));
    if (aad)
    {
        SHA256_Update(&ctx, aad, aad_len);
    }

    if (BN_bn2binpad(pub->n, tmp, n_size) <= 0)
    {
        return 0;
    }
    SHA256_Update(&ctx, tmp, n_size);

    if (BN_bn2binpad(proof->setup.d, tmp, d_size) <= 0)
    {
        return 0;
    }
    SHA256_Update(&ctx, tmp, d_size);

    assert((uint32_t)BN_num_bytes(proof->setup.P) <= d_size);
    if (BN_bn2binpad(proof->setup.P, tmp, d_size) <= 0)
    {
        return 0;
    }
    SHA256_Update(&ctx, tmp, d_size);

    assert((uint32_t)BN_num_bytes(proof->setup.Q) <= d_size);
    if (BN_bn2binpad(proof->setup.Q, tmp, d_size) <= 0)
    {
        return 0;
    }
    SHA256_Update(&ctx, tmp, d_size);

    assert((uint32_t)BN_num_bytes(proof->A) <= d_size);
    if (BN_bn2binpad(proof->A, tmp, d_size) <= 0)
    {
        return 0;
    }
    SHA256_Update(&ctx, tmp, d_size);

    assert((uint32_t)BN_num_bytes(proof->B) <= d_size);
    if (BN_bn2binpad(proof->B, tmp, d_size) <= 0)
    {
        return 0;
    }
    SHA256_Update(&ctx, tmp, d_size);

    assert((uint32_t)BN_num_bytes(proof->C) <= d_size);
    if (BN_bn2binpad(proof->C, tmp, d_size) <= 0)
    {
        return 0;
    }
    SHA256_Update(&ctx, tmp, d_size);

    SHA256_Final(seed, &ctx);

    return 1;

}

static inline uint32_t paillier_large_factors_quadratic_z_size_bytes(const uint32_t n_bitlsize)
{
    return ((n_bitlsize + 1) / 2 + ((ZKPOK_OPTIM_L_SIZE(n_bitlsize) + ZKPOK_OPTIM_NU_SIZE(n_bitlsize)) * 8 ) + 7) / 8;
}

static inline uint8_t* serialize_paillier_large_factors_quadratic(const range_proof_paillier_large_factors_quadratic_zkp_t* zkp,
                                                                  const uint32_t n_bitlsize,
                                                                  uint8_t *serialized_proof)
{
    uint8_t* ptr = serialized_proof;
    const uint32_t d_size = (uint32_t)BN_num_bytes(zkp->setup.d);
    const uint32_t z_size = paillier_large_factors_quadratic_z_size_bytes(n_bitlsize);
    const uint32_t lambda_size = (3 * ZKPOK_OPTIM_L_SIZE(n_bitlsize)) + ZKPOK_OPTIM_NU_SIZE(n_bitlsize);

    *(uint32_t*)ptr =  d_size;
    ptr += sizeof(uint32_t);

    if (BN_bn2binpad(zkp->setup.d, ptr, d_size) <= 0)
    {
        return NULL;
    }
    ptr += d_size; // store sizeof(uint32_t) + 1 * d_size

    if (BN_bn2binpad(zkp->setup.P, ptr, d_size) <= 0)
    {
        return NULL;
    }
    ptr += d_size; // store sizeof(uint32_t) + 2 * d_size

    if (BN_bn2binpad(zkp->setup.Q, ptr, d_size) <= 0)
    {
        return NULL;
    }
    ptr += d_size; // store sizeof(uint32_t) + 3 * d_size

    if (BN_bn2binpad(zkp->A, ptr, d_size) <= 0)
    {
        return NULL;
    }
    ptr += d_size; // store sizeof(uint32_t) + 4 * d_size

    if (BN_bn2binpad(zkp->B, ptr, d_size) <= 0)
    {
        return NULL;
    }
    ptr += d_size; // store sizeof(uint32_t) + 5 * d_size

    if (BN_bn2binpad(zkp->C, ptr, d_size) <= 0)
    {
        return NULL;
    }
    ptr += d_size; // store sizeof(uint32_t) + 6 * d_size

    assert((uint32_t)BN_num_bytes(zkp->z1) <= z_size); //can be smaller because depends on a random value of alpha
    if (BN_bn2binpad(zkp->z1, ptr, z_size) <= 0)
    {
        return NULL;
    }
    ptr += z_size; // store sizeof(uint32_t) + 6 * d_size +  z_size

    assert((uint32_t)BN_num_bytes(zkp->z2) <= z_size); //can be smalle because depends on a random value of beta
    if (BN_bn2binpad(zkp->z2, ptr, z_size) <= 0)
    {
        return NULL;
    }
    ptr += z_size; // store sizeof(uint32_t) + 6 * d_size +  2 * z_size

    if (BN_bn2binpad(zkp->lambda1, ptr, lambda_size) <= 0)
    {
        return NULL;
    }
    ptr += lambda_size; // store sizeof(uint32_t) + 6 * d_size +  2 * z_size + lambda_size

    if (BN_bn2binpad(zkp->lambda2, ptr, lambda_size) <= 0)
    {
        return NULL;
    }
    ptr += lambda_size; // store sizeof(uint32_t) + 6 * d_size +  2 * z_size + 2 * lambda_size

    if (BN_bn2binpad(zkp->w, ptr, d_size) <= 0)
    {
        return NULL;
    }
    ptr += d_size; // store sizeof(uint32_t) + 7 * d_size +  2 * z_size + 2 * lambda_size

    return ptr;
}

static inline uint32_t paillier_large_factors_quadratic_proof_size_from_dsize(const uint32_t d_size, const uint32_t n_bitlen)
{
    const uint32_t z_size = paillier_large_factors_quadratic_z_size_bytes(n_bitlen) ;
    return sizeof(uint32_t) + 7 * d_size + 2 * z_size + 2 * (3 * ZKPOK_OPTIM_L_SIZE(n_bitlen) + ZKPOK_OPTIM_NU_SIZE(n_bitlen));
}

static inline uint32_t paillier_large_factors_quadratic_proof_size(const paillier_public_key_t* pub, const uint32_t d_prime_len)
{
    const uint32_t d_bitsize = d_prime_len ? d_prime_len * 8 : range_proof_paillier_large_factors_quadratic_zkp_compute_d_bitsize(pub);
    const uint32_t d_size = (d_bitsize + 7) / 8; //convert to bytes of d
    const uint32_t n_bitlen = paillier_public_key_size(pub);

    return paillier_large_factors_quadratic_proof_size_from_dsize(d_size, n_bitlen);
}


static inline const uint8_t* deserialize_paillier_large_factors_quadratic(range_proof_paillier_large_factors_quadratic_zkp_t* zkp,
                                                                          const uint8_t* serialized_proof,
                                                                          const uint32_t n_bitlsize,
                                                                          uint32_t proof_len,
                                                                          BN_CTX* ctx)
{
    const uint32_t z_size = paillier_large_factors_quadratic_z_size_bytes(n_bitlsize);
    const uint32_t lambda_size = (3 * ZKPOK_OPTIM_L_SIZE(n_bitlsize)) + ZKPOK_OPTIM_NU_SIZE(n_bitlsize);
    const uint8_t* ptr = serialized_proof;
    uint32_t d_size;
    if (proof_len < sizeof(uint32_t))
    {
        return NULL;
    }

    d_size = *(const uint32_t*)ptr; // read sizeof(uint32_t)
    ptr += sizeof(uint32_t);
    if (!d_size || d_size > MAX_D_SIZE)
    {
        return NULL;
    }

    if (proof_len < paillier_large_factors_quadratic_proof_size_from_dsize(d_size, n_bitlsize))
    {
        return NULL;
    }

    if (!BN_bin2bn(ptr, d_size, zkp->setup.d))
    {
        return NULL;
    }
    ptr += d_size; // read sizeof(uint32_t) + 1 * d_size

    if (!BN_rshift1(zkp->setup.d_minus_1_over_2, zkp->setup.d))
    {
        return NULL;
    }

    if (!BN_MONT_CTX_set(zkp->setup.d_mont, zkp->setup.d, ctx))
    {
        return NULL;
    }

    if (!BN_bin2bn(ptr, d_size, zkp->setup.P))
    {
        return NULL;
    }
    ptr += d_size; // read sizeof(uint32_t) + 2 * d_size

    if (!BN_bin2bn(ptr, d_size, zkp->setup.Q))
    {
        return NULL;
    }
    ptr += d_size; // read sizeof(uint32_t) + 3 * d_size

    if (!BN_bin2bn(ptr, d_size, zkp->A))
    {
        return NULL;
    }
    ptr += d_size; // read sizeof(uint32_t) + 4 * d_size

    if (!BN_bin2bn(ptr, d_size, zkp->B))
    {
        return NULL;
    }
    ptr += d_size; // read sizeof(uint32_t) + 5 * d_size

    if (!BN_bin2bn(ptr, d_size, zkp->C))
    {
        return NULL;
    }
    ptr += d_size; // read sizeof(uint32_t) + 6 * d_size

    if (!BN_bin2bn(ptr, z_size, zkp->z1))
    {
        return NULL;
    }
    ptr += z_size; // read sizeof(uint32_t) + 6 * d_size + z_size

    if (!BN_bin2bn(ptr, z_size, zkp->z2))
    {
        return NULL;
    }
    ptr += z_size; // read sizeof(uint32_t) + 6 * d_size + 2* z_size

    if (!BN_bin2bn(ptr, lambda_size, zkp->lambda1))
    {
        return NULL;
    }
    ptr += lambda_size; // read sizeof(uint32_t) + 6 * d_size + 2* z_size + lambda_size

    if (!BN_bin2bn(ptr, lambda_size, zkp->lambda2))
    {
        return NULL;
    }
    ptr += lambda_size;// read sizeof(uint32_t) + 6 * d_size + 2* z_size + 2 * lambda_size

    if (!BN_bin2bn(ptr, d_size, zkp->w))
    {
        return NULL;
    }
    ptr += d_size; // read sizeof(uint32_t) + 7 * d_size + 2* z_size + 2 * lambda_size

    return ptr;
}


zero_knowledge_proof_status range_proof_paillier_large_factors_quadratic_zkp_generate(const paillier_private_key_t *priv,
                                                                                      const uint8_t *aad,
                                                                                      const uint32_t aad_len,
                                                                                      const uint8_t *d_prime,
                                                                                      const uint32_t d_prime_len,
                                                                                      uint8_t *serialized_proof,
                                                                                      uint32_t proof_len,
                                                                                      uint32_t *real_proof_len)
{
    BN_CTX *ctx = NULL;
    BIGNUM *alpha = NULL, *beta = NULL, *rho = NULL, *sigma = NULL, *mu = NULL, *e = NULL, *r = NULL, *s = NULL, *g = NULL, *h = NULL, *d = NULL, *tmp = NULL;
    long ret = -1;
    range_proof_paillier_large_factors_quadratic_zkp_t zkp;
    uint8_t seed[SHA256_DIGEST_LENGTH];
    uint32_t required_len;
    uint32_t n_bitlsize;
    uint8_t* end_of_serialized_data;

    if (!priv || (!aad && aad_len) || (!serialized_proof && proof_len) || (!d_prime_len && d_prime))
    {
        return ZKP_INVALID_PARAMETER;
    }

    required_len = paillier_large_factors_quadratic_proof_size(&priv->pub, d_prime_len);

    if (real_proof_len)
    {
        *real_proof_len = required_len;
    }

    if (proof_len < required_len)
    {
        return ZKP_INSUFFICIENT_BUFFER;
    }

    n_bitlsize = paillier_public_key_size(&priv->pub);

    if (ZKPOK_OPTIM_L_SIZE(n_bitlsize) > SHA256_DIGEST_LENGTH)
    {
        return ZKP_INVALID_PARAMETER;
    }

    ctx = BN_CTX_new();
    if (!ctx)
    {
        return ZKP_OUT_OF_MEMORY;
    }

    BN_CTX_start(ctx);
    ret = range_proof_paillier_large_factors_quadratic_zkp_initialize(&zkp, ctx);
    if (ZKP_SUCCESS != ret)
    {
        goto cleanup;
    }

    g = BN_CTX_get(ctx);
    h = BN_CTX_get(ctx);
    r = BN_CTX_get(ctx);
    s = BN_CTX_get(ctx);

    if (!g || !h || !r || !s)
    {
        ret = ZKP_OUT_OF_MEMORY;
        goto cleanup;
    }

    alpha = BN_CTX_get(ctx);
    beta  = BN_CTX_get(ctx);
    sigma = BN_CTX_get(ctx);
    rho   = BN_CTX_get(ctx);
    mu    = BN_CTX_get(ctx);
    e     = BN_CTX_get(ctx);
    tmp   = BN_CTX_get(ctx);

    if (!alpha || !beta || !sigma || !rho || !mu || !e || !tmp)
    {
        ret = ZKP_OUT_OF_MEMORY;
        goto cleanup;
    }

    if (d_prime)
    {
        d = BN_CTX_get(ctx);
        if (!d)
        {
            ret = ZKP_OUT_OF_MEMORY;
            goto cleanup;
        }

        if (!BN_bin2bn(d_prime, d_prime_len, d))
        {
            goto cleanup;
        }
    }

    ret = range_proof_pailler_quadratic_generate_setup(&zkp.setup, r, s, g, h, d, priv, aad, aad_len, ctx);
    if (ZKP_SUCCESS != ret)
    {
        goto cleanup;
    }

    ret = -1; //reset for OpenSSL errors

    // tmp will hold floor(sqrt(N) << k), computed as (N >> |N|/2) << k
    if (!BN_rshift(tmp, priv->pub.n, (n_bitlsize + 1) / 2 - ((ZKPOK_OPTIM_L_SIZE(n_bitlsize) + ZKPOK_OPTIM_NU_SIZE(n_bitlsize)) * 8 )) ||
        !BN_rand_range(alpha, tmp) ||
        !BN_rand_range(beta, tmp)  ||
        // sigma and rho must be 3l + nu bits
        !BN_rand(sigma, ZKPOK_OPTIM_SMALL_GROUP_EXPONENT_BITS(n_bitlsize) + ZKPOK_OPTIM_L_SIZE(n_bitlsize) * 8, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY) ||
        !BN_rand(rho, ZKPOK_OPTIM_SMALL_GROUP_EXPONENT_BITS(n_bitlsize) + ZKPOK_OPTIM_L_SIZE(n_bitlsize) * 8, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY)   ||
        // we now pick mu to be 3*l + n_bit/2 + nu bits long
        !BN_lshift(tmp, tmp, (2 * ZKPOK_OPTIM_L_SIZE(n_bitlsize)) * 8) ||
        !BN_rand_range(mu, tmp)    ||
        !BN_mod_exp2_mont(zkp.A, g, alpha, h, rho, zkp.setup.d, ctx, zkp.setup.d_mont)  ||
        !BN_mod_exp2_mont(zkp.B, g, beta, h, sigma, zkp.setup.d, ctx, zkp.setup.d_mont) ||
        !BN_mod_exp2_mont(zkp.C, zkp.setup.Q, alpha, h, mu, zkp.setup.d, ctx, zkp.setup.d_mont)
    )
    {
        goto cleanup;
    }

    // generate seed based on zkp values
    if (!generate_paillier_large_factors_quadratic_zkp_seed(&zkp, &priv->pub, aad, aad_len, seed))
    {
        ret = ZKP_UNKNOWN_ERROR;
        goto cleanup;
    }

    if (!BN_bin2bn(seed, ZKPOK_OPTIM_L_SIZE(n_bitlsize), e))
    {
        goto cleanup;
    }

    if ( // z1 = alpha + ep
        !BN_mul(zkp.z1, e, priv->p, ctx) ||
        !BN_add(zkp.z1, zkp.z1, alpha) ||
        // z2 = beta + eq
        !BN_mul(zkp.z2, e, priv->q, ctx) ||
        !BN_add(zkp.z2, zkp.z2, beta) ||
        // lambda1 = rho + er [(d-1)/2]
        !BN_mod_mul(zkp.lambda1, e, r, zkp.setup.d_minus_1_over_2, ctx) ||
        !BN_mod_add_quick(zkp.lambda1, zkp.lambda1, rho, zkp.setup.d_minus_1_over_2) ||
        // lambda2 = sigma + es [(d-1)/2]
        !BN_mod_mul(zkp.lambda2, e, s, zkp.setup.d_minus_1_over_2, ctx) ||
        !BN_mod_add_quick(zkp.lambda2, zkp.lambda2, sigma, zkp.setup.d_minus_1_over_2) ||
        // w = mu - esp [(d-1)/2]
        !BN_mod_mul(zkp.w, s, priv->p, zkp.setup.d_minus_1_over_2, ctx) ||
        !BN_mod_mul(zkp.w, zkp.w, e, zkp.setup.d_minus_1_over_2, ctx) ||
        !BN_mod_sub_quick(zkp.w, mu, zkp.w, zkp.setup.d_minus_1_over_2)
    )
    {
        goto cleanup;
    }

    end_of_serialized_data = serialize_paillier_large_factors_quadratic(&zkp, n_bitlsize, serialized_proof);

    if (!end_of_serialized_data)
    {
        ret = ZKP_UNKNOWN_ERROR;
        goto cleanup;
    }

    // clean up all the remaining bytes
    // can happen if initial size of d was incorerct and real d takes less bytes
    OPENSSL_cleanse(end_of_serialized_data, proof_len - (end_of_serialized_data - serialized_proof));

    if (real_proof_len)
    {
        *real_proof_len = (end_of_serialized_data - serialized_proof);
    }

    ret = ZKP_SUCCESS;

cleanup:
    if (-1 == ret)
    {
        ERR_clear_error();
        ret = ZKP_UNKNOWN_ERROR;
    }
    if (r)
    {
        BN_clear(r);
    }
    if (s)
    {
        BN_clear(s);
    }

    if (alpha)
    {
        BN_clear(alpha);
    }
    if (beta)
    {
        BN_clear(beta);
    }
    if (sigma)
    {
        BN_clear(sigma);
    }
    if (rho)
    {
        BN_clear(rho);
    }
    if (mu)
    {
        BN_clear(mu);
    }
    if (tmp)
    {
        BN_clear(tmp);
    }


    BN_CTX_end(ctx);
    BN_CTX_free(ctx);

    if (zkp.setup.d_mont)
    {
        BN_MONT_CTX_free(zkp.setup.d_mont);
    }

    return ret;
}

static zero_knowledge_proof_status range_proof_paillier_large_factors_quadratic_verify_setup(const paillier_large_factors_quadratic_setup_t* setup, const paillier_public_key_t* pub, BN_CTX* ctx)
{
    long ret = -1;

    BN_CTX_start(ctx);

    BIGNUM* tmp = BN_CTX_get(ctx);
    if (!tmp)
    {
        return ZKP_OUT_OF_MEMORY;
    }

    // ensure that the d is large enough
    if ((uint32_t)BN_num_bits(setup->d) < range_proof_paillier_large_factors_quadratic_zkp_compute_d_bitsize(pub))
    {
        ret = ZKP_VERIFICATION_FAILED;
        goto cleanup;
    }

    if (!BN_add(tmp, setup->d_minus_1_over_2, setup->d_minus_1_over_2) ||
        !BN_add_word(tmp, 1))
    {
        goto cleanup;
    }

    if (BN_cmp(tmp, setup->d) != 0 ||
        BN_is_prime_ex(setup->d, BN_prime_checks, ctx, NULL) != 1 ||
        BN_is_prime_ex(setup->d_minus_1_over_2, BN_prime_checks, ctx, NULL) != 1 ||
        BN_cmp(setup->d, setup->P) <= 0 || // make sure P, Q are smaller than 'd'
        BN_cmp(setup->d, setup->Q) <= 0 ||
        BN_kronecker(setup->P, setup->d, ctx) != 1 || // make sure that P, Q are indeed quadratic residues.
        BN_kronecker(setup->Q, setup->d, ctx) != 1)
    {
        ret = ZKP_VERIFICATION_FAILED;
        goto cleanup;
    }

    ret = ZKP_SUCCESS;

cleanup:
    if (-1 == ret)
    {
        ERR_clear_error();
        ret = ZKP_UNKNOWN_ERROR;
    }

    BN_CTX_end(ctx);

    return ret;
}

static zero_knowledge_proof_status range_proof_paillier_large_factors_quadratic_zkp_verify_internal(const paillier_public_key_t *pub,
                                                                                                    const uint8_t *aad,
                                                                                                    const uint32_t aad_len,
                                                                                                    const range_proof_paillier_large_factors_quadratic_zkp_t* zkp,
                                                                                                    const BIGNUM* g,
                                                                                                    const BIGNUM* h,
                                                                                                    BN_CTX* ctx)
{
    long ret = -1;
    uint8_t seed[SHA256_DIGEST_LENGTH];
    uint32_t n_bitsize;

    BN_CTX_start(ctx);

    BIGNUM* upper_limit = BN_CTX_get(ctx);
    BIGNUM* lhs = BN_CTX_get(ctx);
    BIGNUM* rhs = BN_CTX_get(ctx);
    BIGNUM* e = BN_CTX_get(ctx);

    if (!upper_limit || !lhs || !rhs || !e)
    {
        ret = ZKP_OUT_OF_MEMORY;
        goto cleanup;
    }

    n_bitsize = paillier_public_key_size(pub);
    if (ZKPOK_OPTIM_L_SIZE(n_bitsize) > SHA256_DIGEST_LENGTH)
    {
        ret = ZKP_INVALID_PARAMETER;
        goto cleanup;
    }

    ret = range_proof_paillier_large_factors_quadratic_verify_setup(&zkp->setup, pub, ctx);
    if (ret != ZKP_SUCCESS)
    {
        goto cleanup;
    }

    //reset ret to handle OpenSSL errors
    ret = -1;

    if (!BN_rshift(upper_limit, pub->n, (n_bitsize + 1) / 2 - ((ZKPOK_OPTIM_L_SIZE(n_bitsize) + ZKPOK_OPTIM_NU_SIZE(n_bitsize)) * 8)))
    {
        goto cleanup;
    }


    if (BN_cmp(zkp->z1, upper_limit) >= 0 ||
        BN_cmp(zkp->z2, upper_limit) >= 0 )
    {
        ret = ZKP_VERIFICATION_FAILED;
        goto cleanup;
    }

    if (!generate_paillier_large_factors_quadratic_zkp_seed(zkp, pub, aad, aad_len, seed))
    {
        ret = ZKP_UNKNOWN_ERROR;
        goto cleanup;
    }


    if (!BN_bin2bn(seed, ZKPOK_OPTIM_L_SIZE(n_bitsize), e))
    {
        goto cleanup;
    }

    if (!BN_mod_exp2_mont(lhs, g, zkp->z1, h, zkp->lambda1, zkp->setup.d, ctx, zkp->setup.d_mont) ||
        !BN_mod_exp2_mont(rhs, zkp->A, BN_value_one(), zkp->setup.P, e, zkp->setup.d, ctx, zkp->setup.d_mont))
    {
        goto cleanup;
    }

    if (BN_cmp(lhs, rhs) != 0)
    {
        ret = ZKP_VERIFICATION_FAILED;
        goto cleanup;
    }

    if (!BN_mod_exp2_mont(lhs, g, zkp->z2, h, zkp->lambda2, zkp->setup.d, ctx, zkp->setup.d_mont) ||
        !BN_mod_exp2_mont(rhs, zkp->B, BN_value_one(), zkp->setup.Q, e, zkp->setup.d, ctx, zkp->setup.d_mont))
    {
        goto cleanup;
    }

    if (BN_cmp(lhs, rhs) != 0)
    {
        ret = ZKP_VERIFICATION_FAILED;
        goto cleanup;
    }


    if (!BN_mul(e, e, pub->n, ctx) ||
        !BN_mod_exp2_mont(lhs, zkp->setup.Q, zkp->z1, h, zkp->w, zkp->setup.d, ctx, zkp->setup.d_mont) ||
        !BN_mod_exp2_mont(rhs, zkp->C, BN_value_one(), g, e, zkp->setup.d, ctx, zkp->setup.d_mont))
    {
        goto cleanup;
    }

    if (BN_cmp(lhs, rhs) != 0)
    {
        ret = ZKP_VERIFICATION_FAILED;
        goto cleanup;
    }

    ret = ZKP_SUCCESS;

cleanup:
    if (-1 == ret)
    {
        ERR_clear_error();
        ret = ZKP_UNKNOWN_ERROR;
    }

    BN_CTX_end(ctx);

    return ret;
}

zero_knowledge_proof_status range_proof_paillier_large_factors_quadratic_zkp_verify(const paillier_public_key_t *pub,
                                                                                    const uint8_t *aad,
                                                                                    const uint32_t aad_len,
                                                                                    const uint8_t *serialized_proof,
                                                                                    const uint32_t proof_len)
{
    BN_CTX *ctx = NULL;
    BIGNUM *g = NULL, *h = NULL;
    long ret = -1;
    range_proof_paillier_large_factors_quadratic_zkp_t zkp;

    if (!pub || (!aad && aad_len) || !serialized_proof)
    {
        return ZKP_INVALID_PARAMETER;
    }

    // at least the size of a uint32_t
    if (proof_len < sizeof(uint32_t))
    {
        return ZKP_INSUFFICIENT_BUFFER;
    }

    ctx = BN_CTX_new();
    if (!ctx)
    {
        return ZKP_OUT_OF_MEMORY;
    }

    BN_CTX_start(ctx);
    ret = range_proof_paillier_large_factors_quadratic_zkp_initialize(&zkp, ctx);
    if (ret != ZKP_SUCCESS)
    {
        goto cleanup;
    }

    g = BN_CTX_get(ctx);
    h = BN_CTX_get(ctx);
    if (!g || !h)
    {
        ret = ZKP_OUT_OF_MEMORY;
        goto cleanup;
    }

    if (!deserialize_paillier_large_factors_quadratic(&zkp, serialized_proof,  paillier_public_key_size(pub), proof_len, ctx))
    {
        ret = ZKP_UNKNOWN_ERROR;
        goto cleanup;
    }

    ret = range_proof_pailler_quadratic_generate_basis(g, h, zkp.setup.d, aad, aad_len, ctx);
    if (ret != ZKP_SUCCESS)
    {
        goto cleanup;
    }

    ret = range_proof_paillier_large_factors_quadratic_zkp_verify_internal(pub, aad, aad_len, &zkp, g, h, ctx);

cleanup:
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);

    if (zkp.setup.d_mont)
    {
        BN_MONT_CTX_free(zkp.setup.d_mont);
    }

    return ret;
}



// paillier small group with encrypted dlog
// the serialize_proof should point to a buffer of size at least
// exponent_zkpok_serialized_size_internal(damgard_fujisaki->n, paillier->paillier_public.n)
static zero_knowledge_proof_status range_proof_paillier_commitment_encrypt_exponent_zkpok_generate(const damgard_fujisaki_public_t *damgard_fujisaki,
                                                                                                   const paillier_commitment_private_key_t *paillier,
                                                                                                   const elliptic_curve256_algebra_ctx_t *algebra,
                                                                                                   const uint8_t *aad,
                                                                                                   const uint32_t aad_len,
                                                                                                   const uint8_t* secret,
                                                                                                   const uint32_t secret_len,
                                                                                                   const BIGNUM *ciphertext,
                                                                                                   const BIGNUM *r,
                                                                                                   const uint8_t use_extended_seed,
                                                                                                   uint8_t *serialized_proof)
{
    BN_CTX *ctx = NULL;
    drng_t *rng = NULL;
    range_proof_exponent_zkpok_t zkpok;
    long ret = -1;
    BIGNUM *alpha = NULL, *lambda_p = NULL, *mu = NULL, *mu_p = NULL, *e = NULL, *x = NULL, *tmp = NULL;
    const BIGNUM *q;
    elliptic_curve256_scalar_t alpha_bin;
    uint8_t seed[SHA256_DIGEST_LENGTH];
    elliptic_curve256_point_t public_point;
    uint32_t paillier_n_bitsize;
    if (!damgard_fujisaki || !paillier || !algebra || !aad || !aad_len || !secret || !secret_len || !ciphertext || !r || !serialized_proof)
    {
        return ZKP_INVALID_PARAMETER;
    }

    // because we require two proofs
    if (damgard_fujisaki->dimension < 2)
    {
        return ZKP_INVALID_PARAMETER;
    }

    ctx = BN_CTX_new();
    if (!ctx)
    {
        return ZKP_OUT_OF_MEMORY;
    }

    BN_CTX_start(ctx);
    alpha = BN_CTX_get(ctx);
    lambda_p = BN_CTX_get(ctx);
    mu_p = BN_CTX_get(ctx);
    mu = BN_CTX_get(ctx);
    e = BN_CTX_get(ctx);
    x = BN_CTX_get(ctx);
    tmp = BN_CTX_get(ctx);
    if (!alpha || !lambda_p || !mu || !mu_p || !e || !x || !tmp)
    {
        goto cleanup;
    }

    // all members of zkpok are allocated from the ctx
    ret = init_exponent_zkpok(&zkpok, ctx);
    if (ret != ZKP_SUCCESS)
    {
        goto cleanup;
    }

    ret = -1; //reset for OpenSSL errors

    if (!BN_bin2bn(secret, secret_len, x))
    {
        goto cleanup;
    }

    q = algebra->order_internal(algebra);

    paillier_n_bitsize = (uint32_t)paillier_commitment_public_bitsize(&paillier->pub);

    // generate S, D, Y, T
    if (!BN_set_bit(tmp, (secret_len + ZKPOK_OPTIM_EPSILON_SIZE(paillier_n_bitsize)) * 8)) // tmp = 2^(secret_len + ZKPOK_OPTIM_EPSILON_SIZE) * 8))
    {
        goto cleanup;
    }

    // rand alpha
    if (!BN_rand_range(alpha, tmp))
    {
        goto cleanup;
    }

    // rand mu
    if (!BN_copy(tmp, damgard_fujisaki->n) || !BN_lshift(tmp, tmp, ZKPOK_OPTIM_NU_SIZE(paillier_n_bitsize) * 8)) //tmp = n * 2^(ZKPOK_OPTIM_NU_SIZE*8)
    {
        goto cleanup;
    }

    if (!BN_rand_range(mu, tmp))
    {
        goto cleanup;
    }


    // rand mu_p
    if (!BN_lshift(tmp, tmp, ZKPOK_OPTIM_EPSILON_SIZE(paillier_n_bitsize) * 8))// tmp = n * 2^(ZKPOK_OPTIM_NU_SIZE*8 + ZKPOK_OPTIM_EPSILON_SIZE * 8)
    {
        goto cleanup;
    }

    if (!BN_rand_range(mu_p, tmp))
    {
        goto cleanup;
    }

    // the r_power_bitsize is called n(lambda prime) in the paper and it used for encryption of alpha
    // which is bigger than private share, thus we use larger exponent as in paillier_commitment_encrypt_with_exponent_zkpok_generate
    ret = convert_paillier_to_zkp_status(paillier_commitment_encrypt_openssl_with_private_internal(paillier,
                                                                                                   ZKPOK_OPTIM_SMALL_GROUP_EXPONENT_BITS(paillier_n_bitsize) + ZKPOK_OPTIM_EPSILON_SIZE(paillier_n_bitsize) * 8,
                                                                                                   alpha,
                                                                                                   ctx,
                                                                                                   zkpok.D,
                                                                                                   lambda_p));
    if (ret != ZKP_SUCCESS)
    {
        goto cleanup;
    }

    const BIGNUM* first_ped_committed_values[] = {x, r};
    ret = convert_ring_pedersen_to_zkp_status(damgard_fujisaki_create_commitment_internal(damgard_fujisaki,
                                                                                         first_ped_committed_values,
                                                                                         2,
                                                                                         mu,
                                                                                         zkpok.S,
                                                                                         ctx));
    if (ret != ZKP_SUCCESS)
    {
        goto cleanup;
    }

    const BIGNUM* second_ped_committed_values[] = {alpha, lambda_p};
    ret = convert_ring_pedersen_to_zkp_status(damgard_fujisaki_create_commitment_internal(damgard_fujisaki,
                                                                                         second_ped_committed_values,
                                                                                         2,
                                                                                         mu_p,
                                                                                         zkpok.T,
                                                                                         ctx));
    if (ret != ZKP_SUCCESS)
    {
        goto cleanup;
    }

    if (!BN_mod(tmp, alpha, q, ctx))
    {
        ret = -1; // OpenSSL error
        goto cleanup;
    }

    if (BN_bn2binpad(tmp, alpha_bin, sizeof(elliptic_curve256_scalar_t)) <= 0)
    {
        ret = -1;
        goto cleanup;
    }

    ret = convert_algebra_to_zkp_status(algebra->generator_mul(algebra, &zkpok.Y, &alpha_bin));
    if (ret != ZKP_SUCCESS)
    {
        goto cleanup;
    }

    ret = convert_algebra_to_zkp_status(algebra->generator_mul_data(algebra, secret, secret_len, &public_point));
    if (ret != ZKP_SUCCESS)
    {
        goto cleanup;
    }

    const uint32_t ring_pedersen_n_size = (uint32_t)BN_num_bytes(damgard_fujisaki->n);
    const uint32_t paillier_n_size = (uint32_t)BN_num_bytes(paillier->pub.n);

    // sample e
    if (!genarate_exponent_zkpok_seed(paillier_n_size, ring_pedersen_n_size, &zkpok, ciphertext, &public_point, aad, aad_len, use_extended_seed, seed))
    {
        ret = ZKP_UNKNOWN_ERROR;
        goto cleanup;
    }

    ret = convert_drng_to_zkp_status(drng_new(seed, SHA256_DIGEST_LENGTH, &rng));
    if (ret != ZKP_SUCCESS)
    {
        goto cleanup;
    }

    do
    {
        elliptic_curve256_scalar_t val;
        ret = convert_drng_to_zkp_status(drng_read_deterministic_rand(rng, val, ZKPOK_OPTIM_L_SIZE(paillier_n_bitsize)));
        if (ret != ZKP_SUCCESS)
        {
            goto cleanup;
        }
        ret = -1; //OpsnSSL error
        if (!BN_bin2bn(val, ZKPOK_OPTIM_L_SIZE(paillier_n_bitsize), e))
        {
            goto cleanup;
        }

    } while (BN_cmp(e, q) >= 0);

    // calc z1, z2, z3
    if (!BN_mul(zkpok.z1, e, x, ctx))
    {
        goto cleanup;
    }

    if (!BN_add(zkpok.z1, zkpok.z1, alpha))
    {
        goto cleanup;
    }


    if (!BN_mul(zkpok.z2, r, e, ctx))
    {
        goto cleanup;
    }

    if (!BN_add(zkpok.z2, zkpok.z2, lambda_p))
    {
        goto cleanup;
    }


    if (!BN_mul(zkpok.z3, e, mu, ctx))
    {
        goto cleanup;
    }

    if (!BN_add(zkpok.z3, zkpok.z3, mu_p))
    {
        goto cleanup;
    }

    ret = serialize_exponent_zkpok(&zkpok, damgard_fujisaki->n, paillier->pub.n, serialized_proof) != NULL ? ZKP_SUCCESS : ZKP_OUT_OF_MEMORY;

cleanup:
    if (-1 == ret)
    {
        ERR_clear_error();
        ret = ZKP_UNKNOWN_ERROR;
    }

    if (x)
    {
        //because x holds the secret
        BN_clear(x);
        BN_clear(alpha);
        BN_clear(lambda_p);
    }

    drng_free(rng);
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    return ret;
}


zero_knowledge_proof_status paillier_commitment_encrypt_with_exponent_zkpok_generate(const damgard_fujisaki_public_t *damgard_fujisaki,
                                                                                     const paillier_commitment_private_key_t *paillier,
                                                                                     const elliptic_curve256_algebra_ctx_t *algebra,
                                                                                     const uint8_t *aad,
                                                                                     const uint32_t aad_len,
                                                                                     const uint8_t* secret,
                                                                                     const uint32_t secret_len,
                                                                                     const uint8_t use_extended_seed,
                                                                                     paillier_with_range_proof_t **proof)
{
    BIGNUM *ciphertext = NULL, *randomizer_power = NULL, *msg = NULL;
    BN_CTX * ctx = NULL;
    zero_knowledge_proof_status ret = ZKP_UNKNOWN_ERROR;
    uint32_t paillier_n_bitsize;
    paillier_with_range_proof_t *local_proof = NULL;
    if (!damgard_fujisaki || !paillier || !secret || (aad_len && !aad) || !proof)
    {
        return ZKP_INVALID_PARAMETER;
    }

    if (damgard_fujisaki->dimension < 2)
    {
        return ZKP_INVALID_PARAMETER;
    }

    ctx = BN_CTX_new();
    if (!ctx)
    {
        return ZKP_OUT_OF_MEMORY;
    }
    BN_CTX_start(ctx);

    ciphertext = BN_CTX_get(ctx);
    randomizer_power = BN_CTX_get(ctx);
    msg = BN_CTX_get(ctx);
    if (!ciphertext || !randomizer_power || !msg)
    {
        ret = ZKP_OUT_OF_MEMORY;
        goto cleanup;
    }

    if (!BN_bin2bn(secret, secret_len, msg))
    {
        goto cleanup;
    }

    if (BN_cmp(msg, paillier->pub.n) >= 0)
    {
        // plaintext not in n
        ret = ZKP_INVALID_PARAMETER;
        goto cleanup;
    }

    paillier_n_bitsize = paillier_commitment_public_bitsize(&paillier->pub);

    // the r_power_bitsize is called n(lambda) in the paper and it used for encrypt of private share here
    ret = convert_paillier_to_zkp_status(paillier_commitment_encrypt_openssl_with_private_internal(paillier,
                                                                                                   ZKPOK_OPTIM_SMALL_GROUP_EXPONENT_BITS(paillier_n_bitsize),
                                                                                                   msg,
                                                                                                   ctx,
                                                                                                   ciphertext,
                                                                                                   randomizer_power));

    if ( ret != ZKP_SUCCESS)
    {
        goto cleanup;
    }

    local_proof = (paillier_with_range_proof_t*)calloc(1, sizeof(paillier_with_range_proof_t));
    if (!local_proof)
    {
        ret = ZKP_OUT_OF_MEMORY;
        goto cleanup;
    }


    local_proof->ciphertext_len = BN_num_bytes(ciphertext);
    local_proof->ciphertext = (uint8_t*)calloc(1, local_proof->ciphertext_len);
    local_proof->proof_len = exponent_zkpok_serialized_size_internal(damgard_fujisaki->n, paillier->pub.n);
    local_proof->serialized_proof = (uint8_t*)calloc(1, local_proof->proof_len);

    if (!local_proof->ciphertext || !local_proof->serialized_proof)
    {
        ret = ZKP_OUT_OF_MEMORY;
        goto cleanup;
    }

    BN_bn2bin(ciphertext, local_proof->ciphertext);

    ret = range_proof_paillier_commitment_encrypt_exponent_zkpok_generate(damgard_fujisaki,
                                                                          paillier,
                                                                          algebra,
                                                                          aad,
                                                                          aad_len,
                                                                          secret,
                                                                          secret_len,
                                                                          ciphertext,
                                                                          randomizer_power,
                                                                          use_extended_seed,
                                                                          local_proof->serialized_proof);

cleanup:
    if (randomizer_power)
    {
        BN_clear(randomizer_power);
    }

    if (msg)
    {
        BN_clear(msg);
    }

    BN_CTX_end(ctx);
    BN_CTX_free(ctx);

    if (ret != ZKP_SUCCESS)
    {
        range_proof_free_paillier_with_range_proof(local_proof);
        *proof = NULL;
    }
    else
    {
        *proof = local_proof;
    }
    return ret;
}

zero_knowledge_proof_status paillier_commitment_exponent_zkpok_verify(const damgard_fujisaki_private_t* damgard_fujisaki,
                                                                      const paillier_commitment_public_key_t* paillier,
                                                                      const elliptic_curve256_algebra_ctx_t* algebra,
                                                                      const uint8_t* aad,
                                                                      const uint32_t aad_len,
                                                                      const elliptic_curve256_point_t* public_point,
                                                                      const const_paillier_with_range_proof_t* proof,
                                                                      const uint8_t use_extended_seed)
{
    BN_CTX *ctx = NULL;
    drng_t *rng = NULL;
    range_proof_exponent_zkpok_t zkpok;
    uint32_t needed_proof_len;
    long ret = -1;
    BIGNUM *e = NULL, *tmp1 = NULL, *tmp2 = NULL;
    const BIGNUM *q;
    uint8_t seed[SHA256_DIGEST_LENGTH];
    elliptic_curve256_scalar_t val;
    elliptic_curve256_scalar_t z1;
    elliptic_curve256_point_t p1;
    elliptic_curve256_point_t p2;
    uint32_t paillier_n_bitsize;

    if (!damgard_fujisaki ||
        !paillier ||
        !algebra ||
        !aad ||
        !aad_len ||
        !public_point ||
        !proof ||
        !proof->ciphertext ||
        !proof->ciphertext_len ||
        !proof->serialized_proof ||
        !proof->proof_len)
    {
        return ZKP_INVALID_PARAMETER;
    }

    paillier_n_bitsize = paillier_commitment_public_bitsize(paillier);
    needed_proof_len = exponent_zkpok_serialized_size_internal(damgard_fujisaki->pub.n, paillier->n);
    if (proof->proof_len < needed_proof_len)
    {
        return ZKP_INVALID_PARAMETER;
    }

    ctx = BN_CTX_new();

    if (!ctx)
    {
        return ZKP_OUT_OF_MEMORY;
    }

    BN_CTX_start(ctx);

    e = BN_CTX_get(ctx);
    tmp1 = BN_CTX_get(ctx);
    tmp2 = BN_CTX_get(ctx);

    if (!e || !tmp1 || !tmp2)
    {
        goto cleanup;
    }

    ret = init_exponent_zkpok(&zkpok, ctx);
    if (ret != ZKP_SUCCESS)
    {
        goto cleanup;
    }

    ret = ZKP_VERIFICATION_FAILED;

    if (!deserialize_exponent_zkpok(&zkpok, damgard_fujisaki->pub.n, paillier->n, proof->serialized_proof))
    {
        goto cleanup;
    }

    if (is_coprime_fast(zkpok.D, paillier->n, ctx) != 1)
    {
        goto cleanup;
    }

    if (!BN_bin2bn(proof->ciphertext, proof->ciphertext_len, tmp1))
    {
        ret = -1; //OpenSSL error
        goto cleanup;
    }

    if (is_coprime_fast(tmp1, paillier->n, ctx) != 1)
    {
        goto cleanup;
    }

    // \tilde(P) in the paper
    if (is_coprime_fast(zkpok.S, damgard_fujisaki->pub.n, ctx) != 1)
    {
        goto cleanup;
    }
    // \tilde(B) in the paper
    if (is_coprime_fast(zkpok.T, damgard_fujisaki->pub.n, ctx) != 1)
    {
        goto cleanup;
    }

    const uint32_t ring_pedersen_n_size = (uint32_t)BN_num_bytes(damgard_fujisaki->pub.n);
    const uint32_t paillier_n_size = (uint32_t)BN_num_bytes(paillier->n);

    // sample e
    if (!genarate_exponent_zkpok_seed(paillier_n_size, ring_pedersen_n_size, &zkpok, tmp1, public_point, aad, aad_len, use_extended_seed, seed))
    {
        ret = ZKP_OUT_OF_MEMORY;
        goto cleanup;
    }

    const size_t z1_num_of_bytes = (size_t)BN_num_bytes(zkpok.z1);
    const size_t z2_num_of_bytes = (size_t)BN_num_bytes(zkpok.z2);

    if (z1_num_of_bytes> ZKPOK_OPTIM_NX_SIZE(paillier_n_bitsize) + ZKPOK_OPTIM_EPSILON_SIZE(paillier_n_bitsize))
    {
        goto cleanup;
    }

    if (z2_num_of_bytes > (ZKPOK_OPTIM_NLAMBDA_SIZE(paillier_n_bitsize) + ZKPOK_OPTIM_EPSILON_SIZE(paillier_n_bitsize)))
    {
        goto cleanup;
    }

    q = algebra->order_internal(algebra);

    // This is a tricky part: zero out part of the val, ASSUME it is big endian,
    // fill last ZKPOK_OPTIM_L_SIZE bytes with random values
    // All this done to prevent later converting BIG_NUM e back into bytes
    // for the elliptic curve algebra
    OPENSSL_cleanse(val, sizeof(elliptic_curve256_scalar_t));

    if (sizeof(elliptic_curve256_scalar_t) < ZKPOK_OPTIM_L_SIZE(paillier_n_bitsize))
    {
        ret = ZKP_UNKNOWN_ERROR;
        goto cleanup;
    }
    uint8_t* p_val = val + sizeof(elliptic_curve256_scalar_t) - ZKPOK_OPTIM_L_SIZE(paillier_n_bitsize);


    ret = convert_drng_to_zkp_status(drng_new(seed, SHA256_DIGEST_LENGTH, &rng));
    if (ret != ZKP_SUCCESS)
    {
        goto cleanup;
    }

    do
    {

        ret = convert_drng_to_zkp_status(drng_read_deterministic_rand(rng, p_val, ZKPOK_OPTIM_L_SIZE(paillier_n_bitsize)));
        if (ret != ZKP_SUCCESS)
        {
            goto cleanup;
        }

        if (!BN_bin2bn(p_val, ZKPOK_OPTIM_L_SIZE(paillier_n_bitsize), e))
        {
            ret = -1; //OpenSSL Error
            goto cleanup;
        }
    } while (BN_cmp(e, q) >= 0);

    ret = convert_paillier_to_zkp_status(paillier_commitment_encrypt_openssl_fixed_power_internal(paillier, tmp2, zkpok.z2, zkpok.z1, ctx));

    if (ret != ZKP_SUCCESS)
    {
        goto cleanup;
    }

    ret = -1; //reset for OpenSSL errors;

    if (!BN_mod_exp_mont(tmp1, tmp1, e, paillier->n2, ctx, paillier->mont_n2))
    {
        goto cleanup;
    }


    if (!BN_mod_mul(tmp1, tmp1, zkpok.D, paillier->n2, ctx))
    {
        goto cleanup;
    }


    if (BN_cmp(tmp1, tmp2) != 0)
    {
        ret = ZKP_VERIFICATION_FAILED;
        goto cleanup;
    }

    if (!BN_mod_exp(tmp1, zkpok.S, e, damgard_fujisaki->pub.n, ctx))
    {
        goto cleanup;
    }


    if (!BN_mod_mul(tmp1, tmp1, zkpok.T, damgard_fujisaki->pub.n, ctx))
    {
        goto cleanup;
    }


    const BIGNUM* verification_pedersen_commitments[] = {zkpok.z1, zkpok.z2};
    ret = damgard_fujisaki_verify_commitment_internal(damgard_fujisaki, verification_pedersen_commitments, 2, zkpok.z3, tmp1, ctx);
    if (ret != RING_PEDERSEN_SUCCESS)
    {
        goto cleanup;
    }

    //prepare z1 point
    if (!BN_mod(zkpok.z1, zkpok.z1, q, ctx))
    {
        ret = -1;
        goto cleanup;
    }

    if (BN_bn2binpad(zkpok.z1, z1, sizeof(elliptic_curve256_scalar_t)) <= 0)
    {
        ret = -1;
        goto cleanup;
    }

    ret = ZKP_VERIFICATION_FAILED;

    if (algebra->point_mul(algebra, &p1, public_point, &val) != ELLIPTIC_CURVE_ALGEBRA_SUCCESS)
    {
        goto cleanup;
    }

    if (algebra->add_points(algebra, &p1, &p1, &zkpok.Y) != ELLIPTIC_CURVE_ALGEBRA_SUCCESS)
    {
        goto cleanup;
    }

    if (algebra->generator_mul(algebra, &p2, &z1) != ELLIPTIC_CURVE_ALGEBRA_SUCCESS)
    {
        goto cleanup;
    }

    if (0 == memcmp(p1, p2, sizeof(elliptic_curve256_point_t)))
    {
        ret = ZKP_SUCCESS;
    }

cleanup:

    if (-1 == ret)
    {
        ERR_clear_error();
        ret = ZKP_UNKNOWN_ERROR;
    }

    drng_free(rng);
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    return ret;
}

