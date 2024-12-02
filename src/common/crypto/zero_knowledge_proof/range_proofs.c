#include "crypto/zero_knowledge_proof/range_proofs.h"
#include "crypto/drng/drng.h"
#include "../paillier/paillier_internal.h"

#include <openssl/bn.h>
#include <openssl/rand.h>

#include <string.h>

#define ZKPOK_L_SIZE sizeof(elliptic_curve256_scalar_t)
#define ZKPOK_EPSILON_SIZE 2 * sizeof(elliptic_curve256_scalar_t)

#define EXPONENT_ZKPOK_SALT "Exponent vs Paillier Encryption zkpok"
#define DIFFIE_HELLMAN_ZKPOK_SALT "Range Proof with Diffie Hellman Commitment"
#define PAILLIER_LARGE_FACTORS_ZKP_SALT "Range Proof Paillier factors"

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
  range_proof_exponent_zkpok_t base; // diffie_hellman is extansion to the exponent zkpok where rddh.Z<->log.Y
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
        return ZKP_SUCCESS;
    return ZKP_OUT_OF_MEMORY;
}

static inline int genarate_zkpok_seed_internal(const range_proof_exponent_zkpok_t *proof, const BIGNUM *ciphertext, const elliptic_curve256_point_t *X, const uint8_t *aad, uint32_t aad_len, SHA256_CTX *ctx)
{
    uint8_t *n = NULL;
    uint32_t max_size;

    SHA256_Update(ctx, EXPONENT_ZKPOK_SALT, sizeof(EXPONENT_ZKPOK_SALT));
    if (aad)
        SHA256_Update(ctx, aad, aad_len);
    max_size = MAX(BN_num_bytes(proof->D), BN_num_bytes(proof->S)); // we assome the the paillier n is larger then ring pedersen n
    max_size = MAX(max_size, (uint32_t)BN_num_bytes(ciphertext));
    n = (uint8_t*)malloc(max_size);
    if (!n)
        return 0;
    
    BN_bn2bin(ciphertext, n);
    SHA256_Update(ctx, n, BN_num_bytes(ciphertext));
    SHA256_Update(ctx, *X, sizeof(elliptic_curve256_point_t));

    BN_bn2bin(proof->S, n);
    SHA256_Update(ctx, n, BN_num_bytes(proof->S));
    BN_bn2bin(proof->D, n);
    SHA256_Update(ctx, n, BN_num_bytes(proof->D));
    SHA256_Update(ctx, proof->Y, sizeof(elliptic_curve256_point_t));
    if ((uint32_t)BN_num_bytes(proof->T) > max_size) // should never happen
    {
        uint8_t *tmp = realloc(n, BN_num_bytes(proof->T));
        if (!tmp)
        {
            free(n);
            return 0;
        }
        n = tmp;
    }
    BN_bn2bin(proof->T, n);
    SHA256_Update(ctx, n, BN_num_bytes(proof->T));
    free(n);
    return 1;
}

static inline int genarate_exponent_zkpok_seed(const range_proof_exponent_zkpok_t *proof, const BIGNUM *ciphertext, const elliptic_curve256_point_t *X, const uint8_t *aad, uint32_t aad_len, uint8_t *seed)
{
    SHA256_CTX ctx;
    
    SHA256_Init(&ctx);
    if (!genarate_zkpok_seed_internal(proof, ciphertext, X, aad, aad_len, &ctx))
        return 0;
    SHA256_Final(seed, &ctx);
    return 1;
}

static inline uint32_t exponent_zkpok_serialized_size(const ring_pedersen_public_t *pub, const paillier_public_key_t *paillier)
{
    return 
        sizeof(uint32_t) + // sizeof(ring_pedersen->n)
        sizeof(uint32_t) + // sizeof(paillier->n)
        BN_num_bytes(pub->n) + // sizeof(S)
        2 * BN_num_bytes(paillier->n) + // sizeof(D)
        sizeof(elliptic_curve256_point_t) + // sizeof(Y)
        BN_num_bytes(pub->n) + // sizeof(T)
        ZKPOK_EPSILON_SIZE + sizeof(elliptic_curve256_scalar_t) + 1 + // sizeof(z1)
        BN_num_bytes(paillier->n) + // sizeof(z2)
        ZKPOK_EPSILON_SIZE + sizeof(elliptic_curve256_scalar_t) + BN_num_bytes(pub->n) + 1; // sizeof(z3)
}

static inline uint8_t* serialize_exponent_zkpok(const range_proof_exponent_zkpok_t *proof, const BIGNUM *ring_pedersen_n, const BIGNUM *paillier_n, uint8_t *serialized_proof)
{
    const uint32_t ring_pedersen_n_size = BN_num_bytes(ring_pedersen_n);
    const uint32_t paillier_n_size = BN_num_bytes(paillier_n);
    uint8_t *ptr = serialized_proof;
    *(uint32_t*)ptr = ring_pedersen_n_size;
    ptr += sizeof(uint32_t);
    *(uint32_t*)ptr = paillier_n_size;
    ptr += sizeof(uint32_t);
    BN_bn2binpad(proof->S, ptr, ring_pedersen_n_size);
    ptr += ring_pedersen_n_size;
    BN_bn2binpad(proof->D, ptr, paillier_n_size * 2);
    ptr += paillier_n_size * 2;
    memcpy(ptr, proof->Y, sizeof(elliptic_curve256_point_t));
    ptr += sizeof(elliptic_curve256_point_t);
    BN_bn2binpad(proof->T, ptr, ring_pedersen_n_size);
    ptr += ring_pedersen_n_size;
    BN_bn2binpad(proof->z1, ptr, ZKPOK_EPSILON_SIZE + sizeof(elliptic_curve256_scalar_t) + 1);
    ptr += ZKPOK_EPSILON_SIZE + sizeof(elliptic_curve256_scalar_t) + 1;
    BN_bn2binpad(proof->z2, ptr, paillier_n_size);
    ptr += paillier_n_size;
    BN_bn2binpad(proof->z3, ptr, ZKPOK_EPSILON_SIZE + sizeof(elliptic_curve256_scalar_t) + ring_pedersen_n_size + 1);
    ptr += ZKPOK_EPSILON_SIZE + sizeof(elliptic_curve256_scalar_t) + ring_pedersen_n_size + 1;
    return ptr;
}

static inline const uint8_t* deserialize_exponent_zkpok(range_proof_exponent_zkpok_t *proof, const BIGNUM *ring_pedersen_n, const BIGNUM *paillier_n, const uint8_t *serialized_proof)
{
    const uint32_t ring_pedersen_n_size = BN_num_bytes(ring_pedersen_n);
    const uint32_t paillier_n_size = BN_num_bytes(paillier_n);
    const uint8_t *ptr = serialized_proof;

    if (*(uint32_t*)ptr != ring_pedersen_n_size)
        return NULL;
    ptr += sizeof(uint32_t);
    if (*(uint32_t*)ptr != paillier_n_size)
        return NULL;
    ptr += sizeof(uint32_t);
    if (!BN_bin2bn(ptr, ring_pedersen_n_size, proof->S))
        return NULL;
    ptr += ring_pedersen_n_size;
    if (!BN_bin2bn(ptr, paillier_n_size * 2, proof->D))
        return NULL;
    ptr += paillier_n_size * 2;
    memcpy(proof->Y, ptr, sizeof(elliptic_curve256_point_t));
    ptr += sizeof(elliptic_curve256_point_t);
    if (!BN_bin2bn(ptr, ring_pedersen_n_size, proof->T))
        return NULL;
    ptr += ring_pedersen_n_size;
    if (!BN_bin2bn(ptr, ZKPOK_EPSILON_SIZE + sizeof(elliptic_curve256_scalar_t) + 1, proof->z1))
        return NULL;
    ptr += ZKPOK_EPSILON_SIZE + sizeof(elliptic_curve256_scalar_t) + 1;
    if (!BN_bin2bn(ptr, paillier_n_size, proof->z2))
        return NULL;
    ptr += paillier_n_size;
    if (!BN_bin2bn(ptr, ZKPOK_EPSILON_SIZE + sizeof(elliptic_curve256_scalar_t) + ring_pedersen_n_size + 1, proof->z3))
        return NULL;
    ptr += ZKPOK_EPSILON_SIZE + sizeof(elliptic_curve256_scalar_t) + ring_pedersen_n_size + 1;
    return ptr;
}

zero_knowledge_proof_status range_proof_paillier_exponent_zkpok_generate(const ring_pedersen_public_t *ring_pedersen, const paillier_public_key_t *paillier, const elliptic_curve256_algebra_ctx_t *algebra, 
    const uint8_t *aad, uint32_t aad_len, const elliptic_curve256_scalar_t *secret, const paillier_ciphertext_t *ciphertext, uint8_t *serialized_proof, uint32_t proof_len, uint32_t *real_proof_len)
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
    if (!BN_copy(tmp, ring_pedersen->n) || !BN_lshift(tmp, tmp, sizeof(elliptic_curve256_scalar_t)))
    {
        status = ZKP_OUT_OF_MEMORY;
        goto cleanup;
    }

    if (!BN_rand_range(mu, tmp))
        goto cleanup;

    // rand gamma
    if (!BN_lshift(tmp, tmp, ZKPOK_EPSILON_SIZE))
    {
        status = ZKP_OUT_OF_MEMORY;
        goto cleanup;
    }

    if (!BN_rand_range(gamma, tmp))
        goto cleanup;

    do
    {
        BN_rand_range(r, paillier->n);
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
    BN_bn2binpad(tmp, alpha_bin, sizeof(elliptic_curve256_scalar_t));
    if (algebra->generator_mul(algebra, &zkpok.Y, &alpha_bin) != ELLIPTIC_CURVE_ALGEBRA_SUCCESS)
        goto cleanup;

    if (algebra->generator_mul(algebra, &public_point, secret) != ELLIPTIC_CURVE_ALGEBRA_SUCCESS)
        goto cleanup;

    // sample e
    if (!genarate_exponent_zkpok_seed(&zkpok, ciphertext->ciphertext, &public_point, aad, aad_len, seed))
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
    
    serialize_exponent_zkpok(&zkpok, ring_pedersen->n, paillier->n, serialized_proof);
    status = ZKP_SUCCESS;
cleanup:
    if (x)
        BN_clear(x);
    drng_free(rng);
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    return status;
}

zero_knowledge_proof_status range_proof_paillier_encrypt_with_exponent_zkpok_generate(const ring_pedersen_public_t *ring_pedersen, const paillier_public_key_t *paillier, const elliptic_curve256_algebra_ctx_t *algebra, 
    const uint8_t *aad, uint32_t aad_len, const elliptic_curve256_scalar_t *secret, paillier_with_range_proof_t **proof)
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

    local_proof->ciphertext_len = BN_num_bytes(ciphertext->ciphertext);
    local_proof->ciphertext = (uint8_t*)malloc(local_proof->ciphertext_len);
    local_proof->proof_len = exponent_zkpok_serialized_size(ring_pedersen, paillier);
    local_proof->serialized_proof = (uint8_t*)malloc(local_proof->proof_len);

    if (!local_proof->ciphertext || !local_proof->serialized_proof)
        goto cleanup;

    BN_bn2bin(ciphertext->ciphertext, local_proof->ciphertext);
    status = range_proof_paillier_exponent_zkpok_generate(ring_pedersen, paillier, algebra, aad, aad_len, secret, ciphertext, local_proof->serialized_proof, local_proof->proof_len, NULL);
    
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

zero_knowledge_proof_status range_proof_exponent_zkpok_verify(const ring_pedersen_private_t *ring_pedersen, const paillier_public_key_t *paillier, const elliptic_curve256_algebra_ctx_t *algebra, 
    const uint8_t *aad, uint32_t aad_len, const elliptic_curve256_point_t *public_point, const paillier_with_range_proof_t *proof)
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

    // sample e
    if (!genarate_exponent_zkpok_seed(&zkpok, tmp1, public_point, aad, aad_len, seed))
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
    
    BN_bn2binpad(zkpok.z1, z1, sizeof(elliptic_curve256_scalar_t));
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

zero_knowledge_proof_status range_proof_exponent_zkpok_batch_verify(const ring_pedersen_private_t *ring_pedersen, const paillier_public_key_t *paillier, const elliptic_curve256_algebra_ctx_t *algebra, 
    const uint8_t *aad, uint32_t aad_len, uint32_t batch_size, const elliptic_curve256_point_t *public_points, const paillier_with_range_proof_t *proofs)
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
    
    if (!ring_pedersen || !paillier || !algebra || !aad || !aad_len || !public_points || !proofs)
        return ZKP_INVALID_PARAMETER;

    needed_proof_len = exponent_zkpok_serialized_size(&ring_pedersen->pub, paillier);

    for (size_t i = 0; i < batch_size; i++)
    {
        if (!proofs[i].ciphertext || !proofs[i].ciphertext_len || !proofs[i].serialized_proof || proofs[i].proof_len < needed_proof_len)
            return ZKP_INVALID_PARAMETER;
    }
    

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

    q = algebra->order_internal(algebra);

    status = ZKP_UNKNOWN_ERROR;

    for (size_t i = 0; i < batch_size; i++)
    {
        if (!deserialize_exponent_zkpok(&zkpok, ring_pedersen->pub.n, paillier->n, proofs[i].serialized_proof))
        {
            status = ZKP_VERIFICATION_FAILED;
            goto cleanup;
        }

        if (is_coprime_fast(zkpok.D, paillier->n, ctx) != 1)
        {
            status = ZKP_VERIFICATION_FAILED;
            goto cleanup;
        }

        if (!BN_bin2bn(proofs[i].ciphertext, proofs[i].ciphertext_len, tmp1))
        {
            status = ZKP_OUT_OF_MEMORY;
            goto cleanup;
        }

        if (is_coprime_fast(tmp1, paillier->n, ctx) != 1)
        {
            status = ZKP_VERIFICATION_FAILED;
            goto cleanup;
        }

        // sample e
        if (!genarate_exponent_zkpok_seed(&zkpok, tmp1, &public_points[i], aad, aad_len, seed))
        {
            status = ZKP_UNKNOWN_ERROR;
            goto cleanup;
        }
        
        if ((size_t)BN_num_bytes(zkpok.z1) > sizeof(elliptic_curve256_scalar_t) + ZKPOK_EPSILON_SIZE)
        {
            status = ZKP_VERIFICATION_FAILED;
            goto cleanup;
        }

        if (drng_new(seed, SHA256_DIGEST_LENGTH, &rng) != DRNG_SUCCESS)
            goto cleanup;
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
        drng_free(rng);
        rng = NULL;

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
        
        BN_bn2binpad(zkpok.z1, z1, sizeof(z1));
        if (algebra->point_mul(algebra, &p1, &public_points[i], &val) != ELLIPTIC_CURVE_ALGEBRA_SUCCESS)
            goto cleanup;
        if (algebra->add_points(algebra, &p1, &p1, &zkpok.Y) != ELLIPTIC_CURVE_ALGEBRA_SUCCESS)
            goto cleanup;
        if (algebra->generator_mul(algebra, &p2, &z1) != ELLIPTIC_CURVE_ALGEBRA_SUCCESS)
            goto cleanup;

        status = memcmp(p1, p2, sizeof(elliptic_curve256_point_t)) == 0 ? ZKP_SUCCESS : ZKP_VERIFICATION_FAILED;
    }

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

static inline int genarate_diffie_hellman_zkpok_seed(const range_proof_diffie_hellman_zkpok_t *proof, const BIGNUM *ciphertext, const elliptic_curve256_point_t *A, const elliptic_curve256_point_t *B, const elliptic_curve256_point_t *X, const uint8_t *aad, uint32_t aad_len, uint8_t *seed)
{
    SHA256_CTX ctx;
    
    SHA256_Init(&ctx);
    if (!genarate_zkpok_seed_internal(&proof->base, ciphertext, X, aad, aad_len, &ctx))
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

static inline void serialize_diffie_hellman_zkpok(const range_proof_diffie_hellman_zkpok_t *proof, const BIGNUM *ring_pedersen_n, const BIGNUM *paillier_n, uint8_t *serialized_proof)
{
    uint8_t *ptr = serialize_exponent_zkpok(&proof->base, ring_pedersen_n, paillier_n, serialized_proof);
    memcpy(ptr, proof->Y, sizeof(elliptic_curve256_point_t));
    memcpy(ptr + sizeof(elliptic_curve256_point_t), proof->w, sizeof(elliptic_curve256_scalar_t));
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

zero_knowledge_proof_status range_proof_diffie_hellman_zkpok_generate(const ring_pedersen_public_t *ring_pedersen, const paillier_public_key_t *paillier, const elliptic_curve256_algebra_ctx_t *algebra, 
    const uint8_t *aad, uint32_t aad_len, const elliptic_curve256_scalar_t *secret, const elliptic_curve256_scalar_t *a, const elliptic_curve256_scalar_t *b, const paillier_ciphertext_t *ciphertext, 
    uint8_t *serialized_proof, uint32_t proof_len, uint32_t *real_proof_len)
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
    if (!BN_copy(tmp, ring_pedersen->n) || !BN_lshift(tmp, tmp, sizeof(elliptic_curve256_scalar_t)))
    {
        status = ZKP_OUT_OF_MEMORY;
        goto cleanup;
    }

    if (!BN_rand_range(mu, tmp))
        goto cleanup;

    // rand gamma
    if (!BN_lshift(tmp, tmp, ZKPOK_EPSILON_SIZE))
    {
        status = ZKP_OUT_OF_MEMORY;
        goto cleanup;
    }

    if (!BN_rand_range(gamma, tmp))
        goto cleanup;

    do
    {
        BN_rand_range(r, paillier->n);
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
    BN_bn2binpad(tmp, alpha_bin, sizeof(elliptic_curve256_scalar_t));
    
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

    // sample e
    if (!genarate_diffie_hellman_zkpok_seed(&zkpok, ciphertext->ciphertext, &A, &B, &X, aad, aad_len, seed))
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
    
    serialize_diffie_hellman_zkpok(&zkpok, ring_pedersen->n, paillier->n, serialized_proof);
    status = ZKP_SUCCESS;
cleanup:
    if (x)
        BN_clear(x);
    drng_free(rng);
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    return status;
}

zero_knowledge_proof_status range_proof_paillier_encrypt_with_diffie_hellman_zkpok_generate(const ring_pedersen_public_t *ring_pedersen, const paillier_public_key_t *paillier, const elliptic_curve256_algebra_ctx_t *algebra, 
    const uint8_t *aad, uint32_t aad_len, const elliptic_curve256_scalar_t *secret, const elliptic_curve256_scalar_t *a, const elliptic_curve256_scalar_t *b, paillier_with_range_proof_t **proof)
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

    local_proof->ciphertext_len = BN_num_bytes(ciphertext->ciphertext);
    local_proof->ciphertext = (uint8_t*)malloc(local_proof->ciphertext_len);
    local_proof->proof_len = diffie_hellman_zkpok_serialized_size(ring_pedersen, paillier);
    local_proof->serialized_proof = (uint8_t*)malloc(local_proof->proof_len);

    if (!local_proof->ciphertext || !local_proof->serialized_proof)
        goto cleanup;

    BN_bn2bin(ciphertext->ciphertext, local_proof->ciphertext);
    status = range_proof_diffie_hellman_zkpok_generate(ring_pedersen, paillier, algebra, aad, aad_len, secret, a, b, ciphertext, local_proof->serialized_proof, local_proof->proof_len, NULL);
    
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

zero_knowledge_proof_status range_proof_diffie_hellman_zkpok_verify(const ring_pedersen_private_t *ring_pedersen, const paillier_public_key_t *paillier, const elliptic_curve256_algebra_ctx_t *algebra, 
    const uint8_t *aad, uint32_t aad_len, const elliptic_curve256_point_t *public_point, const elliptic_curve256_point_t *A, const elliptic_curve256_point_t *B, const paillier_with_range_proof_t *proof)
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

    // sample e
    if (!genarate_diffie_hellman_zkpok_seed(&zkpok, tmp1, A, B, public_point, aad, aad_len, seed))
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
    
    BN_bn2binpad(zkpok.base.z1, z1, sizeof(elliptic_curve256_scalar_t));
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
    const uint32_t ring_pedersen_n_size = BN_num_bytes(ring_pedersen_n);
    const uint32_t paillier_n_size = BN_num_bytes(paillier_n);
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
    
    BN_bn2binpad(proof->P, ptr, ring_pedersen_n_size);
    ptr += ring_pedersen_n_size;
    BN_bn2binpad(proof->Q, ptr, ring_pedersen_n_size);
    ptr += ring_pedersen_n_size;
    BN_bn2binpad(proof->A, ptr, ring_pedersen_n_size);
    ptr += ring_pedersen_n_size;
    BN_bn2binpad(proof->B, ptr, ring_pedersen_n_size);
    ptr += ring_pedersen_n_size;
    BN_bn2binpad(proof->T, ptr, ring_pedersen_n_size);
    ptr += ring_pedersen_n_size;
    BN_bn2binpad(proof->lambda, ptr, lambda_size);
    ptr += lambda_size;
    BN_bn2binpad(proof->z1, ptr, z_size);
    ptr += z_size;
    BN_bn2binpad(proof->z2, ptr, z_size);
    ptr += z_size;
    BN_bn2binpad(proof->w1, ptr, w_size);
    ptr += w_size;
    BN_bn2binpad(proof->w2, ptr, w_size);
    ptr += w_size;
    BN_bn2binpad(proof->v, ptr, v_size);
    ptr += v_size;
    return ptr;
}

static inline const uint8_t* deserialize_paillier_large_factors_zkp(range_proof_paillier_large_factors_zkp_t *proof, const BIGNUM *ring_pedersen_n, const BIGNUM *paillier_n, const uint8_t *serialized_proof)
{
    const uint32_t ring_pedersen_n_size = BN_num_bytes(ring_pedersen_n);
    const uint32_t paillier_n_size = BN_num_bytes(paillier_n);
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

static inline int genarate_paillier_large_factors_zkp_seed(const range_proof_paillier_large_factors_zkp_t *proof, const paillier_public_key_t *pub, const uint8_t *aad, uint32_t aad_len, uint8_t *seed)
{
    SHA256_CTX ctx;
    uint8_t *n = (uint8_t*)malloc(BN_num_bytes(proof->lambda));
    
    if (!n)
        return 0;
    
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, PAILLIER_LARGE_FACTORS_ZKP_SALT, sizeof(PAILLIER_LARGE_FACTORS_ZKP_SALT));
    if (aad)
        SHA256_Update(&ctx, aad, aad_len);
    BN_bn2bin(pub->n, n);
    SHA256_Update(&ctx, n, BN_num_bytes(pub->n));
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

zero_knowledge_proof_status range_proof_paillier_large_factors_zkp_generate(const paillier_private_key_t *priv, const ring_pedersen_public_t *ring_pedersen, const uint8_t *aad, uint32_t aad_len, uint8_t *serialized_proof, uint32_t proof_len, uint32_t *real_proof_len)
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

    if (!genarate_paillier_large_factors_zkp_seed(&zkp, &priv->pub, aad, aad_len, e_val))
    {
        status = ZKP_OUT_OF_MEMORY;
        goto cleanup;
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
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    return status;
}

zero_knowledge_proof_status range_proof_paillier_large_factors_zkp_verify(const paillier_public_key_t *pub, const ring_pedersen_private_t *ring_pedersen, const uint8_t *aad, uint32_t aad_len, const uint8_t *serialized_proof, uint32_t proof_len)
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
    if (!genarate_paillier_large_factors_zkp_seed(&zkp, pub, aad, aad_len, e_val))
    {
        status = ZKP_UNKNOWN_ERROR;
        goto cleanup;
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
