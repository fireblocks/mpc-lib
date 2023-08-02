#include "crypto/commitments/ring_pedersen.h"
#include "crypto/drng/drng.h"
#include "../paillier/paillier_internal.h"

#include <assert.h>

#include <openssl/bn.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#define RING_PEDERSEN_STATISTICAL_SECURITY 80

typedef struct
{
  BIGNUM *A[RING_PEDERSEN_STATISTICAL_SECURITY];
  BIGNUM *z[RING_PEDERSEN_STATISTICAL_SECURITY];
} ring_pedersen_param_proof_t;

// private function to initialize montgomery context implementation
static inline void ring_pedersen_init_mont(const ring_pedersen_public_t *pub, BN_CTX *ctx)
{
    if (!pub->mont)
    {
        ((ring_pedersen_public_t*)pub)->mont = BN_MONT_CTX_new();
        if (pub->mont)
        {
            if (!BN_MONT_CTX_set(pub->mont, pub->n, ctx))
            {
                BN_MONT_CTX_free(pub->mont);
                ((ring_pedersen_public_t*)pub)->mont = NULL;
            }
        }
    }
}

ring_pedersen_status ring_pedersen_init_montgomery(const ring_pedersen_public_t *pub, BN_CTX *ctx)
{
    ring_pedersen_init_mont(pub, ctx);
    return pub->mont ? RING_PEDERSEN_SUCCESS : RING_PEDERSEN_OUT_OF_MEMORY;
}

ring_pedersen_status ring_pedersen_generate_key_pair(uint32_t key_len, ring_pedersen_public_t **pub, ring_pedersen_private_t **priv)
{
    ring_pedersen_status ret = RING_PEDERSEN_UNKNOWN_ERROR;
    BIGNUM *p, *q, *tmp, *n, *lamda, *phi, *r, *s, *t;
    BN_CTX *ctx = NULL;
    ring_pedersen_public_t *local_pub = NULL;
    ring_pedersen_private_t *local_priv = NULL;

    if (!pub || !priv)
        return RING_PEDERSEN_INVALID_PARAMETER;
    if (key_len < MIN_KEY_LEN_IN_BITS)
        return RING_PEDERSEN_KEYLEN_TOO_SHORT;
    if ((ctx = BN_CTX_new()) == NULL)
        return RING_PEDERSEN_OUT_OF_MEMORY;

    *pub = NULL;
    *priv = NULL;

    BN_CTX_start(ctx);

    tmp = BN_CTX_get(ctx);
    r = BN_CTX_get(ctx);
    p = BN_CTX_get(ctx);
    q = BN_CTX_get(ctx);
    
    n = BN_new();
    lamda = BN_new();
    phi = BN_new();
    s = BN_new();
    t = BN_new();
    
    if (!p || !q || !tmp || !n || !phi || !lamda || !r || !s || !t)
        goto cleanup;

    BN_set_flags(phi, BN_FLG_CONSTTIME);
    BN_set_flags(p, BN_FLG_CONSTTIME);
    BN_set_flags(q, BN_FLG_CONSTTIME);
    BN_set_flags(lamda, BN_FLG_CONSTTIME);

    if (!BN_generate_prime_ex(p, key_len / 2, 1, NULL, NULL, NULL))
        goto cleanup;
    if (!BN_generate_prime_ex(q, key_len / 2, 1, NULL, NULL, NULL))
        goto cleanup;

    // Compute n = pq
    if (!BN_mul(n, p, q, ctx))
        goto cleanup;

    if (!BN_sub(phi, n, p))
        goto cleanup;
    if (!BN_sub(phi, phi, q))
        goto cleanup;
    if (!BN_add_word(phi, 1))
        goto cleanup;
    if (!BN_rand_range(lamda, phi))
        goto cleanup;
    
    do
    {
        if (!BN_rand_range(r, n))
            goto cleanup;
    }
    while (!BN_gcd(tmp, r, n, ctx) || !BN_is_one(tmp));

    if (!BN_mod_sqr(t, r, n, ctx))
        goto cleanup;
    if (!BN_mod_exp(s, t, lamda, n, ctx))
        goto cleanup;

    local_priv = (ring_pedersen_private_t*)malloc(sizeof(ring_pedersen_private_t));
    if (!local_priv)
    {
        ret = RING_PEDERSEN_OUT_OF_MEMORY;
        goto cleanup;
    }
    local_priv->pub.n = n;
    local_priv->pub.s = s;
    local_priv->pub.t = t;
    local_priv->pub.mont = NULL;
    local_priv->lamda = lamda;
    local_priv->phi_n = phi;
    
    local_pub = (ring_pedersen_public_t*)malloc(sizeof(ring_pedersen_public_t));
    if (!local_pub)
    {
        ret = RING_PEDERSEN_OUT_OF_MEMORY;
        goto cleanup;
    }
    local_pub->n = BN_dup(n);
    local_pub->s = BN_dup(s);
    local_pub->t = BN_dup(t);
    local_pub->mont = NULL;

    if (!local_pub->n || !local_pub->s || !local_pub->t)
    {
        ret = RING_PEDERSEN_OUT_OF_MEMORY;
        goto cleanup;
    }
    
    *priv = local_priv;
    *pub = local_pub;

    ret = RING_PEDERSEN_SUCCESS;
cleanup:
    if (ctx)
    {
        if (p)
            BN_clear(p);
        if (q)
            BN_clear(q);
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
    }

    if (ret != RING_PEDERSEN_SUCCESS)
    {
        // handle errors
        if (local_priv)
            free(local_priv);
        ring_pedersen_free_public(local_pub); // as the public key uses duplication of p, s and t it's not sefficent just to free it
        BN_free(n);
        BN_free(lamda);
        BN_free(phi);
        BN_free(s);
        BN_free(t);
    }

    return ret;
}

static uint32_t ring_pedersen_public_serialize_internal(const ring_pedersen_public_t *pub, uint8_t *buffer, uint32_t buffer_len)
{
    uint32_t needed_len = 0;
    uint32_t n_len = 0;
    uint32_t s_len = 0;
    uint32_t t_len = 0;
    uint8_t *p = buffer;
    
    n_len = (uint32_t)BN_num_bytes(pub->n);
    s_len = (uint32_t)BN_num_bytes(pub->s);
    t_len = (uint32_t)BN_num_bytes(pub->t);
    needed_len = sizeof(uint32_t) * 3 + n_len + s_len + t_len;
    if (!buffer || buffer_len < needed_len)
        return needed_len;
    *(uint32_t*)p = n_len;
    p += sizeof(uint32_t);
    BN_bn2bin(pub->n, p);
    p += n_len;
    *(uint32_t*)p = s_len;
    p += sizeof(uint32_t);
    BN_bn2bin(pub->s, p);
    p += s_len;
    *(uint32_t*)p = t_len;
    p += sizeof(uint32_t);
    BN_bn2bin(pub->t, p);
    return needed_len;
}

static uint32_t ring_pedersen_public_deserialize_internal(ring_pedersen_public_t *pub, const uint8_t *buffer, uint32_t buffer_len)
{
    uint32_t len = 0;
    const uint8_t *p = buffer;

    pub->mont = NULL;
    if (!buffer || buffer_len < (sizeof(uint32_t) * 3))
        return 0;
    len = *(uint32_t*)p;
    p += sizeof(uint32_t);
    if (len > (buffer_len - sizeof(uint32_t) * 3))
        return 0;

    buffer_len -= sizeof(uint32_t);
    pub->n = BN_bin2bn(p, len, NULL);
    p += len;
    buffer_len -= len;
    
    len = *(uint32_t*)p;
    p += sizeof(uint32_t);
    if (len > (buffer_len - sizeof(uint32_t) * 2))
        return 0;
    buffer_len -= sizeof(uint32_t);
    pub->s = BN_bin2bn(p, len, NULL);
    p += len;
    buffer_len -= len;

    len = *(uint32_t*)p;
    p += sizeof(uint32_t);
    if (len > (buffer_len - sizeof(uint32_t)))
        return 0;
    buffer_len -= sizeof(uint32_t);
    pub->t = BN_bin2bn(p, len, NULL);
    p += len;
    
    if (!pub->n || !pub->s || !pub->t)
        return 0;

    if (BN_num_bits(pub->n) < MIN_KEY_LEN_IN_BITS)
        return 0;
    
    if (BN_cmp(pub->s, pub->n) > 0 || BN_cmp(pub->t, pub->n) > 0)
        return 0;

    return p - buffer;
}

uint32_t ring_pedersen_public_size(const ring_pedersen_public_t *pub)
{
    if (pub)
        return BN_num_bytes(pub->n) * 8;
    return 0;
}

uint8_t *ring_pedersen_public_serialize(const ring_pedersen_public_t *pub, uint8_t *buffer, uint32_t buffer_len, uint32_t *real_buffer_len)
{
    uint32_t needed_len = 0;
    
    if (!pub)
        return NULL;
    needed_len = ring_pedersen_public_serialize_internal(pub, buffer, buffer_len);
    if (real_buffer_len)
        *real_buffer_len = needed_len;
    if (!buffer || buffer_len < needed_len)
        return NULL;
    return buffer;
}

ring_pedersen_public_t *ring_pedersen_public_deserialize(const uint8_t *buffer, uint32_t buffer_len)
{
    ring_pedersen_public_t *pub;
    uint32_t len;
    
    pub = (ring_pedersen_public_t*)calloc(1, sizeof(ring_pedersen_public_t));
    if (!pub)
        return NULL;

    len = ring_pedersen_public_deserialize_internal(pub, buffer, buffer_len);
    if (!len)
    {
        ring_pedersen_free_public(pub);
        return NULL;
    }
    assert(buffer_len == len);
    return pub;
}

void ring_pedersen_free_public(ring_pedersen_public_t *pub)
{
    if (pub)
    {
        if (pub->mont)
            BN_MONT_CTX_free(pub->mont);
        BN_free(pub->n);
        BN_free(pub->s);
        BN_free(pub->t);
        free(pub);
    }
}

const ring_pedersen_public_t* ring_pedersen_private_key_get_public(const ring_pedersen_private_t *priv)
{
    if (priv)
        return &priv->pub;
    return NULL;
}

uint8_t *ring_pedersen_private_serialize(const ring_pedersen_private_t *priv, uint8_t *buffer, uint32_t buffer_len, uint32_t *real_buffer_len)
{
    uint32_t needed_len = 0;
    uint32_t lamda_len = 0;
    uint32_t phi_len = 0;
    uint8_t *p = buffer;
    
    if (!priv)
        return NULL;
    lamda_len = BN_num_bytes(priv->lamda);
    phi_len = BN_num_bytes(priv->phi_n);
    needed_len = ring_pedersen_public_serialize_internal(&priv->pub, NULL, 0) + sizeof(uint32_t) * 2 + lamda_len + phi_len;
    if (real_buffer_len)
        *real_buffer_len = needed_len;
    if (!buffer || buffer_len < needed_len)
        return NULL;
    p += ring_pedersen_public_serialize_internal(&priv->pub, buffer, buffer_len);
    *(uint32_t*)p = lamda_len;
    p += sizeof(uint32_t);
    BN_bn2bin(priv->lamda, p);
    p += lamda_len;
    *(uint32_t*)p = phi_len;
    p += sizeof(uint32_t);
    BN_bn2bin(priv->phi_n, p);
    return buffer;
}

ring_pedersen_private_t *ring_pedersen_private_deserialize(const uint8_t *buffer, uint32_t buffer_len)
{
    ring_pedersen_private_t *priv;
    uint32_t len = 0;
    const uint8_t *p;

    priv = (ring_pedersen_private_t*)calloc(1, sizeof(ring_pedersen_private_t));
    if (!priv)
        return NULL;

    len = ring_pedersen_public_deserialize_internal(&priv->pub, buffer, buffer_len);
    if (!len)
        goto cleanup;

    p = buffer + len;
    buffer_len -= len;
    
    if (buffer_len < (sizeof(uint32_t) * 2))
        goto cleanup;
    
    len = *(uint32_t*)p;
    p += sizeof(uint32_t);
    if (len > (buffer_len - sizeof(uint32_t) * 2))
        goto cleanup;
    buffer_len -= sizeof(uint32_t);
    priv->lamda = BN_bin2bn(p, len, NULL);
    BN_set_flags(priv->lamda, BN_FLG_CONSTTIME);
    p += len;
    buffer_len -= len;

    len = *(uint32_t*)p;
    p += sizeof(uint32_t);
    if (len > (buffer_len - sizeof(uint32_t)))
        goto cleanup;
    buffer_len -= sizeof(uint32_t);
    priv->phi_n = BN_bin2bn(p, len, NULL);
    BN_set_flags(priv->phi_n, BN_FLG_CONSTTIME);
    buffer_len -= len;
    assert(buffer_len == 0);

    if (!priv->lamda || !priv->phi_n)
        goto cleanup;
    return priv;

cleanup:
    ring_pedersen_free_private(priv);
    return NULL;
}

void ring_pedersen_free_private(ring_pedersen_private_t *priv)
{
    if (priv)
    {
        if (priv->pub.mont)
            BN_MONT_CTX_free(priv->pub.mont);
        BN_free(priv->pub.n);
        BN_free(priv->pub.s);
        BN_free(priv->pub.t);
        BN_clear_free(priv->lamda);
        BN_clear_free(priv->phi_n);
        free(priv);
    }
}

static inline zero_knowledge_proof_status init_ring_pedersen_param_zkp(ring_pedersen_param_proof_t *proof, BN_CTX *ctx)
{
    for (size_t i = 0; i < RING_PEDERSEN_STATISTICAL_SECURITY; i++)
    {
        proof->A[i] = BN_CTX_get(ctx);
        proof->z[i] = BN_CTX_get(ctx);
        if (!proof->A[i] || !proof->z[i])
            return ZKP_OUT_OF_MEMORY;
    }
    return ZKP_SUCCESS;
}

static inline int genarate_zkp_seed(const ring_pedersen_public_t *pub, const ring_pedersen_param_proof_t *proof, const uint8_t *aad, uint32_t aad_len, uint8_t *seed)
{
    SHA256_CTX ctx;
    uint8_t *a;
    uint32_t size = (uint32_t)BN_num_bytes(pub->n);

    a = (uint8_t*)malloc(size);
    if (!a)
        return 0;

    SHA256_Init(&ctx);
    if (aad)
        SHA256_Update(&ctx, aad, aad_len);
    if (BN_bn2binpad(pub->n, a, size) < 0)
    {
        free(a);
        return 0;
    }
    SHA256_Update(&ctx, a, size);
    if (BN_bn2binpad(pub->s, a, size) < 0)
    {
        free(a);
        return 0;
    }
    SHA256_Update(&ctx, a, size);
    if (BN_bn2binpad(pub->t, a, size) < 0)
    {
        free(a);
        return 0;
    }
    SHA256_Update(&ctx, a, size);

    for (size_t i = 0; i < RING_PEDERSEN_STATISTICAL_SECURITY; i++)
    {
        if (BN_bn2binpad(proof->A[i], a, size) < 0)
        {
            free(a);
            return 0;
        }
        SHA256_Update(&ctx, a, size);
    }
    free(a);
    SHA256_Final(seed, &ctx);
    return 1;
}

/* serialization format is sizeof(pub->n) || RING_PEDERSEN_STATISTICAL_SECURITY || (A || z) * RING_PEDERSEN_STATISTICAL_SECURITY */
static inline uint32_t ring_pedersen_param_zkp_serialized_size(const ring_pedersen_public_t *pub)
{
    int n_len = BN_num_bytes(pub->n);
    return sizeof(uint32_t) * 2 + (n_len * 2) * RING_PEDERSEN_STATISTICAL_SECURITY;
}

static inline void serialize_ring_pedersen_param_zkp(const ring_pedersen_param_proof_t *proof, const BIGNUM *n, uint8_t *serialized_proof)
{
    uint32_t n_len = BN_num_bytes(n);
    uint8_t *ptr = serialized_proof;
    *(uint32_t*)ptr = n_len;
    ptr += sizeof(uint32_t);
    *(uint32_t*)ptr = RING_PEDERSEN_STATISTICAL_SECURITY;
    ptr += sizeof(uint32_t);
    
    for (uint32_t i = 0; i < RING_PEDERSEN_STATISTICAL_SECURITY; ++i)
    {
        BN_bn2binpad(proof->A[i], ptr, n_len);
        ptr += n_len;
        BN_bn2binpad(proof->z[i], ptr, n_len);
        ptr += n_len;
    }
}

static inline int deserialize_ring_pedersen_param_zkp(ring_pedersen_param_proof_t *proof, const BIGNUM *n, const uint8_t *serialized_proof)
{
    uint32_t n_len = BN_num_bytes(n);
    uint32_t proof_n_len;
    const uint8_t *ptr = serialized_proof;
    proof_n_len = *(uint32_t*)ptr;
    ptr += sizeof(uint32_t);

    if (n_len != proof_n_len)
        return 0;
    
    if (*(uint32_t*)ptr < RING_PEDERSEN_STATISTICAL_SECURITY)
        return 0;
    ptr += sizeof(uint32_t);

    for (uint32_t i = 0; i < RING_PEDERSEN_STATISTICAL_SECURITY; ++i)
    {
        if (!BN_bin2bn(ptr, n_len, proof->A[i]))
            return 0;
        ptr += n_len;
        if (!BN_bin2bn(ptr, n_len, proof->z[i]))
            return 0;
        ptr += n_len;
    }
    return 1;
}

zero_knowledge_proof_status ring_pedersen_parameters_zkp_generate(const ring_pedersen_private_t *priv, const uint8_t *aad, uint32_t aad_len, uint8_t *serialized_proof, uint32_t proof_len, uint32_t *proof_real_len)
{
    BN_CTX *ctx = NULL;
    drng_t *rng = NULL;
    ring_pedersen_param_proof_t proof;
    uint32_t needed_proof_len;
    zero_knowledge_proof_status status = ZKP_OUT_OF_MEMORY;
    uint8_t seed[SHA256_DIGEST_LENGTH];
    
    if (!priv || !aad || !aad_len || (!serialized_proof && proof_len))
        return ZKP_INVALID_PARAMETER;

    needed_proof_len = ring_pedersen_param_zkp_serialized_size(&priv->pub);
    if (proof_real_len)
        *proof_real_len = needed_proof_len;
    if (proof_len < needed_proof_len)
        return ZKP_INSUFFICIENT_BUFFER;

    ctx = BN_CTX_new();

    if (!ctx)
        return ZKP_OUT_OF_MEMORY;
    
    BN_CTX_start(ctx);

    ring_pedersen_init_mont(&priv->pub, ctx);
    
    status = init_ring_pedersen_param_zkp(&proof, ctx);
    if (status != ZKP_SUCCESS)
        goto cleanup;

    status = ZKP_UNKNOWN_ERROR;

    for (uint32_t i = 0; i < RING_PEDERSEN_STATISTICAL_SECURITY; ++i)
    {
        if (!BN_rand_range(proof.z[i], priv->phi_n))
            goto cleanup;
        if (!BN_mod_exp_mont(proof.A[i], priv->pub.t, proof.z[i], priv->pub.n, ctx, priv->pub.mont))
            goto cleanup;
    }

    if (!genarate_zkp_seed(&priv->pub, &proof, aad, aad_len, seed))
        goto cleanup;
    if (drng_new(seed, SHA256_DIGEST_LENGTH, &rng) != DRNG_SUCCESS)
        goto cleanup;

    for (uint32_t i = 0; i < RING_PEDERSEN_STATISTICAL_SECURITY; ++i)
    {
        uint8_t e;
        if (drng_read_deterministic_rand(rng, &e, 1) != DRNG_SUCCESS)
            goto cleanup;
        
        if (e & 0x01)
        {
            // both z and lamda are in Z(phi(n)) so the add_quick version can be used
            if (!BN_mod_add_quick(proof.z[i], proof.z[i], priv->lamda, priv->phi_n))
                goto cleanup;
        }
    }

    serialize_ring_pedersen_param_zkp(&proof, priv->pub.n, serialized_proof);
    status = ZKP_SUCCESS;
cleanup:
    drng_free(rng);
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    return status;
}

zero_knowledge_proof_status ring_pedersen_parameters_zkp_verify(const ring_pedersen_public_t *pub, const uint8_t *aad, uint32_t aad_len, const uint8_t *serialized_proof, uint32_t proof_len)
{
    BN_CTX *ctx = NULL;
    drng_t *rng = NULL;
    BIGNUM *t_pow_z;
    ring_pedersen_param_proof_t proof;
    zero_knowledge_proof_status status = ZKP_OUT_OF_MEMORY;
    uint8_t seed[SHA256_DIGEST_LENGTH];
    
    if (!pub || !aad || !aad_len || !serialized_proof || proof_len != ring_pedersen_param_zkp_serialized_size(pub))
        return ZKP_INVALID_PARAMETER;

    ctx = BN_CTX_new();

    if (!ctx)
        return ZKP_OUT_OF_MEMORY;
    
    BN_CTX_start(ctx);
    
    status = init_ring_pedersen_param_zkp(&proof, ctx);
    if (status != ZKP_SUCCESS)
        goto cleanup;

    t_pow_z = BN_CTX_get(ctx);
    
    if (!t_pow_z)
        goto cleanup;

    status = ZKP_VERIFICATION_FAILED;

    if (BN_is_prime_ex(pub->n, 256, ctx, NULL))
        goto cleanup;

    if (!is_coprime_fast(pub->n, pub->t, ctx))
        goto cleanup;

    ring_pedersen_init_mont(pub, ctx);

    if (!deserialize_ring_pedersen_param_zkp(&proof, pub->n, serialized_proof))
        goto cleanup;
    if (!genarate_zkp_seed(pub, &proof, aad, aad_len, seed))
    {
        status = ZKP_UNKNOWN_ERROR;
        goto cleanup;
    }
    if (drng_new(seed, SHA256_DIGEST_LENGTH, &rng) != DRNG_SUCCESS)
        goto cleanup;
    
    for (uint64_t i = 0; i < RING_PEDERSEN_STATISTICAL_SECURITY; ++i)
    {
        uint8_t e;
        if (drng_read_deterministic_rand(rng, &e, 1) != DRNG_SUCCESS)
            goto cleanup;

        if (!BN_mod_exp_mont(t_pow_z, pub->t, proof.z[i], pub->n, ctx, pub->mont))
            goto cleanup;

        if (e & 0x01)
        {
            if (!BN_mod_mul(proof.A[i], proof.A[i], pub->s, pub->n, ctx))
                goto cleanup;
        }

        if (BN_cmp(t_pow_z, proof.A[i]) != 0)
            goto cleanup;
    }
    status = ZKP_SUCCESS;

cleanup:
    drng_free(rng);
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    return status;
}

ring_pedersen_status ring_pedersen_create_commitment_internal(const ring_pedersen_public_t *pub, const BIGNUM *x, const BIGNUM *r, BIGNUM *commitment, BN_CTX *ctx)
{
    BIGNUM *tmp = NULL;
    ring_pedersen_status status = RING_PEDERSEN_OUT_OF_MEMORY;

    BN_CTX_start(ctx);
    tmp = BN_CTX_get(ctx);
    
    if (!tmp)
        goto cleanup;

    ring_pedersen_init_mont(pub, ctx);
    
    status = RING_PEDERSEN_UNKNOWN_ERROR;
    if (!BN_mod_exp2_mont(commitment, pub->s, x, pub->t, r, pub->n, ctx, pub->mont))
        goto cleanup;

    status = RING_PEDERSEN_SUCCESS;
cleanup:
    BN_CTX_end(ctx);
    return status;
}

ring_pedersen_status ring_pedersen_create_commitment(const ring_pedersen_public_t *pub, const uint8_t *x, uint32_t x_len, const uint8_t *r, uint32_t r_len, uint8_t *commitment, uint32_t commitment_len, uint32_t *commitment_real_len)
{
    BN_CTX *ctx = NULL;
    BIGNUM *bn_x = NULL, *bn_r = NULL;
    uint32_t needed_len = 0;
    ring_pedersen_status status = RING_PEDERSEN_OUT_OF_MEMORY;
    
    if (!pub || !x || !x_len || !r || !r_len || (!commitment && commitment_len))
        return RING_PEDERSEN_INVALID_PARAMETER;

    needed_len = BN_num_bytes(pub->n);
    if (commitment_real_len)
        *commitment_real_len = needed_len;
    if (commitment_len < needed_len)
        return RING_PEDERSEN_BUFFER_TOO_SHORT;

    ctx = BN_CTX_new();

    if (!ctx)
        return RING_PEDERSEN_OUT_OF_MEMORY;

    BN_CTX_start(ctx);
    bn_x = BN_CTX_get(ctx);
    bn_r = BN_CTX_get(ctx);

    if (!bn_x || ! bn_r)
        goto cleanup;
    
    if (!BN_bin2bn(x, x_len, bn_x))
        goto cleanup;
    if (!BN_bin2bn(r, r_len, bn_r))
        goto cleanup;

    status = ring_pedersen_create_commitment_internal(pub, bn_x, bn_r, bn_x, ctx);
    if (status != RING_PEDERSEN_SUCCESS)
        goto cleanup;

    if (BN_bn2binpad(bn_x, commitment, needed_len) < 0)
    {
        status = RING_PEDERSEN_UNKNOWN_ERROR;
        goto cleanup;
    }

cleanup:
    if (bn_x)
        BN_clear(bn_x);
    if (bn_r)
        BN_clear(bn_r);
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);

    return status;
}

static ring_pedersen_status ring_pedersen_verify_commitment_internal(const ring_pedersen_private_t *priv, const BIGNUM *x, const BIGNUM *r, const BIGNUM *commitment, BN_CTX *ctx)
{
    BIGNUM *tmp = NULL;
    ring_pedersen_status status = RING_PEDERSEN_OUT_OF_MEMORY;

    BN_CTX_start(ctx);
    tmp = BN_CTX_get(ctx);
    
    if (!tmp)
        goto cleanup;

    ring_pedersen_init_mont(&priv->pub, ctx);
    
    status = RING_PEDERSEN_UNKNOWN_ERROR;
    if (!BN_mod_mul(tmp, priv->lamda, x, priv->phi_n, ctx))
        goto cleanup;
    if (!BN_mod_add(tmp, tmp, r, priv->phi_n, ctx))
        goto cleanup;
    if (!BN_mod_exp_mont(tmp, priv->pub.t, tmp, priv->pub.n, ctx, priv->pub.mont))
        goto cleanup;

    status = BN_cmp(tmp, commitment) == 0 ? RING_PEDERSEN_SUCCESS : RING_PEDERSEN_INVALID_COMMITMENT;
cleanup:
    BN_CTX_end(ctx);
    return status;
}

ring_pedersen_status ring_pedersen_verify_commitment(const ring_pedersen_private_t *priv, const uint8_t *x, uint32_t x_len, const uint8_t *r, uint32_t r_len, const uint8_t *commitment, uint32_t commitment_len)
{
    BN_CTX *ctx = NULL;
    BIGNUM *bn_x = NULL, *bn_r = NULL, *commit = NULL;
    ring_pedersen_status status = RING_PEDERSEN_OUT_OF_MEMORY;
    
    if (!priv || !x || !x_len || !r || !r_len || !commitment || !commitment_len)
        return RING_PEDERSEN_INVALID_PARAMETER;

    if (commitment_len != (uint32_t)BN_num_bytes(priv->pub.n))
        return RING_PEDERSEN_INVALID_PARAMETER;

    ctx = BN_CTX_new();

    if (!ctx)
        return RING_PEDERSEN_OUT_OF_MEMORY;

    BN_CTX_start(ctx);
    bn_x = BN_CTX_get(ctx);
    bn_r = BN_CTX_get(ctx);
    commit = BN_CTX_get(ctx);

    if (!bn_x || ! bn_r || !commit)
        goto cleanup;
    
    if (!BN_bin2bn(x, x_len, bn_x))
        goto cleanup;
    if (!BN_bin2bn(r, r_len, bn_r))
        goto cleanup;
    if (!BN_bin2bn(commitment, commitment_len, commit))
        goto cleanup;

    status = ring_pedersen_verify_commitment_internal(priv, bn_x, bn_r, commit, ctx);
cleanup:
    if (bn_x)
        BN_clear(bn_x);
    if (bn_r)
        BN_clear(bn_r);
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);

    return status;
}

ring_pedersen_status ring_pedersen_verify_batch_commitments_internal(const ring_pedersen_private_t *priv, uint32_t batch_size, const BIGNUM **x, const BIGNUM **r, const BIGNUM **commitments, BN_CTX *ctx)
{
    BIGNUM *t_exp = NULL, *B = NULL, *tmp1 = NULL, *tmp2 = NULL;
    ring_pedersen_status status = RING_PEDERSEN_OUT_OF_MEMORY;
    
    if (!priv || !batch_size || !x || !r || !commitments || !ctx)
        return RING_PEDERSEN_INVALID_PARAMETER;

    for (size_t i = 0; i < batch_size; i++)
    {
        if (!x[i] || !r[i] || !commitments[i])
            return RING_PEDERSEN_INVALID_PARAMETER;
    }
    
    BN_CTX_start(ctx);
    t_exp = BN_CTX_get(ctx);
    B = BN_CTX_get(ctx);
    tmp1 = BN_CTX_get(ctx);
    tmp2 = BN_CTX_get(ctx);
    BN_one(B);

    if (!t_exp || !B || !tmp1 || !tmp2)
        goto cleanup;

    ring_pedersen_init_mont(&priv->pub, ctx);
    status = RING_PEDERSEN_UNKNOWN_ERROR;

    for (size_t i = 0; i < batch_size; i++)
    {
        uint64_t gamma;
        if (RAND_bytes((uint8_t*)&gamma, sizeof(uint64_t)) != 1)
            goto cleanup;
        gamma &= 0xffffffffff; // 40bits
        if (!BN_mod_mul(tmp1, priv->lamda, x[i], priv->phi_n, ctx))
            goto cleanup;
        if (!BN_mod_add(tmp1, tmp1, r[i], priv->phi_n, ctx))
            goto cleanup;
        if (!BN_mul_word(tmp1, gamma))
            goto cleanup;
        if (!BN_add(t_exp, t_exp, tmp1))
            goto cleanup;

        if (!BN_set_word(tmp2, gamma))
            goto cleanup;
        if (!BN_mod_exp_mont(tmp1, commitments[i], tmp2, priv->pub.n, ctx, priv->pub.mont))
            goto cleanup;
        if (!BN_mod_mul(B, B, tmp1, priv->pub.n, ctx))
            goto cleanup;
    }
    if (!BN_mod(t_exp, t_exp, priv->phi_n, ctx))
        goto cleanup;
    if (!BN_mod_exp_mont(t_exp, priv->pub.t, t_exp, priv->pub.n, ctx, priv->pub.mont))
        goto cleanup;
    status = BN_cmp(t_exp, B) == 0 ? RING_PEDERSEN_SUCCESS : RING_PEDERSEN_INVALID_COMMITMENT;
    
cleanup:
    BN_CTX_end(ctx);
    return status;
}

ring_pedersen_status ring_pedersen_verify_batch_commitments(const ring_pedersen_private_t *priv, uint32_t batch_size, const ring_pedersen_batch_data_t *x, const ring_pedersen_batch_data_t *r, const ring_pedersen_batch_data_t *commitments)
{
    BN_CTX *ctx = NULL;
    BIGNUM *t_exp = NULL, *B = NULL, *tmp1 = NULL, *tmp2 = NULL;
    ring_pedersen_status status = RING_PEDERSEN_OUT_OF_MEMORY;
    uint32_t commitment_len;
    
    if (!priv || !batch_size || !x || !r || !commitments)
        return RING_PEDERSEN_INVALID_PARAMETER;

    commitment_len = (uint32_t)BN_num_bytes(priv->pub.n);

    for (size_t i = 0; i < batch_size; i++)
    {
        if (!x[i].data || !x[i].size || !r[i].data || !r[i].size || !commitments[i].data || !commitments[i].size || commitments[i].size != commitment_len)
            return RING_PEDERSEN_INVALID_PARAMETER;
    }
    ctx = BN_CTX_new();
    if (!ctx)
        return RING_PEDERSEN_OUT_OF_MEMORY;

    BN_CTX_start(ctx);

    t_exp = BN_CTX_get(ctx);
    B = BN_CTX_get(ctx);
    tmp1 = BN_CTX_get(ctx);
    tmp2 = BN_CTX_get(ctx);
    BN_one(B);

    if (!t_exp || !B || !tmp1 || !tmp2)
        goto cleanup;


    status = RING_PEDERSEN_UNKNOWN_ERROR;
    ring_pedersen_init_mont(&priv->pub, ctx);

    for (size_t i = 0; i < batch_size; i++)
    {
        uint64_t gamma;
        if (RAND_bytes((uint8_t*)&gamma, sizeof(uint64_t)) != 1)
            goto cleanup;
        if (!BN_bin2bn(x[i].data, x[i].size, tmp1))
            goto cleanup;
        if (!BN_bin2bn(r[i].data, r[i].size, tmp2))
            goto cleanup;
        if (!BN_mod_mul(tmp1, priv->lamda, tmp1, priv->phi_n, ctx))
            goto cleanup;
        if (!BN_mod_add(tmp1, tmp1, tmp2, priv->phi_n, ctx))
            goto cleanup;
        if (!BN_mul_word(tmp1, gamma))
            goto cleanup;
        if (!BN_add(t_exp, t_exp, tmp1))
            goto cleanup;

        if (!BN_bin2bn(commitments[i].data, commitments[i].size, tmp1))
            goto cleanup;
        if (!BN_set_word(tmp2, gamma))
            goto cleanup;
        if (!BN_mod_exp_mont(tmp1, tmp1, tmp2, priv->pub.n, ctx, priv->pub.mont))
            goto cleanup;
        if (!BN_mod_mul(B, B, tmp1, priv->pub.n, ctx))
            goto cleanup;
    }
    if (!BN_mod(t_exp, t_exp, priv->phi_n, ctx))
        goto cleanup;
    if (!BN_mod_exp_mont(t_exp, priv->pub.t, t_exp, priv->pub.n, ctx, priv->pub.mont))
        goto cleanup;
    status = BN_cmp(t_exp, B) == 0 ? RING_PEDERSEN_SUCCESS : RING_PEDERSEN_INVALID_COMMITMENT;
    
cleanup:
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    return status;
}
