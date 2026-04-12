#include "damgard_fujisaki_internal.h"
#include "crypto/commitments/damgard_fujisaki.h"
#include "crypto/zero_knowledge_proof/range_proofs.h"
#include "crypto/drng/drng.h"
#include "crypto/algebra_utils/algebra_utils.h"
#include "crypto/algebra_utils/status_convert.h"
#include "../zero_knowledge_proof/zkp_constants_internal.h"
#include <string.h>
#include <assert.h>

#include <openssl/err.h>

#define MIN_KEY_LEN_IN_BITS (256)
#define DAMGARD_FUJISAKI_TOUGH_PRIME_BITSIZE 256
#define MAX_ALLOWED_DIMENSIONS 128

// the ctx is used only for initialization purpose
// it is not preserved and the pub->mont does not depend on context
// after the initialization
ring_pedersen_status damgard_fujisaki_init_montgomery(damgard_fujisaki_public_t* pub, BN_CTX* ctx)
{
    if (!pub->mont)
    {
        pub->mont = BN_MONT_CTX_new();
        if (pub->mont)
        {
            if (!BN_MONT_CTX_set(pub->mont, pub->n, ctx))
            {
                BN_MONT_CTX_free(pub->mont);
                pub->mont = NULL;
            }
        }
    }

    return pub->mont ? RING_PEDERSEN_SUCCESS : RING_PEDERSEN_OUT_OF_MEMORY;    
}

static inline void damgard_fujisaki_cleanup_public(damgard_fujisaki_public_t* pub)
{
    if (pub)
    {
        BN_MONT_CTX_free(pub->mont); //safe to be called on null
        
        if (pub->s)
        {
            for (uint32_t i = 0; i < pub->dimension; ++i)
            {
                BN_free(pub->s[i]);
            }
            free(pub->s);
            pub->s = NULL;
        }
        BN_free(pub->n);
        pub->n = NULL;
        BN_free(pub->t);
        pub->t = NULL;
    }
}

static inline void damgard_fujisaki_cleanup_private(damgard_fujisaki_private_t* priv)
{
    if (priv)
    {
        if (priv->lambda)
        {
            for (uint32_t i = 0; i < priv->pub.dimension; ++i)
            {
                BN_clear_free(priv->lambda[i]);
                priv->lambda[i] = NULL;
            }
            free(priv->lambda);
            priv->lambda = NULL;
        }
        BN_clear_free(priv->phi_n);
        priv->phi_n = NULL;
        BN_clear_free(priv->p);
        priv->p = NULL;
        BN_clear_free(priv->q);
        priv->q = NULL;
        BN_clear_free(priv->qinvp);
        priv->qinvp = NULL;
        damgard_fujisaki_cleanup_public(&priv->pub);
    }
}


void damgard_fujisaki_free_public(damgard_fujisaki_public_t* pub)
{
    damgard_fujisaki_cleanup_public(pub);
    free(pub);
}

void damgard_fujisaki_free_private(damgard_fujisaki_private_t* priv)
{
    damgard_fujisaki_cleanup_private(priv);
    free(priv);
}


const damgard_fujisaki_public_t* damgard_fujisaki_private_key_get_public(const damgard_fujisaki_private_t* priv)
{
    if (!priv)
    {
        return NULL;
    }

    return &priv->pub;
}

uint32_t damgard_fujisaki_public_size(const damgard_fujisaki_public_t* pub) 
{
    if (pub)
    {
        return BN_num_bytes(pub->n) * 8;
    }

    return 0;
}


ring_pedersen_status damgard_fujisaki_create_commitment_internal(const damgard_fujisaki_public_t* pub, const BIGNUM** x, const uint32_t batch_size, const BIGNUM* r, BIGNUM* commitment, BN_CTX* ctx)
{
    long ret = -1;
    BIGNUM* tmp = NULL;

    if (!ctx || !x || !batch_size || !r || !commitment)
    {
        return RING_PEDERSEN_INVALID_PARAMETER;
    }

    if (!pub || !pub->mont)
    {
        return RING_PEDERSEN_INVALID_PARAMETER;
    }
    
    if (batch_size > pub->dimension)
    {
        return RING_PEDERSEN_INVALID_PARAMETER;
    }

    BN_CTX_start(ctx);

    tmp = BN_CTX_get(ctx);
    if (!tmp)
    {
        goto cleanup;
    }

    if (!BN_mod_exp_mont(commitment, pub->t, r, pub->n, ctx, pub->mont))
    {
        goto cleanup;
    }
        
    for (uint32_t i = 0; i < batch_size; ++i) 
    {
        if (!BN_mod_exp_mont(tmp, pub->s[i], x[i], pub->n, ctx, pub->mont))
        {
            goto cleanup;
        }
            
        if (!BN_mod_mul(commitment, commitment, tmp, pub->n, ctx))
        {
            goto cleanup;
        }
            
    }
    
    ret = RING_PEDERSEN_SUCCESS;

cleanup:
    if (-1 == ret)
    {
        ERR_clear_error();
        ret = RING_PEDERSEN_UNKNOWN_ERROR;
    }

    BN_CTX_end(ctx);

    return ret;
}

static ring_pedersen_status damgard_fujisaki_create_commitment_with_private_internal(const damgard_fujisaki_private_t* priv, 
                                                                                     const BIGNUM** x, 
                                                                                     const uint32_t batch_size,
                                                                                     const BIGNUM* r, 
                                                                                     BIGNUM* commitment, 
                                                                                     BN_CTX* ctx)
{
    long ret = -1;

    BN_CTX_start(ctx);

    BIGNUM* tmp1 = BN_CTX_get(ctx);
    BIGNUM* tmp2 = BN_CTX_get(ctx);
    if (!tmp1 || !tmp2)
    {
        goto cleanup;
    }
       
    
    if (!BN_mod(tmp1, r, priv->phi_n, ctx))
    {
        goto cleanup;
    }
        
    for (uint32_t i = 0; i < batch_size; ++i) 
    {
        if (!BN_mod_mul(tmp2, priv->lambda[i], x[i], priv->phi_n, ctx))
        {
            goto cleanup;
        }
            
        if (!BN_mod_add_quick(tmp1, tmp1, tmp2, priv->phi_n))
        {
            goto cleanup;
        }
    }

    ret = algebra_to_ring_pedersen_status(crt_mod_exp(commitment, priv->pub.t, tmp1, priv->p, priv->q, priv->qinvp, priv->pub.n, ctx));

    if (ret != RING_PEDERSEN_SUCCESS)
    {
        goto cleanup;
    }

cleanup:
    if (ret == -1)
    {
        ERR_clear_error();
        ret = RING_PEDERSEN_UNKNOWN_ERROR;
    }
    
    BN_CTX_end(ctx);

    return ret;    
}

//internal version uses BIGNUM instead of bytes arrays
ring_pedersen_status damgard_fujisaki_verify_commitment_internal(const damgard_fujisaki_private_t* priv, 
                                                                 const BIGNUM** x,
                                                                 const uint32_t batch_size,
                                                                 const BIGNUM* r,
                                                                 const BIGNUM* commitment,
                                                                 BN_CTX* ctx)
{
    BIGNUM* expected_commitment = NULL;
    long ret = -1;

    if (!ctx || !x || !batch_size || !r || !commitment)
    {
        return RING_PEDERSEN_INVALID_PARAMETER;
    }

    if (!priv || !priv->pub.mont)
    {
        return RING_PEDERSEN_INVALID_PARAMETER;
    }

    if (batch_size > priv->pub.dimension)
    {
        return RING_PEDERSEN_INVALID_PARAMETER;
    }

    BN_CTX_start(ctx);

    expected_commitment = BN_CTX_get(ctx);
    if (!expected_commitment)
    {
        return RING_PEDERSEN_OUT_OF_MEMORY;
    }
    
    ret = damgard_fujisaki_create_commitment_with_private_internal(priv, x, batch_size, r, expected_commitment, ctx);
    if (ret != RING_PEDERSEN_SUCCESS)
    {
        goto cleanup;
    }
    
    if (0 != BN_cmp(expected_commitment, commitment))
    {
        ret = RING_PEDERSEN_INVALID_COMMITMENT;
    } 
    
cleanup:
    
    BN_CTX_end(ctx);

    return ret;
}

static ring_pedersen_status damgard_fujisaki_generate_key_inner(const uint32_t key_len, 
                                                                const uint32_t dimension,
                                                                damgard_fujisaki_private_t* priv,
                                                                BN_CTX* ctx) 
{
    long ret = -1;
    BIGNUM *tmp, *r;

    BN_CTX_start(ctx);

    tmp = BN_CTX_get(ctx);
    r = BN_CTX_get(ctx);
    
    if (!tmp || !r)
    {
        goto cleanup;
    }

    // generate_tough_prime always generates primes which are 3 in mod 4
    ret = algebra_to_ring_pedersen_status(generate_tough_prime(priv->p, key_len / 2, DAMGARD_FUJISAKI_TOUGH_PRIME_BITSIZE, NULL, NULL, ctx));
        
    if (ret != RING_PEDERSEN_SUCCESS)
    {
        goto cleanup;
    }
    
    ret = algebra_to_ring_pedersen_status(generate_tough_prime(priv->q, key_len / 2, DAMGARD_FUJISAKI_TOUGH_PRIME_BITSIZE, NULL, NULL, ctx));
    if (ret != RING_PEDERSEN_SUCCESS)
    {
        goto cleanup;
    }

    ret = -1; // reset ret 

    // Compute n = pq
    if (!BN_mul(priv->pub.n, priv->p, priv->q, ctx))
    {
        goto cleanup;
    }
        
    // compute phi = n - p - q + 1
    if (!BN_sub(priv->phi_n, priv->pub.n, priv->p) ||
        !BN_sub(priv->phi_n, priv->phi_n, priv->q) ||
        !BN_add_word(priv->phi_n, 1))
    {
        goto cleanup;
    } 

    // generate random r in mod n which is not p and not q
    do
    {
        if (!BN_rand_range(r, priv->pub.n))
        {
            goto cleanup;
        }
    }
    while (!BN_gcd(tmp, r, priv->pub.n, ctx) || !BN_is_one(tmp));

    // t = r ^ 2 mod n
    if (!BN_mod_sqr(priv->pub.t, r, priv->pub.n, ctx))
    {
        goto cleanup;
    }
    
    BN_clear(r); //r is secret, forget it

    for (uint32_t i = 0; i < dimension; ++i) 
    {
        // generate lambda which will have twice security bits of the RSA key
        if (!BN_rand(priv->lambda[i], 2 * get_min_secure_exponent_size((uint32_t)BN_num_bits(priv->pub.n)), BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY))
        {
            goto cleanup;
        }
            
        //s[i] = t ^ lambda[i]
        if (!BN_mod_exp(priv->pub.s[i], priv->pub.t, priv->lambda[i], priv->pub.n, ctx))
        {
            goto cleanup;
        }
    }
    
    // calculate q inverse in modulo p    
    if (!BN_mod_inverse(priv->qinvp, priv->q, priv->p, ctx))
    {
        goto cleanup;
    }

    ret = RING_PEDERSEN_SUCCESS;
cleanup:
    if (-1 == ret)
    {
        ERR_clear_error();
        ret = RING_PEDERSEN_UNKNOWN_ERROR;
    }
  
    BN_CTX_end(ctx);
    return ret;
}


ring_pedersen_status damgard_fujisaki_generate_private_key(const uint32_t key_len, const uint32_t dimension, damgard_fujisaki_private_t** priv) 
{
    long ret = RING_PEDERSEN_OUT_OF_MEMORY;
    BN_CTX* ctx = NULL;
    damgard_fujisaki_private_t* local_priv = NULL;

    if (!priv || !dimension || dimension > MAX_ALLOWED_DIMENSIONS)
    {
        return RING_PEDERSEN_INVALID_PARAMETER;
    }

    *priv = NULL;

    if (key_len < MIN_KEY_LEN_IN_BITS)
    {
        return RING_PEDERSEN_KEYLEN_TOO_SHORT;
    }
    
    local_priv = (damgard_fujisaki_private_t*) calloc(1, sizeof(damgard_fujisaki_private_t));
    if (!local_priv) 
    {
        return RING_PEDERSEN_OUT_OF_MEMORY;
    }

    local_priv->pub.s = (BIGNUM**) calloc(dimension, sizeof(BIGNUM*));
    local_priv->lambda = (BIGNUM**) calloc(dimension, sizeof(BIGNUM*));

    if (!local_priv->pub.s || !local_priv->lambda) 
    {
        goto cleanup;
    }

    ctx = BN_CTX_secure_new();

    if (NULL == ctx)
    {
        goto cleanup;
    }
    
    local_priv->pub.n = BN_new();
    local_priv->p = BN_new();
    local_priv->q = BN_new();
    local_priv->qinvp = BN_new();
    local_priv->pub.t = BN_new();
    local_priv->phi_n = BN_new();

    if (!local_priv->pub.n || !local_priv->p || !local_priv->q || !local_priv->qinvp || !local_priv->phi_n || !local_priv->pub.t)
    {
        goto cleanup;
    }
        
    BN_set_flags(local_priv->phi_n, BN_FLG_CONSTTIME);
    BN_set_flags(local_priv->p,     BN_FLG_CONSTTIME);
    BN_set_flags(local_priv->q,     BN_FLG_CONSTTIME);
    BN_set_flags(local_priv->qinvp, BN_FLG_CONSTTIME);

    local_priv->pub.dimension = dimension; //must set dimension before allocating internal memory for free to work

    for (uint32_t i = 0; i < dimension; ++i) 
    {
        local_priv->pub.s[i] = BN_new();
        local_priv->lambda[i] = BN_new();
        if (!local_priv->pub.s[i] || !local_priv->lambda[i]) 
        {
            ret = RING_PEDERSEN_OUT_OF_MEMORY;
            goto cleanup;
        }

        BN_set_flags(local_priv->lambda[i], BN_FLG_CONSTTIME);
    }

    ret = damgard_fujisaki_generate_key_inner(key_len, dimension, local_priv, ctx);
    if (ret != RING_PEDERSEN_SUCCESS)
    {
        goto cleanup;
    }
    
    ret = damgard_fujisaki_init_montgomery(&local_priv->pub, ctx);

cleanup:
    
    BN_CTX_free(ctx);

    if (ret == RING_PEDERSEN_SUCCESS) 
    {
        *priv = local_priv;
    }
    else
    {
        damgard_fujisaki_free_private(local_priv);
    }

    return ret;
}

static ring_pedersen_status damgard_fujisaki_duplicate_public_key(const damgard_fujisaki_public_t* src, damgard_fujisaki_public_t** dst) 
{
    long ret = RING_PEDERSEN_OUT_OF_MEMORY;
    BN_CTX* ctx  = NULL;
    damgard_fujisaki_public_t* pub = NULL;

    if (!src || !dst || !src->dimension)
    {
        return RING_PEDERSEN_INVALID_PARAMETER;
    }
    
    *dst = NULL;

    ctx = BN_CTX_new();
    if (!ctx)
    {
        return RING_PEDERSEN_OUT_OF_MEMORY;
    }

    pub = (damgard_fujisaki_public_t*)calloc(1, sizeof(damgard_fujisaki_public_t));
    if (!pub)
    {
        goto cleanup;
    }
    
    pub->s = (BIGNUM**) calloc(src->dimension, sizeof(BIGNUM*));
    if (!pub->s)
    {
        goto cleanup;
    }
    pub->dimension = src->dimension;
    pub->n = BN_dup(src->n);
    pub->t = BN_dup(src->t);
    
    if (!pub->n || !pub->t) 
    {
        goto cleanup;
    }

    for (uint32_t i = 0; i < src->dimension; ++i) 
    {
        pub->s[i] = BN_dup(src->s[i]);
        if (!pub->s[i]) 
        {
            goto cleanup;
        }
    }

    ret = damgard_fujisaki_init_montgomery(pub, ctx);
    
cleanup:
    
    BN_CTX_free(ctx);

    if (ret)
    {
        damgard_fujisaki_free_public(pub);
        pub = NULL;
        *dst = NULL;
    }
    else
    {
        *dst = pub;
    }
    return ret;
}


ring_pedersen_status damgard_fujisaki_generate_key_pair(const uint32_t key_len, 
                                                        const uint32_t dimension, 
                                                        damgard_fujisaki_public_t** pub, 
                                                        damgard_fujisaki_private_t** priv) 
{
    long ret = -1;
    if (!pub || !priv || !dimension)
    {
        return RING_PEDERSEN_INVALID_PARAMETER;
    }
    
    *pub = NULL;
    *priv = NULL;

    ret = damgard_fujisaki_generate_private_key(key_len, dimension, priv);
    if (RING_PEDERSEN_SUCCESS != ret)
    {
        return ret;
    }

    ret = damgard_fujisaki_duplicate_public_key(&(*priv)->pub, pub);
    if (RING_PEDERSEN_SUCCESS != ret)
    {
        damgard_fujisaki_free_private(*priv);
        *priv = NULL;
    }

    return ret;
}

static inline uint32_t damgard_fujisaki_public_serialized_size(const damgard_fujisaki_public_t* pub) 
{
    const uint32_t size_n = BN_num_bytes(pub->n);

    return sizeof(uint32_t) // size(n)
        + size_n // n
        + sizeof(uint32_t) // dimension
        + size_n // t
        + pub->dimension * size_n; // s times dimensions
}

uint8_t* damgard_fujisaki_public_serialize(const damgard_fujisaki_public_t* pub, uint8_t* buffer, const uint32_t buffer_len, uint32_t* real_buffer_len) 
{
    uint32_t needed_len = 0;
    uint32_t size_n = 0;
    uint8_t* pos = buffer;

    if (!pub || (!buffer && buffer_len))
    {
        return NULL;
    }
        
    size_n = BN_num_bytes(pub->n);

    needed_len = damgard_fujisaki_public_serialized_size(pub);

    if (real_buffer_len)
    {
        *real_buffer_len = needed_len;
    }

    if (!buffer || buffer_len < needed_len)
    {
        return NULL;
    }
        
    // size(n)
    *(uint32_t*)pos =  size_n;
    pos += sizeof(uint32_t);
    
    // n
    if (BN_bn2binpad(pub->n, pos, size_n) == -1) 
    {
        return NULL;
    }
    pos += size_n;

    // dimension
    *(uint32_t*)pos =  pub->dimension;
    pos += sizeof(uint32_t);

    // t
    if (BN_bn2binpad(pub->t, pos, size_n) == -1) 
    {
        return NULL;
    }
    pos += size_n;

    // s_i
    for (uint32_t i = 0; i < pub->dimension; ++i) 
    {
        if (BN_bn2binpad(pub->s[i], pos, size_n) == -1) 
        {
            return NULL;
        }
        pos += size_n;
    }

    return buffer;
}

static inline uint32_t damgard_fujisaki_public_deserialize_internal(damgard_fujisaki_public_t* pub, const uint8_t* const buffer, uint32_t buffer_len) 
{
    uint32_t n_len = 0;

    if (!buffer || (buffer_len < 2*sizeof(uint32_t)))
    {
        return 0;
    }
    
    // read n_len from buffer
    // from now on use only pos pointer
    n_len = *(const uint32_t *)buffer;
    const uint8_t* pos = buffer + sizeof(uint32_t);
    
    if (n_len > (8 * 1024))
    {
        // too large
        return 0;
    }
    else if (buffer_len < (2*sizeof(uint32_t) + n_len))
    {
        return 0;
    }

    pub->n = BN_new();
    pub->t = BN_new();
    if (!pub->n || !pub->t)
    {
        goto cleanup;
    }

    if (!BN_bin2bn(pos, n_len, pub->n))
    {
        goto cleanup;
    }
    pos += n_len;

    pub->dimension = *(const uint32_t *)pos;
    pos += sizeof(uint32_t);
    if (pub->dimension == 0 || pub->dimension > MAX_ALLOWED_DIMENSIONS)
    {
        goto cleanup;
    }
    
    if (buffer_len < (2 * sizeof(uint32_t)) + (2 * n_len) + (pub->dimension * n_len))
    {
        goto cleanup;
    }

    pub->s = (BIGNUM**) calloc(pub->dimension, sizeof(BIGNUM*));

    if (!pub->s)
    {
        goto cleanup;
    }

    if (!BN_bin2bn(pos, n_len, pub->t))
    {
        goto cleanup;
    }
        
    pos += n_len;
    
    for (uint32_t i = 0; i < pub->dimension; ++i) 
    {
        if (NULL == (pub->s[i] = BN_bin2bn(pos, n_len, NULL)))
        {
            goto cleanup;
        }
        pos += n_len;
    }
    
    return (uint32_t)(pos - buffer);

cleanup:
    damgard_fujisaki_cleanup_public(pub);
    return 0;
}

damgard_fujisaki_public_t* damgard_fujisaki_public_deserialize(const uint8_t* const buffer, const uint32_t buffer_len) 
{
    damgard_fujisaki_public_t* pub = (damgard_fujisaki_public_t*) calloc(1, sizeof(damgard_fujisaki_public_t));
    BN_CTX* ctx = BN_CTX_new();

    if (!pub || !ctx)
    {
        goto cleanup;
    }

    const uint32_t bytes_consumed = damgard_fujisaki_public_deserialize_internal(pub, buffer, buffer_len);
    if (0 == bytes_consumed || bytes_consumed != buffer_len)
    {
        goto cleanup;
    }
    
    if (damgard_fujisaki_init_montgomery(pub, ctx) != RING_PEDERSEN_SUCCESS)
    {
        goto cleanup;
    }
    
    BN_CTX_free(ctx);
    return pub;
cleanup:
    
    damgard_fujisaki_free_public(pub);
    BN_CTX_free(ctx);

    return NULL;
}

static inline uint32_t damgard_fujisaki_private_serialized_size(const damgard_fujisaki_private_t* priv) 
{
    const uint32_t size_n = BN_num_bytes(priv->pub.n);
    assert((uint32_t)BN_num_bytes(priv->p) == size_n / 2);
    assert((uint32_t)BN_num_bytes(priv->q) == size_n / 2);
    const uint32_t dimension = priv->pub.dimension;
    const uint32_t public_key_size = damgard_fujisaki_public_serialized_size(&priv->pub);
    return public_key_size + 
         (size_n / 2) * 2 + // for p and q
         + dimension * size_n; // lambda_i for 0 <= i < dimension
}

uint8_t *damgard_fujisaki_private_serialize(const damgard_fujisaki_private_t* priv, 
                                            uint8_t* buffer, 
                                            const uint32_t buffer_len, 
                                            uint32_t* real_buffer_len) 
{
    uint32_t needed_len = 0;
    uint32_t size_n = 0;
    uint32_t serialized_size = 0;
    uint8_t* ptr = buffer;
    if (!priv || (!buffer && buffer_len))
    {
        return NULL;
    }

    size_n = BN_num_bytes(priv->pub.n);
    needed_len = damgard_fujisaki_private_serialized_size(priv);

    if (real_buffer_len)
    {
        *real_buffer_len = needed_len;
    }
        
    if (buffer_len < needed_len)
    {
        return NULL;
    }

    if (!damgard_fujisaki_public_serialize(&priv->pub, ptr, buffer_len, &serialized_size) || (serialized_size == 0))
    {
        return NULL;
    }
    ptr += serialized_size;

    // p
    if (BN_bn2binpad(priv->p, ptr, size_n / 2) == -1) 
    {
        return NULL;
    }
    ptr += size_n / 2;

    // q
    if (BN_bn2binpad(priv->q, ptr, size_n / 2) == -1) 
    {
        return NULL;
    }
    ptr += size_n / 2;

    // lambda_i
    for (uint32_t i = 0; i < priv->pub.dimension; ++i) 
    {
        if (BN_bn2binpad(priv->lambda[i], ptr, size_n) == -1) 
        {
            return NULL;
        }
        ptr += size_n;
    }

    return buffer;
}

damgard_fujisaki_private_t* damgard_fujisaki_private_deserialize(const uint8_t* buffer, uint32_t buffer_len) 
{
    uint32_t size_n = 0;
    uint32_t parsed_size = 0;
    BN_CTX* ctx = NULL;
        
    damgard_fujisaki_private_t* priv = (damgard_fujisaki_private_t*) calloc(1, sizeof(damgard_fujisaki_private_t));
    if (!priv)
    {
        return NULL;
    }

    parsed_size = damgard_fujisaki_public_deserialize_internal(&priv->pub, buffer, buffer_len);
    if (!parsed_size)
    {
        goto cleanup;
    }
    
    size_n = (uint32_t)BN_num_bytes(priv->pub.n);

    buffer_len -= parsed_size;
    buffer += parsed_size;

    // check that the buffer is large enough to hold the rest of the key
    if (buffer_len < 2 * (size_n / 2) + priv->pub.dimension * size_n)
    {
        goto cleanup;
    }

    priv->phi_n = BN_new();
    priv->p = BN_new();
    priv->q = BN_new();
    priv->qinvp = BN_new();
    priv->lambda = (BIGNUM**) calloc(priv->pub.dimension, sizeof(BIGNUM*));

    if (!priv->phi_n || !priv->p || !priv->q || !priv->qinvp || !priv->lambda)
    {
        goto cleanup;
    }

    BN_set_flags(priv->phi_n,   BN_FLG_CONSTTIME);
    BN_set_flags(priv->p,       BN_FLG_CONSTTIME);
    BN_set_flags(priv->q,       BN_FLG_CONSTTIME);
    BN_set_flags(priv->qinvp,   BN_FLG_CONSTTIME);

    ctx = BN_CTX_secure_new();
    if (!ctx)
    {
        goto cleanup;
    }
    BN_CTX_start(ctx);

    // p        
    if (!BN_bin2bn(buffer, size_n / 2, priv->p))
    {
        goto cleanup;
    }
    buffer += size_n / 2;
    buffer_len -= size_n / 2;

    // q
    if (!BN_bin2bn(buffer, size_n / 2, priv->q))
    {
        goto cleanup;
    }
    buffer += size_n / 2;
    buffer_len -= size_n / 2;


    // lambda array
    for (uint32_t i = 0; i < priv->pub.dimension; ++i) 
    {
        priv->lambda[i] = BN_new();
        if (!priv->lambda[i] || !BN_bin2bn(buffer, size_n, priv->lambda[i]))
        {
            goto cleanup;
        }
        
        BN_set_flags(priv->lambda[i],   BN_FLG_CONSTTIME);        

        buffer += size_n;
        buffer_len -= size_n;
    }

    assert(buffer_len == 0);

    // compute qinvp
    if (!BN_mod_inverse(priv->qinvp, priv->q, priv->p, ctx))
    {
        goto cleanup;
    }

    // compute phi = n - p - q + 1
    if (!BN_sub(priv->phi_n, priv->pub.n, priv->p) ||
        !BN_sub(priv->phi_n, priv->phi_n, priv->q) ||
        !BN_add_word(priv->phi_n, 1))
    {
        goto cleanup;
    } 

    if (damgard_fujisaki_init_montgomery(&priv->pub, ctx) != RING_PEDERSEN_SUCCESS)
    {
        goto cleanup;
    }

    if (ctx) 
    {
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
    }

    return priv;
cleanup:
    damgard_fujisaki_free_private(priv);

    if (ctx) 
    {
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
    }

    return NULL;
}
