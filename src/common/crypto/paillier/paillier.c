#include "paillier_internal.h"
#include "crypto/zero_knowledge_proof/range_proofs.h"
#include "crypto/algebra_utils/status_convert.h"
#include "crypto/algebra_utils/algebra_utils.h"
#include "../zero_knowledge_proof/zkp_constants_internal.h"

#include <string.h>
#include <assert.h>

#include <openssl/err.h>

#define MIN_KEY_LEN_IN_BITS 256


uint64_t paillier_L(BIGNUM *res, const BIGNUM *x, const BIGNUM *n, BN_CTX *ctx)
{
    uint64_t ret = -1;

    BIGNUM *x_copy = BN_dup(x);
    
    if (!x_copy)
    {
        ret = PAILLIER_ERROR_OUT_OF_MEMORY;
        goto cleanup;
    }

    if (!BN_sub_word(x_copy, 1))
    {
        goto cleanup;
    }

    if (!BN_div(res, NULL, x_copy, n, ctx))
    {
        goto cleanup;
    }

    ret = PAILLIER_SUCCESS;
cleanup:
    if (ret)
    {
        ret = paillier_error_from_openssl();
    }

    BN_clear_free(x_copy);
    return ret;
}

static long paillier_generate_private(uint32_t key_len, paillier_private_key_t *priv)
{
    long ret = -1;
    BIGNUM *p = NULL, *q = NULL;
    BIGNUM *tmp = NULL, *n = NULL, *n2 = NULL;
    BIGNUM *lambda = NULL,  *mu = NULL;
    BIGNUM *three = NULL, *seven = NULL, *eight = NULL;
    BN_CTX *ctx = NULL;
    
    if (!priv)
    {
        return PAILLIER_ERROR_INVALID_PARAM;
    }
    if (key_len < MIN_KEY_LEN_IN_BITS)
    {
        return PAILLIER_ERROR_KEYLEN_TOO_SHORT;
    }

    ctx = BN_CTX_secure_new();
    if (!ctx)
    {
        //not jumping to cleanup to avoid initializing all local variables
        return PAILLIER_ERROR_OUT_OF_MEMORY; 
    }

    BN_CTX_start(ctx);

    tmp = BN_CTX_get(ctx);
    three = BN_CTX_get(ctx);
    seven = BN_CTX_get(ctx);
    eight = BN_CTX_get(ctx);

    p = BN_new();
    q = BN_new();
    n = BN_new();
    n2 = BN_new();
    lambda = BN_new();
    mu = BN_new();
    
    if (!p || !q || !tmp || !n || !n2 || !lambda || !mu || !three || !seven || !eight)
    {
        goto cleanup;
    }

    BN_set_flags(n, BN_FLG_CONSTTIME);
    BN_set_flags(n2, BN_FLG_CONSTTIME);
    BN_set_flags(p, BN_FLG_CONSTTIME);
    BN_set_flags(q, BN_FLG_CONSTTIME);
    BN_set_flags(lambda, BN_FLG_CONSTTIME);
    BN_set_flags(mu, BN_FLG_CONSTTIME);

    if (!BN_set_word(three, 3))
    {
        goto cleanup;
    }

    if (!BN_set_word(seven, 7))
    {
        goto cleanup;
    }
    
    if (!BN_set_word(eight, 8))
    {
        goto cleanup;
    }

    // Choose two large prime p,q numbers having gcd(pq, (p-1)(q-1)) == 1
    do
    {   // note - originally we had used p and q to be 4*k + 3. The new form keeps this requirement because
        // both p and q still satisfies 4 * k + 3

        // p needs to be in the form of p = 8 * k + 3 ( p = 3 mod 8) to allow efficient calculation off fourth roots 
        // (needed in paillier blum zkp)
        if (!BN_generate_prime_ex(p, key_len / 2, 0, eight, three, NULL))
        {
            goto cleanup;
        }

        // and set must be q = 7 mod 8 (8 * k + 7)
        if (!BN_generate_prime_ex(q, key_len / 2, 0, eight, seven, NULL))
        {
            goto cleanup;
        }

        if (BN_num_bits(p) != BN_num_bits(q))
        {
            continue;
        }

        // Compute n = pq
        if (!BN_mul(n, p, q, ctx))
        {
            goto cleanup;
        }

        if (!BN_sub(lambda, n, p))
        {
            goto cleanup;
        }

        if (!BN_sub(lambda, lambda, q))
        {
            goto cleanup;
        }

        if (!BN_add_word(lambda, 1))
        {
            goto cleanup;
        }
    } while (BN_cmp(p, q) == 0 || 
             !BN_gcd(tmp, lambda, n, ctx) || 
             !BN_is_one(tmp));

    if (!BN_sqr(n2, n, ctx))
    {
        goto cleanup;
    }

    // if num_bits(q) == num_bits(p), we can optimize g lambda and mu selection see https://en.wikipedia.org/wiki/Paillier_cryptosystem
    if (!BN_mod_inverse(mu, lambda, n, ctx))
    {
        goto cleanup;
    }

    priv->pub.n = n;
    priv->pub.n2 = n2;
    priv->p = p;
    priv->q = q;
    priv->lambda = lambda;
    priv->mu = mu;

    ret = PAILLIER_SUCCESS;

cleanup:
    if (-1 == ret)
    {
        ret = paillier_error_from_openssl();
    }

    if (ctx)
    {
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
    }

    if (ret)
    {
        // handle errors
        BN_clear_free(p);
        BN_clear_free(q);
        BN_free(n);
        BN_free(n2);
        BN_clear_free(lambda);
        BN_clear_free(mu);
    }

    return ret;

}

long paillier_generate_key_pair(uint32_t key_len, paillier_public_key_t **pub, paillier_private_key_t **priv)
{
    long ret = -1;
    paillier_private_key_t *local_priv = NULL;
    paillier_public_key_t *local_pub = NULL;
    if (!pub || !priv)
    {
        return PAILLIER_ERROR_INVALID_PARAM;
    }
    
    (*priv) = NULL;
    (*pub) = NULL;

    if (key_len < MIN_KEY_LEN_IN_BITS)
    {
        return PAILLIER_ERROR_KEYLEN_TOO_SHORT;
    }
    
    local_priv = (paillier_private_key_t*)calloc(1, sizeof(paillier_private_key_t));
    local_pub = (paillier_public_key_t*)calloc(1, sizeof(paillier_public_key_t));
    if (!local_priv || !local_pub)
    {
        ret = PAILLIER_ERROR_OUT_OF_MEMORY;
        goto cleanup;
    }

    ret = paillier_generate_private(key_len, local_priv);
    if (ret != PAILLIER_SUCCESS)
    {
        goto cleanup;
    }
    
    local_pub->n = BN_dup(local_priv->pub.n);
    local_pub->n2 = BN_dup(local_priv->pub.n2);

    if (!local_pub->n || !local_pub->n2)
    {
        ret = PAILLIER_ERROR_OUT_OF_MEMORY;
        goto cleanup;
    }

cleanup:
    
    if (ret)
    {
        paillier_free_private_key(local_priv);
        paillier_free_public_key(local_pub);
    }
    else
    {
        *priv = local_priv;
        *pub = local_pub;
    }

    return ret;
}

long paillier_public_key_n(const paillier_public_key_t *pub, uint8_t *n, uint32_t n_len, uint32_t *n_real_len)
{
    uint32_t len = 0;
    if (!pub)
    {
        return PAILLIER_ERROR_INVALID_KEY;
    }
    if (!n && n_len)
    {
        return PAILLIER_ERROR_INVALID_PARAM;
    }

    len = BN_num_bytes(pub->n);

    if (n_real_len)
    {
        *n_real_len = len;
    }

    if (n_len < len)
    {
        return PAILLIER_ERROR_KEYLEN_TOO_SHORT;
    }

    return BN_bn2bin(pub->n, n) > 0 ? PAILLIER_SUCCESS : paillier_error_from_openssl();
}

uint32_t paillier_public_key_size(const paillier_public_key_t *pub)
{
    if (pub)
    {
        return BN_num_bytes(pub->n) * 8;
    }

    return 0;
}

uint8_t *paillier_public_key_serialize(const paillier_public_key_t *pub, uint8_t *buffer, const uint32_t buffer_len, uint32_t *real_buffer_len)
{
    uint32_t needed_len = 0;
    uint32_t n_len = 0;
    uint8_t *p = buffer;
    
    if (!pub)
    {
        return NULL;
    }

    n_len = (uint32_t)BN_num_bytes(pub->n);
    needed_len = sizeof(uint32_t) + n_len;

    if (real_buffer_len)
    {
        *real_buffer_len = needed_len;
    }

    if (!buffer || buffer_len < needed_len)
    {
        return NULL;
    }

    memcpy(p, &n_len, sizeof(uint32_t));
    p += sizeof(uint32_t);
    if (BN_bn2binpad(pub->n, p, n_len) <= 0)
    {
        return NULL;
    }
    return buffer;
}

static inline void paillier_free_public_key_cleanup(paillier_public_key_t *pub)
{
    if (pub)
    {
        BN_free(pub->n);
        pub->n = NULL;
        BN_free(pub->n2);
        pub->n2 = NULL;
    }
}

static paillier_public_key_t* paillier_public_key_deserialize_internal(const uint8_t* buffer, 
                                                                       uint32_t n_len, 
                                                                       BN_CTX *ctx, 
                                                                       paillier_public_key_t* pub)
{
    BN_CTX_start(ctx);
    pub->n = BN_bin2bn(buffer, n_len, NULL);
    pub->n2 = BN_new();

    if (!pub->n || !pub->n2)
    {
        goto cleanup;
    }

    if (BN_num_bits(pub->n) < MIN_KEY_LEN_IN_BITS)
    {
        goto cleanup;
    }

    if (!BN_sqr(pub->n2, pub->n, ctx))
    {
        goto cleanup;
    }

    BN_CTX_end(ctx);
    return pub;

cleanup:

    BN_CTX_end(ctx);
    paillier_free_public_key_cleanup(pub);
    return NULL;
}

paillier_public_key_t *paillier_public_key_deserialize(const uint8_t *buffer, uint32_t buffer_len)
{
    paillier_public_key_t *pub = NULL;
    uint32_t len = 0;
    BN_CTX *ctx = NULL;

    if (!buffer || buffer_len < (sizeof(uint32_t) + MIN_KEY_LEN_IN_BITS / 8))
    {
        return NULL;
    }

    ctx = BN_CTX_new();
    if (!ctx)
    {
        return NULL;
    }

    pub = (paillier_public_key_t*)calloc(1, sizeof(paillier_public_key_t));
    if (!pub)
    {
        goto cleanup;
    }
    
    memcpy(&len, buffer, sizeof(uint32_t));
    buffer_len -= sizeof(uint32_t);
    buffer += sizeof(uint32_t);

    if (len > buffer_len)
    {
        goto cleanup;
    }

    if (!paillier_public_key_deserialize_internal(buffer, len, ctx, pub))
    {
        goto cleanup;
    }

    assert(len == buffer_len); // catch possible bugs in debug mode.
    
    BN_CTX_free(ctx);
    return pub;

cleanup:

    BN_CTX_free(ctx);
    paillier_free_public_key(pub);
    return NULL;
}



void paillier_free_public_key(paillier_public_key_t *pub)
{
    paillier_free_public_key_cleanup(pub);
    free(pub);
}

long paillier_private_key_n(const paillier_private_key_t *priv, uint8_t *n, uint32_t n_len, uint32_t *n_real_len)
{
    uint32_t len = 0;
    if (!priv)
    {
        return PAILLIER_ERROR_INVALID_KEY;
    }
    
    if (!n && n_len)
    {
        return PAILLIER_ERROR_INVALID_PARAM;
    }

    len = BN_num_bytes(priv->pub.n);
    if (n_real_len)
    {
        *n_real_len = len;
    }
    
    if (n_len < len)
    {
        return PAILLIER_ERROR_KEYLEN_TOO_SHORT;
    }

    return BN_bn2binpad(priv->pub.n, n, len) > 0 ? PAILLIER_SUCCESS : paillier_error_from_openssl();
}

const paillier_public_key_t* paillier_private_key_get_public(const paillier_private_key_t *priv)
{
    if (priv)
    {
        return &priv->pub;
    }
    return NULL;
}

uint8_t *paillier_private_key_serialize(const paillier_private_key_t *priv, uint8_t *buffer, const uint32_t buffer_len, uint32_t *real_buffer_len)
{
    uint32_t needed_len = 0;
    uint32_t p_len = 0;
    uint8_t *p = buffer;
    
    if (!priv)
    {
        return NULL;
    }

    p_len = (uint32_t)BN_num_bytes(priv->p);
    assert(p_len == (uint32_t)BN_num_bytes(priv->q));
    needed_len = sizeof(uint32_t) + 2 * p_len;

    if (real_buffer_len)
    {
        *real_buffer_len = needed_len;
    }

    if (!buffer || buffer_len < needed_len)
    {
        return NULL;
    }

    memcpy(p, &p_len, sizeof(uint32_t));
    p += sizeof(uint32_t);
    BN_bn2bin(priv->p, p);
    p +=p_len;
    BN_bn2bin(priv->q, p);
    return buffer;
}

static paillier_private_key_t* paillier_private_key_deserialize_internal(const uint8_t *buffer, 
                                                                         uint32_t p_len,
                                                                         paillier_private_key_t* priv, 
                                                                         BN_CTX *ctx)
{
    
    BN_CTX_start(ctx);
 
    priv->p = BN_bin2bn(buffer, p_len, NULL);
    buffer += p_len;
    priv->q = BN_bin2bn(buffer, p_len, NULL);
    priv->pub.n = BN_new();
    priv->pub.n2 = BN_new();
    priv->lambda = BN_new();
    priv->mu = BN_new();
    
    if (!priv->p || !priv->q || !priv->lambda || !priv->mu || !priv->pub.n || !priv->pub.n2)
    {
        goto cleanup;
    }

    BN_set_flags(priv->p, BN_FLG_CONSTTIME);
    BN_set_flags(priv->q, BN_FLG_CONSTTIME);
    BN_set_flags(priv->pub.n, BN_FLG_CONSTTIME);
    BN_set_flags(priv->pub.n2, BN_FLG_CONSTTIME);
    BN_set_flags(priv->lambda, BN_FLG_CONSTTIME);
    BN_set_flags(priv->mu, BN_FLG_CONSTTIME);

    if (!BN_mul(priv->pub.n, priv->p, priv->q, ctx))
    {
        goto cleanup;
    }

    if (!BN_sqr(priv->pub.n2, priv->pub.n, ctx))
    {
        goto cleanup;
    }

    if (!BN_sub(priv->lambda, priv->pub.n, priv->p))
    {
        goto cleanup;
    }

    if (!BN_sub(priv->lambda, priv->lambda, priv->q))
    {
        goto cleanup;
    }

    if (!BN_add_word(priv->lambda, 1))
    {
        goto cleanup;
    }

    if (!BN_mod_inverse(priv->mu, priv->lambda, priv->pub.n, ctx))
    {
        goto cleanup;
    }

    if (BN_num_bits(priv->pub.n) < MIN_KEY_LEN_IN_BITS)
    {
        goto cleanup;
    }

    BN_CTX_end(ctx);

    return priv;

cleanup:

    BN_CTX_end(ctx);
    
    
    return NULL;
}

paillier_private_key_t* paillier_private_key_deserialize(const uint8_t* buffer, uint32_t buffer_len)
{
    paillier_private_key_t *priv = NULL;
    BN_CTX *ctx = NULL;
    
    if (!buffer || buffer_len < (sizeof(uint32_t) + MIN_KEY_LEN_IN_BITS / 8)) // len(p) + len(q) == len(n)
    {
        return NULL;
    }
    
    uint32_t len = 0;

    memcpy(&len, buffer, sizeof(uint32_t));
    buffer += sizeof(uint32_t);
    buffer_len -= sizeof(uint32_t);

    if (len > 65535 || 2 * len  > buffer_len)
    {
        return NULL;
    }

    ctx = BN_CTX_new();
    if (!ctx)
    {
        return NULL;
    }

    priv = (paillier_private_key_t*)calloc(1, sizeof(paillier_private_key_t));

    if (priv && !paillier_private_key_deserialize_internal(buffer, len, priv, ctx))
    {
        paillier_free_private_key(priv);
        priv = NULL;
    }

    BN_CTX_free(ctx);

    return priv;
}

static inline void paillier_free_private_key_cleanup(paillier_private_key_t *priv)
{
    if (priv)
    {
        paillier_free_public_key_cleanup(&priv->pub);
        BN_clear_free(priv->p);
        BN_clear_free(priv->q);
        BN_clear_free(priv->lambda);
        BN_clear_free(priv->mu);
    }
}

void paillier_free_private_key(paillier_private_key_t *priv)
{
    paillier_free_private_key_cleanup(priv);
    free(priv);
}

long paillier_encrypt_openssl_internal(const paillier_public_key_t *key, BIGNUM *ciphertext, const BIGNUM *r, const BIGNUM *plaintext, BN_CTX *ctx)
{
    int ret = -1;

    // Verify that r E Zn*
    if (is_coprime_fast(r, key->n, ctx) != 1)
    {
        return PAILLIER_ERROR_INVALID_RANDOMNESS;
    }

    BN_CTX_start(ctx);

    BIGNUM *tmp1 = BN_CTX_get(ctx);
    BIGNUM *tmp2 = BN_CTX_get(ctx);

    if (!tmp1 || !tmp2)
    {
        goto cleanup;
    }

    // Compute ciphertext = g^plaintext*r^n mod n^2
    // as will select g=n+1 ciphertext = (1+n*plaintext)*r^n mod n^2, see https://en.wikipedia.org/wiki/Paillier_cryptosystem
    if (!BN_mul(tmp1, key->n, plaintext, ctx))
    {
        goto cleanup;
    }
    if (!BN_add_word(tmp1, 1))
    {
        goto cleanup;
    }
    if (!BN_mod_exp(tmp2, r, key->n, key->n2, ctx))
    {
        goto cleanup;
    }
    if (!BN_mod_mul(ciphertext, tmp1, tmp2, key->n2, ctx))
    {
        goto cleanup;
    }

    ret = PAILLIER_SUCCESS;

cleanup:
    if (-1 == ret)
    {
        ret = paillier_error_from_openssl();
    }
    // Clear sensitive intermediates unconditionally, e.g. if we error in any of the BN arithmetic steps.
    // tmp1 = (1 + n * plaintext) - plaintext-derived
    // tmp2 = r^n mod n^2 - randomness-derived
    if (tmp1)
    {
        BN_clear(tmp1);
    }
    if (tmp2)
    {
        BN_clear(tmp2);
    }
    BN_CTX_end(ctx);

    return ret;
}

static inline long encrypt_openssl(const paillier_public_key_t *key, BIGNUM *ciphertext, const BIGNUM *plaintext, BN_CTX *ctx)
{
    long ret = -1;
    BN_CTX_start(ctx);

    BIGNUM *r = BN_CTX_get(ctx);
    
    if (!r)
    {
        ret = paillier_error_from_openssl();
    }
    else
    {
        do
        {
            if (!BN_rand_range(r, key->n))
            {
                ret = paillier_error_from_openssl();
                break;
            }
            
            ret = paillier_encrypt_openssl_internal(key, ciphertext, r, plaintext, ctx);

        } while (ret == PAILLIER_ERROR_INVALID_RANDOMNESS);
    }
    BN_clear(r);
    BN_CTX_end(ctx);

    return ret;
}

long paillier_decrypt_openssl_internal(const paillier_private_key_t *key, const BIGNUM *ciphertext, BIGNUM *plaintext, BN_CTX *ctx)
{
    int ret = -1;
    BN_CTX_start(ctx);

    BIGNUM *tmp = BN_CTX_get(ctx);

    if (!tmp)
    {
        goto cleanup;
    }

    // verify that ciphertext and n are coprime
    if (is_coprime_fast(ciphertext, key->pub.n, ctx) != 1)
    {
        ret = PAILLIER_ERROR_INVALID_CIPHER_TEXT;
        goto cleanup;
    }

    // Compute the plaintext = paillier_L(ciphertext^lambda mod n2)*mu mod n
    if (!BN_mod_exp(tmp, ciphertext, key->lambda, key->pub.n2, ctx))
    {
        goto cleanup;
    }

    ret = paillier_L(tmp, tmp, key->pub.n, ctx);
    if (ret != PAILLIER_SUCCESS)
    {
        goto cleanup;
    }
    
    ret = -1; //revert to openssl error

    if (!BN_mod_mul(plaintext, tmp, key->mu, key->pub.n, ctx))
    {
        goto cleanup;
    }

    ret = PAILLIER_SUCCESS;

cleanup:
    if (-1 == ret)
    {
        ret = paillier_error_from_openssl();
    }
    BN_clear(tmp);
    BN_CTX_end(ctx);
    return ret;
}

long paillier_encrypt(const paillier_public_key_t *key, const uint8_t *plaintext, uint32_t plaintext_len, uint8_t *ciphertext, uint32_t ciphertext_len, uint32_t *ciphertext_real_len)
{
    long ret = -1;
    int len = 0;
    BIGNUM *msg = NULL, *c = NULL;
    BN_CTX *ctx = NULL;
    uint32_t n2_size;
    if (!key)
    {
        return PAILLIER_ERROR_INVALID_KEY;
    }

    n2_size = (uint32_t)BN_num_bytes(key->n2);

    if (!plaintext || plaintext_len > (uint32_t)BN_num_bytes(key->n))
    {
        return PAILLIER_ERROR_INVALID_PLAIN_TEXT;
    }

    if (ciphertext_real_len)
    {
        *ciphertext_real_len = n2_size;
    }

    if (!ciphertext || ciphertext_len < n2_size)
    {
        return PAILLIER_ERROR_INVALID_CIPHER_TEXT;
    }

    ctx = BN_CTX_new();
    if (!ctx)
    {
        return PAILLIER_ERROR_OUT_OF_MEMORY;
    }
    
    BN_CTX_start(ctx);
    msg = BN_CTX_get(ctx);
    c = BN_CTX_get(ctx);
    if (!c || !msg)
    {
        goto cleanup;
    }

    if (!BN_bin2bn(plaintext, plaintext_len, msg))
    {
        goto cleanup;
    }

    if (BN_cmp(msg, key->n) >= 0)
    {
        // plaintext not in n
        ret = PAILLIER_ERROR_INVALID_PLAIN_TEXT;
        goto cleanup;
    }

    ret = encrypt_openssl(key, c, msg, ctx);
    if (PAILLIER_SUCCESS != ret)
    {
        goto cleanup;
    }

    len = BN_bn2binpad(c, ciphertext, n2_size);
    if (len <= 0)
    {
        ret = PAILLIER_ERROR_UNKNOWN;
        goto cleanup;
    }

    if (ciphertext_real_len)
    {
        *ciphertext_real_len = len;
    }

cleanup:
    if (-1 == ret)
    {
        ret = paillier_error_from_openssl();
    }

    if (ctx)
    {
        BN_clear(msg);
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
    }
    return ret;
}

long paillier_encrypt_to_ciphertext(const paillier_public_key_t *key, const uint8_t *plaintext, uint32_t plaintext_len, paillier_ciphertext_t **ciphertext)
{
    long ret = -1;
    paillier_ciphertext_t *c = NULL;
    BN_CTX *ctx = NULL;
    BIGNUM *msg = NULL;

    if (!key)
    {
        return PAILLIER_ERROR_INVALID_KEY;
    }
    if (!plaintext || plaintext_len > (uint32_t)BN_num_bytes(key->n))
    {
        return PAILLIER_ERROR_INVALID_PLAIN_TEXT;
    }
    if (!ciphertext)
    {
        return PAILLIER_ERROR_INVALID_CIPHER_TEXT;
    }

    c = (paillier_ciphertext_t*)calloc(1, sizeof(paillier_ciphertext_t));
    if (!c)
    {
        return PAILLIER_ERROR_OUT_OF_MEMORY;
    }
    
    c->cipher_size = (uint32_t)BN_num_bytes(key->n2);

    if ((c->ciphertext = BN_new()) == NULL)
    {
        goto cleanup;
    }

    if ((c->r = BN_new()) == NULL)
    {
        goto cleanup;
    }

    if ((ctx = BN_CTX_new()) == NULL)
    {
        goto cleanup;
    }

    BN_CTX_start(ctx);
    msg = BN_CTX_get(ctx);
    
    if (!msg || !BN_bin2bn(plaintext, plaintext_len, msg))
    {
        goto cleanup;
    }

    if (BN_cmp(msg, key->n) >= 0)
    {
        // plaintext not in n
        ret = PAILLIER_ERROR_INVALID_PLAIN_TEXT;
        goto cleanup;
    }

    do
    {
        if (!BN_rand_range(c->r, key->n))
        {
            ret = -1; // reset ret so open ssl error will be fetched
            break;
        }

        ret = paillier_encrypt_openssl_internal(key, c->ciphertext, c->r, msg, ctx);
    } while (ret == PAILLIER_ERROR_INVALID_RANDOMNESS);
    
    if (PAILLIER_SUCCESS != ret)
    {
        goto cleanup;
    }

    *ciphertext = c;
    c = NULL;

cleanup:
    if (-1 == ret)
    {
        ret = paillier_error_from_openssl();
    }

    if (msg)
    {
        BN_clear(msg);
    }
    if (ctx)
    {
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
    }
    paillier_free_ciphertext(c);
    return ret;
}

long paillier_encrypt_integer(const paillier_public_key_t *key, uint64_t plaintext, uint8_t *ciphertext, uint32_t ciphertext_len, uint32_t *ciphertext_real_len)
{
    long ret = -1;
    int len = 0;
    BN_CTX *ctx = NULL;
    BIGNUM *msg = NULL, *c = NULL;
    uint32_t n2_size = 0;

    if (!key)
    {
        return PAILLIER_ERROR_INVALID_KEY;
    }

    n2_size = (uint32_t)BN_num_bytes(key->n2);

    if (ciphertext_real_len)
    {
        *ciphertext_real_len = n2_size;
    }

    if (!ciphertext || ciphertext_len < n2_size)
    {
        return PAILLIER_ERROR_INVALID_CIPHER_TEXT;
    }
    
    ctx = BN_CTX_new();
    if (!ctx)
    {
        goto cleanup;
    }

    BN_CTX_start(ctx);
    msg = BN_CTX_get(ctx);
    c = BN_CTX_get(ctx);
    
    if (!msg || !c)
    {
        goto cleanup;
    }

    if (!BN_set_word(msg, plaintext))
    {
        goto cleanup;
    }
    
    ret = encrypt_openssl(key, c, msg, ctx);
    if (PAILLIER_SUCCESS != ret)
    {
        goto cleanup;
    }

    len = BN_bn2binpad(c, ciphertext, n2_size);
    if (len <= 0)
    {
        ret = PAILLIER_ERROR_UNKNOWN;
        goto cleanup;
    }

    if (ciphertext_real_len)
    {
        *ciphertext_real_len = n2_size;
    }

cleanup:
    if (-1 == ret)
    {
        ret = paillier_error_from_openssl();
    }

    if (ctx)
    {
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
    }

    return ret;
}

long paillier_decrypt(const paillier_private_key_t *key, const uint8_t *ciphertext, uint32_t ciphertext_len, uint8_t *plaintext, uint32_t plaintext_len, uint32_t *plaintext_real_len)
{
    long ret = -1;
    int len = 0;

    BIGNUM *msg = NULL, *c = NULL;
    BN_CTX *ctx = NULL;

    if (!key)
    {
        return PAILLIER_ERROR_INVALID_KEY;
    }

    if (!ciphertext || ciphertext_len > (uint32_t)BN_num_bytes(key->pub.n2))
    {
        return PAILLIER_ERROR_INVALID_CIPHER_TEXT;
    }

    if (plaintext_real_len)
    {
        *plaintext_real_len = (uint32_t)BN_num_bytes(key->pub.n);
    }

    if (!plaintext || plaintext_len < (uint32_t)BN_num_bytes(key->pub.n))
    {
        return PAILLIER_ERROR_INVALID_PLAIN_TEXT;
    }

    ctx = BN_CTX_new();
    if (!ctx)
    {
        return PAILLIER_ERROR_OUT_OF_MEMORY;
    }

    BN_CTX_start(ctx);
    c = BN_CTX_get(ctx);
    msg = BN_CTX_get(ctx);

    if (!c || !msg)
    {
        goto cleanup;
    }

    if (!BN_bin2bn(ciphertext, ciphertext_len, c))
    {
        goto cleanup;
    }

    if (BN_cmp(c, key->pub.n2) >= 0)
    {
        // ciphertext not in n^2
        ret = PAILLIER_ERROR_INVALID_CIPHER_TEXT;
        goto cleanup;
    }

    ret = paillier_decrypt_openssl_internal(key, c, msg, ctx);
    if (PAILLIER_SUCCESS != ret)
    {
        goto cleanup;
    }

    len = BN_bn2bin(msg, plaintext);
    if (len == 0 && BN_is_zero(msg))
    {
        plaintext[0] = 0;
        len = 1;
    }
    else if (len <= 0)
    {
        ret = PAILLIER_ERROR_UNKNOWN;
        goto cleanup;
    }

    if (plaintext_real_len)
    {
        *plaintext_real_len = len;
    }

cleanup:
    if (-1 == ret)
    {
        ret = paillier_error_from_openssl();
    }

    if (ctx)
    {
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
    }

    return ret;
}

long paillier_decrypt_integer(const paillier_private_key_t *key, const uint8_t *ciphertext, uint32_t ciphertext_len, uint64_t *plaintext)
{

    long ret = -1;
    BIGNUM *msg = NULL, *c = NULL;
    BN_CTX *ctx = NULL;

    if (!key)
    {
        return PAILLIER_ERROR_INVALID_KEY;
    }

    if (ciphertext_len > (uint32_t)BN_num_bytes(key->pub.n2))
    {
        return PAILLIER_ERROR_INVALID_CIPHER_TEXT;
    }

    if (!plaintext)
    {
        return PAILLIER_ERROR_INVALID_PLAIN_TEXT;
    }
    
    ctx = BN_CTX_new();
    if (!ctx)
    {
        return PAILLIER_ERROR_OUT_OF_MEMORY;
    }
        
    BN_CTX_start(ctx);

    c = BN_CTX_get(ctx);
    msg = BN_CTX_get(ctx);

    if (!c || !msg) 
    {
        goto cleanup;
    }

    if (!BN_bin2bn(ciphertext, ciphertext_len, c))
    {
        goto cleanup;
    }

    if (BN_cmp(c, key->pub.n2) >= 0)
    {
        // ciphertext not in n^2
        ret = PAILLIER_ERROR_INVALID_CIPHER_TEXT;
        goto cleanup;
    }

    ret = paillier_decrypt_openssl_internal(key, c, msg, ctx);
    if (PAILLIER_SUCCESS != ret)
    {
        goto cleanup;
    }
    
    if ((uint32_t)BN_num_bytes(msg) > sizeof(*plaintext))
    {
        ret = PAILLIER_ERROR_INVALID_PLAIN_TEXT;
        goto cleanup;
    }

    *plaintext = BN_get_word(msg);

cleanup:
    if (-1 == ret)
    {
        ret = paillier_error_from_openssl();
    }

    if (ctx)
    {
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
    }

    return ret;
}

long paillier_add(const paillier_public_key_t *key, 
                  const uint8_t *a_ciphertext, 
                  uint32_t a_ciphertext_len, 
                  const uint8_t *b_ciphertext, 
                  uint32_t b_ciphertext_len, 
                  uint8_t *result, 
                  uint32_t result_len, 
                  uint32_t *result_real_len)
{
    BN_CTX *ctx = NULL;
    BIGNUM *a = NULL;
    BIGNUM *b = NULL;
    BIGNUM *res = NULL;
    long ret = -1;
    int len = 0;
    uint32_t n2_size;

    if (!key)
    {
        return PAILLIER_ERROR_INVALID_KEY;
    }
    
    n2_size = (uint32_t)BN_num_bytes(key->n2);

    if (!a_ciphertext || a_ciphertext_len > n2_size ||
        !b_ciphertext || b_ciphertext_len > n2_size)
    {
        return PAILLIER_ERROR_INVALID_CIPHER_TEXT;
    }
    
    if (result_real_len)
    {
        *result_real_len = n2_size;
    }
    
    if (!result || result_len < n2_size)
    {
        return PAILLIER_ERROR_INVALID_CIPHER_TEXT;
    }
    
    ctx = BN_CTX_new();
    if (!ctx)
    {
        return PAILLIER_ERROR_OUT_OF_MEMORY;
    }
    
    BN_CTX_start(ctx);
    a = BN_CTX_get(ctx);
    b = BN_CTX_get(ctx);
    res = BN_CTX_get(ctx);

    if (!a || !b || !res)
    {
        goto cleanup;
    }

    if (!BN_bin2bn(a_ciphertext, a_ciphertext_len, a))
    {
        goto cleanup;
    }

    if (!BN_bin2bn(b_ciphertext, b_ciphertext_len, b))
    {
        goto cleanup;
    }

    // verify that a_ciphertext and b_ciphertext are coprime to n
    if (is_coprime_fast(a, key->n, ctx) != 1 ||
        is_coprime_fast(b, key->n, ctx) != 1)
    {
        ret = PAILLIER_ERROR_INVALID_CIPHER_TEXT;
        goto cleanup;
    }
    
    if (!BN_mod_mul(res, a, b, key->n2, ctx))
    {
        goto cleanup;
    }
        

    len = BN_bn2binpad(res, result, n2_size);
    if (len <= 0)
    {
        ret = PAILLIER_ERROR_UNKNOWN;
        goto cleanup;
    }

    if (result_real_len)
    {
        *result_real_len = n2_size;
    }

    ret = PAILLIER_SUCCESS;

cleanup:
    if (-1 == ret)
    {
        ret = paillier_error_from_openssl();
    }

    if (ctx)
    {
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
    }
    return ret;
}

long paillier_add_integer(const paillier_public_key_t *key, const uint8_t *a_ciphertext, uint32_t a_ciphertext_len, uint64_t b, uint8_t *result, uint32_t result_len, uint32_t *result_real_len)
{
    BN_CTX *ctx = NULL;
    BIGNUM *bn_a = NULL;
    BIGNUM *bn_b = NULL;
    BIGNUM *res = NULL;
    long ret = -1;
    int len = 0;
    uint32_t n2_size;

    if (!key)
    {
        return PAILLIER_ERROR_INVALID_KEY;
    }
    
    n2_size = (uint32_t)BN_num_bytes(key->n2);

    if (!a_ciphertext || a_ciphertext_len > n2_size)
    {
        return PAILLIER_ERROR_INVALID_CIPHER_TEXT;
    }

    if (result_real_len)
    {
        *result_real_len = n2_size;
    }

    if (!result || result_len < n2_size)
    {
        return PAILLIER_ERROR_INVALID_CIPHER_TEXT;
    }
    
    ctx = BN_CTX_new();
    if (!ctx)
    {
        return PAILLIER_ERROR_OUT_OF_MEMORY;
    }

    BN_CTX_start(ctx);
    bn_a = BN_CTX_get(ctx);
    bn_b = BN_CTX_get(ctx);
    res = BN_CTX_get(ctx);
    if (!bn_a || !bn_b || !res)
    {
        goto cleanup;
    }

    if (!BN_bin2bn(a_ciphertext, a_ciphertext_len, bn_a))
    {
        goto cleanup;
    }
        
    
    if (!BN_set_word(bn_b, b))
    {
        goto cleanup;
    }
        
    // verify that a_ciphertext and n are coprime
    if (is_coprime_fast(bn_a, key->n, ctx) != 1)
    {
        ret = PAILLIER_ERROR_INVALID_CIPHER_TEXT;
        goto cleanup;
    }
    
    ret = encrypt_openssl(key, res, bn_b, ctx);
    if (PAILLIER_SUCCESS != ret)
    {
        goto cleanup;
    }
    
    ret = -1; //reset ret so next open ssl error would be logged.

    if (!BN_mod_mul(res, bn_a, res, key->n2, ctx))
    {
        goto cleanup;
    }
        

    len = BN_bn2binpad(res, result, n2_size);
    if (len <= 0)
    {
        ret = PAILLIER_ERROR_UNKNOWN;
        goto cleanup;
    }

    if (result_real_len)
    {
        *result_real_len = len;
    }

    ret = PAILLIER_SUCCESS;

cleanup:
    if (-1 == ret)
    {
        ret = paillier_error_from_openssl();
    }

    if (ctx)
    {
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
    }
    return ret;
}

long paillier_sub(const paillier_public_key_t *key, 
                  const uint8_t *a_ciphertext, 
                  uint32_t a_ciphertext_len, 
                  const uint8_t *b_ciphertext, 
                  uint32_t b_ciphertext_len, 
                  uint8_t *result, 
                  uint32_t result_len, 
                  uint32_t *result_real_len)
{
    BN_CTX *ctx = NULL;
    BIGNUM *a = NULL;
    BIGNUM *b = NULL;
    BIGNUM *res = NULL;
    long ret = -1;
    int len = 0;
    uint32_t n2_size;

    if (!key)
    {
        return PAILLIER_ERROR_INVALID_KEY;
    }

    n2_size = (uint32_t)BN_num_bytes(key->n2);

    if (!a_ciphertext || a_ciphertext_len > n2_size ||
        !b_ciphertext || b_ciphertext_len > n2_size)
    {
        return PAILLIER_ERROR_INVALID_CIPHER_TEXT;
    }
        
    if (result_real_len)
    {
        *result_real_len = n2_size;
    }

    if (!result || result_len < n2_size)
    {
        return PAILLIER_ERROR_INVALID_CIPHER_TEXT;
    }

    ctx = BN_CTX_new();
    if (!ctx)
    {
        return PAILLIER_ERROR_OUT_OF_MEMORY;
    }
    
    BN_CTX_start(ctx);
    a = BN_CTX_get(ctx);
    b = BN_CTX_get(ctx);
    res = BN_CTX_get(ctx);
    if (!a || !b || !res)
    {
        goto cleanup;
    }

    if (!BN_bin2bn(a_ciphertext, a_ciphertext_len, a))
    {
        goto cleanup;
    }

    if (!BN_bin2bn(b_ciphertext, b_ciphertext_len, b))
    {
        goto cleanup;
    }

    // verify that a_ciphertext and b_ciphertext are coprime to n
    if (is_coprime_fast(a, key->n, ctx) != 1 ||
        is_coprime_fast(b, key->n, ctx) != 1)
    {
        ret = PAILLIER_ERROR_INVALID_CIPHER_TEXT;
        goto cleanup;
    }
    
    if (!BN_mod_inverse(b, b, key->n2, ctx))
    {
        goto cleanup;
    }

    if (!BN_mod_mul(res, a, b, key->n2, ctx))
        goto cleanup;

    len = BN_bn2binpad(res, result, n2_size);
    if (len <= 0)
    {
        ret = PAILLIER_ERROR_UNKNOWN;
        goto cleanup;
    }

    if (result_real_len)
    {
        *result_real_len = len;
    }
    
    ret = PAILLIER_SUCCESS;

cleanup:
    if (-1 == ret)
    {
        ret = paillier_error_from_openssl();
    }
    
    if (ctx)
    {
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
    }
    return ret;
}

long paillier_sub_integer(const paillier_public_key_t *key, const uint8_t *a_ciphertext, uint32_t a_ciphertext_len, uint64_t b, uint8_t *result, uint32_t result_len, uint32_t *result_real_len)
{
    BN_CTX *ctx = NULL;
    BIGNUM *bn_a = NULL;
    BIGNUM *bn_b = NULL;
    BIGNUM *res = NULL;
    long ret = -1;
    int len = 0;
    uint32_t n2_size;

    if (!key)
    {        
        return PAILLIER_ERROR_INVALID_KEY;
    }
    
    n2_size = (uint32_t)BN_num_bytes(key->n2);

    if (!a_ciphertext || a_ciphertext_len > n2_size)
    {
        return PAILLIER_ERROR_INVALID_CIPHER_TEXT;
    }
    if (result_real_len)
    {
        *result_real_len = n2_size;
    }

    if (!result || result_len < n2_size)
    {
        return PAILLIER_ERROR_INVALID_CIPHER_TEXT;
    }

    ctx = BN_CTX_new();
    if (!ctx)
    {
        return PAILLIER_ERROR_OUT_OF_MEMORY;
    }
        
    
    BN_CTX_start(ctx);
    bn_a = BN_CTX_get(ctx);
    bn_b = BN_CTX_get(ctx);
    res = BN_CTX_get(ctx);
    if (!bn_a || !bn_b || !res)
    {
        goto cleanup;
    }
    if (!BN_bin2bn(a_ciphertext, a_ciphertext_len, bn_a))
    {
        goto cleanup;
    }

    if (!BN_set_word(bn_b, b))
    {
        goto cleanup;
    }
        
    
    // verify that a_ciphertext and n are coprime
    if (is_coprime_fast(bn_a, key->n, ctx) != 1)
    {
        ret = PAILLIER_ERROR_INVALID_CIPHER_TEXT;
        goto cleanup;
    }

    ret = encrypt_openssl(key, res, bn_b, ctx);
    if (ret)
    {
        goto cleanup;
    }

    ret = -1; //reset ret so new open ssl errors could be logged   
    
    if (!BN_mod_inverse(res, res, key->n2, ctx))
    {
        goto cleanup;
    }

    if (!BN_mod_mul(res, bn_a, res, key->n2, ctx))
    {
        goto cleanup;
    }

    len = BN_bn2binpad(res, result, n2_size);
    if (len <= 0)
    {
        ret = PAILLIER_ERROR_UNKNOWN;
        goto cleanup;
    }

    if (result_real_len)
    {
        *result_real_len = len;
    }
        
    ret = PAILLIER_SUCCESS;

cleanup:
    if (-1 == ret)
    {
        ret = paillier_error_from_openssl();
    }

    if (ctx)
    {
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
    }
    return ret;
}

long paillier_mul(const paillier_public_key_t *key, 
                  const uint8_t *a_ciphertext, 
                  uint32_t a_ciphertext_len, 
                  const uint8_t *b_plaintext, 
                  uint32_t b_plaintext_len, 
                  uint8_t *result, 
                  uint32_t result_len, 
                  uint32_t *result_real_len)
{
    BN_CTX *ctx = NULL;
    BIGNUM *bn_a = NULL;
    BIGNUM *bn_b = NULL;
    BIGNUM *res = NULL;
    long ret = -1;
    int len = 0;
    uint32_t n2_size;

    if (!key)
    {
        return PAILLIER_ERROR_INVALID_KEY;
    }
    
    n2_size = (uint32_t)BN_num_bytes(key->n2);

    if (!a_ciphertext || a_ciphertext_len > n2_size)
    {
        return PAILLIER_ERROR_INVALID_CIPHER_TEXT;
    }
        
    if (!b_plaintext || b_plaintext_len > (uint32_t)BN_num_bytes(key->n))
    {
        return PAILLIER_ERROR_INVALID_PLAIN_TEXT;
    }
        
    if (result_real_len)
    {
        *result_real_len = n2_size;
    }
        
    if (!result || result_len < n2_size)
    {
        return PAILLIER_ERROR_INVALID_CIPHER_TEXT;
    }
        
    ctx = BN_CTX_new();
    if (!ctx)
    {
        return PAILLIER_ERROR_OUT_OF_MEMORY;
    }
    
    BN_CTX_start(ctx);
    bn_a = BN_CTX_get(ctx);
    bn_b = BN_CTX_get(ctx);
    res = BN_CTX_get(ctx);

    if (!bn_a || !bn_b || !res)
    {
        goto cleanup;
    }

    if (!BN_bin2bn(a_ciphertext, a_ciphertext_len, bn_a))
    {
        goto cleanup;
    }
        
    if (!BN_bin2bn(b_plaintext, b_plaintext_len, bn_b))
    {
        goto cleanup;
    }
    
    // verify that a_ciphertext and n are coprime
    if (is_coprime_fast(bn_a, key->n, ctx) != 1)
    {
        ret = PAILLIER_ERROR_INVALID_CIPHER_TEXT;
        goto cleanup;
    }
    
    if (!BN_mod_exp(res, bn_a, bn_b, key->n2, ctx))
    {
        goto cleanup;
    }

    len = BN_bn2binpad(res, result, n2_size);
    if (len <= 0)
    {
        ret = PAILLIER_ERROR_UNKNOWN;
        goto cleanup;
    }

    if (result_real_len)
    {
        *result_real_len = n2_size;
    }
        
    ret = PAILLIER_SUCCESS;

cleanup:
    if (-1 == ret)
    {
        ret = paillier_error_from_openssl();
    }
        
    if (ctx)
    {
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
    }
    return ret;
}

long paillier_mul_integer(const paillier_public_key_t *key, 
                          const uint8_t *a_ciphertext, 
                          uint32_t a_ciphertext_len, 
                          uint64_t b, 
                          uint8_t *result, 
                          uint32_t result_len, 
                          uint32_t *result_real_len)
{
    BN_CTX *ctx = NULL;
    BIGNUM *bn_a = NULL;
    BIGNUM *bn_b = NULL;
    BIGNUM *res = NULL;
    long ret = -1;
    int len = 0;
    uint32_t n2_size;

    if (!key)
    {
        return PAILLIER_ERROR_INVALID_KEY;
    }
    
    n2_size = (uint32_t)BN_num_bytes(key->n2);

    if (!a_ciphertext || a_ciphertext_len > n2_size)
    {
        return PAILLIER_ERROR_INVALID_CIPHER_TEXT;
    }
        
    if (result_real_len)
    {
        *result_real_len = n2_size;
    }
        
    if (!result || result_len < n2_size)
    {
        return PAILLIER_ERROR_INVALID_CIPHER_TEXT;
    }

    ctx = BN_CTX_new();
    if (!ctx)
    {
        return PAILLIER_ERROR_OUT_OF_MEMORY;
    }
        
    BN_CTX_start(ctx);
    bn_a = BN_CTX_get(ctx);
    bn_b = BN_CTX_get(ctx);
    res = BN_CTX_get(ctx);
    if (!bn_a || !bn_b || !res)
    {
        goto cleanup;
    }

    if (!BN_bin2bn(a_ciphertext, a_ciphertext_len, bn_a))
    {
        goto cleanup;
    }
        
    if (!BN_set_word(bn_b, b))
    {
        goto cleanup;
    }
        
    // verify that a_ciphertext and n are coprime
    if (is_coprime_fast(bn_a, key->n, ctx) != 1)
    {
        ret = PAILLIER_ERROR_INVALID_CIPHER_TEXT;
        goto cleanup;
    }
    
    if (!BN_mod_exp(res, bn_a, bn_b, key->n2, ctx))
    {
        goto cleanup;
    }
        

    len = BN_bn2binpad(res, result, n2_size);
    if (len <= 0)
    {
        ret = PAILLIER_ERROR_UNKNOWN;
        goto cleanup;
    }
    
    if (result_real_len)
    {
        *result_real_len = n2_size;
    }
        
    
    ret = PAILLIER_SUCCESS;

cleanup:
    if (-1 == ret)
    {
        ret = paillier_error_from_openssl();
    }
        
    if (ctx)
    {
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
    }
    return ret;
}

long paillier_get_ciphertext(const paillier_ciphertext_t *ciphertext_object, 
                             uint8_t *ciphertext, 
                             uint32_t ciphertext_len, 
                             uint32_t *ciphertext_real_len)
{
    if (!ciphertext_object)
    {
        return PAILLIER_ERROR_INVALID_CIPHER_TEXT;
    }
    if (!ciphertext && ciphertext_len)
    {
        return PAILLIER_ERROR_INVALID_PARAM;
    }

    const uint32_t encrypted_bytes = (uint32_t)BN_num_bytes(ciphertext_object->ciphertext);
    
    if (encrypted_bytes > ciphertext_object->cipher_size)
    {
        return PAILLIER_ERROR_INVALID_CIPHER_TEXT;
    }

    if (ciphertext_real_len)
    {
        *ciphertext_real_len = ciphertext_object->cipher_size;
    }
        
    if (!ciphertext || ciphertext_len < ciphertext_object->cipher_size)
    {
        return PAILLIER_ERROR_INVALID_CIPHER_TEXT;
    }
        
    
    if (BN_bn2binpad(ciphertext_object->ciphertext, ciphertext, ciphertext_object->cipher_size) <= 0)
    {
        return PAILLIER_ERROR_UNKNOWN;
    }

    return PAILLIER_SUCCESS;
}

void paillier_free_ciphertext(paillier_ciphertext_t *ciphertext_object)
{
    if (ciphertext_object)
    {
        BN_free(ciphertext_object->ciphertext);
        BN_clear_free(ciphertext_object->r);
        free(ciphertext_object);
    }
}

long paillier_error_from_openssl()
{
    long ret = ERR_get_error() * -1;
    if (0 == ret)
    {
        ret = PAILLIER_ERROR_UNKNOWN;
    }

    return ret;
}