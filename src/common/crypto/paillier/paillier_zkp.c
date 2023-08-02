#include "paillier_internal.h"
#include "alpha.h"

#include <string.h>
#include <assert.h>

#include <openssl/err.h>

#ifndef ENCLAVE
#define memset_s(dest, destsz, ch, count) memset(dest, ch, count)
#endif

#define FACTORIZANTION_ZKP_K 10
#define COPRIME_ZKP_K 16
#define PAILLIER_BLUM_STATISTICAL_SECURITY 80

#define FACTORIZANTION_ZKP_SALT "factorization zkpok"
#define COPRIME_ZKP_SALT "coprime zkp"
#define PAILLIER_BLUM_ZKP_SALT "paillier blum modulus zkp"

typedef struct
{
  BIGNUM *w;
  BIGNUM *x[PAILLIER_BLUM_STATISTICAL_SECURITY];
  BIGNUM *z[PAILLIER_BLUM_STATISTICAL_SECURITY];
  uint8_t a[PAILLIER_BLUM_STATISTICAL_SECURITY];
  uint8_t b[PAILLIER_BLUM_STATISTICAL_SECURITY];
} zkp_paillier_blum_modulus_proof_t;

static BIGNUM* deterministic_rand(const sha256_md_t seed, uint32_t n_len, BIGNUM *bn_r, sha256_md_t *out_md)
{
    SHA512_CTX sha512_ctx;
    uint8_t *r;
    uint8_t *r_ptr;
    
    r = (uint8_t*)malloc(n_len + SHA512_DIGEST_LENGTH);
    if (!r)
        return NULL;
    memcpy(r, seed, sizeof(sha256_md_t));
    r_ptr = r;

    for (size_t i = 0; i < n_len / PAILLIER_SHA256_LEN; ++i)
    {
        SHA512_Init(&sha512_ctx);
        SHA512_Update(&sha512_ctx, r_ptr, PAILLIER_SHA256_LEN);
        SHA512_Final(r_ptr, &sha512_ctx);
        r_ptr += PAILLIER_SHA256_LEN;
    }
    if (out_md)
        memcpy(*out_md, r_ptr, sizeof(sha256_md_t));
    BN_bin2bn(r, n_len, bn_r);
    free(r);
    return bn_r;
}

static inline long update_with_bignum(SHA256_CTX *ctx, const BIGNUM *bn)
{
    uint8_t *n = NULL;
    uint32_t len = BN_num_bytes(bn);
    n = (uint8_t*)malloc(len);
    if (!n)
        return PAILLIER_ERROR_OUT_OF_MEMORY;
    if (BN_bn2bin(bn, n) <= 0) // should never happen
    {
        free(n);
        return ERR_peek_error() * -1;
    }
    SHA256_Update(ctx, n, len);
    free(n);
    return PAILLIER_SUCCESS;
}

long paillier_generate_factorization_zkpok(const paillier_private_key_t *priv, const uint8_t *aad, uint32_t aad_len, uint8_t x[PAILLIER_SHA256_LEN], uint8_t *y, uint32_t y_len, uint32_t *y_real_len)
{
    BN_CTX *ctx = NULL;
    BN_MONT_CTX *mont = NULL;
    BIGNUM *A = NULL, *r = NULL, *e = NULL, *bn_y = NULL, *z = NULL;
    uint8_t *n = NULL;
    uint8_t *tmp = NULL;
    SHA256_CTX sha256_ctx;
    SHA512_CTX sha512_ctx;
    sha512_md_t sha512_md;
    sha256_md_t seed;
    uint32_t n_len;

    long ret = -1;

    if (!priv)
        return PAILLIER_ERROR_INVALID_KEY;
    if (!aad && aad_len)
        return PAILLIER_ERROR_INVALID_PARAM;
    if (!x)
        return PAILLIER_ERROR_INVALID_PARAM;
    if (!y && y_len)
        return PAILLIER_ERROR_INVALID_PARAM;
    
    n_len = BN_num_bytes(priv->pub.n);
    assert(n_len % PAILLIER_SHA256_LEN == 0);
    if (n_len % PAILLIER_SHA256_LEN != 0)
        return PAILLIER_ERROR_INVALID_KEY;
    
    if ((ctx = BN_CTX_new()) == NULL)
        return ERR_get_error() * -1;

    BN_CTX_start(ctx);
    
    if (!(A = BN_CTX_get(ctx)))
        goto cleanup;
    
    if (!BN_rshift1(A, priv->pub.n))
        goto cleanup;
        
    if (y_real_len)
        *y_real_len = BN_num_bytes(A);
    if (!y || y_len < (uint32_t)BN_num_bytes(A))
    {
        ret = PAILLIER_ERROR_BUFFER_TOO_SHORT;
        goto cleanup;
    }
    
    if (!(r = BN_CTX_get(ctx)))
        goto cleanup;
    if (!(e = BN_CTX_get(ctx)))
        goto cleanup;
    if (!(bn_y = BN_CTX_get(ctx)))
        goto cleanup;
    if (!(z = BN_CTX_get(ctx)))
        goto cleanup;  

    if (!BN_rand_range(r, A))
        goto cleanup;

    n = (uint8_t*)malloc(n_len);
    if (!n)
    {
        ret = PAILLIER_ERROR_OUT_OF_MEMORY;
        goto cleanup;
    }
    if (!BN_bn2bin(priv->pub.n, n))
        goto cleanup;
    
    tmp = (uint8_t*)malloc(n_len);
    if (!tmp)
    {
        ret = PAILLIER_ERROR_OUT_OF_MEMORY;
        goto cleanup;
    }

    SHA256_Init(&sha256_ctx);
    SHA256_Update(&sha256_ctx, FACTORIZANTION_ZKP_SALT, sizeof(FACTORIZANTION_ZKP_SALT));
    SHA256_Update(&sha256_ctx, n, n_len);
    if (aad)
        SHA256_Update(&sha256_ctx, aad, aad_len);
    SHA256_Final(seed, &sha256_ctx);

    SHA512_Init(&sha512_ctx);
    SHA256_Init(&sha256_ctx);

    SHA512_Update(&sha512_ctx, n, n_len);

    if (!(mont = BN_MONT_CTX_new()))
        goto cleanup;

    if (!BN_MONT_CTX_set(mont, priv->pub.n, ctx))
        goto cleanup;

    for (size_t i = 0; i < FACTORIZANTION_ZKP_K; ++i)
    {
        do
        {
            deterministic_rand(seed, n_len, z, &seed);
        } while (BN_cmp(z, priv->pub.n) >= 0);
        
        if (!BN_bn2bin(z, tmp))
            goto cleanup;
        SHA512_Update(&sha512_ctx, tmp, BN_num_bytes(z));
        if (!BN_mod_exp_mont(z, z, r, priv->pub.n, ctx, mont))
            goto cleanup;
        if (!BN_bn2bin(z, tmp))
            goto cleanup;
        SHA256_Update(&sha256_ctx, tmp, BN_num_bytes(z));
    }
    SHA256_Final(x, &sha256_ctx);
    SHA512_Update(&sha512_ctx, x, PAILLIER_SHA256_LEN);
    SHA512_Final(sha512_md, &sha512_ctx);
    
    if (!BN_bin2bn(sha512_md, sizeof(sha512_md), e))
        goto cleanup;
    
    if (!BN_usub(bn_y, priv->pub.n, priv->lamda))
        goto cleanup;
    if (!BN_mul(bn_y, bn_y, e, ctx))
        goto cleanup;
    if (!BN_mod_add(bn_y, bn_y, r, A, ctx))
        goto cleanup;

    if (BN_bn2binpad(bn_y, y, BN_num_bytes(A)) <= 0)
        goto cleanup;

    ret = PAILLIER_SUCCESS;
    
cleanup:
    if (ret < 0)
        ret = ERR_get_error() * -1;
    free(n);
    free(tmp);
    BN_MONT_CTX_free(mont);
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    return ret;
}

long paillier_verify_factorization_zkpok(const paillier_public_key_t *pub, const uint8_t *aad, uint32_t aad_len, const uint8_t x[PAILLIER_SHA256_LEN], const uint8_t *y, uint32_t y_len)
{
    BN_CTX *ctx = NULL;
    BN_MONT_CTX *mont = NULL;
    BIGNUM *e = NULL, *bn_y = NULL, *exp = NULL;
    BIGNUM *z[FACTORIZANTION_ZKP_K];
    uint8_t *n = NULL;
    uint8_t *tmp = NULL;
    SHA256_CTX sha256_ctx;
    SHA512_CTX sha512_ctx;
    sha512_md_t sha512_md;
    sha256_md_t sha256_md;
    sha256_md_t seed;
    uint32_t n_len;

    long ret = -1;

    if (!pub)
        return PAILLIER_ERROR_INVALID_KEY;
    if (!aad && aad_len)
        return PAILLIER_ERROR_INVALID_PARAM;
    if (!x)
        return PAILLIER_ERROR_INVALID_PARAM;
    if (!y || !y_len)
        return PAILLIER_ERROR_INVALID_PARAM;
    
    n_len = BN_num_bytes(pub->n);
    assert(n_len % PAILLIER_SHA256_LEN == 0);
    if (n_len % PAILLIER_SHA256_LEN != 0)
        return PAILLIER_ERROR_INVALID_KEY;
    
    if ((ctx = BN_CTX_new()) == NULL)
        return ERR_get_error() * -1;

    BN_CTX_start(ctx);
    
    if (!(e = BN_CTX_get(ctx)))
        goto cleanup;
    if (!(bn_y = BN_CTX_get(ctx)))
        goto cleanup;
    if (!(exp = BN_CTX_get(ctx)))
        goto cleanup;

    n = (uint8_t*)malloc(n_len);
    if (!n)
    {
        ret = PAILLIER_ERROR_OUT_OF_MEMORY;
        goto cleanup;
    }
    if (!BN_bn2bin(pub->n, n))
        goto cleanup;
    
    tmp = (uint8_t*)malloc(n_len);
    if (!tmp)
    {
        ret = PAILLIER_ERROR_OUT_OF_MEMORY;
        goto cleanup;
    }

    SHA256_Init(&sha256_ctx);
    SHA256_Update(&sha256_ctx, FACTORIZANTION_ZKP_SALT, sizeof(FACTORIZANTION_ZKP_SALT));
    SHA256_Update(&sha256_ctx, n, n_len);
    if (aad)
        SHA256_Update(&sha256_ctx, aad, aad_len);
    SHA256_Final(seed, &sha256_ctx);

    SHA512_Init(&sha512_ctx);

    SHA512_Update(&sha512_ctx, n, n_len);

    for (size_t i = 0; i < FACTORIZANTION_ZKP_K; ++i)
    {
        if (!(z[i] = BN_CTX_get(ctx)))
            goto cleanup;

        do
        {
            deterministic_rand(seed, n_len, z[i], &seed);
        } while (BN_cmp(z[i], pub->n) >= 0);
        
        if (!BN_bn2bin(z[i], tmp))
            goto cleanup;
        SHA512_Update(&sha512_ctx, tmp, BN_num_bytes(z[i]));
    }
    SHA512_Update(&sha512_ctx, x, PAILLIER_SHA256_LEN);
    SHA512_Final(sha512_md, &sha512_ctx);
    
    if (!BN_bin2bn(sha512_md, sizeof(sha512_md), e))
        goto cleanup;
    
    SHA256_Init(&sha256_ctx);
    
    if (!BN_bin2bn(y, y_len, bn_y))
        goto cleanup;
    if (!BN_mul(exp, pub->n, e, ctx))
        goto cleanup;
    if (!BN_sub(exp, exp, bn_y))
        goto cleanup;
    
    if (!BN_lshift1(bn_y, bn_y))
        goto cleanup;
    if (!BN_add_word(bn_y, 1))
        goto cleanup;
    
    if (BN_cmp(bn_y, pub->n) >= 0)
    {
        ret = PAILLIER_ERROR_INVALID_PROOF;
        goto cleanup;
    }

    SHA256_Init(&sha256_ctx);

    if (!(mont = BN_MONT_CTX_new()))
        goto cleanup;

    if (!BN_MONT_CTX_set(mont, pub->n, ctx))
        goto cleanup;

    for (size_t i = 0; i < FACTORIZANTION_ZKP_K; ++i)
    {
        if (!BN_mod_exp_mont(z[i], z[i], exp, pub->n, ctx, mont))
            goto cleanup;
        if (!BN_mod_inverse(z[i], z[i], pub->n, ctx))
            goto cleanup;
        if (!BN_bn2bin(z[i], tmp))
            goto cleanup;

        SHA256_Update(&sha256_ctx, tmp, BN_num_bytes(z[i]));
    }
    SHA256_Final(sha256_md, &sha256_ctx);

    ret = memcmp(x, sha256_md, PAILLIER_SHA256_LEN) == 0 ? PAILLIER_SUCCESS : PAILLIER_ERROR_INVALID_PROOF;
    
cleanup:
    if (ret < 0)
        ret = ERR_get_error() * -1;
    free(n);
    free(tmp);
    BN_MONT_CTX_free(mont);
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    return ret;
}

long paillier_generate_coprime_zkp(const paillier_private_key_t *priv, const uint8_t *aad, uint32_t aad_len, uint8_t *y, uint32_t y_len, uint32_t *y_real_len)
{
    BN_CTX *ctx = NULL;
    BN_MONT_CTX *mont = NULL;
    BIGNUM *x = NULL, *M = NULL, *tmp = NULL;
    uint8_t *n = NULL;
    uint8_t *y_ptr = y;
    SHA256_CTX sha256_ctx;
    sha256_md_t seed;
    uint32_t n_len;

    long ret = -1;

    if (!priv)
        return PAILLIER_ERROR_INVALID_KEY;
    if (!aad && aad_len)
        return PAILLIER_ERROR_INVALID_PARAM;
    if (!y && y_len)
        return PAILLIER_ERROR_INVALID_PARAM;
    
    n_len = BN_num_bytes(priv->pub.n);
    
    assert(n_len % PAILLIER_SHA256_LEN == 0);
    if (n_len % PAILLIER_SHA256_LEN != 0)
        return PAILLIER_ERROR_INVALID_KEY;

    
    if (y_real_len)
        *y_real_len = n_len * COPRIME_ZKP_K;
    if (!y || y_len < n_len * COPRIME_ZKP_K)
        return PAILLIER_ERROR_BUFFER_TOO_SHORT;

    if ((ctx = BN_CTX_new()) == NULL)
        return ERR_get_error() * -1;

    BN_CTX_start(ctx);
    
    if (!(x = BN_CTX_get(ctx)))
        goto cleanup;
    if (!(M = BN_CTX_get(ctx)))
        goto cleanup;
    if (!(tmp = BN_CTX_get(ctx)))
        goto cleanup;
    
    BN_set_flags(M, BN_FLG_CONSTTIME);
    if (!BN_mod_inverse(M, priv->pub.n, priv->lamda, ctx))
        goto cleanup;
    
    n = (uint8_t*)malloc(n_len);
    if (!n)
    {
        ret = PAILLIER_ERROR_OUT_OF_MEMORY;
        goto cleanup;
    }
    if (!BN_bn2bin(priv->pub.n, n))
        goto cleanup;
    
    SHA256_Init(&sha256_ctx);
    SHA256_Update(&sha256_ctx, COPRIME_ZKP_SALT, sizeof(COPRIME_ZKP_SALT));
    SHA256_Update(&sha256_ctx, n, n_len);
    if (aad)
        SHA256_Update(&sha256_ctx, aad, aad_len);
    SHA256_Final(seed, &sha256_ctx);
    free(n);
    n = NULL;

    if (!(mont = BN_MONT_CTX_new()))
        goto cleanup;

    if (!BN_MONT_CTX_set(mont, priv->pub.n, ctx))
        goto cleanup;

    for (size_t i = 0; i < COPRIME_ZKP_K; ++i)
    {
        int res;
        do
        {
            deterministic_rand(seed, n_len, x, &seed);
            res = is_coprime_fast(x, priv->pub.n, ctx);
        } while (res == 0);

        if (res == -1)
            goto cleanup;
        
        if (!BN_mod_exp_mont(tmp, x, M, priv->pub.n, ctx, mont))
            goto cleanup;
        if (BN_bn2binpad(tmp, y_ptr, n_len) < 0)
            goto cleanup;
        y_ptr += n_len;
    }
    
    ret = PAILLIER_SUCCESS;

cleanup:
    if (ret < 0)
        ret = ERR_get_error() * -1;
    free(n);
    BN_MONT_CTX_free(mont);
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    return ret;
}

long paillier_verify_coprime_zkp(const paillier_public_key_t *pub, const uint8_t *aad, uint32_t aad_len, const uint8_t *y, uint32_t y_len)
{
    BN_CTX *ctx = NULL;
    BN_MONT_CTX *mont = NULL;
    BIGNUM *x = NULL, *bn_y = NULL, *tmp = NULL;
    uint8_t *n = NULL;
    const uint8_t *y_ptr = y;
    SHA256_CTX sha256_ctx;
    sha256_md_t seed;
    uint32_t n_len;

    long ret = -1;

    if (!pub)
        return PAILLIER_ERROR_INVALID_KEY;
    if (!aad && aad_len)
        return PAILLIER_ERROR_INVALID_PARAM;
    if (!y && y_len)
        return PAILLIER_ERROR_INVALID_PARAM;
    
    n_len = BN_num_bytes(pub->n);
    
    assert(n_len % PAILLIER_SHA256_LEN == 0);
    if (n_len % PAILLIER_SHA256_LEN != 0)
        return PAILLIER_ERROR_INVALID_KEY;

    assert(y_len == n_len * COPRIME_ZKP_K);
    if (!y || y_len < n_len * COPRIME_ZKP_K)
        return PAILLIER_ERROR_INVALID_PARAM;
    
    if ((ctx = BN_CTX_new()) == NULL)
        return ERR_get_error() * -1;

    BN_CTX_start(ctx);
    
    if (BN_is_prime_ex(pub->n, 256, ctx, NULL))
    {
        ret = PAILLIER_ERROR_INVALID_KEY;
        goto cleanup;
    }

    if (!(x = BN_CTX_get(ctx)))
        goto cleanup;
    if (!(bn_y = BN_CTX_get(ctx)))
        goto cleanup;
    if (!(tmp = BN_CTX_get(ctx)))
        goto cleanup;
    
    if (!BN_bin2bn(alpha_bin, alpha_bin_len, tmp))
        goto cleanup;
    
    if (is_coprime_fast(tmp, pub->n, ctx) != 1)
    {
        ret = PAILLIER_ERROR_INVALID_KEY;
        goto cleanup;
    }

    n = (uint8_t*)malloc(n_len);
    if (!n)
    {
        ret = PAILLIER_ERROR_OUT_OF_MEMORY;
        goto cleanup;
    }
    if (!BN_bn2bin(pub->n, n))
        goto cleanup;
    
    SHA256_Init(&sha256_ctx);
    SHA256_Update(&sha256_ctx, COPRIME_ZKP_SALT, sizeof(COPRIME_ZKP_SALT));
    SHA256_Update(&sha256_ctx, n, n_len);
    if (aad)
        SHA256_Update(&sha256_ctx, aad, aad_len);
    SHA256_Final(seed, &sha256_ctx);
    free(n);
    n = NULL;

    if (!(mont = BN_MONT_CTX_new()))
        goto cleanup;

    if (!BN_MONT_CTX_set(mont, pub->n, ctx))
        goto cleanup;

    for (size_t i = 0; i < COPRIME_ZKP_K; ++i)
    {
        int res;
        do
        {
            deterministic_rand(seed, n_len, x, &seed);
            res = is_coprime_fast(x, pub->n, ctx);
        } while (res == 0);
        
        if (res == -1)
            goto cleanup;

        if (!BN_mod(x, x, pub->n, ctx))
            goto cleanup;
        if (!BN_bin2bn(y_ptr, n_len, bn_y))
            goto cleanup;
        if (!BN_mod_exp_mont(tmp, bn_y, pub->n, pub->n, ctx, mont))
            goto cleanup;
        if (BN_cmp(tmp, x) != 0)
        {
            ret = PAILLIER_ERROR_INVALID_PROOF;
            goto cleanup;
        }
        y_ptr += n_len;
    }
    
    ret = PAILLIER_SUCCESS;

cleanup:
    if (ret < 0)
        ret = ERR_get_error() * -1;
    free(n);
    BN_MONT_CTX_free(mont);
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    return ret;
}

static inline long init_paillier_blum_zkp(zkp_paillier_blum_modulus_proof_t *proof, BN_CTX *ctx)
{
    proof->w = BN_CTX_get(ctx);
    if (!proof->w)
        return PAILLIER_ERROR_OUT_OF_MEMORY;
    for (size_t i = 0; i < PAILLIER_BLUM_STATISTICAL_SECURITY; i++)
    {
        proof->x[i] = BN_CTX_get(ctx);
        proof->z[i] = BN_CTX_get(ctx);
        if (!proof->x[i] || !proof->z[i])
            return PAILLIER_ERROR_OUT_OF_MEMORY;
    }
    return PAILLIER_SUCCESS;
}

/* serialization format is sizeof(pub->n) || w || (x || z || a || b) * PAILLIER_BLUM_STATISTICAL_SECURITY */
static inline uint32_t paillier_blum_zkp_serialized_size(const paillier_public_key_t *pub)
{
    int n_len = BN_num_bytes(pub->n);
    return sizeof(uint32_t) + n_len + (n_len * 2 + sizeof(uint8_t) * 2) * PAILLIER_BLUM_STATISTICAL_SECURITY;
}

static inline void serialize_paillier_blum_zkp(const zkp_paillier_blum_modulus_proof_t *proof, uint32_t n_len, uint8_t *serialized_proof)
{
    uint8_t *ptr = serialized_proof;
    *(uint32_t*)ptr = n_len;
    ptr += sizeof(uint32_t);
    BN_bn2binpad(proof->w, ptr, n_len);
    ptr += n_len;

    for (uint32_t i = 0; i < PAILLIER_BLUM_STATISTICAL_SECURITY; ++i)
    {
        BN_bn2binpad(proof->x[i], ptr, n_len);
        ptr += n_len;
        BN_bn2binpad(proof->z[i], ptr, n_len);
        ptr += n_len;
        *ptr++ = proof->a[i];
        *ptr++ = proof->b[i];
    }
}

static inline int deserialize_paillier_blum_zkp(zkp_paillier_blum_modulus_proof_t *proof, uint32_t n_len, const uint8_t *serialized_proof)
{
    uint32_t proof_n_len;
    const uint8_t *ptr = serialized_proof;
    proof_n_len = *(uint32_t*)ptr;
    ptr += sizeof(uint32_t);

    if (n_len != proof_n_len)
        return 0;

    if (!BN_bin2bn(ptr, n_len, proof->w))
        return 0;
    ptr += n_len;

    for (uint32_t i = 0; i < PAILLIER_BLUM_STATISTICAL_SECURITY; ++i)
    {
        if (!BN_bin2bn(ptr, n_len, proof->x[i]))
            return 0;
        ptr += n_len;
        if (!BN_bin2bn(ptr, n_len, proof->z[i]))
            return 0;
        ptr += n_len;
        proof->a[i] = *ptr++;
        proof->b[i] = *ptr++;
    }
    return 1;
}

long paillier_generate_paillier_blum_zkp(const paillier_private_key_t *priv, const uint8_t *aad, uint32_t aad_len, uint8_t *serialized_proof, uint32_t proof_len, uint32_t *proof_real_len)
{
    BN_CTX *ctx = NULL;
    BIGNUM *p_remainder = NULL, *q_remainder = NULL;
    BIGNUM *n_inverse_mod_phi_n = NULL;
    BIGNUM *p_minus_1 = NULL, *q_minus_1 = NULL;
    BIGNUM *p_exp_4th = NULL, *q_exp_4th = NULL;
    BIGNUM *tmp = NULL, *y_mod_pq = NULL;
    BIGNUM *correction = NULL;
    BIGNUM *p_4th_root = NULL, *q_4th_root = NULL;
    BIGNUM *y = NULL;
    BIGNUM *a = NULL, *b = NULL;
    zkp_paillier_blum_modulus_proof_t proof;
    SHA256_CTX sha256_ctx;
    sha256_md_t seed;
    uint32_t n_len;
    uint32_t needed_proof_len;

    long ret = -1;

    if (!priv)
        return PAILLIER_ERROR_INVALID_KEY;
    if (!aad && aad_len)
        return PAILLIER_ERROR_INVALID_PARAM;
    if (!serialized_proof && proof_len)
        return PAILLIER_ERROR_INVALID_PARAM;

    needed_proof_len = paillier_blum_zkp_serialized_size(&priv->pub);
    if (proof_real_len)
        *proof_real_len = needed_proof_len;

    if (proof_len < needed_proof_len)
        return PAILLIER_ERROR_BUFFER_TOO_SHORT;
    memset_s(serialized_proof, proof_len, 0, proof_len);
    
    n_len = BN_num_bytes(priv->pub.n);
    if ((ctx = BN_CTX_new()) == NULL)
        return ERR_get_error() * -1;

    BN_CTX_start(ctx);
    if (init_paillier_blum_zkp(&proof, ctx) != PAILLIER_SUCCESS)
        goto cleanup;
    
    p_remainder = BN_CTX_get(ctx);
    q_remainder = BN_CTX_get(ctx);
    tmp = BN_CTX_get(ctx);
    a = BN_CTX_get(ctx);
    b = BN_CTX_get(ctx);
    correction = BN_CTX_get(ctx);
    if (!q_remainder || !p_remainder || !tmp || !a || !b || !correction)
        goto cleanup;
    
    // Generate w with (-1, 1) Jacobi signs wrt (p,q) by Chinese remainder theorem
    // Satisfying w = -a^4 mod p and w = b^4 mod q for random a,b
    if (!BN_mod_inverse(p_remainder, priv->p, priv->q, ctx))
        goto cleanup;
    if (!BN_mod_inverse(q_remainder, priv->q, priv->p, ctx))
        goto cleanup;
    if (!BN_mod_mul(p_remainder, p_remainder, priv->p, priv->pub.n, ctx))
        goto cleanup;
    if (!BN_mod_mul(q_remainder, q_remainder, priv->q, priv->pub.n, ctx))
        goto cleanup;
    if (!BN_rand_range(a, priv->p))
        goto cleanup;
    if (!BN_rand_range(b, priv->q))
        goto cleanup;

    // Compute correction as a mod p and b mod q, this will be the "QR-corrected" 4th root of w (later)
    if (!BN_mod_mul(tmp, q_remainder, a, priv->pub.n, ctx))
        goto cleanup;
    if (!BN_mod_mul(correction, p_remainder, b, priv->pub.n, ctx))
        goto cleanup;
    if (!BN_mod_add_quick(correction, tmp, correction, priv->pub.n))
        goto cleanup;

    // Set w = -a^4*q*q_inv_mod_p + b^4*p*p_inv_mod_q to satisfy above
    // Notice correction^4 = a^4*q*q_inv_mod_p + b^4*p*p_inv_mod_q (this is "QR-corrected" w)
    if (!BN_sqr(a, a, ctx))
        goto cleanup;
    if (!BN_sqr(a, a, ctx))
        goto cleanup;
    if (!BN_sqr(b, b, ctx))
        goto cleanup;
    if (!BN_sqr(b, b, ctx))
        goto cleanup;
    if (!BN_mod_mul(a, q_remainder, a, priv->pub.n, ctx))
        goto cleanup;
    if (!BN_mod_mul(b, p_remainder, b, priv->pub.n, ctx))
        goto cleanup;
    if (!BN_mod_sub_quick(proof.w, b, a, priv->pub.n))
        goto cleanup;

    n_inverse_mod_phi_n = BN_CTX_get(ctx);
    if (!n_inverse_mod_phi_n)
        goto cleanup;
    if (!BN_mod_inverse(n_inverse_mod_phi_n, priv->pub.n, priv->lamda, ctx))    // To compute z[i]
        goto cleanup;

    // Taking each y[i] 4th root (by exponentation with p_exp_4th = ((p-1)/2)^2 mod (p -1) - double sqrt
    // Checking result^4 = y[i] or -y[i], which defines the legendre symbol
    p_minus_1 = BN_dup(priv->p);
    q_minus_1 = BN_dup(priv->q);
    if (!p_minus_1 || !q_minus_1)
        goto cleanup;

    if (!BN_sub_word(p_minus_1, 1))
        goto cleanup;
    if (!BN_sub_word(q_minus_1, 1))
        goto cleanup;

    p_exp_4th = BN_dup(priv->p);
    q_exp_4th = BN_dup(priv->q);
    if (!p_exp_4th || !q_exp_4th)
        goto cleanup;

    if (!BN_add_word(p_exp_4th, 1))
        goto cleanup;
    if (!BN_rshift(p_exp_4th, p_exp_4th, 2))
        goto cleanup;
    if (!BN_mod_sqr(p_exp_4th, p_exp_4th, p_minus_1, ctx))
        goto cleanup;

    if (!BN_add_word(q_exp_4th, 1))
        goto cleanup;
    if (!BN_rshift(q_exp_4th, q_exp_4th, 2))
        goto cleanup;
    if (!BN_mod_sqr(q_exp_4th, q_exp_4th, q_minus_1, ctx))
        goto cleanup;
    BN_clear_free(p_minus_1);
    BN_clear_free(q_minus_1);
    p_minus_1 = NULL;
    q_minus_1 = NULL;

    y_mod_pq = BN_CTX_get(ctx);
    p_4th_root = BN_CTX_get(ctx);
    q_4th_root = BN_CTX_get(ctx);

    if (!y_mod_pq || !p_4th_root || !q_4th_root)
        goto cleanup;
    
    SHA256_Init(&sha256_ctx);
    SHA256_Update(&sha256_ctx, PAILLIER_BLUM_ZKP_SALT, sizeof(PAILLIER_BLUM_ZKP_SALT));
    if (aad)
        SHA256_Update(&sha256_ctx, aad, aad_len);
    ret = update_with_bignum(&sha256_ctx, priv->pub.n);
    if (ret != PAILLIER_SUCCESS)
        goto cleanup;
    ret = update_with_bignum(&sha256_ctx, proof.w);
    if (ret != PAILLIER_SUCCESS)
        goto cleanup;
    SHA256_Final(seed, &sha256_ctx);
    ret = -1;

    y = BN_CTX_get(ctx);
    if (!y)
        goto cleanup;
    
    for (uint32_t i = 0; i < PAILLIER_BLUM_STATISTICAL_SECURITY; ++i)
    {
        do
        {
            deterministic_rand(seed, n_len, y, &seed);
        } while (BN_cmp(y, priv->pub.n) >= 0);
        uint8_t legendre_p;   // 0 is QR, 1 if QNR
        uint8_t legendre_q;
        if (!BN_mod_exp(proof.z[i], y, n_inverse_mod_phi_n, priv->pub.n, ctx))
            goto cleanup;
        
        // Compute potential 4th root modulo prime, and get legendre symbol 0/1 using 4th power
        // This gives the 4th root of QR-corrected y (namely 8th root of y^2)
        if (!BN_mod(y_mod_pq, y, priv->p, ctx))
            goto cleanup;
        if (!BN_mod_exp(p_4th_root, y_mod_pq, p_exp_4th, priv->p, ctx))
            goto cleanup;
        if (!BN_mod_sqr(tmp, p_4th_root, priv->p, ctx))
            goto cleanup;
        if (!BN_mod_sqr(tmp, tmp, priv->p, ctx))
            goto cleanup;
        legendre_p = BN_cmp(tmp, y_mod_pq) != 0;

        if (!BN_mod(y_mod_pq, y, priv->q, ctx))
            goto cleanup;
        if (!BN_mod_exp(q_4th_root, y_mod_pq, q_exp_4th, priv->q, ctx))
            goto cleanup;
        if (!BN_mod_sqr(tmp, q_4th_root, priv->q, ctx))
            goto cleanup;
        if (!BN_mod_sqr(tmp, tmp, priv->q, ctx))
            goto cleanup;
        legendre_q = BN_cmp(tmp, y_mod_pq) != 0;

        // CRT compute x as 4th root of "QR-corrected" y (include w later)
        if (!BN_mod_mul(p_4th_root, p_4th_root, q_remainder, priv->pub.n, ctx))
            goto cleanup;
        if (!BN_mod_mul(q_4th_root, q_4th_root, p_remainder, priv->pub.n, ctx))
            goto cleanup;
        if (!BN_mod_add_quick(proof.x[i], p_4th_root, q_4th_root, priv->pub.n))
            goto cleanup;

        // According to choice of w above with Jacobi symbol of (-1,1) 
        proof.a[i] = legendre_q;                   
        proof.b[i] = legendre_q != legendre_p;

        // Include w in QR-corrected y, namely x^4 = (-1)^a*w^b*y
        if (proof.b[i])
        {
            if (!BN_mod_mul(proof.x[i], proof.x[i], correction, priv->pub.n, ctx))
                goto cleanup;
        }
    }
    serialize_paillier_blum_zkp(&proof, n_len, serialized_proof);

    ret = PAILLIER_SUCCESS;
cleanup:
    if (ret < 0)
        ret = ERR_get_error() * -1;
    BN_clear_free(p_minus_1);
    BN_clear_free(q_minus_1);
    BN_clear_free(p_exp_4th);
    BN_clear_free(q_exp_4th);

    if (p_remainder)
        BN_clear(p_remainder);
    if (q_remainder)
        BN_clear(q_remainder);
    if (n_inverse_mod_phi_n)
        BN_clear(n_inverse_mod_phi_n);
    if (a)
        BN_clear(a);
    if (b)
        BN_clear(b);
    if (correction)
        BN_clear(correction);
    if (tmp)
        BN_clear(tmp);
    if (y_mod_pq)
        BN_clear(y_mod_pq);
    if (p_4th_root)
        BN_clear(p_4th_root);
    if (q_4th_root)
        BN_clear(q_4th_root);
    if (y)
        BN_clear(y);
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    return ret;
}

long paillier_verify_paillier_blum_zkp(const paillier_public_key_t *pub, const uint8_t *aad, uint32_t aad_len, const uint8_t *serialized_proof, uint32_t proof_len)
{
    BN_CTX *ctx = NULL;
    zkp_paillier_blum_modulus_proof_t proof;
    SHA256_CTX sha256_ctx;
    sha256_md_t seed;
    uint32_t n_len;
    BIGNUM *y = NULL;
    BIGNUM *tmp = NULL;

    long ret = -1;

    if (!pub)
        return PAILLIER_ERROR_INVALID_KEY;
    if (!aad && aad_len)
        return PAILLIER_ERROR_INVALID_PARAM;
    if (!serialized_proof || proof_len != paillier_blum_zkp_serialized_size(pub))
        return PAILLIER_ERROR_INVALID_PARAM;

    if (!BN_is_odd(pub->n)) // must be odd
        return PAILLIER_ERROR_INVALID_KEY;
    if (BN_is_bit_set(pub->n, 1) != 0) // should be even because n % 4 == 1
        return PAILLIER_ERROR_INVALID_KEY;
    
    ctx = BN_CTX_new();
    BN_CTX_start(ctx);
    
    if (BN_is_prime_ex(pub->n, 256, ctx, NULL))
    {
        ret = PAILLIER_ERROR_INVALID_KEY;
        goto cleanup;
    }

    n_len = BN_num_bytes(pub->n);

    if (init_paillier_blum_zkp(&proof, ctx) != PAILLIER_SUCCESS)
        goto cleanup;
    if (!deserialize_paillier_blum_zkp(&proof, n_len, serialized_proof))
    {
        ret = PAILLIER_ERROR_INVALID_PROOF;
        goto cleanup;
    }

    SHA256_Init(&sha256_ctx);
    SHA256_Update(&sha256_ctx, PAILLIER_BLUM_ZKP_SALT, sizeof(PAILLIER_BLUM_ZKP_SALT));
    if (aad)
        SHA256_Update(&sha256_ctx, aad, aad_len);
    ret = update_with_bignum(&sha256_ctx, pub->n);
    if (ret != PAILLIER_SUCCESS)
        goto cleanup;
    ret = update_with_bignum(&sha256_ctx, proof.w);
    if (ret != PAILLIER_SUCCESS)
        goto cleanup;
    SHA256_Final(seed, &sha256_ctx);
    ret = -1;

    y = BN_CTX_get(ctx);
    tmp = BN_CTX_get(ctx);
    if (!y || !tmp)
        goto cleanup;

    for (uint32_t i = 0; i < PAILLIER_BLUM_STATISTICAL_SECURITY; ++i)
    {
        do
        {
            deterministic_rand(seed, n_len, y, &seed);
        } while (BN_cmp(y, pub->n) >= 0);
        
        if (!BN_mod_exp(tmp, proof.z[i], pub->n, pub->n, ctx))
            goto cleanup;
        if (BN_cmp(tmp, y) != 0)
        {
            ret = PAILLIER_ERROR_INVALID_PROOF;
            goto cleanup;
        }

        if (!BN_mod_sqr(tmp, proof.x[i], pub->n, ctx))
            goto cleanup;
        if (!BN_mod_sqr(tmp, tmp, pub->n, ctx))
            goto cleanup;
        if (proof.b[i]) 
        {
            if (!BN_mod_mul(y, proof.w, y, pub->n, ctx))
                goto cleanup;
        }
        if (proof.a[i]) 
        {
            if (!BN_sub(y, pub->n, y))
                goto cleanup;
        }
        if (BN_cmp(tmp, y) != 0)
        {
            ret = PAILLIER_ERROR_INVALID_PROOF;
            goto cleanup;
        }
    }
    ret = PAILLIER_SUCCESS;
cleanup:
    if (ret < 0)
        ret = ERR_get_error() * -1;
    
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    return ret;
}
