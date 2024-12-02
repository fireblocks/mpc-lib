#include "paillier_internal.h"
#include "alpha.h"

#include <string.h>
#include <assert.h>

#include <openssl/err.h>
#include <openssl/rand.h>

#define FACTORIZANTION_ZKP_K 10
#define COPRIME_ZKP_K 16
#define PAILLIER_BLUM_STATISTICAL_SECURITY 80 //this is the original security actually used by CMP

// this is the minimal required security
// can be used if (pub->n mod 4) == 1
#define PAILLIER_BLUM_STATISTICAL_SECURITY_MINIMAL_REQUIRED 64 

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
    uint8_t *r_ptr = NULL;
    uint8_t *r = (uint8_t*)malloc(n_len + SHA512_DIGEST_LENGTH);
    if (!r)
    {
        return NULL;
    }

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
    {
        memcpy(*out_md, r_ptr, sizeof(sha256_md_t));
    }

    BN_bin2bn(r, n_len, bn_r);
    free(r);
    return bn_r;
}

static inline long update_with_bignum(SHA256_CTX *ctx, const BIGNUM *bn)
{
    uint32_t len = BN_num_bytes(bn);
    uint8_t *n  = (uint8_t*)malloc(len);
    if (!n)
    {
        return PAILLIER_ERROR_OUT_OF_MEMORY;
    }

    if (BN_bn2bin(bn, n) <= 0) // should never happen
    {
        free(n);
        return -1; //so that the caller would know to read OpenSSL error
    }

    SHA256_Update(ctx, n, len);
    free(n);
    return PAILLIER_SUCCESS;
}

long paillier_generate_factorization_zkpok(const paillier_private_key_t *priv, 
                                           const uint8_t *aad, 
                                           uint32_t aad_len, 
                                           uint8_t x[PAILLIER_SHA256_LEN], 
                                           uint8_t *y, 
                                           uint32_t y_len, 
                                           uint32_t *y_real_len)
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
    {
        return PAILLIER_ERROR_INVALID_KEY;
    }
    if (!aad && aad_len)
    {
        return PAILLIER_ERROR_INVALID_PARAM;
    }
    if (!x)
    {
        return PAILLIER_ERROR_INVALID_PARAM;
    }
    if (!y && y_len)
    {
        return PAILLIER_ERROR_INVALID_PARAM;
    }
    
    n_len = BN_num_bytes(priv->pub.n);
    assert(n_len % PAILLIER_SHA256_LEN == 0);
    if (n_len % PAILLIER_SHA256_LEN != 0)
    {
        return PAILLIER_ERROR_INVALID_KEY;
    }
    
    ctx = BN_CTX_new();
    if (!ctx)
    {
        return ERR_get_error() * -1;
    }

    BN_CTX_start(ctx);
    
    A = BN_CTX_get(ctx);
    r = BN_CTX_get(ctx);
    e = BN_CTX_get(ctx);
    bn_y = BN_CTX_get(ctx);
    z = BN_CTX_get(ctx);

    if (!A || !r || !e || !bn_y || !z)
    {
        goto cleanup;
    }

    mont = BN_MONT_CTX_new();
    if (!mont)
    {
        goto cleanup;
    }
    
    if (!BN_rshift1(A, priv->pub.n))
    {
        goto cleanup;
    }
        
    if (y_real_len)
    {
        *y_real_len = BN_num_bytes(A);
    }

    if (!y || y_len < (uint32_t)BN_num_bytes(A))
    {
        ret = PAILLIER_ERROR_BUFFER_TOO_SHORT;
        goto cleanup;
    }
    
    if (!BN_rand_range(r, A))
    {
        goto cleanup;
    }

    n = (uint8_t*)malloc(n_len);
    if (!n)
    {
        ret = PAILLIER_ERROR_OUT_OF_MEMORY;
        goto cleanup;
    }

    if (!BN_bn2bin(priv->pub.n, n))
    {
        goto cleanup;
    }
    
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
    {
        SHA256_Update(&sha256_ctx, aad, aad_len);
    }
    SHA256_Final(seed, &sha256_ctx);

    SHA512_Init(&sha512_ctx);
    SHA256_Init(&sha256_ctx);

    SHA512_Update(&sha512_ctx, n, n_len);


    if (!BN_MONT_CTX_set(mont, priv->pub.n, ctx))
    {
        goto cleanup;
    }

    for (size_t i = 0; i < FACTORIZANTION_ZKP_K; ++i)
    {
        do
        {
            deterministic_rand(seed, n_len, z, &seed);
        } while (BN_cmp(z, priv->pub.n) >= 0);
        
        if (!BN_bn2bin(z, tmp))
        {
            goto cleanup;
        }
        SHA512_Update(&sha512_ctx, tmp, BN_num_bytes(z));
        if (!BN_mod_exp_mont(z, z, r, priv->pub.n, ctx, mont))
        {
            goto cleanup;
        }
        if (!BN_bn2bin(z, tmp))
        {
            goto cleanup;
        }
        SHA256_Update(&sha256_ctx, tmp, BN_num_bytes(z));
    }
    SHA256_Final(x, &sha256_ctx);
    SHA512_Update(&sha512_ctx, x, PAILLIER_SHA256_LEN);
    SHA512_Final(sha512_md, &sha512_ctx);
    
    if (!BN_bin2bn(sha512_md, sizeof(sha512_md), e))
    {
        goto cleanup;
    }
    
    if (!BN_usub(bn_y, priv->pub.n, priv->lamda))
    {
        goto cleanup;
    }
    if (!BN_mul(bn_y, bn_y, e, ctx))
    {
        goto cleanup;
    }
    if (!BN_mod_add(bn_y, bn_y, r, A, ctx))
    {
        goto cleanup;
    }

    if (BN_bn2binpad(bn_y, y, BN_num_bytes(A)) <= 0)
    {
        goto cleanup;
    }

    ret = PAILLIER_SUCCESS;
    
cleanup:
    if (ret < 0)
    {
        ret = ERR_get_error() * -1;
    }
    free(n);
    free(tmp);
    BN_MONT_CTX_free(mont); //it is OK to call it on NULL
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    return ret;
}

long paillier_verify_factorization_zkpok(const paillier_public_key_t *pub, 
                                         const uint8_t *aad, 
                                         uint32_t aad_len, 
                                         const uint8_t x[PAILLIER_SHA256_LEN], 
                                         const uint8_t *y, 
                                         uint32_t y_len)
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
    {
        return PAILLIER_ERROR_INVALID_KEY;
    }
    if (!aad && aad_len)
    {
        return PAILLIER_ERROR_INVALID_PARAM;
    }
    if (!x)
    {
        return PAILLIER_ERROR_INVALID_PARAM;
    }
    if (!y || !y_len)
    {
        return PAILLIER_ERROR_INVALID_PARAM;
    }
    
    n_len = BN_num_bytes(pub->n);
    assert(n_len % PAILLIER_SHA256_LEN == 0);
    if (n_len % PAILLIER_SHA256_LEN != 0)
    {
        return PAILLIER_ERROR_INVALID_KEY;
    }
    
    ctx = BN_CTX_new();
    if (!ctx)
    {
        return ERR_get_error() * -1;
    }

    BN_CTX_start(ctx);
    
    e = BN_CTX_get(ctx);
    bn_y = BN_CTX_get(ctx);
    exp = BN_CTX_get(ctx);

    if (!e || !bn_y || !exp)
    {
        goto cleanup;
    }

    mont = BN_MONT_CTX_new();
    if (!mont)
    {
        goto cleanup;
    }

    n = (uint8_t*)malloc(n_len);
    if (!n)
    {
        ret = PAILLIER_ERROR_OUT_OF_MEMORY;
        goto cleanup;
    }

    if (!BN_bn2bin(pub->n, n))
    {
        goto cleanup;
    }
    
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
    {
        SHA256_Update(&sha256_ctx, aad, aad_len);
    }
    SHA256_Final(seed, &sha256_ctx);

    SHA512_Init(&sha512_ctx); //reinitialize the context for reuse

    SHA512_Update(&sha512_ctx, n, n_len);

    for (size_t i = 0; i < FACTORIZANTION_ZKP_K; ++i)
    {
        if (!(z[i] = BN_CTX_get(ctx)))
        {
            goto cleanup;
        }

        do
        {
            deterministic_rand(seed, n_len, z[i], &seed);
        } while (BN_cmp(z[i], pub->n) >= 0);
        
        if (!BN_bn2bin(z[i], tmp))
        {
            goto cleanup;
        }
        SHA512_Update(&sha512_ctx, tmp, BN_num_bytes(z[i]));
    }
    SHA512_Update(&sha512_ctx, x, PAILLIER_SHA256_LEN);
    SHA512_Final(sha512_md, &sha512_ctx);
    
    if (!BN_bin2bn(sha512_md, sizeof(sha512_md), e))
    {
        goto cleanup;
    }
    
    if (!BN_bin2bn(y, y_len, bn_y))
    {
        goto cleanup;
    }
    if (!BN_mul(exp, pub->n, e, ctx))
    {
        goto cleanup;
    }
    if (!BN_sub(exp, exp, bn_y))
    {
        goto cleanup;
    }
    
    if (!BN_lshift1(bn_y, bn_y))
    {
        goto cleanup;
    }
    if (!BN_add_word(bn_y, 1))
    {
        goto cleanup;
    }
    
    if (BN_cmp(bn_y, pub->n) >= 0)
    {
        ret = PAILLIER_ERROR_INVALID_PROOF;
        goto cleanup;
    }

    SHA256_Init(&sha256_ctx); //reinitialize the context for reuse


    if (!BN_MONT_CTX_set(mont, pub->n, ctx))
    {
        goto cleanup;
    }

    for (size_t i = 0; i < FACTORIZANTION_ZKP_K; ++i)
    {
        if (!BN_mod_exp_mont(z[i], z[i], exp, pub->n, ctx, mont))
        {
            goto cleanup;
        }
        if (!BN_mod_inverse(z[i], z[i], pub->n, ctx))
        {
            goto cleanup;
        }
        if (!BN_bn2bin(z[i], tmp))
        {
            goto cleanup;
        }

        SHA256_Update(&sha256_ctx, tmp, BN_num_bytes(z[i]));
    }

    SHA256_Final(sha256_md, &sha256_ctx);

    ret = (memcmp(x, sha256_md, PAILLIER_SHA256_LEN) == 0) ? PAILLIER_SUCCESS : PAILLIER_ERROR_INVALID_PROOF;
    
cleanup:
    if (ret < 0)
    {
        ret = ERR_get_error() * -1;
    }
    free(n);
    free(tmp);
    BN_MONT_CTX_free(mont); //It is OK to call it on NULL
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
    {
        return PAILLIER_ERROR_INVALID_KEY;
    }
    
    if (!aad && aad_len)
    {
        return PAILLIER_ERROR_INVALID_PARAM;
    }

    if (!y && y_len)
    {
        return PAILLIER_ERROR_INVALID_PARAM;
    }
    
    n_len = BN_num_bytes(priv->pub.n);
    
    assert(n_len % PAILLIER_SHA256_LEN == 0);
    if (n_len % PAILLIER_SHA256_LEN != 0)
    {
        return PAILLIER_ERROR_INVALID_KEY;
    }

    
    if (y_real_len)
    {
        *y_real_len = n_len * COPRIME_ZKP_K;
    }

    if (!y || y_len < n_len * COPRIME_ZKP_K)
    {
        return PAILLIER_ERROR_BUFFER_TOO_SHORT;
    }

    ctx = BN_CTX_new();
    if (!ctx)
    {
        return ERR_get_error() * -1;
    }

    BN_CTX_start(ctx);
    
    x = BN_CTX_get(ctx);
    M = BN_CTX_get(ctx);
    tmp = BN_CTX_get(ctx);

    if (!x || !M || !tmp)
    {
        goto cleanup;
    }

    mont = BN_MONT_CTX_new();
    if (!mont)
    {
        goto cleanup;
    }
    
    BN_set_flags(M, BN_FLG_CONSTTIME);
    if (!BN_mod_inverse(M, priv->pub.n, priv->lamda, ctx))
    {
        goto cleanup;
    }
    
    n = (uint8_t*)malloc(n_len);
    if (!n)
    {
        ret = PAILLIER_ERROR_OUT_OF_MEMORY;
        goto cleanup;
    }

    if (!BN_bn2bin(priv->pub.n, n))
    {
        goto cleanup;
    }
    
    SHA256_Init(&sha256_ctx);
    SHA256_Update(&sha256_ctx, COPRIME_ZKP_SALT, sizeof(COPRIME_ZKP_SALT));
    SHA256_Update(&sha256_ctx, n, n_len);
    if (aad)
    {
        SHA256_Update(&sha256_ctx, aad, aad_len);
    }
    SHA256_Final(seed, &sha256_ctx);
    free(n);
    n = NULL;


    if (!BN_MONT_CTX_set(mont, priv->pub.n, ctx))
    {
        goto cleanup;
    }

    for (size_t i = 0; i < COPRIME_ZKP_K; ++i)
    {
        int is_coprime_res;
        do
        {
            deterministic_rand(seed, n_len, x, &seed);
            is_coprime_res = is_coprime_fast(x, priv->pub.n, ctx);
        } while (is_coprime_res == 0);

        if (is_coprime_res == -1)
        {
            goto cleanup;
        }
        
        if (!BN_mod_exp_mont(tmp, x, M, priv->pub.n, ctx, mont))
        {
            goto cleanup;
        }
            
        if (BN_bn2binpad(tmp, y_ptr, n_len) < 0)
        {
            goto cleanup;
        }
            
        y_ptr += n_len;
    }
    
    ret = PAILLIER_SUCCESS;

cleanup:
    if (ret < 0)
    {
        ret = ERR_get_error() * -1;
    }
        
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
    {
        return PAILLIER_ERROR_INVALID_KEY;
    }
        
    if (!aad && aad_len)
    {
        return PAILLIER_ERROR_INVALID_PARAM;
    }
        
    if (!y && y_len)
    {
        return PAILLIER_ERROR_INVALID_PARAM;
    }
        
    
    n_len = BN_num_bytes(pub->n);
    
    assert(n_len % PAILLIER_SHA256_LEN == 0);
    if (n_len % PAILLIER_SHA256_LEN != 0)
    {
        return PAILLIER_ERROR_INVALID_KEY;
    }

    assert(y_len == n_len * COPRIME_ZKP_K);
    if (!y || y_len < n_len * COPRIME_ZKP_K)
    {
        return PAILLIER_ERROR_INVALID_PARAM;
    }
    
    ctx = BN_CTX_new();
    if (!ctx)
    {
        return ERR_get_error() * -1;
    }

    BN_CTX_start(ctx);
    
    if (BN_is_prime_ex(pub->n, 256, ctx, NULL))
    {
        ret = PAILLIER_ERROR_INVALID_KEY;
        goto cleanup;
    }

    x = BN_CTX_get(ctx);
    bn_y = BN_CTX_get(ctx);
    tmp = BN_CTX_get(ctx);

    if (!x || !bn_y || !tmp)
    {
        goto cleanup;
    }

    mont = BN_MONT_CTX_new();
    if (!mont)
    {
        goto cleanup;
    }
    
    if (!BN_bin2bn(alpha_bin, alpha_bin_len, tmp))
    {
        goto cleanup;
    }
        
    
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
    {
        goto cleanup;
    }
        
    
    SHA256_Init(&sha256_ctx);
    SHA256_Update(&sha256_ctx, COPRIME_ZKP_SALT, sizeof(COPRIME_ZKP_SALT));
    SHA256_Update(&sha256_ctx, n, n_len);
    if (aad)
    {
        SHA256_Update(&sha256_ctx, aad, aad_len);
    }
    SHA256_Final(seed, &sha256_ctx);
    free(n);
    n = NULL;

    if (!BN_MONT_CTX_set(mont, pub->n, ctx))
    {
        goto cleanup;
    }

    for (size_t i = 0; i < COPRIME_ZKP_K; ++i)
    {
        int is_coprime_res;
        do
        {
            deterministic_rand(seed, n_len, x, &seed);
            is_coprime_res = is_coprime_fast(x, pub->n, ctx);
        } while (is_coprime_res == 0);
        
        if (is_coprime_res == -1)
        {
            goto cleanup;
        }

        if (!BN_mod(x, x, pub->n, ctx))
        {
            goto cleanup;
        }
            
        if (!BN_bin2bn(y_ptr, n_len, bn_y))
        {
            goto cleanup;
        }
            
        if (!BN_mod_exp_mont(tmp, bn_y, pub->n, pub->n, ctx, mont))
        {
            goto cleanup;
        }
            
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
    {
        ret = ERR_get_error() * -1;
    }
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
    {
        return PAILLIER_ERROR_OUT_OF_MEMORY;
    }

    for (size_t i = 0; i < PAILLIER_BLUM_STATISTICAL_SECURITY; i++)
    {
        proof->x[i] = BN_CTX_get(ctx);
        proof->z[i] = BN_CTX_get(ctx);
        if (!proof->x[i] || !proof->z[i])
        {
            return PAILLIER_ERROR_OUT_OF_MEMORY;
    }
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
    {
        return 0;
    }
        

    if (!BN_bin2bn(ptr, n_len, proof->w))
    {
        return 0;
    }
        
    ptr += n_len;

    for (uint32_t i = 0; i < PAILLIER_BLUM_STATISTICAL_SECURITY; ++i)
    {
        if (!BN_bin2bn(ptr, n_len, proof->x[i]))
        {
            return 0;
        }
            
        ptr += n_len;
        if (!BN_bin2bn(ptr, n_len, proof->z[i]))
        {
            return 0;
        }
            
        ptr += n_len;
        proof->a[i] = *ptr++;
        proof->b[i] = *ptr++;
    }
    return 1;
}

static inline uint8_t get_2bit_number(const uint8_t* array, const uint32_t i) 
{
    // Calculate which byte the 2-bit number is in
    const uint32_t byte_index = i / 4;
    
    // Calculate the bit position within that byte (0, 2, 4, or 6)
    const uint32_t bit_position = (i % 4) * 2;
    
    // Extract the 2-bit number by shifting and masking
    return (uint8_t)(array[byte_index] >> bit_position) & 0x03;
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

    // since it is needed to randomly choose one of the 4 roots 
    // in a loop of PAILLIER_BLUM_STATISTICAL_SECURITY iterations
    // there is a need for 2 * PAILLIER_BLUM_STATISTICAL_SECURITY bits. 
    // adding 7 will round up if PAILLIER_BLUM_STATISTICAL_SECURITY is not multiple of 8
    uint8_t random_bytes[(PAILLIER_BLUM_STATISTICAL_SECURITY * 2 + 7) / 8];

    long ret = -1;

    if (!priv)
    {
        return PAILLIER_ERROR_INVALID_KEY;
    }
    if (!aad && aad_len)
    {
        return PAILLIER_ERROR_INVALID_PARAM;
    }
    if (!serialized_proof && proof_len)
    {
        return PAILLIER_ERROR_INVALID_PARAM;
    }

    //assume that (BN_mod_word(priv->p, 8) == 3 && BN_mod_word(priv->q, 8) == 7)

    needed_proof_len = paillier_blum_zkp_serialized_size(&priv->pub);
    if (proof_real_len)
    {
        *proof_real_len = needed_proof_len;
    }

    if (proof_len < needed_proof_len)
    {
        return PAILLIER_ERROR_BUFFER_TOO_SHORT;
    }
    
    OPENSSL_cleanse(serialized_proof, proof_len);
    
    n_len = BN_num_bytes(priv->pub.n);

    ctx = BN_CTX_new();
    if (!ctx)
    {
        return PAILLIER_ERROR_OUT_OF_MEMORY;
    }

    BN_CTX_start(ctx);
    ret = init_paillier_blum_zkp(&proof, ctx);

    if (ret != PAILLIER_SUCCESS)
    {
        goto cleanup;
    }
    
    //reset return value so if following statements fail a propper error would be reported
    ret = -1; 
    
    p_remainder = BN_CTX_get(ctx);
    q_remainder = BN_CTX_get(ctx);
    tmp = BN_CTX_get(ctx);
    a = BN_CTX_get(ctx);
    b = BN_CTX_get(ctx);
    correction = BN_CTX_get(ctx);
    if (!q_remainder || !p_remainder || !tmp || !a || !b || !correction)
    {
        ret = PAILLIER_ERROR_OUT_OF_MEMORY;
        goto cleanup;
    }
    
    n_inverse_mod_phi_n = BN_CTX_get(ctx);
    if (!n_inverse_mod_phi_n)
    {
        ret = PAILLIER_ERROR_OUT_OF_MEMORY;
        goto cleanup;
    }

    y_mod_pq = BN_CTX_get(ctx);
    p_4th_root = BN_CTX_get(ctx);
    q_4th_root = BN_CTX_get(ctx);

    if (!y_mod_pq || !p_4th_root || !q_4th_root)
    {
        ret = PAILLIER_ERROR_OUT_OF_MEMORY;
        goto cleanup;
    }

    y = BN_CTX_get(ctx);
    if (!y)
    {
        ret = PAILLIER_ERROR_OUT_OF_MEMORY;
        goto cleanup;
    }

    // Generate w with (-1, 1) Jacobi signs wrt (p,q) by Chinese remainder theorem
    // Satisfying w = -a^4 mod p and w = b^4 mod q
    // choose w to be 2^n and calculate a and b

    // calculate p_remainder and  q_remainder wich will be used to quickly find value in mod n if we know
    // the value in mod p and mod q using Chinese remainder theorem
    if (!BN_mod_inverse(p_remainder, priv->p, priv->q, ctx)) // p_remainder = p^(-1) mod q
    {
        goto cleanup;
    }
    if (!BN_mod_inverse(q_remainder, priv->q, priv->p, ctx)) // q_remainder = q^(-1) mod p
    {
        goto cleanup;
    }

    //since p and q are secret, their dericative require also const time calculations
    BN_set_flags(p_remainder, BN_FLG_CONSTTIME);
    BN_set_flags(q_remainder, BN_FLG_CONSTTIME);

    if (!BN_mod_mul(p_remainder, p_remainder, priv->p, priv->pub.n, ctx)) // p_remainder = (p^(-1) mod q) * p  mod n
    {
        goto cleanup;
    }
    if (!BN_mod_mul(q_remainder, q_remainder, priv->q, priv->pub.n, ctx)) // q_remainder = (q^(-1) mod p) * q  mod n
    {
        goto cleanup;
    }


    if (!BN_mod_inverse(n_inverse_mod_phi_n, priv->pub.n, priv->lamda, ctx))    // To compute z[i]
    {
        goto cleanup;
    }

    //since n_inverse_mod_phi_n is secret, it requires const time calculations
    BN_set_flags(n_inverse_mod_phi_n, BN_FLG_CONSTTIME);

    // Taking each y[i] 4th root (by exponentation with p_exp_4th = ((p-1)/2)^2 mod (p -1) - double sqrt
    // Checking result^4 = y[i] or -y[i], which defines the legendre symbol
    p_minus_1 = BN_dup(priv->p);
    q_minus_1 = BN_dup(priv->q);
    if (!p_minus_1 || !q_minus_1)
    {
        ret = PAILLIER_ERROR_OUT_OF_MEMORY;
        goto cleanup;
    }

    //since p and q are primes, the are odd. Clearing last bit is same as doing minus 1
    // so p_minus_1 = p -1 , q_minus_1 = q - 1
    if (!BN_clear_bit(p_minus_1, 0) || !BN_clear_bit(q_minus_1, 0))
    {
        goto cleanup;
    }

    // p-1 and q-1 are secret as well
    BN_set_flags(p_minus_1, BN_FLG_CONSTTIME);
    BN_set_flags(q_minus_1, BN_FLG_CONSTTIME);

    p_exp_4th = BN_dup(priv->p);
    q_exp_4th = BN_dup(priv->q);
    if (!p_exp_4th || !q_exp_4th)
    {
        ret = PAILLIER_ERROR_OUT_OF_MEMORY;
        goto cleanup;
    }

    BN_set_flags(p_exp_4th, BN_FLG_CONSTTIME);
    BN_set_flags(q_exp_4th, BN_FLG_CONSTTIME);

    
    // Since p = 3[4], then ((p+1)/4)^2 mod (p-1) = (2/4)^2 mod (p-1) = 1/4 mod (p-1)
    // So the exponent ((p+1)/4)^2 can be used to compute 4th root.

    if (!BN_add_word(p_exp_4th, 1)) //p_exp_4th = p + 1
    {
        goto cleanup;
    }

    if (!BN_rshift(p_exp_4th, p_exp_4th, 2)) //p_exp_4th = (p + 1) / 4 
    {
        goto cleanup;
    }
    if (!BN_mod_sqr(p_exp_4th, p_exp_4th, p_minus_1, ctx))  // p_exp_4th = ((p + 1) / 4) ^ 2 mod (p -1)
    {
        goto cleanup;
    }

    if (!BN_add_word(q_exp_4th, 1)) // q_exp_4th = q + 1
    {
        goto cleanup;
    }
    if (!BN_rshift(q_exp_4th, q_exp_4th, 2)) // q_exp_4th = (q + 1) / 4
    {
        goto cleanup;
    }
    if (!BN_mod_sqr(q_exp_4th, q_exp_4th, q_minus_1, ctx)) // q_exp_4th = ((q + 1) / 4) ^2 mod (q - 1)
    {
        goto cleanup;
    }

    BN_clear_free(p_minus_1);
    BN_clear_free(q_minus_1);

    p_minus_1 = NULL;
    q_minus_1 = NULL;


    // We want to generate w such that (w|p) = -1  and  (w|q) = 1
    // In the case where (p,q) = (3,7) mod 8, 2 will always be a non square mod p, and a square mod q,
    // so fulfills the above condition. For the security proof to hold, though, we need to set w = 2^N [N].
    // Otherwise, we generate w with (-1, 1) Jacobi signs wrt (p,q) by Chinese remainder theorem
    // Satisfying w = -a^4 mod p and w = b^4 mod q for random a,b
    // set w to 2 and computer (w=2^n % n)
    if (!BN_set_word(proof.w, 2) || !BN_mod_exp(proof.w, proof.w, priv->pub.n, priv->pub.n, ctx))
    {
        goto cleanup;
    }

    // Compute correction as a mod p and b mod q, this will be the "QR-corrected" 4th root of w (later)
    // It mainly means that
    //   | correction^4 = -w mod p
    //   | correction^4 = w mod q
    // reminder: p_exp_4th = ((p + 1) / 4) ^ 2 mod (p - 1) which is (2/4) ^2 mod (p - 1) = 1/4 mod (p - 1) 
    //           q_exp_4th = ((q + 1) / 4) ^ 2 mod (q - 1) which is (2/4) ^2 mod (q - 1) = 1/4 mod (q - 1)
    //           and we need to calculate w ^ 1/4 mod (N)
    if (!BN_mod_exp(a, proof.w, p_exp_4th, priv->p, ctx) || // a = (w ^ ((2/4) ^2 mod (p - 1))) mod p
        !BN_mod_exp(b, proof.w, q_exp_4th, priv->q, ctx))   // b = (w ^ ((2/4) ^2 mod (q - 1))) mod q
    {
        goto cleanup;
    }

    //now we need to move from mod p and mod q into mod n
    if (!BN_mod_mul(a, q_remainder, a, priv->pub.n, ctx))
    {
        goto cleanup;
    }
    if (!BN_mod_mul(b, p_remainder, b, priv->pub.n, ctx))
    {
        goto cleanup;
    }

    if (!BN_mod_sub_quick(correction, b, a, priv->pub.n))
    {
        goto cleanup;
    }

    // Calculate seed for deterministric rand which in turn will be used for generating y values using hash of the current state.
    // This comes instead of receiving y values from the other party
    
    SHA256_Init(&sha256_ctx);
    SHA256_Update(&sha256_ctx, PAILLIER_BLUM_ZKP_SALT, sizeof(PAILLIER_BLUM_ZKP_SALT));
    if (aad)
    {
        SHA256_Update(&sha256_ctx, aad, aad_len);
    }

    ret = update_with_bignum(&sha256_ctx, priv->pub.n);
    if (ret != PAILLIER_SUCCESS)
    {
        goto cleanup;
    }

    ret = update_with_bignum(&sha256_ctx, proof.w);
    if (ret != PAILLIER_SUCCESS)
    {
        goto cleanup;
    }

    SHA256_Final(seed, &sha256_ctx);

    //reset return value so if following statements fail a propper error would be reported
    ret = -1;

    // The following randomization is needed for the security proof
    if (RAND_bytes(random_bytes, sizeof(random_bytes)) != 1) 
    {
        goto cleanup;
    }    
    
    for (uint32_t i = 0; i < PAILLIER_BLUM_STATISTICAL_SECURITY; ++i)
    {

        uint8_t legendre_p;   // 0 is QR, 1 if QNR
        uint8_t legendre_q;

        do
        {
            deterministic_rand(seed, n_len, y, &seed);
        } while (BN_cmp(y, priv->pub.n) >= 0);

        //while we could do it only once, we still fill all z values for the backward compatibility
        if (!BN_mod_exp(proof.z[i], y, n_inverse_mod_phi_n, priv->pub.n, ctx))
        {
            goto cleanup;
        }
        
        // Compute potential 4th root modulo prime, and get legendre symbol 0/1 using 4th power
        // This gives the 4th root of QR-corrected y (namely 8th root of y^2)
        if (!BN_mod(y_mod_pq, y, priv->p, ctx))
        {
            goto cleanup;
        }
        if (!BN_mod_exp(p_4th_root, y_mod_pq, p_exp_4th, priv->p, ctx))
        {
            goto cleanup;
        }
        if (!BN_mod_sqr(tmp, p_4th_root, priv->p, ctx))
        {
            goto cleanup;
        }
        if (!BN_mod_sqr(tmp, tmp, priv->p, ctx))
        {
            goto cleanup;
        }
        legendre_p = BN_cmp(tmp, y_mod_pq) != 0;

        if (!BN_mod(y_mod_pq, y, priv->q, ctx))
        {
            goto cleanup;
        }
        if (!BN_mod_exp(q_4th_root, y_mod_pq, q_exp_4th, priv->q, ctx))
        {
            goto cleanup;
        }
        if (!BN_mod_sqr(tmp, q_4th_root, priv->q, ctx))
        {
            goto cleanup;
        }
        if (!BN_mod_sqr(tmp, tmp, priv->q, ctx))
        {
            goto cleanup;
        }
        legendre_q = BN_cmp(tmp, y_mod_pq) != 0;

        // CRT compute x as 4th root of "QR-corrected" y (include w later)
        if (!BN_mod_mul(p_4th_root, p_4th_root, q_remainder, priv->pub.n, ctx))
        {
            goto cleanup;
        }
        if (!BN_mod_mul(q_4th_root, q_4th_root, p_remainder, priv->pub.n, ctx))
        {
            goto cleanup;
        }
        
        // We'll chose proof.x[i] randomly as  +/- p_4th_root +/-q_4th_root
        switch (get_2bit_number(random_bytes, i)) 
        {
        case 0:
            // p_4th_root + q_4th_root
        if (!BN_mod_add_quick(proof.x[i], p_4th_root, q_4th_root, priv->pub.n))
            {
                goto cleanup;
            }
            break;
        case 1:
            // p_4th_root - q_4th_root
            if (!BN_mod_sub_quick(proof.x[i], p_4th_root, q_4th_root, priv->pub.n))
            {
            goto cleanup;
            }
            break;
        case 2:
            // - p_4th_root + q_4th_root
            if (!BN_mod_sub_quick(proof.x[i], q_4th_root, p_4th_root, priv->pub.n))
            {
                goto cleanup;
            }
            break;
        case 3:
            // - p_4th_root - q_4th_root
            if (!BN_mod_add_quick(proof.x[i], p_4th_root, q_4th_root, priv->pub.n) ||
                !BN_sub(proof.x[i], priv->pub.n, proof.x[i])) //negate x in mod n
            {
                goto cleanup;
            }
            break;
        }

        // According to choice of w above with Jacobi symbol of (-1,1) 
        proof.a[i] = legendre_q;                   
        proof.b[i] = legendre_q != legendre_p;

        // Include w in QR-corrected y, namely x^4 = (-1)^a*w^b*y
        if (proof.b[i])
        {
            if (!BN_mod_mul(proof.x[i], proof.x[i], correction, priv->pub.n, ctx))
            {
                goto cleanup;
        }
    }
    }

    serialize_paillier_blum_zkp(&proof, n_len, serialized_proof);

    ret = PAILLIER_SUCCESS;
cleanup:
    if (ret < 0)
    {
        ret = ERR_get_error() * -1;
    }

    //where DUPed - need to be freed explicitly
    BN_clear_free(p_minus_1);
    BN_clear_free(q_minus_1);
    BN_clear_free(p_exp_4th);
    BN_clear_free(q_exp_4th);

    if (p_remainder)
    {
        BN_clear(p_remainder); //will be freed with context
    }
    if (q_remainder)
    {
        BN_clear(q_remainder); //will be freed with context
    }
    if (n_inverse_mod_phi_n)
    {
        BN_clear(n_inverse_mod_phi_n); //will be freed with context
    }
    if (a)
    {
        BN_clear(a); //will be freed with context
    }
    if (b)
    {
        BN_clear(b); //will be freed with context
    }
    if (correction)
    {
        BN_clear(correction); //will be freed with context
    }
    if (tmp)
    {
        BN_clear(tmp); //will be freed with context
    }
    if (y_mod_pq)
    {
        BN_clear(y_mod_pq); //will be freed with context
    }
    if (p_4th_root)
    {
        BN_clear(p_4th_root); //will be freed with context
    }
    if (q_4th_root)
    {
        BN_clear(q_4th_root); //will be freed with context
    }
    if (y)
    {
        BN_clear(y); //will be freed with context
    }

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
    {
        return PAILLIER_ERROR_INVALID_KEY;
    }
        
    if (!aad && aad_len)
    {
        return PAILLIER_ERROR_INVALID_PARAM;
    }
        
    if (!serialized_proof || proof_len != paillier_blum_zkp_serialized_size(pub))
    {
        return PAILLIER_ERROR_INVALID_PARAM;
    }
        

    if (!BN_is_odd(pub->n)) // must be odd
    {
        return PAILLIER_ERROR_INVALID_KEY;
    }
        
    if (BN_is_bit_set(pub->n, 1) != 0) // should be even because n % 4 == 1
    {
        return PAILLIER_ERROR_INVALID_KEY;
    }
        
    
    ctx = BN_CTX_new();
    if (!ctx)
    {
        return PAILLIER_ERROR_OUT_OF_MEMORY;
    }

    BN_CTX_start(ctx);
    
    y = BN_CTX_get(ctx);
    tmp = BN_CTX_get(ctx);
    if (!y || !tmp)
    {
        goto cleanup;
    }

    if (BN_is_prime_ex(pub->n, 256, ctx, NULL))
    {
        ret = PAILLIER_ERROR_INVALID_KEY;
        goto cleanup;
    }

    n_len = BN_num_bytes(pub->n);

    if (init_paillier_blum_zkp(&proof, ctx) != PAILLIER_SUCCESS)
    {
        goto cleanup;
    }
        
    if (!deserialize_paillier_blum_zkp(&proof, n_len, serialized_proof))
    {
        ret = PAILLIER_ERROR_INVALID_PROOF;
        goto cleanup;
    }

    SHA256_Init(&sha256_ctx);
    SHA256_Update(&sha256_ctx, PAILLIER_BLUM_ZKP_SALT, sizeof(PAILLIER_BLUM_ZKP_SALT));
    if (aad)
    {
        SHA256_Update(&sha256_ctx, aad, aad_len);
    }
        
    ret = update_with_bignum(&sha256_ctx, pub->n);
    if (ret != PAILLIER_SUCCESS)
    {
        goto cleanup;
    }
        
    ret = update_with_bignum(&sha256_ctx, proof.w);
    if (ret != PAILLIER_SUCCESS)
    {
        goto cleanup;
    }
        
    SHA256_Final(seed, &sha256_ctx);

    ret = -1; //reset return value so goto cleanup could be used

    if (is_coprime_fast(proof.w, pub->n, ctx) != 1)
    {
        ret = PAILLIER_ERROR_INVALID_PROOF;
        goto cleanup;
    }


    //prepare tmp for the 1st iteration to verify z
    if (!BN_mod_exp(tmp, proof.z[0], pub->n, pub->n, ctx))
    {
        goto cleanup;
    }

    // during development of 2 out of 2 MPC it was decided that 
    // PAILLIER_BLUM_STATISTICAL_SECURITY_MINIMAL_REQUIRED is enough
    for (uint32_t i = 0; i < PAILLIER_BLUM_STATISTICAL_SECURITY_MINIMAL_REQUIRED; ++i)
    {
        do
        {
            deterministic_rand(seed, n_len, y, &seed);
        } while (BN_cmp(y, pub->n) >= 0);
        
        if (is_coprime_fast(y, pub->n, ctx) != 1)
        {
            ret = PAILLIER_ERROR_INVALID_PROOF;
            goto cleanup;
        }

        // also z is enough to verify only once for the 1st y
        if (0 == i)
        {
            if (BN_cmp(tmp, y) != 0) //ensure that y == z^n in mod n
            {
                ret = PAILLIER_ERROR_INVALID_PROOF;
                goto cleanup;
            }

            if (BN_is_one(y)) //theck that y is not 1
            {
                ret = PAILLIER_ERROR_INVALID_PROOF;
                goto cleanup;
            }
            
            if (!BN_sub(tmp, pub->n, BN_value_one())) //tmp = n - 1
            {
            goto cleanup;
            }

            if (0 == BN_cmp(tmp, y)) //check if y == n - 1
        {
            ret = PAILLIER_ERROR_INVALID_PROOF;
            goto cleanup;
        }
        }

        if (!BN_mod_sqr(tmp, proof.x[i], pub->n, ctx))
        {
            goto cleanup;
        }
            
        if (!BN_mod_sqr(tmp, tmp, pub->n, ctx))
        {
            goto cleanup;
        }
            
        if (proof.b[i]) 
        {
            if (!BN_mod_mul(y, proof.w, y, pub->n, ctx))
            {
                goto cleanup;
        }
        }

        if (proof.a[i]) 
        {
            if (!BN_sub(y, pub->n, y))
            {
                goto cleanup;
        }
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
    {
        ret = ERR_get_error() * -1;
    }
        
    
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    return ret;
}
