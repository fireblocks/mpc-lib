#include "paillier_commitment_internal.h"
#include "crypto/paillier_commitment/paillier_commitment.h"
#include "crypto/commitments/damgard_fujisaki.h"
#include "crypto/zero_knowledge_proof/range_proofs.h"
#include "crypto/algebra_utils/algebra_utils.h"
#include "../zero_knowledge_proof/zkp_constants_internal.h"
#include "../paillier/paillier_internal.h"
#include "../commitments/damgard_fujisaki_internal.h"


#include <assert.h>
#include <string.h>
#include <openssl/bn.h>
#include <openssl/err.h>

#define PAILLIER_COMMITMENTS_MIN_KEY_BITSIZE            (1024)
#define PAILLIER_COMMITMENTS_TOUGH_SUBPRIMES_BITSIZE    (256)

static inline uint32_t PAILLIER_COMMITMENTS_LAMBDA_BITSIZE(const uint32_t n_bitlen)
{
          return (2 * ZKPOK_OPTIM_L_SIZE(n_bitlen) * 8);
}

#define PAILLIER_COMMITMENTS_MIN_KEY_SIZE               (PAILLIER_COMMITMENTS_MIN_KEY_BITSIZE / 8)
#define PAILLIER_COMMITMENTS_MAX_KEY_SIZE               (8192)
#define PAILLIER_COMMITMENTS_MAX_SERIALIZED_SIZE        (64 * 1024)

static inline long paillier_commitment_init_montgomery(paillier_commitment_public_key_t *pub, BN_CTX *ctx)
{
    BN_CTX *local_ctx = ctx ? ctx : BN_CTX_new();
    if (!local_ctx)
    {
        return PAILLIER_ERROR_OUT_OF_MEMORY;
    }

    if (!pub->mont_n2)
    {
        pub->mont_n2 = BN_MONT_CTX_new();
        if (pub->mont_n2)
        {
            if (!BN_MONT_CTX_set(pub->mont_n2, pub->n2, local_ctx))
            {
                BN_MONT_CTX_free(pub->mont_n2);
                pub->mont_n2 = NULL;
            }
        }
    }

    if (local_ctx != ctx)
    {
        BN_CTX_free(local_ctx);
        local_ctx = NULL;
    }

    return pub->mont_n2 ? PAILLIER_SUCCESS : PAILLIER_ERROR_OUT_OF_MEMORY;
}

static void paillier_commitment_cleanup_public_key(paillier_commitment_public_key_t *pub)
{
    if (pub)
    {
        BN_free(pub->n);
        pub->n = NULL;

        BN_free(pub->t);
        pub->t = NULL;

        BN_free(pub->s);
        pub->s = NULL;

        BN_free(pub->n2);
        pub->n2 = NULL;

        BN_free(pub->rho);
        pub->rho = NULL;

        BN_free(pub->sigma_0);
        pub->sigma_0 = NULL;

        if (pub->mont_n2)
        {
            BN_MONT_CTX_free(pub->mont_n2);
            pub->mont_n2 = NULL;
        }
    }
}

static void paillier_commitment_cleanup_private_key(paillier_commitment_private_key_t *priv)
{
    if (priv)
    {
        paillier_commitment_cleanup_public_key(&priv->pub);

        BN_clear_free(priv->p);
        priv->p = NULL;

        BN_clear_free(priv->q);
        priv->q = NULL;

        BN_clear_free(priv->lambda);
        priv->lambda = NULL;

        BN_clear_free(priv->p2);
        priv->p2 = NULL;

        BN_clear_free(priv->q2);
        priv->q2 = NULL;

        BN_clear_free(priv->q2_inv_p2);
        priv->q2_inv_p2 = NULL;

        BN_clear_free(priv->phi_n);
        priv->phi_n = NULL;

        BN_clear_free(priv->phi_n_inv);
        priv->phi_n_inv = NULL;
    }

}

void paillier_commitment_free_public_key(paillier_commitment_public_key_t *pub)
{
    paillier_commitment_cleanup_public_key(pub);
    free(pub);
}


void paillier_commitment_free_private_key(paillier_commitment_private_key_t *priv)
{
    paillier_commitment_cleanup_private_key(priv);
    free(priv);
}

uint32_t paillier_commitment_public_bitsize(const paillier_commitment_public_key_t *pub)
{
    if (pub)
    {
        // we use number of bytes to allow some tolerance
        // since we multiply to primes of half bitlength the result may be not exactly twice number of bits
        // the smallest product of multiplying two primes of size n bits will have 2n-2 bits
        // This is why we use number of bytes to round up
        return (uint32_t)BN_num_bytes(pub->n) * 8;
    }

    return 0;
}

static inline void paillier_commitment_set_consttime_flag(paillier_commitment_private_key_t *priv)
{
    BN_set_flags(priv->p,           BN_FLG_CONSTTIME);
    BN_set_flags(priv->q,           BN_FLG_CONSTTIME);
    BN_set_flags(priv->lambda,      BN_FLG_CONSTTIME);
    BN_set_flags(priv->p2,          BN_FLG_CONSTTIME);
    BN_set_flags(priv->q2,          BN_FLG_CONSTTIME);
    BN_set_flags(priv->q2_inv_p2,   BN_FLG_CONSTTIME);
    BN_set_flags(priv->phi_n,       BN_FLG_CONSTTIME);
    BN_set_flags(priv->phi_n_inv,   BN_FLG_CONSTTIME);
}

static long paillier_commitment_generate_private(const uint32_t key_len, paillier_commitment_private_key_t *priv, BN_CTX *ctx)
{
    long ret = -1;
    BIGNUM *tmp = NULL, *r = NULL;
    BIGNUM *three = NULL, *seven = NULL, *eight = NULL;

    BN_CTX_start(ctx);

    tmp = BN_CTX_get(ctx);
    three = BN_CTX_get(ctx);
    seven = BN_CTX_get(ctx);
    eight = BN_CTX_get(ctx);
    r = BN_CTX_get(ctx);

    if (!tmp || !three || !seven || !eight || !r)
    {
        goto cleanup;
    }

    if (!BN_set_word(three, 3) ||
        !BN_set_word(seven, 7) ||
        !BN_set_word(eight, 8))
    {
        goto cleanup;
    }

    priv->p = BN_new();
    priv->q = BN_new();
    priv->lambda = BN_new();
    priv->p2 = BN_new();
    priv->q2 = BN_new();
    priv->q2_inv_p2 = BN_new();
    priv->phi_n = BN_new();
    priv->phi_n_inv = BN_new();
    if (!priv->p            ||
        !priv->q            ||
        !priv->lambda       ||
        !priv->p2           ||
        !priv->q2           ||
        !priv->q2_inv_p2    ||
        !priv->phi_n        ||
        !priv->phi_n_inv)
    {
        goto cleanup;
    }

    priv->pub.t = BN_new();
    priv->pub.s = BN_new();
    priv->pub.n = BN_new();
    priv->pub.n2 = BN_new();
    priv->pub.rho = BN_new();
    priv->pub.sigma_0 = BN_new();


    if (!priv->pub.t        ||
        !priv->pub.s        ||
        !priv->pub.n        ||
        !priv->pub.n2       ||
        !priv->pub.rho      ||
        !priv->pub.sigma_0)
    {
        goto cleanup;
    }

    paillier_commitment_set_consttime_flag(priv);
    BN_set_flags(r, BN_FLG_CONSTTIME); //r is secret as well

    // Choose two large prime p,q numbers having gcd(pq, (p-1)(q-1)) == 1
    do
    {   // note - originally we had used p and q to be 4*k + 3. The new form keeps this requirement because
        // both p and q still satisfies 4 * k + 3

        // p needs to be in the form of p = 8 * k + 3 ( p = 3 mod 8) to allow efficient calculation off fourth roots
        // (needed in paillier blum zkp)

        if (ELLIPTIC_CURVE_ALGEBRA_SUCCESS != generate_tough_prime(priv->p, key_len / 2, PAILLIER_COMMITMENTS_TOUGH_SUBPRIMES_BITSIZE, eight, three, ctx))
        {
            ret = PAILLIER_ERROR_UNKNOWN;
            goto cleanup;
        }

        assert((uint32_t)BN_num_bits(priv->p) == (key_len / 2));

        // and set must be q = 7 mod 8 (8 * k + 7)
        if (ELLIPTIC_CURVE_ALGEBRA_SUCCESS != generate_tough_prime(priv->q, key_len / 2, PAILLIER_COMMITMENTS_TOUGH_SUBPRIMES_BITSIZE, eight, seven, ctx))
        {
            goto cleanup;
        }

        //because p and q are tough primes their length can differ in key_len / 2 * PAILLIER_COMMITMENTS_TOUGH_SUBPRIMES_BITSIZE bits
        assert((uint32_t)BN_num_bits(priv->q) == (key_len / 2));


        // Compute n = pq
        if (!BN_mul(priv->pub.n, priv->p, priv->q, ctx))
        {
            ret = PAILLIER_ERROR_UNKNOWN;
            goto cleanup;
        }

        //calculate phi_n
        if (!BN_sub(priv->phi_n, priv->pub.n, priv->p) ||
            !BN_sub(priv->phi_n, priv->phi_n, priv->q) ||
            !BN_add_word(priv->phi_n, 1))
        {
            goto cleanup;
        }

    } while (paillier_commitment_public_bitsize(&priv->pub) != key_len  ||
             BN_cmp(priv->p, priv->q) == 0                              ||
             !BN_gcd(tmp, priv->phi_n, priv->pub.n, ctx)                ||
             !BN_is_one(tmp));

    if (!BN_mod_inverse(priv->phi_n_inv, priv->phi_n, priv->pub.n, ctx))
    {
        goto cleanup;
    }


    if (!BN_sqr(priv->pub.n2, priv->pub.n, ctx) ||
        !BN_sqr(priv->p2, priv->p, ctx) ||
        !BN_sqr(priv->q2, priv->q, ctx) ||
        !BN_mod_inverse(priv->q2_inv_p2, priv->q2, priv->p2, ctx))
    {
        goto cleanup;
    }

    // generate random r in mod n
    do
    {
        if (!BN_rand_range(r, priv->pub.n))
        {
            goto cleanup;
        }

    } while (!BN_gcd(tmp, r, priv->pub.n, ctx) ||
             !BN_is_one(tmp));

    // t = r ^ 2 in mod n
    if (!BN_mod_sqr(priv->pub.t, r, priv->pub.n, ctx))
    {
        goto cleanup;
    }

    // there is an assert in the serialization for sanity function that requires lambda to be of the right size
    if (!BN_rand(priv->lambda, PAILLIER_COMMITMENTS_LAMBDA_BITSIZE(key_len), BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ANY))
    {
        goto cleanup;
    }

    ret = paillier_commitment_init_montgomery(&priv->pub, ctx);

    if (ret != PAILLIER_SUCCESS)
    {
        goto cleanup;
    }

    // s = t ^ lambda mod n
    if (!BN_mod_exp(priv->pub.s, priv->pub.t, priv->lambda, priv->pub.n, ctx))
    {
        goto cleanup;
    }

    // now t^n and s^n in mod n^2
    if (!BN_mod_exp_mont(priv->pub.rho, priv->pub.t, priv->pub.n, priv->pub.n2, ctx, priv->pub.mont_n2) ||
        !BN_mod_exp_mont(priv->pub.sigma_0, priv->pub.s, priv->pub.n, priv->pub.n2, ctx, priv->pub.mont_n2) ||
        !BN_copy(tmp, priv->pub.n) ||
        !BN_add_word(tmp, 1) ||
        !BN_mod_mul(priv->pub.sigma_0, priv->pub.sigma_0, tmp, priv->pub.n2, ctx) ) // sigma_0 = (1+N) * s^N mod n^2
    {
        goto cleanup;
    }



cleanup:
    if (-1 == ret)
    {
        ret = paillier_error_from_openssl();
    }

    if (r)
    {
        BN_clear(r);
    }

    BN_CTX_end(ctx);

    return ret;
}

long paillier_commitment_generate_private_key(const uint32_t key_len, paillier_commitment_private_key_t **priv)
{
    long ret = -1;
    BN_CTX *ctx = NULL;
    paillier_commitment_private_key_t *local_private = NULL;

    if (!priv)
    {
        return PAILLIER_ERROR_INVALID_PARAM;
    }

    *priv = NULL;

    if (key_len < PAILLIER_COMMITMENTS_MIN_KEY_BITSIZE)
    {
        return PAILLIER_ERROR_KEYLEN_TOO_SHORT;

    }
    if (key_len % PAILLIER_COMMITMENTS_TOUGH_SUBPRIMES_BITSIZE != 0)
    {
        //because private key is generated using tough primes the key size should be multiple of PAILLIER_COMMITMENTS_TOUGH_SUBPRIMES_BITSIZE
        return PAILLIER_ERROR_INVALID_PARAM;
    }

    if (key_len > PAILLIER_COMMITMENTS_MAX_KEY_SIZE * 8)
    {
        return PAILLIER_ERROR_INVALID_PARAM;
    }

    *priv = NULL;

    ctx = BN_CTX_secure_new();
    if (!ctx)
    {
        //not jumping to cleanup to avoid initializing all local variables
        return PAILLIER_ERROR_OUT_OF_MEMORY;
    }

    local_private = (paillier_commitment_private_key_t*) calloc(1, sizeof(paillier_commitment_private_key_t));

    if (!local_private)
    {
        ret = PAILLIER_ERROR_OUT_OF_MEMORY;
        goto cleanup;
    }

    ret = paillier_commitment_generate_private(key_len, local_private, ctx);
    if (ret != PAILLIER_SUCCESS)
    {
        goto cleanup;
    }

cleanup:

    BN_CTX_free(ctx);

    if (ret)
    {
        paillier_commitment_free_private_key(local_private);
    }
    else
    {
        *priv = local_private;
    }

    return ret;
}

const paillier_commitment_public_key_t * paillier_commitment_private_cast_to_public(const paillier_commitment_private_key_t *priv)
{
    return &priv->pub;
}

long paillier_commitment_public_key_serialize(const paillier_commitment_public_key_t *pub,
                                              const int is_reduced,
                                              uint8_t *buffer,
                                              const uint32_t buffer_len,
                                              uint32_t *real_buffer_len)
{
    uint32_t needed_len, n_len = 0;
    uint8_t *ptr = buffer;

    if (!pub)
    {
        return PAILLIER_ERROR_INVALID_PARAM;
    }

    n_len = (uint32_t)BN_num_bytes(pub->n);
    needed_len = sizeof(uint32_t) + n_len * 3; //n, t, s
    if (!is_reduced)
    {
        // serialize also rho and sigma_0
        needed_len += 4 * n_len;
    }

    if (real_buffer_len)
    {
        *real_buffer_len = needed_len;
    }

    if (buffer_len < needed_len)
    {
        return PAILLIER_ERROR_BUFFER_TOO_SHORT;
    }

    if (!buffer)
    {
        return PAILLIER_ERROR_INVALID_PARAM;
    }

    *(uint32_t*)ptr = n_len;
    ptr += sizeof(uint32_t);

    if (BN_bn2binpad(pub->n, ptr, n_len) <= 0)
    {
        return paillier_error_from_openssl();
    }
    ptr += n_len;

    if (BN_bn2binpad(pub->t, ptr, n_len) <= 0)
    {
        return paillier_error_from_openssl();
    }
    ptr += n_len;

    if (BN_bn2binpad(pub->s, ptr, n_len) <= 0)
    {
        return paillier_error_from_openssl();
    }
    ptr += n_len;

    if (!is_reduced)
    {
        if (BN_bn2binpad(pub->rho, ptr, 2 * n_len) <= 0)
        {
            return paillier_error_from_openssl();
        }
        ptr += 2 * n_len;

        if (BN_bn2binpad(pub->sigma_0, ptr, 2 * n_len) <= 0)
        {
            return paillier_error_from_openssl();
        }
        ptr += 2 * n_len;
    }

    assert ( (uint32_t)(ptr - buffer) == needed_len );

    return PAILLIER_SUCCESS;
}


paillier_commitment_public_key_t * paillier_commitment_public_key_deserialize(const int is_reduced, const uint8_t *buffer, uint32_t buffer_len)
{

    paillier_commitment_public_key_t *pub = NULL;
    uint32_t n_len = 0;
    BN_CTX *ctx = NULL;
    uint32_t needed_len;

    if (!buffer || buffer_len < (sizeof(uint32_t) + 3 * PAILLIER_COMMITMENTS_MIN_KEY_SIZE))
    {
        return NULL;
    }

    ctx = BN_CTX_new();
    if (NULL == ctx)
    {
        return NULL;
    }

    pub = (paillier_commitment_public_key_t*)calloc(1, sizeof(paillier_commitment_public_key_t));
    if (!pub)
    {
        goto cleanup;
    }

    n_len = *(const uint32_t* ) buffer;
    buffer += sizeof(uint32_t);

    if (n_len < PAILLIER_COMMITMENTS_MIN_KEY_SIZE || n_len > PAILLIER_COMMITMENTS_MAX_KEY_SIZE)
    {
        goto cleanup;
    }

    // if not reduced, read also t_n and s_n which are 2 * n_len bytes each
    needed_len = sizeof(uint32_t) + (is_reduced ? 3 : 7) * n_len;

    assert (buffer_len == needed_len);
    if (buffer_len < needed_len)
    {
        goto cleanup;
    }

    pub->n = BN_bin2bn(buffer, n_len, NULL);
    buffer += n_len;

    pub->t = BN_bin2bn(buffer, n_len, NULL);
    buffer += n_len;

    pub->s = BN_bin2bn(buffer, n_len, NULL);
    buffer += n_len;

    if (!pub->n || !pub->t || !pub->s)
    {
        goto cleanup;
    }

    //restore n2
    pub->n2 = BN_new();
    if (!pub->n2 || !BN_sqr(pub->n2, pub->n, ctx))
    {
        goto cleanup;
    }

    if (PAILLIER_SUCCESS != paillier_commitment_init_montgomery(pub, ctx))
    {
        goto cleanup;
    }

    if (!is_reduced)
    {
        // restore t_n and s_n
        pub->rho = BN_bin2bn(buffer, 2 * n_len, NULL);
        buffer += 2 * n_len;

        pub->sigma_0 = BN_bin2bn(buffer, 2 * n_len, NULL);
        buffer += 2 * n_len;
        if (!pub->rho || !pub->sigma_0)
        {
            goto cleanup;
        }
    }
    else
    {
        // calculate t_n and s_n
        pub->rho = BN_new();
        pub->sigma_0 = BN_new();
        if (!pub->rho ||
            !pub->sigma_0)
        {
            goto cleanup;
        }

        if (!BN_mod_exp_mont(pub->sigma_0, pub->s, pub->n, pub->n2, ctx, pub->mont_n2) ||
            !BN_copy(pub->rho, pub->n) || //use rho as temp value
            !BN_add_word(pub->rho, 1) ||
            !BN_mod_mul(pub->sigma_0, pub->sigma_0, pub->rho, pub->n2, ctx) || // sigma_0 = (1+N) * s^N mod n^2
            !BN_mod_exp_mont(pub->rho, pub->t, pub->n, pub->n2, ctx, pub->mont_n2) ) // rho = t^N
        {
            goto cleanup;
        }

    }

    if (PAILLIER_SUCCESS != paillier_commitment_init_montgomery(pub, ctx))
    {
        goto cleanup;
    }

    BN_CTX_free(ctx);
    return pub;

cleanup:

    BN_CTX_free(ctx);

    paillier_commitment_free_public_key(pub);
    return NULL;
}

#define NUM_OF_ADDITIONAL_COMMITMENT_VALUES (10)

long paillier_commitment_private_key_serialize(const paillier_commitment_private_key_t *priv,
                                               uint8_t *buffer,
                                               const uint32_t buffer_len,
                                               uint32_t *real_buffer_len)
{
    uint32_t needed_len, n_len = 0, prime_len = 0, lambda_len = 0;
    uint8_t *ptr = buffer;

    if (!priv)
    {
        return PAILLIER_ERROR_INVALID_PARAM;
    }

    n_len = BN_num_bytes(priv->pub.n);
    prime_len = BN_num_bytes(priv->p);
    lambda_len = PAILLIER_COMMITMENTS_LAMBDA_BITSIZE(n_len * 8) / 8;

    assert((uint32_t)BN_num_bytes(priv->q) == prime_len);
    assert((uint32_t)BN_num_bytes(priv->lambda) == lambda_len);


    // going to store p, q, lambda, t, s, rho, sigma_0, q2_inv_p2 and phi_n_inv
    needed_len = sizeof(uint32_t) +
                 prime_len * 2 + // p and q
                 lambda_len +
                 n_len * NUM_OF_ADDITIONAL_COMMITMENT_VALUES;

    if (real_buffer_len)
    {
        *real_buffer_len = needed_len;
    }

    if (buffer_len < needed_len)
    {
        return PAILLIER_ERROR_BUFFER_TOO_SHORT;
    }

    if (!buffer)
    {
        return PAILLIER_ERROR_INVALID_PARAM;
    }

    *(uint32_t*)ptr = n_len;
    ptr += sizeof(uint32_t);

    if (BN_bn2binpad(priv->p, ptr, prime_len) <= 0)
    {
        return paillier_error_from_openssl();
    }
    ptr += prime_len;

    if (BN_bn2binpad(priv->q, ptr, prime_len) <= 0)
    {
        return paillier_error_from_openssl();
    }
    ptr += prime_len;

    if (BN_bn2binpad(priv->lambda, ptr, lambda_len) <= 0)
    {
        return paillier_error_from_openssl();
    }
    ptr += lambda_len;


    if (BN_bn2binpad(priv->pub.t, ptr, n_len) <= 0)
    {
        return paillier_error_from_openssl();
    }
    ptr += n_len;

    if (BN_bn2binpad(priv->pub.s, ptr, n_len) <= 0)
    {
        return paillier_error_from_openssl();
    }
    ptr += n_len;

    if (BN_bn2binpad(priv->pub.rho, ptr, 2 * n_len) <= 0)
    {
        return paillier_error_from_openssl();
    }
    ptr += 2 * n_len;

    if (BN_bn2binpad(priv->pub.sigma_0, ptr, 2 * n_len) <= 0)
    {
        return paillier_error_from_openssl();
    }
    ptr += 2 * n_len;


    if (BN_bn2binpad(priv->q2_inv_p2, ptr, 2 * n_len) <= 0)
    {
        return paillier_error_from_openssl();
    }
    ptr += 2 * n_len;

     if (BN_bn2binpad(priv->phi_n_inv, ptr, 2 * n_len) <= 0)
    {
        return paillier_error_from_openssl();
    }
    ptr += 2 * n_len;

    assert ( (uint32_t)(ptr - buffer) == needed_len );

    return PAILLIER_SUCCESS;
}

paillier_commitment_private_key_t * paillier_commitment_private_key_deserialize(const uint8_t *buffer, uint32_t buffer_len)
{
    paillier_commitment_private_key_t *priv = NULL;
    uint32_t n_len = 0, lambda_len = 0, prime_len = 0;
    BN_CTX *ctx = NULL;

    if (!buffer || buffer_len <  sizeof(uint32_t))
    {
        return NULL;
    }

    ctx = BN_CTX_new();
    if (NULL == ctx)
    {
        return NULL;
    }

    priv = (paillier_commitment_private_key_t*)calloc(1, sizeof(paillier_commitment_private_key_t));
    if (!priv)
    {
        goto cleanup;
    }

    n_len = *(const uint32_t*)buffer;
    buffer += sizeof(uint32_t);
    prime_len = ((n_len * 8  / 2)  + 7) / 8;
    lambda_len = PAILLIER_COMMITMENTS_LAMBDA_BITSIZE(n_len * 8) / 8;

    // sanity to prevent large allocations
    if (n_len > PAILLIER_COMMITMENTS_MAX_KEY_SIZE)
    {
        goto cleanup;
    }

    if (buffer_len < sizeof(uint32_t)  + prime_len * 2 + lambda_len + n_len * NUM_OF_ADDITIONAL_COMMITMENT_VALUES)
    {
        goto cleanup;
    }

    priv->p = BN_bin2bn(buffer, prime_len, NULL);
    buffer += prime_len;

    priv->q = BN_bin2bn(buffer, prime_len, NULL);
    buffer += prime_len;

    priv->lambda = BN_bin2bn(buffer, lambda_len, NULL);
    buffer += lambda_len;

    priv->pub.t = BN_bin2bn(buffer, n_len, NULL);
    buffer += n_len;

    priv->pub.s = BN_bin2bn(buffer, n_len, NULL);
    buffer += n_len;

    priv->pub.rho = BN_bin2bn(buffer, 2 * n_len, NULL);
    buffer += 2 * n_len;

    priv->pub.sigma_0 = BN_bin2bn(buffer, 2 * n_len, NULL);
    buffer += 2 * n_len;

    priv->q2_inv_p2 = BN_bin2bn(buffer, 2 * n_len, NULL);
    buffer += 2 * n_len;

    priv->phi_n_inv = BN_bin2bn(buffer, 2 * n_len, NULL);
    buffer += 2 * n_len;

    if (!priv->p ||
        !priv->q ||
        !priv->lambda ||
        !priv->pub.t ||
        !priv->pub.s ||
        !priv->pub.rho ||
        !priv->pub.sigma_0 ||
        !priv->q2_inv_p2 ||
        !priv->phi_n_inv)
    {
        goto cleanup;
    }

    // restore n and n2
    priv->pub.n = BN_new();
    priv->pub.n2 = BN_new();
    if (!priv->pub.n || !priv->pub.n2)
    {
        goto cleanup;
    }

    priv->p2 = BN_new();
    priv->q2 = BN_new();
    priv->phi_n = BN_new();

    if (!priv->p2 || !priv->q2 || !priv->phi_n)
    {
        goto cleanup;
    }

    // Compute n = pq
    if (!BN_mul(priv->pub.n, priv->p, priv->q, ctx))
    {
        goto cleanup;
    }

    // calculate phi_n = n - p - q + 1
    if (!BN_sub(priv->phi_n, priv->pub.n, priv->p) ||
        !BN_sub(priv->phi_n, priv->phi_n, priv->q) ||
        !BN_add_word(priv->phi_n, 1))
    {
        goto cleanup;
    }

    // calculate n^2, p^2, q^2 and 1/q^2 in mod p^2
    if (!BN_sqr(priv->pub.n2, priv->pub.n, ctx) ||
        !BN_sqr(priv->p2, priv->p, ctx) ||
        !BN_sqr(priv->q2, priv->q, ctx))
    {
        goto cleanup;
    }

    paillier_commitment_set_consttime_flag(priv);

    if (PAILLIER_SUCCESS != paillier_commitment_init_montgomery(&priv->pub, ctx))
    {
        goto cleanup;
    }

    BN_CTX_free(ctx);
    return priv;

cleanup:
    BN_CTX_free(ctx);
    paillier_commitment_free_private_key(priv);
    return NULL;
}

// this is the paillier public key encryption with small group.
long paillier_commitment_encrypt_openssl_fixed_power_internal(const paillier_commitment_public_key_t *pub,
                                                              BIGNUM *ciphertext,
                                                              const BIGNUM *r_power,
                                                              const BIGNUM *message,
                                                              BN_CTX *ctx)
{
    BIGNUM *tmp1 = NULL, *tmp2 = NULL;
    int ret = -1;

    if (!pub || !ciphertext  || !message || !r_power || !ctx)
    {
        return PAILLIER_ERROR_INVALID_PARAM;
    }


    BN_CTX_start(ctx);

    tmp1 = BN_CTX_get(ctx);
    tmp2 = BN_CTX_get(ctx);

    if (!tmp1 || !tmp2)
    {
        goto cleanup;
    }

    if (!BN_mul(tmp1, pub->n, message, ctx) || // tmp1 = n * message
        !BN_add_word(tmp1, 1))                 // tmp1 = (1 + n * message)
    {
        goto cleanup;
    }

    if (!BN_mod_exp_mont(tmp2,  pub->rho, r_power, pub->n2, ctx,  pub->mont_n2)) //tmp2 = (t^n)^r_power_local mod n2
    {
        goto cleanup;
    }

    if (!BN_mod_mul(ciphertext, tmp1, tmp2, pub->n2, ctx)) // ciphertext = tmp1 * tmp2 = (t^n)^r_power_local * (1 + n*message) mod n^2
    {
        goto cleanup;
    }

    ret = PAILLIER_SUCCESS;

cleanup:

    if (-1 == ret)
    {
        ret = paillier_error_from_openssl();
    }

    BN_CTX_end(ctx);

    return ret;

}

// r_power is an optional output parameter
static long paillier_commitment_encrypt_openssl_internal(const paillier_commitment_public_key_t *pub,
                                                         const uint32_t r_power_bitsize,
                                                         const BIGNUM *message,
                                                         BN_CTX *ctx,
                                                         BIGNUM *ciphertext)
{
    BIGNUM *r_power = NULL;
    int ret = -1;

    if (!pub || !ciphertext  || !message || !r_power_bitsize || !ctx)
    {
        return PAILLIER_ERROR_INVALID_PARAM;
    }


    // r_power_bitsize can be even bigger because it is used in pedersen commitment and used as a blinding factor


    BN_CTX_start(ctx);

    r_power = BN_CTX_get(ctx);

    if (!r_power)
    {
        goto cleanup;
    }

    // no need to loop and check that r_power is coprime because actual value being used
    // as the blinding factor is rho^r_power. It is rho that has to be coprime with n and
    // it is checked already when rho is generated
    if (!BN_rand(r_power, r_power_bitsize, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY))
    {
        goto cleanup;
    }

    ret = paillier_commitment_encrypt_openssl_fixed_power_internal(pub, ciphertext, r_power, message, ctx);

cleanup:

    if (-1 == ret)
    {
        ret = paillier_error_from_openssl();
    }

    BN_clear(r_power);

    BN_CTX_end(ctx);

    return ret;
}

// r_power is an optional output parameter
long paillier_commitment_encrypt_openssl_with_private_internal(const paillier_commitment_private_key_t *priv,
                                                               const uint32_t r_power_bitsize,
                                                               const BIGNUM *message,
                                                               BN_CTX *ctx,
                                                               BIGNUM *ciphertext,
                                                               BIGNUM *r_power)
{
    int ret = -1;
    BIGNUM *mod_p2, *mod_q2, *tmp;

    if (!priv || !ciphertext  || !r_power_bitsize || !message || !ctx || !r_power)
    {
        return PAILLIER_ERROR_INVALID_PARAM;
    }

    // r_power_bitsize can be even bigger because it is used in pedersen commitment and used as a blinding factor

    BN_CTX_start(ctx);

    mod_p2 = BN_CTX_get(ctx);
    mod_q2 = BN_CTX_get(ctx);
    tmp = BN_CTX_get(ctx);

    if (!mod_p2 || !mod_q2 || !tmp)
    {
        goto cleanup;
    }

    // no need to loop and check that r_power is coprime because actual value being used
    // as the blinding factor is rho^r_power. It is rho that has to be coprime with n and
    // it is checked already when rho is generated
    if (!BN_rand(r_power, r_power_bitsize, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY))
    {
        goto cleanup;
    }

    // Compute ciphertext = g^message*(t^n)^r_power_local mod n^2
    // as will select g=n+1 ciphertext = (1+n*message)*(t^n)^r_power_local mod n^2, see https://en.wikipedia.org/wiki/Paillier_cryptosystem
    // Computed using CRT.

    if (!BN_mod_mul(mod_p2, priv->pub.n, message, priv->p2, ctx) || // mod_p2 = n * message mod p^2
        !BN_add_word(mod_p2, 1)                                  || // mod_p2 = n * message  + 1 mod p^2
        !BN_mod_exp(tmp, priv->pub.rho, r_power, priv->p2, ctx)  || // tmp = (t^n) ^ r_power_local mod p^2
        !BN_mod_mul(mod_p2, mod_p2, tmp, priv->p2, ctx))            // mod_p2 = mod_p2 * tmp = (n * message  + 1) * (t^n) ^ r_power_local mod p_2
    {
        goto cleanup;
    }

    if (!BN_mod_mul(mod_q2, priv->pub.n, message, priv->q2, ctx) || // mod_q2 = n * message mod q^2
        !BN_add_word(mod_q2, 1)                                  || // mod_q2 = n * message + 1 mod q^2
        !BN_mod_exp(tmp, priv->pub.rho, r_power, priv->q2, ctx)  || // tmp = (t^n) ^ r_power_local mod q^2
        !BN_mod_mul(mod_q2, mod_q2, tmp, priv->q2, ctx))            // mod_q2 = mod_q2 * tmp = (n * message + 1) * (t^n)^r_power_local mod q^2
    {
        goto cleanup;
    }

    if (crt_recombine(ciphertext, mod_p2, priv->p2, mod_q2, priv->q2, priv->q2_inv_p2, priv->pub.n2, ctx) != ELLIPTIC_CURVE_ALGEBRA_SUCCESS)
    {
        ret = PAILLIER_ERROR_UNKNOWN;
        goto cleanup;
    }

    ret = PAILLIER_SUCCESS;

cleanup:
    if (-1 == ret)
    {
        ret = paillier_error_from_openssl();
    }

    BN_clear(mod_p2);
    BN_clear(mod_q2);
    BN_CTX_end(ctx);

    return ret;
}


long paillier_commitment_encrypt(const paillier_commitment_public_key_t *pub,
                                 const uint8_t *plaintext,
                                 const uint32_t plaintext_len,
                                 uint8_t *ciphertext,
                                 const uint32_t ciphertext_len,
                                 uint32_t *ciphertext_real_len)
{

    long ret = -1;
    BN_CTX *ctx = NULL;
    BIGNUM *msg = NULL, *c = NULL;

    if (!pub)
    {
        return PAILLIER_ERROR_INVALID_KEY;
    }

    if (!plaintext || plaintext_len > (uint32_t)BN_num_bytes(pub->n))
    {
        return PAILLIER_ERROR_INVALID_PLAIN_TEXT;
    }

    if (ciphertext_real_len)
    {
        *ciphertext_real_len = (uint32_t)BN_num_bytes(pub->n2);
    }

    if (ciphertext_len < (uint32_t)BN_num_bytes(pub->n2))
    {
        return PAILLIER_ERROR_BUFFER_TOO_SHORT;
    }

    if (!ciphertext)
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

    if (BN_cmp(msg, pub->n) >= 0)
    {
        // plaintext not in n
        ret = PAILLIER_ERROR_INVALID_PLAIN_TEXT;
        goto cleanup;
    }

    ret = paillier_commitment_encrypt_openssl_internal(pub, ZKPOK_OPTIM_SMALL_GROUP_EXPONENT_BITS(paillier_commitment_public_bitsize(pub)), msg, ctx, c);

    if (PAILLIER_SUCCESS != ret)
    {
        goto cleanup;
    }

    if (BN_bn2binpad(c, ciphertext, (uint32_t)BN_num_bytes(pub->n2)) <= 0)
    {
        ret = -1;
        goto cleanup;
    }

    ret = PAILLIER_SUCCESS;

cleanup:
    if (PAILLIER_SUCCESS != ret)
    {
        if (-1 == ret)
        {
            ret = paillier_error_from_openssl();
        }
    }

    BN_CTX_end(ctx);
    BN_CTX_free(ctx);

    return ret;
}

long paillier_commitment_decrypt_openssl_internal(const paillier_commitment_private_key_t *priv,
                                                  const BIGNUM *ciphertext,
                                                  BIGNUM *plaintext,
                                                  BN_CTX *ctx)
{
    int ret = -1;
    if (!priv)
    {
        return PAILLIER_ERROR_INVALID_KEY;
    }

    if (!ciphertext)
    {
        return PAILLIER_ERROR_INVALID_CIPHER_TEXT;
    }

    if (!plaintext)
    {
        return PAILLIER_ERROR_INVALID_PLAIN_TEXT;
    }

    if (!ctx)
    {
        return  PAILLIER_ERROR_INVALID_PARAM;
    }


    BN_CTX_start(ctx);

    BIGNUM *tmp = BN_CTX_get(ctx);

    if (!tmp)
    {
        goto cleanup;
    }

    // verify that ciphertext and n are coprime
    if (is_coprime_fast(ciphertext, priv->pub.n, ctx) != 1)
    {
        ret = PAILLIER_ERROR_INVALID_CIPHER_TEXT;
        goto cleanup;
    }

    // Compute the plaintext = paillier_L(ciphertext^lambda mod n2)*mu mod n
    if (ELLIPTIC_CURVE_ALGEBRA_SUCCESS != crt_mod_exp(tmp, ciphertext, priv->phi_n, priv->p2, priv->q2, priv->q2_inv_p2, priv->pub.n2, ctx))
    {
        ret = PAILLIER_ERROR_UNKNOWN;
        goto cleanup;
    }

    ret = paillier_L(tmp, tmp, priv->pub.n, ctx);
    if (ret != PAILLIER_SUCCESS)
    {
        goto cleanup;
    }

    ret = -1; //revert to openssl error

    if (!BN_mod_mul(plaintext, tmp, priv->phi_n_inv, priv->pub.n, ctx))
    {
        goto cleanup;
    }

    ret = PAILLIER_SUCCESS;

cleanup:
    if (-1 == ret)
    {
        ret = paillier_error_from_openssl();
    }

    BN_CTX_end(ctx);
    return ret;
}

long paillier_commitment_decrypt(const paillier_commitment_private_key_t *priv,
                                 const uint8_t *ciphertext,
                                 const uint32_t ciphertext_len,
                                 uint8_t *plaintext,
                                 const uint32_t plaintext_len,
                                 uint32_t *plaintext_real_len)
{
    long ret = -1;
    BN_CTX *ctx = NULL;
    BIGNUM *msg = NULL, *c = NULL;

    if (!priv)
    {
        return PAILLIER_ERROR_INVALID_KEY;
    }

    if (!ciphertext || ciphertext_len > (uint32_t)BN_num_bytes(priv->pub.n2))
    {
        return PAILLIER_ERROR_INVALID_CIPHER_TEXT;
    }

    if (plaintext_real_len)
    {
        *plaintext_real_len = (uint32_t)BN_num_bytes(priv->pub.n);
    }

    if (plaintext_len < (uint32_t)BN_num_bytes(priv->pub.n))
    {
        return PAILLIER_ERROR_BUFFER_TOO_SHORT;
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

    msg = BN_CTX_get(ctx);
    c = BN_CTX_get(ctx);

    if (!msg || !c)
    {
        ret = PAILLIER_ERROR_OUT_OF_MEMORY;
        goto cleanup;
    }

    if (!BN_bin2bn(ciphertext, ciphertext_len, c))
    {
        goto cleanup;
    }

    ret = paillier_commitment_decrypt_openssl_internal(priv, c, msg, ctx);
    if (ret != PAILLIER_SUCCESS)
    {
        goto cleanup;
    }

    if (BN_bn2binpad(msg, plaintext, (uint32_t)BN_num_bytes(priv->pub.n)) <= 0)
    {
        ret = PAILLIER_ERROR_UNKNOWN;
        goto cleanup;
    }

cleanup:
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);

    return ret;
}

long paillier_commitment_commit_with_private_internal(const paillier_commitment_private_key_t *priv,
                                                      const BIGNUM* commited_val,
                                                      const BIGNUM* randomizer_expo,
                                                      const BIGNUM* modifier,
                                                      const BIGNUM* modifier_expo,
                                                      BIGNUM* commitment,
                                                      BN_CTX *ctx)
{
    BIGNUM *commitment_modP2 = NULL, *commitment_modQ2 = NULL;
    BIGNUM *tmp = NULL;
    BN_MONT_CTX *mont_p2 = NULL, *mont_q2 = NULL;

    long ret = -1;

    if (!priv || !commited_val || !randomizer_expo || !commitment || !ctx)
    {
        return PAILLIER_ERROR_INVALID_PARAM;
    }

    // check that either both or none are passed
    if (!((!modifier && !modifier_expo) || (modifier && modifier_expo)))
    {
        return PAILLIER_ERROR_INVALID_PARAM;
    }

    BN_CTX_start(ctx);
    commitment_modP2 = BN_CTX_get(ctx);
    commitment_modQ2 = BN_CTX_get(ctx);
    tmp = BN_CTX_get(ctx);
    if (!commitment_modP2 || !commitment_modQ2 || !tmp)
    {
        ret = PAILLIER_ERROR_OUT_OF_MEMORY;
        goto cleanup;
    }
    mont_p2 = BN_MONT_CTX_new();
    mont_q2 = BN_MONT_CTX_new();
    if (!mont_p2 || !mont_q2)
    {
        ret = PAILLIER_ERROR_OUT_OF_MEMORY;
        goto cleanup;
    }

    if (!BN_MONT_CTX_set(mont_p2, priv->p2, ctx) ||
        !BN_MONT_CTX_set(mont_q2, priv->q2, ctx))
    {
        goto cleanup;
    }

    if (!BN_mod_exp2_mont(commitment_modP2, priv->pub.sigma_0, commited_val,  priv->pub.rho, randomizer_expo, priv->p2 , ctx, mont_p2) ||
        !BN_mod_exp2_mont(commitment_modQ2, priv->pub.sigma_0, commited_val,  priv->pub.rho, randomizer_expo, priv->q2 , ctx, mont_q2))
    {
        goto cleanup;
    }

    if (modifier)
    {
        if (!BN_mod_exp_mont(tmp, modifier, modifier_expo, priv->p2 , ctx, mont_p2) ||
            !BN_mod_mul(commitment_modP2, commitment_modP2, tmp, priv->p2, ctx))
        {
            goto cleanup;
        }

        if (!BN_mod_exp_mont(tmp, modifier, modifier_expo, priv->q2 , ctx, mont_q2) ||
            !BN_mod_mul(commitment_modQ2, commitment_modQ2, tmp, priv->q2, ctx))
        {
            goto cleanup;
        }
    }

    if (ELLIPTIC_CURVE_ALGEBRA_SUCCESS != crt_recombine(commitment, commitment_modP2, priv->p2, commitment_modQ2, priv->q2, priv->q2_inv_p2, priv->pub.n2, ctx))
    {
        ret = PAILLIER_ERROR_UNKNOWN;
        goto cleanup;
    }

    ret = PAILLIER_SUCCESS;

cleanup:
    if (-1 == ret)
    {
        ret = paillier_error_from_openssl();
    }

    if (commitment_modP2)
    {
        BN_clear(commitment_modP2);
    }

    if (commitment_modQ2)
    {
        BN_clear(commitment_modQ2);
    }

    BN_MONT_CTX_free(mont_p2);
    BN_MONT_CTX_free(mont_q2);

    BN_CTX_end(ctx);
    return ret;


}


long paillier_commitment_commit_internal(const paillier_commitment_public_key_t *pub,
                                         const BIGNUM* commited_val,
                                         const BIGNUM* randomizer_expo,
                                         const BIGNUM* modifier,
                                         const BIGNUM* modifier_expo,
                                         BIGNUM* commitment,
                                         BN_CTX *ctx)
{
    BIGNUM* tmp = NULL;
    long ret = -1;

    if (!pub || !commited_val || !randomizer_expo || !commitment || !ctx)
    {
        return PAILLIER_ERROR_INVALID_PARAM;
    }

    // check that either both or none are passed
    if (!((!modifier && !modifier_expo) || (modifier && modifier_expo)))
    {
        return PAILLIER_ERROR_INVALID_PARAM;
    }

    BN_CTX_start(ctx);
    tmp = BN_CTX_get(ctx);
    if (!tmp)
    {
        ret = PAILLIER_ERROR_OUT_OF_MEMORY;
        goto cleanup;
    }

    if (!BN_mod_exp2_mont(commitment, pub->sigma_0, commited_val,  pub->rho, randomizer_expo, pub->n2, ctx, pub->mont_n2))
    {
        goto cleanup;
    }

    if (modifier)
    {
        if (!BN_mod_exp_mont(tmp, modifier, modifier_expo, pub->n2, ctx, pub->mont_n2) ||
            !BN_mod_mul(commitment, commitment, tmp, pub->n2, ctx))
        {
            goto cleanup;
        }
    }

    ret = PAILLIER_SUCCESS;
cleanup:
    if (-1 == ret)
    {
        ret = paillier_error_from_openssl();
    }

    BN_CTX_end(ctx);
    return ret;
}

long paillier_commitment_commit(const paillier_commitment_public_key_t *pub,
                                const uint8_t *commited_value,
                                const uint32_t commited_value_len,
                                const uint32_t randomizer_expo_bitlength,
                                const uint8_t *modifier,
                                const uint32_t modifier_size,
                                const uint8_t *modifier_exp,
                                const uint32_t modifier_exp_size,
                                paillier_commitment_with_randomizer_power_t** commitment)
{

    long ret = -1;
    paillier_commitment_with_randomizer_power_t* local_commitment = NULL;
    BIGNUM *bn_commited = NULL, *bn_random_expo_val = NULL;
    BIGNUM *bn_commitment = NULL;
    BIGNUM *bn_modifier = NULL, *bn_modifier_expo = NULL;
    BN_CTX *ctx = NULL;

    if (!pub || !commited_value || !commited_value_len || !randomizer_expo_bitlength || !commitment)
    {
        return PAILLIER_ERROR_INVALID_PARAM;
    }

    *commitment = NULL;

    if (modifier || modifier_size || modifier_exp || modifier_exp_size)
    {
        if (!modifier || !modifier_size || !modifier_exp || !modifier_exp_size)
        {
            return PAILLIER_ERROR_INVALID_PARAM;
        }
    }

    // protect from too large commitments generation
    if ((randomizer_expo_bitlength + 7)/ 8 > PAILLIER_COMMITMENTS_MAX_SERIALIZED_SIZE  ||
        (uint32_t)BN_num_bytes(pub->n2) > PAILLIER_COMMITMENTS_MAX_SERIALIZED_SIZE)
    {
        return PAILLIER_ERROR_INVALID_PARAM;
    }

    local_commitment = (paillier_commitment_with_randomizer_power_t*)calloc(1, sizeof(paillier_commitment_with_randomizer_power_t));
    if (!local_commitment)
    {
        return PAILLIER_ERROR_OUT_OF_MEMORY;
    }

    local_commitment->randomizer_exponent_size = (randomizer_expo_bitlength + 7)/ 8;
    local_commitment->randomizer_exponent = (uint8_t*)calloc(1, local_commitment->randomizer_exponent_size);
    local_commitment->commitment_size = (uint32_t)BN_num_bytes(pub->n2);
    local_commitment->commitment = (uint8_t*)calloc(1, local_commitment->commitment_size);
    if (!local_commitment->randomizer_exponent || !local_commitment->commitment)
    {
        ret = PAILLIER_ERROR_OUT_OF_MEMORY;
        goto cleanup;
    }

    ctx = BN_CTX_new();
    if (ctx == NULL)
    {
        ret = PAILLIER_ERROR_OUT_OF_MEMORY;
        goto cleanup;
    }

    BN_CTX_start(ctx);

    bn_commited = BN_CTX_get(ctx);
    bn_random_expo_val = BN_CTX_get(ctx);
    bn_commitment = BN_CTX_get(ctx);
    if (!bn_commited || !bn_random_expo_val || !bn_commitment)
    {
        ret = PAILLIER_ERROR_OUT_OF_MEMORY;
        goto cleanup;
    }

    if (modifier)
    {
        bn_modifier = BN_CTX_get(ctx);
        bn_modifier_expo = BN_CTX_get(ctx);
        if (!bn_modifier || !bn_modifier_expo)
        {
            ret = PAILLIER_ERROR_OUT_OF_MEMORY;
            goto cleanup;
        }
    }

    if (!BN_bin2bn(commited_value, commited_value_len, bn_commited) ||
        !BN_rand(bn_random_expo_val, randomizer_expo_bitlength, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY))
    {
        goto cleanup;
    }

    if (modifier)
    {
        if (!BN_bin2bn(modifier, modifier_size, bn_modifier) ||
            !BN_bin2bn(modifier_exp, modifier_exp_size, bn_modifier_expo) )
        {
            goto cleanup;
        }
    }

    ret = paillier_commitment_commit_internal(pub, bn_commited, bn_random_expo_val, bn_modifier, bn_modifier_expo, bn_commitment, ctx);
    if (ret != PAILLIER_SUCCESS)
    {
        goto cleanup;
    }

    if (BN_bn2binpad(bn_random_expo_val, local_commitment->randomizer_exponent, local_commitment->randomizer_exponent_size) <= 0 ||
        BN_bn2binpad(bn_commitment, local_commitment->commitment, local_commitment->commitment_size) <= 0)
    {
        ret = -1;
        goto cleanup;
    }

cleanup:
    if (ret != PAILLIER_SUCCESS)
    {
        if (-1 == ret)
        {
            ret = paillier_error_from_openssl();
        }
        paillier_commitment_commitment_free(local_commitment);
    }
    else
    {
        *commitment = local_commitment;
        local_commitment = NULL;
    }

    if (ctx)
    {
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
    }

    return ret;


}

long paillier_commitment_verify(const paillier_commitment_public_key_t *pub,
                                const uint8_t *commited_value,
                                const uint32_t commited_value_len,
                                const uint8_t *modifier,
                                const uint32_t modifier_size,
                                const uint8_t *modifier_exp,
                                const uint32_t modifier_exp_size,
                                const paillier_commitment_with_randomizer_power_t* commitment)
{
    long ret = -1;
    BN_CTX *ctx = NULL;
    BIGNUM *bn_commited = NULL, *bn_random_expo_val = NULL;
    BIGNUM *bn_commitment = NULL, *bn_commitment_expected = NULL;
    BIGNUM *bn_modifier = NULL, *bn_modifier_expo = NULL;

    if (!pub || !commited_value || !commited_value_len || !commitment ||
        !commitment->randomizer_exponent_size || !commitment->randomizer_exponent ||
        !commitment->commitment_size || !commitment->commitment)
    {
        return PAILLIER_ERROR_INVALID_PARAM;
    }

    if (modifier || modifier_size || modifier_exp || modifier_exp_size)
    {
        if (!modifier || !modifier_size || !modifier_exp || !modifier_exp_size)
        {
            return PAILLIER_ERROR_INVALID_PARAM;
        }
    }

    ctx = BN_CTX_new();
    if (ctx == NULL)
    {
        return PAILLIER_ERROR_OUT_OF_MEMORY;
    }

    BN_CTX_start(ctx);

    bn_commited = BN_CTX_get(ctx);
    bn_random_expo_val = BN_CTX_get(ctx);
    bn_commitment = BN_CTX_get(ctx);
    bn_commitment_expected = BN_CTX_get(ctx);
    if (!bn_commited  || !bn_random_expo_val || !bn_commitment || !bn_commitment_expected)
    {
        ret = PAILLIER_ERROR_OUT_OF_MEMORY;
        goto cleanup;
    }

    if (modifier)
    {
        bn_modifier = BN_CTX_get(ctx);
        bn_modifier_expo = BN_CTX_get(ctx);
        if (!bn_modifier || !bn_modifier_expo)
        {
            ret = PAILLIER_ERROR_OUT_OF_MEMORY;
            goto cleanup;
        }
    }

    if (!BN_bin2bn(commited_value, commited_value_len, bn_commited) ||
        !BN_bin2bn(commitment->commitment, commitment->commitment_size, bn_commitment_expected) ||
        !BN_bin2bn(commitment->randomizer_exponent, commitment->randomizer_exponent_size, bn_random_expo_val))
    {
        goto cleanup;
    }

    if (modifier)
    {
        if (!BN_bin2bn(modifier, modifier_size, bn_modifier) ||
            !BN_bin2bn(modifier_exp, modifier_exp_size, bn_modifier_expo) )
        {
            goto cleanup;
        }
    }

    ret = paillier_commitment_commit_internal(pub, bn_commited, bn_random_expo_val, bn_modifier, bn_modifier_expo, bn_commitment, ctx);
    if (ret != PAILLIER_SUCCESS)
    {
        goto cleanup;
    }

    if (BN_cmp(bn_commitment, bn_commitment_expected) != 0)
    {
        ret = PAILLIER_ERROR_INVALID_PROOF;
        goto cleanup;
    }

    ret = PAILLIER_SUCCESS;

cleanup:
    if (-1 == ret)
    {
        ret = paillier_error_from_openssl();
    }

    BN_CTX_end(ctx);
    BN_CTX_free(ctx);

    return ret;
}

void paillier_commitment_commitment_free(paillier_commitment_with_randomizer_power_t* commitment)
{
    if (commitment)
    {
        free(commitment->commitment);
        commitment->commitment = NULL;
        free(commitment->randomizer_exponent);
        commitment->randomizer_exponent = NULL;
        free(commitment);
    }

}

long paillier_commitment_commitment_serialize(const paillier_commitment_with_randomizer_power_t* commitment,
                                              uint8_t *serialized_proof,
                                              uint32_t proof_len,
                                              uint32_t *real_proof_len)
{
    if (!commitment || (!serialized_proof && proof_len))
    {
        return PAILLIER_ERROR_INVALID_PARAM;
    }

    if (real_proof_len)
    {
        *real_proof_len = 2 * sizeof(uint32_t) + commitment->commitment_size + commitment->randomizer_exponent_size;
    }

    if (proof_len < 2 * sizeof(uint32_t) + commitment->commitment_size + commitment->randomizer_exponent_size)
    {
        return PAILLIER_ERROR_BUFFER_TOO_SHORT;
    }

    *(uint32_t*)serialized_proof = commitment->commitment_size;
    serialized_proof += sizeof(uint32_t);

    *(uint32_t*)serialized_proof = commitment->randomizer_exponent_size;
    serialized_proof += sizeof(uint32_t);


    memcpy(serialized_proof, commitment->commitment, commitment->commitment_size);
    serialized_proof += commitment->commitment_size;

    memcpy(serialized_proof, commitment->randomizer_exponent, commitment->randomizer_exponent_size);
    serialized_proof += commitment->randomizer_exponent_size;

    return PAILLIER_SUCCESS;
}

paillier_commitment_with_randomizer_power_t* paillier_commitment_commitment_deserialize(const uint8_t *serialized_proof, const uint32_t proof_len)
{
    paillier_commitment_with_randomizer_power_t* commitment;
    if (proof_len < 2 * sizeof(uint32_t))
    {
        return NULL;
    }

    commitment = calloc(1, sizeof(paillier_commitment_with_randomizer_power_t));
    if (!commitment)
    {
        return NULL;
    }

    commitment->commitment_size = *(const uint32_t*)serialized_proof;
    serialized_proof += sizeof(uint32_t);

    commitment->randomizer_exponent_size = *(const uint32_t*)serialized_proof;
    serialized_proof += sizeof(uint32_t);

    //sanity
    if (commitment->commitment_size > PAILLIER_COMMITMENTS_MAX_SERIALIZED_SIZE ||
        commitment->randomizer_exponent_size > PAILLIER_COMMITMENTS_MAX_SERIALIZED_SIZE)
    {
        paillier_commitment_commitment_free(commitment);
        return NULL;
    }

    if (proof_len < 2 * sizeof(uint32_t) + commitment->commitment_size + commitment->randomizer_exponent_size)
    {
        paillier_commitment_commitment_free(commitment);
        return NULL;
    }

    commitment->commitment = (uint8_t*)malloc(commitment->commitment_size);
    commitment->randomizer_exponent = (uint8_t*)malloc(commitment->randomizer_exponent_size);
    if (!commitment->commitment || !commitment->randomizer_exponent)
    {
        paillier_commitment_commitment_free(commitment);
        return NULL;
    }

    memcpy(commitment->commitment, serialized_proof, commitment->commitment_size);
    serialized_proof += commitment->commitment_size;

    memcpy(commitment->randomizer_exponent, serialized_proof, commitment->randomizer_exponent_size);
    serialized_proof += commitment->randomizer_exponent_size;

    return commitment;
}

long paillier_commitment_paillier_blum_zkp_generate(const paillier_commitment_private_key_t *priv, const uint8_t *aad, uint32_t aad_len, uint8_t *serialized_proof, uint32_t proof_len, uint32_t *proof_real_len)
{
    if (!priv)
    {
        return PAILLIER_ERROR_INVALID_PARAM;
    }
    const paillier_private_key_t paillier_private = {
        { priv->pub.n, priv->pub.n2},
        priv->p,
        priv->q,
        priv->phi_n,
        priv->phi_n_inv
    };

    return paillier_generate_paillier_blum_zkp(&paillier_private, 0 /* compute only the first nth root */, aad, aad_len, serialized_proof, proof_len, proof_real_len);
}

long paillier_commitment_paillier_blum_zkp_verify(const paillier_commitment_public_key_t *pub, const uint8_t *aad, uint32_t aad_len, const uint8_t *serialized_proof, uint32_t proof_len)
{
    if (!pub)
    {
        return PAILLIER_ERROR_INVALID_PARAM;
    }
    const paillier_public_key_t paillier_public = { pub->n, pub->n2};
    return paillier_verify_paillier_blum_zkp(&paillier_public, 0, aad, aad_len, serialized_proof, proof_len);
}

uint32_t range_proof_paillier_commitment_large_factors_zkp_compute_d_bitsize(const paillier_commitment_public_key_t* pub)
{
    if (!pub)
    {
        return 0;
    }
    const paillier_public_key_t paillier_public = { pub->n, pub->n2};
    return range_proof_paillier_large_factors_quadratic_zkp_compute_d_bitsize(&paillier_public);
}

zero_knowledge_proof_status range_proof_paillier_commitment_large_factors_zkp_generate(const paillier_commitment_private_key_t *priv,
                                                                                       const uint8_t *aad,
                                                                                       const uint32_t aad_len,
                                                                                       const uint8_t *d_prime,
                                                                                       const uint32_t d_prime_len,
                                                                                       uint8_t *serialized_proof,
                                                                                       uint32_t proof_len,
                                                                                       uint32_t *real_proof_len)
{
    if (!priv)
    {
        return ZKP_INVALID_PARAMETER;
    }
    const paillier_private_key_t paillier_private = {
        { priv->pub.n, priv->pub.n2},
        priv->p,
        priv->q,
        priv->phi_n,
        priv->phi_n_inv
    };

    return range_proof_paillier_large_factors_quadratic_zkp_generate(&paillier_private, aad, aad_len, d_prime, d_prime_len, serialized_proof, proof_len, real_proof_len);
}

zero_knowledge_proof_status range_proof_paillier_commitment_large_factors_zkp_verify(const paillier_commitment_public_key_t *pub,
                                                                                     const uint8_t *aad,
                                                                                     const uint32_t aad_len,
                                                                                     const uint8_t *serialized_proof,
                                                                                     const uint32_t proof_len)
{
    if (!pub)
    {
        return ZKP_INVALID_PARAMETER;
    }
    const paillier_public_key_t paillier_public = { pub->n, pub->n2};

    return range_proof_paillier_large_factors_quadratic_zkp_verify(&paillier_public, aad, aad_len, serialized_proof, proof_len);
}

zero_knowledge_proof_status paillier_commitment_damgard_fujisaki_parameters_zkp_generate(const paillier_commitment_private_key_t *priv,
                                                                                         const uint8_t* aad,
                                                                                         const uint32_t aad_len,
                                                                                         uint8_t* serialized_proof,
                                                                                         const uint32_t proof_len,
                                                                                         uint32_t* proof_real_len)
{
    zero_knowledge_proof_status ret = ZKP_OUT_OF_MEMORY;
    BN_CTX* ctx = NULL;

    if (!priv)
    {
        return ZKP_INVALID_PARAMETER;
    }

    ctx = BN_CTX_new();
    if (!ctx)
    {
        return ZKP_OUT_OF_MEMORY;
    }
    BN_CTX_start(ctx);

    const damgard_fujisaki_private_t damgard_fujisaki_priv =
    {
        {
            1,                    //dimensions; // number of secrets
            priv->pub.n,          // public part of p * q
            (BIGNUM**)&priv->pub.s,         // for each secret lambda holds its public t^lambda
            priv->pub.t,          // single t used for all s
            NULL                  // montgomery context used for calculations
        },

        (BIGNUM**)&priv->lambda, // secrets, same count as pub->dimension
        priv->phi_n,  // (p-1) * (q-1)
        priv->p,
        priv->q,
        BN_CTX_get(ctx)
    };

    if (!damgard_fujisaki_priv.qinvp)
    {
        goto cleanup;
    }

    if (serialized_proof && proof_len)
    {
        if (RING_PEDERSEN_SUCCESS != damgard_fujisaki_init_montgomery((damgard_fujisaki_public_t*)&damgard_fujisaki_priv.pub, ctx))
        {
            ret = ZKP_OUT_OF_MEMORY;
            goto cleanup;
        }

        if (!BN_mod_inverse(damgard_fujisaki_priv.qinvp, priv->q, priv->p, ctx))
        {
            ret = ZKP_UNKNOWN_ERROR;
            goto cleanup;
        }
    }

    ret = damgard_fujisaki_parameters_zkp_generate(&damgard_fujisaki_priv, aad, aad_len, 1, serialized_proof, proof_len, proof_real_len);

cleanup:
    BN_MONT_CTX_free(damgard_fujisaki_priv.pub.mont); //must manually since manually initialized free
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);

    return ret;
}

zero_knowledge_proof_status paillier_commitment_damgard_fujisaki_parameters_zkp_verify(const paillier_commitment_public_key_t *pub,
                                                                                       const uint8_t* aad,
                                                                                       const uint32_t aad_len,
                                                                                       const uint8_t* serialized_proof,
                                                                                       const uint32_t proof_len)
{
    zero_knowledge_proof_status ret = ZKP_OUT_OF_MEMORY;
    BN_CTX* ctx = NULL;

    if (!pub)
    {
        return ZKP_INVALID_PARAMETER;
    }

    ctx = BN_CTX_new();
    if (!ctx)
    {
        return ZKP_OUT_OF_MEMORY;
    }
    BN_CTX_start(ctx);

    const damgard_fujisaki_public_t damgard_fujisaki_pub =
    {
        1,               // number of secrets
        pub->n,          // public part of p * q
        (BIGNUM **)&pub->s,         // for each secret lambda holds its public t^lambda
        pub->t,          // single t used for all s
        NULL             // montgomery context used for calculations
    };

    if (serialized_proof && proof_len)
    {
        if (RING_PEDERSEN_SUCCESS != damgard_fujisaki_init_montgomery((damgard_fujisaki_public_t*)&damgard_fujisaki_pub, ctx))
        {
            ret = ZKP_OUT_OF_MEMORY;
            goto cleanup;
        }
    }

    ret = damgard_fujisaki_parameters_zkp_verify(&damgard_fujisaki_pub, aad, aad_len, 1, serialized_proof, proof_len);

cleanup:
    BN_MONT_CTX_free(damgard_fujisaki_pub.mont); //must manually since manually initialized free
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);

    return ret;
}

