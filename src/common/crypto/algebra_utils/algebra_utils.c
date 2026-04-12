#include "crypto/algebra_utils/algebra_utils.h"
#include <alloca.h> 
#include <time.h>
#include <openssl/bn.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <assert.h>

// Maximum number of attempts to generate a valid tough prime before giving up
#define PRIME_GENERATION_MAX_TRIES (2000)

// Maximum number of cycles to regenerate sub-primes before failing
#define PRIME_GENERATION_MAX_REGENERATION_CYCLES (100)

// Extra sub-primes generated to increase randomness in tough prime construction
// This ensures a diverse selection of factors, reducing the risk of repeatedly selecting
// the same set of sub-primes, which could lead to failure in generating a valid prime.
#define PRIME_GENERATION_POOL_INCREASE (15)

// In-place swap of two integers using XOR swap algorithm
#define INPLACE_SWAP(A, B) (A) ^= (B); (B) ^= (A); (A) ^= (B)

/**
 * @brief Generates a random permutation of integers in the range [0, permutation_size - 1].
 * 
 * This function shuffles an array of integers from 0 to (permutation_size - 1) using random bytes.
 * The randomness is ensured using OpenSSL's `RAND_bytes`, making the permutation cryptographically secure.
 * 
 * @param[out] permutation      Pointer to a pre-allocated array that will store the generated permutation.
 * @param[in]  permutation_size The number of elements in the permutation array.
 * 
 * @return ELLIPTIC_CURVE_ALGEBRA_SUCCESS on success.
 *         ELLIPTIC_CURVE_ALGEBRA_UNKNOWN_ERROR if random byte generation fails.
 * 
 * @note The function assumes `permutation` is a valid pointer to an allocated array of size `permutation_size`.
 *       Behavior is undefined if `permutation_size` is zero.
 */
static elliptic_curve_algebra_status generate_permutation(uint8_t * const permutation, const uint8_t permutation_size)
{
    uint8_t * const random_storage = (uint8_t*)alloca(sizeof(uint8_t) * permutation_size);
    uint8_t i;
    
    // Initialize values of the permutation
    for (i = 0; i < permutation_size; ++i)
    {
        permutation[i] = i;
    }

    --i; // Set i to the last valid index (permutation_size - 1)
    
    // Generate random bytes for random_storage
    if (1 != RAND_bytes((uint8_t *)random_storage, permutation_size))
    {
        ERR_clear_error();
        return ELLIPTIC_CURVE_ALGEBRA_UNKNOWN_ERROR;
    }

    // Create the permutation by swapping elements based on random values
    while (i > 0) 
    {
        const uint8_t j = random_storage[i] % i; // Use random value to determine index j
        INPLACE_SWAP(permutation[i], permutation[j]); // Swap values at index i and j
        --i;
    }

    return ELLIPTIC_CURVE_ALGEBRA_SUCCESS;
}

// Generates a tough prime of specified bit size using sub-primes
// Uses sub-primes of subprimes_bitsize to generate a larger prime
// If bitsize is too small, simply generates a safe prime instead
// if add and rem are not given the number generated will be 3 mod 4
elliptic_curve_algebra_status generate_tough_prime(BIGNUM* p, const uint32_t bitsize, const uint32_t subprimes_bitsize, const BIGNUM* add, const BIGNUM* rem, BN_CTX* ctx)
{
    BIGNUM** prime_pool = NULL;
    BIGNUM* remainder = NULL;
    uint8_t* permutation = NULL;
    uint8_t pool_size = 0, factors_number = 0;
    long ret = -1;

    // Validate input parameters
    // limit subprime size to prevent overflow during comparison with bitsize
    if (!bitsize || !subprimes_bitsize || !p || !ctx || subprimes_bitsize > (1U<<15) )
    {
        return ELLIPTIC_CURVE_ALGEBRA_INVALID_PARAMETER;
    }
    
    // bitsize must be divisible by subprimes_bitsize
    if ((bitsize % subprimes_bitsize) != 0)
    {
        return ELLIPTIC_CURVE_ALGEBRA_INVALID_PARAMETER;
    }

    // Generate safe prime if bitsize is too small
    if (bitsize < 4 * subprimes_bitsize) 
    {
        if (!BN_generate_prime_ex(p, bitsize, 1, add, rem, NULL))
        {
            return ELLIPTIC_CURVE_ALGEBRA_UNKNOWN_ERROR;
        }
        return ELLIPTIC_CURVE_ALGEBRA_SUCCESS;
    }

    // Limit factors number to prevent excessive memory allocation
    if (bitsize >= (256 - PRIME_GENERATION_POOL_INCREASE) * subprimes_bitsize)
    {
        return ELLIPTIC_CURVE_ALGEBRA_INVALID_PARAMETER;
    }

    BN_CTX_start(ctx);    

    factors_number = (uint8_t)(bitsize / subprimes_bitsize);

    // Set pool size for prime generation
    pool_size = factors_number + PRIME_GENERATION_POOL_INCREASE;

    // Allocate memory for prime pool
    prime_pool = calloc(pool_size, sizeof(BIGNUM * ));
    if (!prime_pool)
    {
        pool_size = 0; // Prevent cleanup from accessing unallocated memory
        ret = ELLIPTIC_CURVE_ALGEBRA_OUT_OF_MEMORY;
        goto cleanup;
    }
    
    for (uint8_t p_idx = 0; p_idx < pool_size; ++p_idx)  
    {
        prime_pool[p_idx] = BN_CTX_get(ctx);
        if (!prime_pool[p_idx])
        {
            goto cleanup;
        }
    }

    remainder = BN_CTX_get(ctx);
    if (!remainder)
    {
        goto cleanup;
    }
        
    permutation = (uint8_t*) alloca(pool_size);

    // Generate small primes and create a composite prime
    uint32_t generation_cycles = 0;
    do
    {
        for (uint8_t p_idx = 0; p_idx < pool_size; ++p_idx) 
        {
            if (!BN_generate_prime_ex(prime_pool[p_idx], subprimes_bitsize, 0, NULL, NULL, NULL))
            {
                goto cleanup;
            }
            assert((uint32_t)BN_num_bits(prime_pool[p_idx]) == subprimes_bitsize);
        }
        
        for (uint32_t trial = 0; trial < PRIME_GENERATION_MAX_TRIES; ++trial) 
        {
            ret = generate_permutation(permutation, pool_size);
            if (ret != ELLIPTIC_CURVE_ALGEBRA_SUCCESS)
            {
                goto cleanup;
            }
            
            ret = -1;
            
            if (!BN_set_word(p, 2))
            {
                goto cleanup;
            }

            
            // Multiply all factors together to form a composite
            for (uint8_t p_idx = 0; p_idx < factors_number; ++p_idx) 
            {
                if (!BN_mul(p, p, prime_pool[permutation[p_idx]], ctx)) 
                {
                    goto cleanup;
                }
            }

            if (!BN_add_word(p, 1)) 
            {
                goto cleanup;
            }

            const uint32_t bitsN = (uint32_t) BN_num_bits(p);

            if (bitsN != bitsize)
            {
                continue;
            }
                
            if (rem && add) 
            {
                if (!BN_mod(remainder, p, add, ctx)) 
                {
                    goto cleanup;
                }

                if (BN_cmp(remainder, rem) != 0) 
                {
                    continue;
                }
            }

            //NIST (FIPS 186-4) suggests 40 rounds for 3072-bit numbers, so 64 rounds is even stricter
            // probability of incorrect classification is 2^(-128) which is less than 10^(-39)
            if (BN_is_prime_fasttest_ex(p, 64, ctx, 1, NULL) == 1) 
            {
                // Found a prime!
                ret = ELLIPTIC_CURVE_ALGEBRA_SUCCESS;
                break;
            }
        }
    } while (ret != ELLIPTIC_CURVE_ALGEBRA_SUCCESS && ++generation_cycles < PRIME_GENERATION_MAX_REGENERATION_CYCLES);

cleanup:
    // Error handling and cleanup
    if (-1 == ret)
    {
        ERR_clear_error();
        ret = ELLIPTIC_CURVE_ALGEBRA_UNKNOWN_ERROR;
    }

    // Clear all generated primes
    for (uint8_t p_idx = 0; p_idx < pool_size; ++p_idx) 
    {
        if (prime_pool[p_idx])
        {
            BN_clear(prime_pool[p_idx]);
        }
    }

    BN_CTX_end(ctx);

    free(prime_pool);

    return ret;
}

// Recombines values modulo p and q using Chinese Remainder Theorem (CRT)
// Uses q_inv_p to compute recombination in a fast way
elliptic_curve_algebra_status crt_recombine(BIGNUM* out, const BIGNUM* mod_p, const BIGNUM* p, const BIGNUM* mod_q, const BIGNUM* q, const BIGNUM* q_inv_p, const BIGNUM* pq, BN_CTX* ctx)
{
    long ret = -1;
    if (!out || !mod_p || !p || !mod_q || !q || !q_inv_p || !pq || !ctx)
    {
        return ELLIPTIC_CURVE_ALGEBRA_INVALID_PARAMETER;
    }
    
    // the following validations added for sanity
    // the function will not return a meaningful result if violated
    assert(is_coprime_fast(p, q, ctx) == 1);                             // Ensure that p and q are coprime (i.e., gcd(p, q) == 1)
    assert(BN_mod_mul(out, q, q_inv_p, p, ctx) && BN_is_one(out));  // Verify q * q_inv_p ≡ 1 mod p (ensuring q_inv_p is a valid modular inverse)
    assert(BN_mul(out, p, q, ctx) && 0 == BN_cmp(out, pq));         // Verify p * q == pq (ensuring pq is the product of p and q)
    assert(BN_cmp(mod_p, p) < 0);                                   // Ensure mod_p is within the range [0, p) 
    assert(BN_cmp(mod_q, q) < 0);                                   // and mod_q is within [0, q)

    
    if (!BN_mod_sub_quick(out, mod_p, mod_q, pq) ||                 // Compute (mod_p - mod_q) mod pq
        !BN_mod_mul(out, out, q_inv_p, pq, ctx) ||                  // Multiply by q_inv_p to compute (mod_p - mod_q) * q_inv_p mod pq
        !BN_mod_mul(out, out, q, pq, ctx)     ||                    // Multiply by q to compute ((mod_p - mod_q) * q_inv_p * q) mod pq
        !BN_mod_add_quick(out, out, mod_q, pq))                     // Compute final result: recombine mod_q and previously computed term
    {
        goto cleanup;
    }

    ret = ELLIPTIC_CURVE_ALGEBRA_SUCCESS;

cleanup:
    if (-1 == ret)
    {
        ERR_clear_error(); 
        ret = ELLIPTIC_CURVE_ALGEBRA_UNKNOWN_ERROR;
    }
   
    return ret;
}

// Exponentiation using CRT to recombine values from mod p and mod q
elliptic_curve_algebra_status crt_mod_exp(BIGNUM* out, const BIGNUM* base, const BIGNUM* expo, const BIGNUM* p, const BIGNUM* q, const BIGNUM* q_inv_p, const BIGNUM* pq, BN_CTX* ctx)
{
    BIGNUM *mod_p = NULL, *mod_q = NULL;
    long ret = -1;

    if (!base || !expo || !p || !q || !q_inv_p || !pq || !ctx)
    {
        return ELLIPTIC_CURVE_ALGEBRA_INVALID_PARAMETER;
    }
    
    BN_CTX_start(ctx);
    
    mod_p = BN_CTX_get(ctx);
    mod_q = BN_CTX_get(ctx);
    if (!mod_p || !mod_q)
    {
        ret = ELLIPTIC_CURVE_ALGEBRA_OUT_OF_MEMORY;
        goto cleanup;
    }

    assert(is_coprime_fast(p, q, ctx) == 1);
    assert(BN_mod_mul(mod_q, q, q_inv_p, p, ctx) &&  BN_is_one(mod_q));
    assert(BN_mul(mod_p, p, q, ctx) && 0 == BN_cmp(mod_p, pq));

    if (!BN_mod_exp(mod_p, base, expo, p, ctx) ||
        !BN_mod_exp(mod_q, base, expo, q, ctx))
    {
        goto cleanup;
    }
    
    ret = crt_recombine(out, mod_p, p, mod_q, q, q_inv_p, pq, ctx);

cleanup:
    if (-1 == ret)
    {
        ERR_clear_error(); 
        ret = ELLIPTIC_CURVE_ALGEBRA_UNKNOWN_ERROR;
    }

    BN_CTX_end(ctx);

    return ret;
}

// Checks if two numbers are coprime using GCD (The Euclidean algorithm)
// WARNING: This function doesn't run in constant time
int is_coprime_fast(const BIGNUM *in_a, const BIGNUM *in_b, BN_CTX *ctx)
{
    BIGNUM *a, *b;
    int ret = -1;

    if (!in_a || !in_b || !ctx)
    {
        return -1;
    }

    // assume 0 is illegal
    if (BN_is_zero(in_a) || BN_is_zero(in_b))
    {
        return -1;
    }

    BN_CTX_start(ctx);
    a = BN_CTX_get(ctx);
    b = BN_CTX_get(ctx);

    if (!a || !BN_copy(a, in_a))
    {
        goto cleanup;
    }

    if (!b || !BN_copy(b, in_b))
    {
        goto cleanup;
    }

    // Ensure a is larger than b
    if (BN_cmp(a, b) < 0)
    {
        BIGNUM *temp = b;
        b = a;
        a = temp;
    }

    // Calculate GCD using the Euclidean algorithm
    while (!BN_is_zero(b))
    {
        BIGNUM *t;
        if (!BN_mod(a, a, b, ctx))
        {
            goto cleanup;
        }
        t = b;
        b = a;
        a = t;
    }
    ret = BN_is_one(a); // If GCD is 1, then a and b are coprime

cleanup:
    BN_CTX_end(ctx);
    return ret;
}


static inline uint32_t keepHighestBit(uint32_t n)
{
    n |= (n >>  1);
    n |= (n >>  2);
    n |= (n >>  4);
    n |= (n >>  8);
    n |= (n >> 16);
    return n - (n >> 1);
}

uint32_t log2_floor(const uint32_t x) 
{
    //see https://en.wikipedia.org/wiki/De_Bruijn_sequence
    //and similar (but not the same) https://graphics.stanford.edu/~seander/bithacks.html#IntegerLogDeBruijn
    static const uint8_t BitPositionLookup[32] = 
    {  
         0,  1, 16,  2, 29, 17,  3, 22, 30, 20, 18, 11, 13,  4,  7, 23,
        31, 15, 28, 21, 19, 10, 12,  6, 14, 27,  9,  5, 26,  8, 25, 24,
    };

    return BitPositionLookup[(keepHighestBit(x) * 0x06EB14F9U) >> 27];
}