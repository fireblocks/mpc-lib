#include "crypto/algebra_utils/algebra_utils.h"
#include "crypto/elliptic_curve_algebra/elliptic_curve_algebra_status.h"

#include <string.h>
#include <tests/catch.hpp>

#include <openssl/bn.h>

// Measure time taken by crt_mod_exp
static long measure_execution_time_ns(
    BIGNUM* out, const BIGNUM* base, const BIGNUM* expo,
    const BIGNUM* p, const BIGNUM* q, const BIGNUM* q_inv_p, const BIGNUM* pq, BN_CTX* ctx)
{
    struct timespec start, end;
    long duration_ns;

    clock_gettime(CLOCK_MONOTONIC, &start);
    crt_mod_exp(out, base, expo, p, q, q_inv_p, pq, ctx);
    clock_gettime(CLOCK_MONOTONIC, &end);

    duration_ns = (end.tv_sec - start.tv_sec) * 1000000000L + (end.tv_nsec - start.tv_nsec);
    return duration_ns;
}


TEST_CASE("is_coprime_fast")
{
    BN_CTX* ctx = BN_CTX_new();
    REQUIRE(NULL != ctx);
    BN_CTX_start(ctx);
    BIGNUM *p = BN_CTX_get(ctx);
    REQUIRE(NULL != p);
    BIGNUM *q = BN_CTX_get(ctx);
    REQUIRE(NULL != q);
    BIGNUM* tmp = BN_CTX_get(ctx);
    REQUIRE(NULL != tmp);
    
    SECTION("verify negative") 
    {
       REQUIRE(BN_generate_prime_ex(p, 1024, 0, NULL, NULL, NULL));
        do 
        {
            REQUIRE(BN_generate_prime_ex(q, 1024, 0, NULL, NULL, NULL));
            REQUIRE(BN_gcd(tmp, q, p, ctx));
        } while(!BN_is_one(tmp));

        REQUIRE(is_coprime_fast(p, q, ctx) == 1);
    }

    SECTION("verify positive") 
    {
        BIGNUM* val = BN_CTX_get(ctx);
        REQUIRE(NULL != val);
        REQUIRE(BN_set_word(val, 7));

        REQUIRE(BN_generate_prime_ex(p, 1024, 0, NULL, NULL, NULL));
        REQUIRE(BN_mul(q, p, val, ctx));
        REQUIRE(is_coprime_fast(p, q, ctx) == 0);
    }

    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
} 

TEST_CASE("tough_prime_generation") 
{
    BN_CTX* ctx = NULL;
    BIGNUM *p = NULL, *seven = NULL, *sixteen = NULL;
    ctx = BN_CTX_new();
    REQUIRE(ctx);
    BN_CTX_start(ctx);
    seven = BN_CTX_get(ctx);
    sixteen = BN_CTX_get(ctx);
    p = BN_CTX_get(ctx);
    REQUIRE(p);
    REQUIRE(BN_set_word(seven, 7));
    REQUIRE(BN_set_word(sixteen, 16));


    SECTION("1024b prime, 256b factors, no constraints") 
    {
        for (int i = 0; i < 5; ++ i)
        {
            REQUIRE(generate_tough_prime(p, 1024, 256, NULL, NULL, ctx) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
            REQUIRE(BN_is_prime_fasttest_ex(p, 64, ctx, 1, NULL) == 1);
            REQUIRE(BN_mod_word(p, 4) == 3);
        }
    }

    SECTION("1536b prime, 256b factors, no constraints") 
    {
        for (int i = 0; i < 5; ++ i)
        {
            REQUIRE(generate_tough_prime(p, 1536, 256, NULL, NULL, ctx) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
            REQUIRE(BN_is_prime_fasttest_ex(p, 64, ctx, 1, NULL) == 1);
            REQUIRE(BN_mod_word(p, 4) == 3);
        }
    }

    SECTION("1024b prime, 256b factors, 7%16") 
    {
        for (int i = 0; i < 5; ++ i)
        {
            REQUIRE(generate_tough_prime(p, 1024, 256, sixteen, seven, ctx) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
            REQUIRE(BN_is_prime_fasttest_ex(p, 64, ctx, 1, NULL) == 1);
            REQUIRE(BN_mod_word(p, 16) == 7);
        }
    }

    SECTION("1536b prime, 256b factors, 7%16") 
    {
        for (int i = 0; i < 5; ++ i)
        {
            REQUIRE(generate_tough_prime(p, 1536, 256, sixteen, seven, ctx) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
            REQUIRE(BN_is_prime_fasttest_ex(p, 64, ctx, 1, NULL) == 1);
            REQUIRE(BN_mod_word(p, 16) == 7);
        }
    }

    SECTION("384b prime, 192b factors, 7%16") 
    {
        // regular prime generation fallback test
        for (int i = 0; i < 5; ++ i)
        {
            REQUIRE(generate_tough_prime(p, 384, 192, sixteen, seven, ctx) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
            REQUIRE(BN_is_prime_fasttest_ex(p, 64, ctx, 1, NULL) == 1);
            REQUIRE(BN_mod_word(p, 16) == 7);
        }
    }
    
    SECTION("384b prime, 192b factors") 
    {
        // regular prime generation fallback test
        for (int i = 0; i < 5; ++ i)
        {
            REQUIRE(generate_tough_prime(p, 384, 192, NULL, NULL, ctx) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
            REQUIRE(BN_is_prime_fasttest_ex(p, 64, ctx, 1, NULL) == 1);
            REQUIRE(BN_mod_word(p, 4) == 3);
        }
    }
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
}

TEST_CASE("CRT validation", "[CRT]") 
{
    BN_CTX* ctx = NULL;
    BIGNUM *p = NULL, *q = NULL, *pq = NULL, *qinvp = NULL, *A = NULL, *B = NULL, *C = NULL, *tmp = NULL;
    ctx = BN_CTX_new();
    REQUIRE(ctx);
    BN_CTX_start(ctx);
    p = BN_CTX_get(ctx);
    q = BN_CTX_get(ctx);
    pq = BN_CTX_get(ctx);
    qinvp = BN_CTX_get(ctx);
    A = BN_CTX_get(ctx);
    B = BN_CTX_get(ctx);
    C = BN_CTX_get(ctx);
    tmp = BN_CTX_get(ctx);
    REQUIRE(tmp);

    SECTION("primes factors") 
    {
        REQUIRE(BN_generate_prime_ex(p, 1024, 0, NULL, NULL, NULL));
        do 
        {
            REQUIRE(BN_generate_prime_ex(q, 1024, 0, NULL, NULL, NULL));
            REQUIRE(BN_gcd(tmp, q, p, ctx));
        } while(!BN_is_one(tmp));

        REQUIRE(BN_mul(pq, p, q, ctx));
        REQUIRE(BN_mod_inverse(qinvp, q, p, ctx));
        for (uint32_t i = 0; i < 10; ++i) 
        {
            REQUIRE(BN_rand_range(C, pq));
            REQUIRE(BN_mod(A, C, p, ctx));
            REQUIRE(BN_mod(B, C, q, ctx));
            REQUIRE(crt_recombine(tmp, A, p, B, q, qinvp, pq, ctx) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
            REQUIRE(BN_cmp(tmp, C) == 0);
            REQUIRE(BN_set_word(tmp, 0)); // reinitialize value
        }

    }

    SECTION("Paillier factors") 
    {
        REQUIRE(BN_generate_prime_ex(p, 1024, 0, NULL, NULL, NULL));
        do 
        {
            REQUIRE(BN_generate_prime_ex(q, 1024, 0, NULL, NULL, NULL));
            REQUIRE(BN_gcd(tmp, q, p, ctx));
        } while(!BN_is_one(tmp));

        REQUIRE(BN_sqr(p, p, ctx));
        REQUIRE(BN_sqr(q, q, ctx));
        REQUIRE(BN_mul(pq, p, q, ctx));
        REQUIRE(BN_mod_inverse(qinvp, q, p, ctx));

        for (uint32_t i = 0; i < 10; ++i) 
        {
            REQUIRE(BN_rand_range(C, pq));
            REQUIRE(BN_mod(A, C, p, ctx));
            REQUIRE(BN_mod(B, C, q, ctx));
            REQUIRE(crt_recombine(tmp, A, p, B, q, qinvp, pq, ctx) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
            REQUIRE(BN_cmp(tmp, C) == 0);
            REQUIRE(BN_set_word(tmp, 0)); // reinitialize value
        }
    }

    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
}

//disabled by default to prevent sporadic failures due to context switches
//can be run using ./test "[CRT]"
TEST_CASE("CRT Constant-Time Validation", "[CRT][.disabled]") 
{
    BN_CTX* ctx = BN_CTX_new();
    REQUIRE(ctx);
    BN_CTX_start(ctx);
    BIGNUM *out = BN_CTX_get(ctx);
    BIGNUM *base = BN_CTX_get(ctx);
    BIGNUM *expo = BN_CTX_get(ctx);
    BIGNUM *p = BN_CTX_get(ctx);
    BIGNUM *q = BN_CTX_get(ctx);
    BIGNUM *pq = BN_CTX_get(ctx);
    BIGNUM *qinvp = BN_CTX_get(ctx);

    REQUIRE((out && base && expo && p && q && pq && qinvp));

    // Generate primes for testing
    REQUIRE(BN_generate_prime_ex(p, 1024, 0, NULL, NULL, NULL));
    REQUIRE(BN_generate_prime_ex(q, 1024, 0, NULL, NULL, NULL));
    // Mark p and q as constant-time
    BN_set_flags(p, BN_FLG_CONSTTIME);
    BN_set_flags(q, BN_FLG_CONSTTIME);

    REQUIRE(BN_mul(pq, p, q, ctx));
    REQUIRE(BN_mod_inverse(qinvp, q, p, ctx));
    BN_set_flags(qinvp, BN_FLG_CONSTTIME);

    long min_time = LONG_MAX;
    long max_time = LONG_MIN;

    // Measure execution time for 10 runs with different inputs
    for (int i = 0; i < 10; ++i) 
    {
        REQUIRE(BN_rand(base, 1024, 0, 0));
        REQUIRE(BN_rand(expo, 1024, 0, 0));

        long exec_time = measure_execution_time_ns(out, base, expo, p, q, qinvp, pq, ctx);
        min_time = std::min(min_time, exec_time);
        max_time = std::max(max_time, exec_time);
    }

    const long MAX_ALLOWED_DIFF_NS = 100000; // Adjust based on your system's noise tolerance
    REQUIRE((max_time - min_time) <= MAX_ALLOWED_DIFF_NS);

    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
}

TEST_CASE("log2_floor function test cases") {

    SECTION("Zero value") 
    {
        REQUIRE(log2_floor(0) == 0);  // By convention, returning 0 for log2(0)
    }

    SECTION("Powers of two") 
    {
        REQUIRE(log2_floor(1) == 0);   // 2^0 = 1
        REQUIRE(log2_floor(2) == 1);   // 2^1 = 2
        REQUIRE(log2_floor(4) == 2);   // 2^2 = 4
        REQUIRE(log2_floor(8) == 3);   // 2^3 = 8
        REQUIRE(log2_floor(16) == 4);  // 2^4 = 16
        REQUIRE(log2_floor(32) == 5);  // 2^5 = 32
        REQUIRE(log2_floor(64) == 6);  // 2^6 = 64
        REQUIRE(log2_floor(128) == 7); // 2^7 = 128
        REQUIRE(log2_floor(256) == 8); // 2^8 = 256
        REQUIRE(log2_floor(512) == 9); // 2^9 = 512
        REQUIRE(log2_floor(1024) == 10); // 2^10 = 1024
        REQUIRE(log2_floor(2048) == 11); // 2^11 = 2048
        REQUIRE(log2_floor(4096) == 12); // 2^12 = 4096
        REQUIRE(log2_floor(8192) == 13); // 2^13 = 8192
        REQUIRE(log2_floor(16384) == 14); // 2^14 = 16384
        REQUIRE(log2_floor(32768) == 15); // 2^15 = 32768
        REQUIRE(log2_floor(65536) == 16); // 2^16 = 65536
        REQUIRE(log2_floor(131072) == 17); // 2^17 = 131072
        REQUIRE(log2_floor(262144) == 18); // 2^18 = 262144
        REQUIRE(log2_floor(524288) == 19); // 2^19 = 524288
        REQUIRE(log2_floor(1048576) == 20); // 2^20 = 1048576
        REQUIRE(log2_floor(2097152) == 21); // 2^21 = 2097152
        REQUIRE(log2_floor(4194304) == 22); // 2^22 = 4194304
        REQUIRE(log2_floor(8388608) == 23); // 2^23 = 8388608
        REQUIRE(log2_floor(16777216) == 24); // 2^24 = 16777216
        REQUIRE(log2_floor(33554432) == 25); // 2^25 = 33554432
        REQUIRE(log2_floor(67108864) == 26); // 2^26 = 67108864
        REQUIRE(log2_floor(134217728) == 27); // 2^27 = 134217728
        REQUIRE(log2_floor(268435456) == 28); // 2^28 = 268435456
        REQUIRE(log2_floor(536870912) == 29); // 2^29 = 536870912
        REQUIRE(log2_floor(1073741824) == 30); // 2^30 = 1073741824
        REQUIRE(log2_floor(2147483648) == 31); // 2^31 = 2147483648
    }

    SECTION("Non-powers of two") 
    {
        REQUIRE(log2_floor(3) == 1);   // 2^1 <= 3 < 2^2
        REQUIRE(log2_floor(5) == 2);   // 2^2 <= 5 < 2^3
        REQUIRE(log2_floor(6) == 2);   // 2^2 <= 6 < 2^3
        REQUIRE(log2_floor(9) == 3);   // 2^3 <= 9 < 2^4
        REQUIRE(log2_floor(15) == 3);  // 2^3 <= 15 < 2^4
        REQUIRE(log2_floor(17) == 4);  // 2^4 <= 17 < 2^5
        REQUIRE(log2_floor(33) == 5);  // 2^5 <= 33 < 2^6
        REQUIRE(log2_floor(100) == 6); // 2^6 <= 100 < 2^7
        REQUIRE(log2_floor(999) == 9); // 2^9 <= 999 < 2^10
        REQUIRE(log2_floor(12345) == 13); // 2^13 <= 12345 < 2^14
        REQUIRE(log2_floor(65535) == 15); // 2^15 <= 65535 < 2^16
        REQUIRE(log2_floor(999999) == 19); // 2^19 <= 999999 < 2^20
    }

    SECTION("Maximum 32-bit value") 
    {
        REQUIRE(log2_floor(0xFFFFFFFF) == 31); // 32-bit maximum unsigned integer
    }
}

#ifdef CATCH_CONFIG_ENABLE_BENCHMARKING

TEST_CASE("tough_prime_generation benchmark", "benchmark") 
{
    BN_CTX* ctx = NULL;
    BIGNUM *p = NULL;
    ctx = BN_CTX_new();
    REQUIRE(ctx);
    BN_CTX_start(ctx);
    p = BN_CTX_get(ctx);
    REQUIRE(p);

    BENCHMARK("1024b tough prime, 256b factors") 
    {
        REQUIRE(generate_tough_prime(p, 1024, 256, NULL, NULL, ctx) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
    };

    BENCHMARK("1536b tough prime, 256b factors") 
    {
        REQUIRE(generate_tough_prime(p, 1536, 256, NULL, NULL, ctx) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
    };

    BENCHMARK("2048b tough prime, 256b factors") 
    {
        REQUIRE(generate_tough_prime(p, 2048, 256, NULL, NULL, ctx) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
    };

    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
}

TEST_CASE("OpenSSL prime generation benchmark", "benchmark") 
{
    BN_CTX* ctx = NULL;
    BIGNUM *p = NULL;
    ctx = BN_CTX_new();
    REQUIRE(ctx);
    BN_CTX_start(ctx);
    p = BN_CTX_get(ctx);
    REQUIRE(p);

    BENCHMARK("1024b regular prime") 
    {
        REQUIRE(BN_generate_prime_ex(p, 1024, 0, NULL, NULL, NULL));
    };

    BENCHMARK("1536b regular prime") 
    {
        REQUIRE(BN_generate_prime_ex(p, 1536, 0, NULL, NULL, NULL));
    };

    BENCHMARK("2048b regular prime") 
    {
        REQUIRE(BN_generate_prime_ex(p, 2048, 0, NULL, NULL, NULL));
    };

    BENCHMARK("1024b strong prime") 
    {
        REQUIRE(BN_generate_prime_ex(p, 1024, 1, NULL, NULL, NULL));
    };

    BENCHMARK("1536b strong prime") 
    {
        REQUIRE(BN_generate_prime_ex(p, 1536, 1, NULL, NULL, NULL));
    };

    BENCHMARK("2048b strong prime") 
    {
        REQUIRE(BN_generate_prime_ex(p, 2048, 1, NULL, NULL, NULL));
    };

    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
}

#endif // CATCH_CONFIG_ENABLE_BENCHMARKING