#include "entropy_test_framework.h"
#include "crypto/elliptic_curve_algebra/elliptic_curve256_algebra.h"
#include "crypto/drng/drng.h"

#include <openssl/rand.h>
#include <openssl/bn.h>

#include <cstring>
#include <vector>
#include <set>

#include <tests/catch.hpp>

using namespace entropy_tests;

// Number of samples for statistical tests
static constexpr size_t ENTROPY_ITERATIONS = 10000;
static constexpr size_t SCALAR_SIZE = 32; // ELLIPTIC_CURVE_FIELD_SIZE
// Skip top N bytes for byte-level stats on curve scalars.
// Scalars are uniform in [0, order) — for curves where order < 2^256,
// the top bytes are biased by the order constraint, making byte-level
// chi-squared/runs/mean tests invalid on those bytes.
// Skipping 4 bytes is safe for all supported curves:
//   secp256k1 order ≈ 2^256 (negligible bias, but skipping is harmless)
//   secp256r1 order has 0x00 bytes at positions 4-7 (need skip >= 8)
//   ed25519   order ≈ 2^252 (top bytes highly constrained)
//   STARK     order ≈ 2^251 (top bytes highly constrained)
// Using 8 to cover secp256r1's unusual order structure.
static constexpr size_t SCALAR_STAT_OFFSET = 8;
static constexpr size_t SCALAR_STAT_SIZE = SCALAR_SIZE - SCALAR_STAT_OFFSET;

// ============================================================================
// Helper: Generate a random scalar using algebra->rand()
// ============================================================================
static void generate_random_scalar(elliptic_curve256_algebra_ctx_t* algebra,
                                   elliptic_curve256_scalar_t* out) {
    auto status = algebra->rand(algebra, out);
    REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
}

// ============================================================================
// Helper: Generate random bytes using OpenSSL RAND_bytes
// ============================================================================
static void generate_openssl_rand(uint8_t* buf, size_t len) {
    REQUIRE(RAND_bytes(buf, (int)len) == 1);
}

// ============================================================================
// TEST CASE: OpenSSL RAND_bytes baseline
// Validates that the testing framework itself works with a known-good RNG
// ============================================================================
TEST_CASE("entropy_baseline_openssl", "[entropy][baseline]")
{
    SECTION("RAND_bytes statistical quality") {
        auto stats = loop_test(generate_openssl_rand, 32, ENTROPY_ITERATIONS);
        REQUIRE(stats.passed_all);
        REQUIRE(stats.chi_squared_p_value > 0.01);
        REQUIRE(std::abs(stats.serial_correlation) < 0.05);
        REQUIRE(std::abs(stats.mean - 127.5) < 5.0);
    }

    SECTION("RAND_bytes frequency test") {
        std::vector<uint8_t> data(ENTROPY_ITERATIONS * 32);
        RAND_bytes(data.data(), (int)data.size());
        REQUIRE(passes_frequency_test(data.data(), data.size()));
    }

    SECTION("RAND_bytes runs test") {
        std::vector<uint8_t> data(ENTROPY_ITERATIONS * 32);
        RAND_bytes(data.data(), (int)data.size());
        REQUIRE(passes_runs_test(data.data(), data.size()));
    }

    SECTION("RAND_bytes bit bias test") {
        std::vector<uint8_t> data(ENTROPY_ITERATIONS * 32);
        RAND_bytes(data.data(), (int)data.size());
        REQUIRE(passes_bit_bias_test(data.data(), data.size(), BIT_BIAS_MAX_DEVIATION));
    }
}

// ============================================================================
// TEST CASE: secp256k1 algebra->rand() entropy
// RNG site #1 in BAM: Private key share generation
// ============================================================================
TEST_CASE("entropy_secp256k1_rand", "[entropy][secp256k1]")
{
    elliptic_curve256_algebra_ctx_t* algebra = elliptic_curve256_new_secp256k1_algebra();
    REQUIRE(algebra != nullptr);

    SECTION("statistical quality - lower bytes") {
        // Test only bytes [SCALAR_STAT_OFFSET:32] per scalar to avoid
        // order-constraint bias in the top bytes (see SCALAR_STAT_OFFSET comment).
        auto stats = loop_test(
            [&](uint8_t* buf, size_t len) {
                REQUIRE(len == SCALAR_STAT_SIZE);
                elliptic_curve256_scalar_t scalar;
                generate_random_scalar(algebra, &scalar);
                memcpy(buf, scalar + SCALAR_STAT_OFFSET, SCALAR_STAT_SIZE);
            },
            SCALAR_STAT_SIZE, ENTROPY_ITERATIONS);

        REQUIRE(stats.passed_all);
        REQUIRE(stats.chi_squared_p_value > 0.01);
    }

    SECTION("uniqueness - no duplicate scalars") {
        std::vector<std::vector<uint8_t>> scalars;
        scalars.reserve(ENTROPY_ITERATIONS);
        for (size_t i = 0; i < ENTROPY_ITERATIONS; i++) {
            elliptic_curve256_scalar_t scalar;
            generate_random_scalar(algebra, &scalar);
            scalars.emplace_back(scalar, scalar + SCALAR_SIZE);
        }
        REQUIRE(count_scalar_duplicates(scalars) == 0);
    }

    SECTION("range - all scalars less than curve order") {
        const uint8_t* order = algebra->order(algebra);
        std::vector<std::vector<uint8_t>> scalars;
        scalars.reserve(ENTROPY_ITERATIONS);
        for (size_t i = 0; i < ENTROPY_ITERATIONS; i++) {
            elliptic_curve256_scalar_t scalar;
            generate_random_scalar(algebra, &scalar);
            scalars.emplace_back(scalar, scalar + SCALAR_SIZE);
        }
        REQUIRE(all_scalars_less_than_order(scalars, order, SCALAR_SIZE));
    }

    SECTION("bit bias - lower bytes") {
        std::vector<uint8_t> all_bytes;
        all_bytes.reserve(ENTROPY_ITERATIONS * SCALAR_STAT_SIZE);
        for (size_t i = 0; i < ENTROPY_ITERATIONS; i++) {
            elliptic_curve256_scalar_t scalar;
            generate_random_scalar(algebra, &scalar);
            all_bytes.insert(all_bytes.end(), scalar + SCALAR_STAT_OFFSET, scalar + SCALAR_SIZE);
        }
        REQUIRE(passes_bit_bias_test(all_bytes.data(), all_bytes.size(), BIT_BIAS_MAX_DEVIATION));
    }

    SECTION("frequency test - lower bytes") {
        std::vector<uint8_t> all_bytes;
        all_bytes.reserve(ENTROPY_ITERATIONS * SCALAR_STAT_SIZE);
        for (size_t i = 0; i < ENTROPY_ITERATIONS; i++) {
            elliptic_curve256_scalar_t scalar;
            generate_random_scalar(algebra, &scalar);
            all_bytes.insert(all_bytes.end(), scalar + SCALAR_STAT_OFFSET, scalar + SCALAR_SIZE);
        }
        REQUIRE(passes_frequency_test(all_bytes.data(), all_bytes.size()));
    }

    elliptic_curve256_algebra_ctx_free(algebra);
}

// ============================================================================
// TEST CASE: secp256r1 algebra->rand() entropy
// ============================================================================
TEST_CASE("entropy_secp256r1_rand", "[entropy][secp256r1]")
{
    elliptic_curve256_algebra_ctx_t* algebra = elliptic_curve256_new_secp256r1_algebra();
    REQUIRE(algebra != nullptr);

    SECTION("statistical quality - lower bytes") {
        // secp256r1 order: FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
        // Bytes 4-7 are 0x00 in the order, causing heavy bias in the top 8 bytes.
        auto stats = loop_test(
            [&](uint8_t* buf, size_t len) {
                REQUIRE(len == SCALAR_STAT_SIZE);
                elliptic_curve256_scalar_t scalar;
                generate_random_scalar(algebra, &scalar);
                memcpy(buf, scalar + SCALAR_STAT_OFFSET, SCALAR_STAT_SIZE);
            },
            SCALAR_STAT_SIZE, ENTROPY_ITERATIONS);

        REQUIRE(stats.passed_all);
        REQUIRE(stats.chi_squared_p_value > 0.01);
    }

    SECTION("uniqueness") {
        std::vector<std::vector<uint8_t>> scalars;
        scalars.reserve(ENTROPY_ITERATIONS);
        for (size_t i = 0; i < ENTROPY_ITERATIONS; i++) {
            elliptic_curve256_scalar_t scalar;
            generate_random_scalar(algebra, &scalar);
            scalars.emplace_back(scalar, scalar + SCALAR_SIZE);
        }
        REQUIRE(count_scalar_duplicates(scalars) == 0);
    }

    SECTION("range") {
        const uint8_t* order = algebra->order(algebra);
        std::vector<std::vector<uint8_t>> scalars;
        scalars.reserve(ENTROPY_ITERATIONS);
        for (size_t i = 0; i < ENTROPY_ITERATIONS; i++) {
            elliptic_curve256_scalar_t scalar;
            generate_random_scalar(algebra, &scalar);
            scalars.emplace_back(scalar, scalar + SCALAR_SIZE);
        }
        REQUIRE(all_scalars_less_than_order(scalars, order, SCALAR_SIZE));
    }

    elliptic_curve256_algebra_ctx_free(algebra);
}

// ============================================================================
// TEST CASE: ed25519 algebra->rand() entropy
// ============================================================================
TEST_CASE("entropy_ed25519_rand", "[entropy][ed25519]")
{
    elliptic_curve256_algebra_ctx_t* algebra = elliptic_curve256_new_ed25519_algebra();
    REQUIRE(algebra != nullptr);

    SECTION("statistical quality - lower bytes") {
        // ed25519 order: 1000000000000000000000000000000014DEF9DEA2F79CD65812631A5CF5D3ED
        // Order ≈ 2^252, so bytes 0-3 are heavily constrained (byte0 = 0x00..0x10).
        auto stats = loop_test(
            [&](uint8_t* buf, size_t len) {
                REQUIRE(len == SCALAR_STAT_SIZE);
                elliptic_curve256_scalar_t scalar;
                generate_random_scalar(algebra, &scalar);
                memcpy(buf, scalar + SCALAR_STAT_OFFSET, SCALAR_STAT_SIZE);
            },
            SCALAR_STAT_SIZE, ENTROPY_ITERATIONS);

        REQUIRE(stats.passed_all);
        REQUIRE(stats.chi_squared_p_value > 0.01);
    }

    SECTION("uniqueness") {
        std::vector<std::vector<uint8_t>> scalars;
        scalars.reserve(ENTROPY_ITERATIONS);
        for (size_t i = 0; i < ENTROPY_ITERATIONS; i++) {
            elliptic_curve256_scalar_t scalar;
            generate_random_scalar(algebra, &scalar);
            scalars.emplace_back(scalar, scalar + SCALAR_SIZE);
        }
        REQUIRE(count_scalar_duplicates(scalars) == 0);
    }

    SECTION("range") {
        const uint8_t* order = algebra->order(algebra);
        std::vector<std::vector<uint8_t>> scalars;
        scalars.reserve(ENTROPY_ITERATIONS);
        for (size_t i = 0; i < ENTROPY_ITERATIONS; i++) {
            elliptic_curve256_scalar_t scalar;
            generate_random_scalar(algebra, &scalar);
            scalars.emplace_back(scalar, scalar + SCALAR_SIZE);
        }
        REQUIRE(all_scalars_less_than_order(scalars, order, SCALAR_SIZE));
    }

    elliptic_curve256_algebra_ctx_free(algebra);
}

// ============================================================================
// TEST CASE: STARK algebra->rand() entropy
// RNG site #2 in BAM: Ephemeral key k (ECDSA nonce)
// ============================================================================
TEST_CASE("entropy_stark_rand", "[entropy][stark]")
{
    elliptic_curve256_algebra_ctx_t* algebra = elliptic_curve256_new_stark_algebra();
    REQUIRE(algebra != nullptr);

    SECTION("statistical quality - lower bytes") {
        // STARK order ≈ 2^251, so bytes 0-3 are heavily constrained.
        auto stats = loop_test(
            [&](uint8_t* buf, size_t len) {
                REQUIRE(len == SCALAR_STAT_SIZE);
                elliptic_curve256_scalar_t scalar;
                generate_random_scalar(algebra, &scalar);
                memcpy(buf, scalar + SCALAR_STAT_OFFSET, SCALAR_STAT_SIZE);
            },
            SCALAR_STAT_SIZE, ENTROPY_ITERATIONS);

        REQUIRE(stats.passed_all);
        REQUIRE(stats.chi_squared_p_value > 0.01);
    }

    SECTION("uniqueness") {
        std::vector<std::vector<uint8_t>> scalars;
        scalars.reserve(ENTROPY_ITERATIONS);
        for (size_t i = 0; i < ENTROPY_ITERATIONS; i++) {
            elliptic_curve256_scalar_t scalar;
            generate_random_scalar(algebra, &scalar);
            scalars.emplace_back(scalar, scalar + SCALAR_SIZE);
        }
        REQUIRE(count_scalar_duplicates(scalars) == 0);
    }

    SECTION("range") {
        const uint8_t* order = algebra->order(algebra);
        std::vector<std::vector<uint8_t>> scalars;
        scalars.reserve(ENTROPY_ITERATIONS);
        for (size_t i = 0; i < ENTROPY_ITERATIONS; i++) {
            elliptic_curve256_scalar_t scalar;
            generate_random_scalar(algebra, &scalar);
            scalars.emplace_back(scalar, scalar + SCALAR_SIZE);
        }
        REQUIRE(all_scalars_less_than_order(scalars, order, SCALAR_SIZE));
    }

    elliptic_curve256_algebra_ctx_free(algebra);
}

// ============================================================================
// TEST CASE: BN_rand entropy (used for Paillier blinding and ZKP parameters)
// RNG sites #3,6,7,8 in BAM: lambda0, alpha, beta, lambda_p
// ============================================================================
TEST_CASE("entropy_bn_rand", "[entropy][bn_rand]")
{
    SECTION("BN_rand 256-bit statistical quality") {
        auto stats = loop_test(
            [](uint8_t* buf, size_t len) {
                REQUIRE(len == 32);
                BIGNUM* bn = BN_new();
                REQUIRE(bn != nullptr);
                REQUIRE(BN_rand(bn, 256, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY) == 1);
                // Pad to 32 bytes big-endian
                memset(buf, 0, 32);
                int num_bytes = BN_num_bytes(bn);
                if (num_bytes > 0 && num_bytes <= 32) {
                    BN_bn2bin(bn, buf + (32 - num_bytes));
                }
                BN_free(bn);
            },
            32, ENTROPY_ITERATIONS);

        REQUIRE(stats.passed_all);
        REQUIRE(stats.chi_squared_p_value > 0.01);
    }

    SECTION("BN_rand uniqueness") {
        std::vector<std::vector<uint8_t>> values;
        values.reserve(ENTROPY_ITERATIONS);
        for (size_t i = 0; i < ENTROPY_ITERATIONS; i++) {
            BIGNUM* bn = BN_new();
            REQUIRE(bn != nullptr);
            REQUIRE(BN_rand(bn, 256, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY) == 1);
            std::vector<uint8_t> val(32, 0);
            int num_bytes = BN_num_bytes(bn);
            if (num_bytes > 0 && num_bytes <= 32) {
                BN_bn2bin(bn, val.data() + (32 - num_bytes));
            }
            values.push_back(std::move(val));
            BN_free(bn);
        }
        REQUIRE(count_scalar_duplicates(values) == 0);
    }

    SECTION("BN_rand 2048-bit statistical quality") {
        // Tests larger BN_rand used for Paillier encryption blinding
        auto stats = loop_test(
            [](uint8_t* buf, size_t len) {
                REQUIRE(len == 256); // 2048 bits
                BIGNUM* bn = BN_new();
                REQUIRE(bn != nullptr);
                REQUIRE(BN_rand(bn, 2048, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY) == 1);
                memset(buf, 0, 256);
                int num_bytes = BN_num_bytes(bn);
                if (num_bytes > 0 && num_bytes <= 256) {
                    BN_bn2bin(bn, buf + (256 - num_bytes));
                }
                BN_free(bn);
            },
            256, 1000); // Fewer iterations for larger values

        REQUIRE(stats.passed_all);
        REQUIRE(stats.chi_squared_p_value > 0.01);
    }
}

// ============================================================================
// TEST CASE: BN_rand_range entropy (used internally by algebra->rand())
// ============================================================================
TEST_CASE("entropy_bn_rand_range", "[entropy][bn_rand_range]")
{
    SECTION("BN_rand_range statistical quality - lower bytes") {
        // Simulate what GFp_curve_algebra_rand does: BN_rand_range(order)
        // Only test lower bytes to avoid order-constraint bias in top bytes.
        BIGNUM* order = BN_new();
        REQUIRE(order != nullptr);
        // secp256k1 order
        REQUIRE(BN_hex2bn(&order,
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141") > 0);

        auto stats = loop_test(
            [&](uint8_t* buf, size_t len) {
                REQUIRE(len == SCALAR_STAT_SIZE);
                uint8_t full_scalar[32];
                BIGNUM* r = BN_new();
                REQUIRE(r != nullptr);
                REQUIRE(BN_rand_range(r, order) == 1);
                memset(full_scalar, 0, 32);
                int num_bytes = BN_num_bytes(r);
                if (num_bytes > 0 && num_bytes <= 32) {
                    BN_bn2bin(r, full_scalar + (32 - num_bytes));
                }
                memcpy(buf, full_scalar + SCALAR_STAT_OFFSET, SCALAR_STAT_SIZE);
                BN_free(r);
            },
            SCALAR_STAT_SIZE, ENTROPY_ITERATIONS);

        REQUIRE(stats.passed_all);
        BN_free(order);
    }
}

// ============================================================================
// TEST CASE: DRNG (Deterministic RNG) - should be deterministic, NOT random
// This is a sanity check that DRNG is NOT used for entropy-critical operations
// ============================================================================
TEST_CASE("entropy_drng_determinism", "[entropy][drng]")
{
    SECTION("DRNG is deterministic - same seed produces same output") {
        drng_t* rng1;
        drng_t* rng2;
        uint8_t buf1[256], buf2[256];

        REQUIRE(drng_new((uint8_t*)"test seed", 9, &rng1) == DRNG_SUCCESS);
        REQUIRE(drng_new((uint8_t*)"test seed", 9, &rng2) == DRNG_SUCCESS);

        REQUIRE(drng_read_deterministic_rand(rng1, buf1, 256) == DRNG_SUCCESS);
        REQUIRE(drng_read_deterministic_rand(rng2, buf2, 256) == DRNG_SUCCESS);

        REQUIRE(memcmp(buf1, buf2, 256) == 0);

        drng_free(rng1);
        drng_free(rng2);
    }

    SECTION("DRNG with different seeds produces different output") {
        drng_t* rng1;
        drng_t* rng2;
        uint8_t buf1[256], buf2[256];

        REQUIRE(drng_new((uint8_t*)"seed A", 6, &rng1) == DRNG_SUCCESS);
        REQUIRE(drng_new((uint8_t*)"seed B", 6, &rng2) == DRNG_SUCCESS);

        REQUIRE(drng_read_deterministic_rand(rng1, buf1, 256) == DRNG_SUCCESS);
        REQUIRE(drng_read_deterministic_rand(rng2, buf2, 256) == DRNG_SUCCESS);

        REQUIRE(memcmp(buf1, buf2, 256) != 0);

        drng_free(rng1);
        drng_free(rng2);
    }
}

// ============================================================================
// TEST CASE: Cross-curve scalar independence
// Verify that scalars from different curves don't correlate
// ============================================================================
TEST_CASE("entropy_cross_curve_independence", "[entropy][cross_curve]")
{
    elliptic_curve256_algebra_ctx_t* secp256k1 = elliptic_curve256_new_secp256k1_algebra();
    elliptic_curve256_algebra_ctx_t* secp256r1 = elliptic_curve256_new_secp256r1_algebra();
    REQUIRE(secp256k1 != nullptr);
    REQUIRE(secp256r1 != nullptr);

    SECTION("interleaved generation maintains quality") {
        // Generate alternating scalars from two different curves
        // and verify each stream maintains statistical quality.
        // Use only lower bytes to avoid order-constraint bias.
        std::vector<uint8_t> k1_bytes, r1_bytes;
        k1_bytes.reserve(5000 * SCALAR_STAT_SIZE);
        r1_bytes.reserve(5000 * SCALAR_STAT_SIZE);

        for (size_t i = 0; i < 5000; i++) {
            elliptic_curve256_scalar_t s1, s2;
            generate_random_scalar(secp256k1, &s1);
            generate_random_scalar(secp256r1, &s2);
            k1_bytes.insert(k1_bytes.end(), s1 + SCALAR_STAT_OFFSET, s1 + SCALAR_SIZE);
            r1_bytes.insert(r1_bytes.end(), s2 + SCALAR_STAT_OFFSET, s2 + SCALAR_SIZE);
        }

        REQUIRE(passes_chi_squared(k1_bytes.data(), k1_bytes.size(), CHI_SQUARED_ALPHA));
        REQUIRE(passes_chi_squared(r1_bytes.data(), r1_bytes.size(), CHI_SQUARED_ALPHA));
    }

    elliptic_curve256_algebra_ctx_free(secp256k1);
    elliptic_curve256_algebra_ctx_free(secp256r1);
}
