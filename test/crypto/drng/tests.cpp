#include "crypto/drng/drng.h"

#include <string.h>

#include <tests/catch.hpp>

TEST_CASE("schnorr", "verify") {
    SECTION("basic") {
        drng_t *rng;
        uint8_t buff[256];
        REQUIRE(drng_new((uint8_t*)"Hello World", 11, &rng) == DRNG_SUCCESS);
        REQUIRE(drng_read_deterministic_rand(rng, buff, 1) == DRNG_SUCCESS);
        REQUIRE(drng_read_deterministic_rand(rng, buff, 31) == DRNG_SUCCESS);
        REQUIRE(drng_read_deterministic_rand(rng, buff, 32) == DRNG_SUCCESS);
        REQUIRE(drng_read_deterministic_rand(rng, buff, 1) == DRNG_SUCCESS);
        REQUIRE(drng_read_deterministic_rand(rng, buff, 32) == DRNG_SUCCESS);
        REQUIRE(drng_read_deterministic_rand(rng, buff, 256) == DRNG_SUCCESS);
        REQUIRE(drng_read_deterministic_rand(rng, buff, 33) == DRNG_SUCCESS);
        drng_free(rng);
    }

    SECTION("deterministic") {
        drng_t *rng1;
        uint8_t buff1[256];
        REQUIRE(drng_new((uint8_t*)"Hello World", 11, &rng1) == DRNG_SUCCESS);
        REQUIRE(drng_read_deterministic_rand(rng1, buff1, 1) == DRNG_SUCCESS);
        REQUIRE(drng_read_deterministic_rand(rng1, buff1 + 1, 31) == DRNG_SUCCESS);
        drng_free(rng1);
        drng_t *rng2;
        uint8_t buff2[256];
        REQUIRE(drng_new((uint8_t*)"Hello World", 11, &rng2) == DRNG_SUCCESS);
        REQUIRE(drng_read_deterministic_rand(rng2, buff2, 32) == DRNG_SUCCESS);
        drng_free(rng2);
        REQUIRE(memcmp(buff1, buff2, 32) == 0);

        REQUIRE(drng_new((uint8_t*)"Hello World", 11, &rng1) == DRNG_SUCCESS);
        REQUIRE(drng_read_deterministic_rand(rng1, buff1, 1) == DRNG_SUCCESS);
        REQUIRE(drng_read_deterministic_rand(rng1, buff1 + 1, 31) == DRNG_SUCCESS);
        REQUIRE(drng_read_deterministic_rand(rng1, buff1 + 32, 32) == DRNG_SUCCESS);
        REQUIRE(drng_read_deterministic_rand(rng1, buff1 + 64, 64) == DRNG_SUCCESS);
        REQUIRE(drng_read_deterministic_rand(rng1, buff1 + 128, 128) == DRNG_SUCCESS);
        drng_free(rng1);
        REQUIRE(drng_new((uint8_t*)"Hello World", 11, &rng2) == DRNG_SUCCESS);
        REQUIRE(drng_read_deterministic_rand(rng2, buff2, 256) == DRNG_SUCCESS);
        drng_free(rng2);
        REQUIRE(memcmp(buff1, buff2, 256) == 0);
    }

    SECTION("invalid param") {
        drng_t *rng;
        uint8_t buff[16] = "NULL";
        REQUIRE(drng_new(NULL, 0, &rng) == DRNG_INVALID_PARAMETER);
        REQUIRE(drng_new(NULL, 1, &rng) == DRNG_INVALID_PARAMETER);
        REQUIRE(drng_new(buff, 0, &rng) == DRNG_INVALID_PARAMETER);
        REQUIRE(drng_new(buff, 5, NULL) == DRNG_INVALID_PARAMETER);
        REQUIRE(drng_new(buff, 5, &rng) == DRNG_SUCCESS);

        REQUIRE(drng_read_deterministic_rand(rng, NULL, 0) == DRNG_INVALID_PARAMETER);
        REQUIRE(drng_read_deterministic_rand(rng, NULL, 1) == DRNG_INVALID_PARAMETER);
        REQUIRE(drng_read_deterministic_rand(rng, buff, 0) == DRNG_INVALID_PARAMETER);
        REQUIRE(drng_read_deterministic_rand(NULL, buff, 16) == DRNG_INVALID_PARAMETER);

        REQUIRE(drng_read_deterministic_rand(rng, (uint8_t*)rng, 16) == DRNG_INVALID_PARAMETER);
        REQUIRE(drng_read_deterministic_rand(rng, ((uint8_t*)rng) + 10, 16) == DRNG_INVALID_PARAMETER);
        REQUIRE(drng_read_deterministic_rand(rng, ((uint8_t*)rng) + 64, 16) == DRNG_INVALID_PARAMETER);
        REQUIRE(drng_read_deterministic_rand(rng, ((uint8_t*)rng) - 10, 16) == DRNG_INVALID_PARAMETER);
        REQUIRE(drng_read_deterministic_rand(rng, ((uint8_t*)rng) - 256, 65536) == DRNG_INVALID_PARAMETER);

        drng_free(rng);
    }
}

TEST_CASE("drng_seed_sensitivity", "[correctness]")
{
    SECTION("1-bit difference in seed produces completely different output")
    {
        uint8_t seed1[32];
        memset(seed1, 0xAB, sizeof(seed1));
        uint8_t seed2[32];
        memcpy(seed2, seed1, sizeof(seed1));
        seed2[0] ^= 0x01;  // Flip one bit

        drng_t *rng1, *rng2;
        REQUIRE(drng_new(seed1, sizeof(seed1), &rng1) == DRNG_SUCCESS);
        REQUIRE(drng_new(seed2, sizeof(seed2), &rng2) == DRNG_SUCCESS);

        uint8_t out1[256], out2[256];
        REQUIRE(drng_read_deterministic_rand(rng1, out1, 256) == DRNG_SUCCESS);
        REQUIRE(drng_read_deterministic_rand(rng2, out2, 256) == DRNG_SUCCESS);

        // Outputs must differ
        REQUIRE(memcmp(out1, out2, 256) != 0);

        // Count differing bytes - should be roughly half (128 out of 256)
        int diff_count = 0;
        for (int i = 0; i < 256; i++)
        {
            if (out1[i] != out2[i]) diff_count++;
        }
        // At minimum 25% of bytes should differ (conservative threshold)
        REQUIRE(diff_count >= 64);

        drng_free(rng1);
        drng_free(rng2);
    }
}
