#include "crypto/drng/drng.h"

#define CATCH_CONFIG_MAIN  
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
        drng_free(rng);
    }
}
