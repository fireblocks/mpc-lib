#include "crypto/GFp_curve_algebra/GFp_curve_algebra.h"

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/objects.h>
#include <openssl/rand.h>

#define CATCH_CONFIG_MAIN  
#include <tests/catch.hpp>

TEST_CASE( "verify", "zkp") {
    GFp_curve_algebra_ctx_t* ctx = secp256k1_algebra_ctx_new();

    SECTION("verify") {
        REQUIRE(ctx);
        elliptic_curve256_point_t proof;
        uint32_t val = 7;
        elliptic_curve_algebra_status status = GFp_curve_algebra_generator_mul_data(ctx, (uint8_t*)&val, sizeof(val), &proof);
        REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        uint8_t res = 0;
        status = GFp_curve_algebra_verify(ctx, (uint8_t*)&val, sizeof(val), &proof, &res);
        REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE(res);
    }

    SECTION("zero") {
        REQUIRE(ctx);
        elliptic_curve256_point_t proof;
        uint32_t val = 0;
        elliptic_curve_algebra_status status = GFp_curve_algebra_generator_mul_data(ctx, (uint8_t*)&val, sizeof(val), &proof);
        REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        uint8_t res = 0;
        status = GFp_curve_algebra_verify(ctx, (uint8_t*)&val, sizeof(val), &proof, &res);
        REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE(res);
    }

    SECTION("invalid order") {
        REQUIRE(ctx);
        elliptic_curve256_point_t proof;
        uint8_t val[32];
        memset(val, 0xff, sizeof(val));
        elliptic_curve_algebra_status status = GFp_curve_algebra_generator_mul_data(ctx, val, sizeof(val), &proof);
        REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        uint8_t res = 0;
        status = GFp_curve_algebra_verify(ctx, (uint8_t*)&val, sizeof(val), &proof, &res);
        REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE(res);
    }

    SECTION("wrong data") {
        REQUIRE(ctx);
        elliptic_curve256_point_t proof;
        uint32_t val = 7;
        elliptic_curve_algebra_status status = GFp_curve_algebra_generator_mul_data(ctx, (uint8_t*)&val, sizeof(val), &proof);
        REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        uint8_t res = 0;
        val = 8;
        status = GFp_curve_algebra_verify(ctx, (uint8_t*)&val, sizeof(val), &proof, &res);
        REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE_FALSE(res);
        val = 7;
        ++proof[3];
        status = GFp_curve_algebra_verify(ctx, (uint8_t*)&val, sizeof(val), &proof, &res);
        REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE_FALSE(res);
    }

    GFp_curve_algebra_ctx_free(ctx);
}

TEST_CASE( "verify_sum", "zkp") {
    GFp_curve_algebra_ctx_t* ctx = secp256k1_algebra_ctx_new();

    SECTION("verify_sum") {
        REQUIRE(ctx);
        elliptic_curve256_point_t proof;
        uint32_t val = 7;
        elliptic_curve_algebra_status status = GFp_curve_algebra_generator_mul_data(ctx, (uint8_t*)&val, sizeof(val), &proof);
        REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        
        elliptic_curve256_point_t proofs[3];
        val = 1;
        status = GFp_curve_algebra_generator_mul_data(ctx, (uint8_t*)&val, sizeof(val), proofs);
        REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        val = 2;
        status = GFp_curve_algebra_generator_mul_data(ctx, (uint8_t*)&val, sizeof(val), proofs + 1);
        REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        val = 4;
        status = GFp_curve_algebra_generator_mul_data(ctx, (uint8_t*)&val, sizeof(val), proofs + 2);
        REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);

        uint8_t res = 0;
        status = GFp_curve_algebra_verify_sum(ctx, &proof, proofs, 3, &res);
        REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE(res);
    }

    SECTION("wrong data") {
        REQUIRE(ctx);
        elliptic_curve256_point_t proof;
        uint32_t val = 7;
        elliptic_curve_algebra_status status = GFp_curve_algebra_generator_mul_data(ctx, (uint8_t*)&val, sizeof(val), &proof);
        REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        
        elliptic_curve256_point_t proofs[3];
        val = 1;
        status = GFp_curve_algebra_generator_mul_data(ctx, (uint8_t*)&val, sizeof(val), proofs);
        REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        val = 2;
        status = GFp_curve_algebra_generator_mul_data(ctx, (uint8_t*)&val, sizeof(val), proofs + 1);
        REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        val = 4;
        status = GFp_curve_algebra_generator_mul_data(ctx, (uint8_t*)&val, sizeof(val), proofs + 2);
        REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);

        uint8_t res = 0;
        status = GFp_curve_algebra_verify_sum(ctx, &proof, proofs, 2, &res);
        REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE_FALSE(res);

        ++proof[4];
        status = GFp_curve_algebra_verify_sum(ctx, &proof, proofs, 3, &res);
        REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE_FALSE(res);

        --proof[4];
        ++proofs[0][5];
        status = GFp_curve_algebra_verify_sum(ctx, &proof, proofs, 3, &res);
        REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE_FALSE(res);
    }

    GFp_curve_algebra_ctx_free(ctx);
}

TEST_CASE( "verify_mul_sum", "zkp") {
    GFp_curve_algebra_ctx_t* ctx = secp256k1_algebra_ctx_new();

    SECTION("verify_mul_sum") {
        REQUIRE(ctx);
        elliptic_curve256_point_t proof;
        uint32_t val = 2*3 + 4*5 + 6*7;
        elliptic_curve_algebra_status status = GFp_curve_algebra_generator_mul_data(ctx, (uint8_t*)&val, sizeof(val), &proof);
        REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        
        elliptic_curve256_point_t proofs[3];
        elliptic_curve256_scalar_t coeff[3] = {0};
        val = 2;
        coeff[0][31] = 3;
        status = GFp_curve_algebra_generator_mul_data(ctx, (uint8_t*)&val, sizeof(val), proofs);
        REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        val = 4;
        coeff[1][31] = 5;
        status = GFp_curve_algebra_generator_mul_data(ctx, (uint8_t*)&val, sizeof(val), proofs + 1);
        REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        val = 6;
        coeff[2][31] = 7;
        status = GFp_curve_algebra_generator_mul_data(ctx, (uint8_t*)&val, sizeof(val), proofs + 2);
        REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);

        uint8_t res = 0;
        status = GFp_curve_algebra_verify_linear_combination(ctx, &proof, proofs, coeff, 3, &res);
        REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE(res);
    }

    SECTION("wrong data") {
        REQUIRE(ctx);
        elliptic_curve256_point_t proof;
        uint32_t val = 2*3 + 4*5 + 6*7;
        elliptic_curve_algebra_status status = GFp_curve_algebra_generator_mul_data(ctx, (uint8_t*)&val, sizeof(val), &proof);
        REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        
        elliptic_curve256_point_t proofs[3];
        elliptic_curve256_scalar_t coeff[3] = {0};
        val = 2;
        coeff[0][31] = 3;
        status = GFp_curve_algebra_generator_mul_data(ctx, (uint8_t*)&val, sizeof(val), proofs);
        REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        val = 4;
        coeff[1][31] = 5;
        status = GFp_curve_algebra_generator_mul_data(ctx, (uint8_t*)&val, sizeof(val), proofs + 1);
        REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        val = 6;
        coeff[2][31] = 7;
        status = GFp_curve_algebra_generator_mul_data(ctx, (uint8_t*)&val, sizeof(val), proofs + 2);
        REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);

        uint8_t res = 0;
        status = GFp_curve_algebra_verify_linear_combination(ctx, &proof, proofs, coeff, 2, &res);
        REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE_FALSE(res);

        ++proof[4];
        status = GFp_curve_algebra_verify_linear_combination(ctx, &proof, proofs, coeff, 3, &res);
        REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE_FALSE(res);

        --proof[4];
        ++coeff[0][31];
        status = GFp_curve_algebra_verify_linear_combination(ctx, &proof, proofs, coeff, 3, &res);
        REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE_FALSE(res);

        --coeff[0][31];
        ++proofs[0][7];
        status = GFp_curve_algebra_verify_linear_combination(ctx, &proof, proofs, coeff, 3, &res);
        REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE_FALSE(res);
    }

    GFp_curve_algebra_ctx_free(ctx);
}

TEST_CASE( "invalid param", "zkp") {
    GFp_curve_algebra_ctx_t* ctx = secp256k1_algebra_ctx_new();

    SECTION("verify") {
        REQUIRE(ctx);
        elliptic_curve256_point_t proof;
        uint32_t val = 7;
        elliptic_curve_algebra_status status = GFp_curve_algebra_generator_mul_data(NULL, (uint8_t*)&val, sizeof(val), &proof);
        REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_INVALID_PARAMETER);
        status = GFp_curve_algebra_generator_mul_data(ctx, NULL, sizeof(val), &proof);
        REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_INVALID_PARAMETER);
        status = GFp_curve_algebra_generator_mul_data(ctx, (uint8_t*)&val, 0, &proof);
        REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_INVALID_PARAMETER);
        status = GFp_curve_algebra_generator_mul_data(ctx, (uint8_t*)&val, sizeof(val), NULL);
        REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_INVALID_PARAMETER);
        uint8_t res = 0;
        status = GFp_curve_algebra_verify(NULL, (uint8_t*)&val, sizeof(val), &proof, &res);
        REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_INVALID_PARAMETER);
        status = GFp_curve_algebra_verify(ctx, NULL, sizeof(val), &proof, &res);
        REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_INVALID_PARAMETER);
        status = GFp_curve_algebra_verify(ctx, (uint8_t*)&val, 0, &proof, &res);
        REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_INVALID_PARAMETER);
        status = GFp_curve_algebra_verify(ctx, (uint8_t*)&val, sizeof(val), NULL, &res);
        REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_INVALID_PARAMETER);
        status = GFp_curve_algebra_verify(ctx, (uint8_t*)&val, sizeof(val), &proof, NULL);
        REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_INVALID_PARAMETER);
    }

    SECTION("verify sum") {
        REQUIRE(ctx);
        elliptic_curve256_point_t proof;
        uint32_t val = 7;
        elliptic_curve_algebra_status status = GFp_curve_algebra_generator_mul_data(ctx, (uint8_t*)&val, sizeof(val), &proof);
        REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        
        elliptic_curve256_point_t proofs[2];
        val = 5;
        status = GFp_curve_algebra_generator_mul_data(ctx, (uint8_t*)&val, sizeof(val), proofs);
        REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        val = 2;
        status = GFp_curve_algebra_generator_mul_data(ctx, (uint8_t*)&val, sizeof(val), proofs + 1);
        REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        
        uint8_t res = 0;
        status = GFp_curve_algebra_verify_sum(NULL, &proof, proofs, 2, &res);
        REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_INVALID_PARAMETER);
        status = GFp_curve_algebra_verify_sum(ctx, NULL, proofs, 2, &res);
        REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_INVALID_PARAMETER);
        status = GFp_curve_algebra_verify_sum(ctx, &proof, NULL, 2, &res);
        REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_INVALID_PARAMETER);
        status = GFp_curve_algebra_verify_sum(ctx, &proof, proofs, 0, &res);
        REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_INVALID_PARAMETER);
        status = GFp_curve_algebra_verify_sum(ctx, &proof, proofs, 2, NULL);
        REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_INVALID_PARAMETER);
    }

    SECTION("verify mul sum") {
        REQUIRE(ctx);
        elliptic_curve256_point_t proof;
        uint32_t val = 7;
        elliptic_curve_algebra_status status = GFp_curve_algebra_generator_mul_data(ctx, (uint8_t*)&val, sizeof(val), &proof);
        REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        
        elliptic_curve256_point_t proofs[2];
        elliptic_curve256_scalar_t coeff[2] = {0};
        coeff[0][31] = 3;
        coeff[1][31] = 7;
        val = 5;
        status = GFp_curve_algebra_generator_mul_data(ctx, (uint8_t*)&val, sizeof(val), proofs);
        REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        val = 2;
        status = GFp_curve_algebra_generator_mul_data(ctx, (uint8_t*)&val, sizeof(val), proofs + 1);
        REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        
        uint8_t res = 0;
        status = GFp_curve_algebra_verify_linear_combination(NULL, &proof, proofs, coeff, 2, &res);
        REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_INVALID_PARAMETER);
        status = GFp_curve_algebra_verify_linear_combination(ctx, NULL, proofs, coeff, 2, &res);
        REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_INVALID_PARAMETER);
        status = GFp_curve_algebra_verify_linear_combination(ctx, &proof, NULL, coeff, 2, &res);
        REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_INVALID_PARAMETER);
        status = GFp_curve_algebra_verify_linear_combination(ctx, &proof, proofs, NULL, 2, &res);
        REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_INVALID_PARAMETER);
        status = GFp_curve_algebra_verify_linear_combination(ctx, &proof, proofs, coeff, 0, &res);
        REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_INVALID_PARAMETER);
        status = GFp_curve_algebra_verify_linear_combination(ctx, &proof, proofs, coeff, 2, NULL);
        REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_INVALID_PARAMETER);
    }

    SECTION("add points") {
        REQUIRE(ctx);
        elliptic_curve256_point_t pa, pb;
        uint32_t a = 7, b = 5;
        elliptic_curve_algebra_status status = GFp_curve_algebra_generator_mul_data(ctx, (uint8_t*)&a, sizeof(a), &pa);
        REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);    
        status = GFp_curve_algebra_generator_mul_data(ctx, (uint8_t*)&b, sizeof(b), &pb);
        REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        
        status = GFp_curve_algebra_add_points(NULL, &pa, &pa, &pb);
        REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_INVALID_PARAMETER);
        status = GFp_curve_algebra_add_points(ctx, NULL, &pa, &pb);
        REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_INVALID_PARAMETER);
        status = GFp_curve_algebra_add_points(ctx, &pa, NULL, &pb);
        REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_INVALID_PARAMETER);
        status = GFp_curve_algebra_add_points(ctx, &pa, &pa, NULL);
        REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_INVALID_PARAMETER);
    }

    SECTION("add scalars") {
        REQUIRE(ctx);
        uint32_t a = 7, b = 5;
        
        elliptic_curve256_scalar_t res;
        elliptic_curve_algebra_status status = GFp_curve_algebra_add_scalars(NULL, &res, (uint8_t*)&a, sizeof(a), (uint8_t*)&b, sizeof(b));
        REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_INVALID_PARAMETER);
        status = GFp_curve_algebra_add_scalars(ctx, NULL, (uint8_t*)&a, sizeof(a), (uint8_t*)&b, sizeof(b));
        REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_INVALID_PARAMETER);
        status = GFp_curve_algebra_add_scalars(ctx, &res, NULL, sizeof(a), (uint8_t*)&b, sizeof(b));
        REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_INVALID_PARAMETER);
        status = GFp_curve_algebra_add_scalars(ctx, &res, (uint8_t*)&a, 0, (uint8_t*)&b, sizeof(b));
        REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_INVALID_PARAMETER);
        status = GFp_curve_algebra_add_scalars(ctx, &res, (uint8_t*)&a, sizeof(a), NULL, sizeof(b));
        REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_INVALID_PARAMETER);
        status = GFp_curve_algebra_add_scalars(ctx, &res, (uint8_t*)&a, sizeof(a), (uint8_t*)&b, 0);
        REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_INVALID_PARAMETER);
    }

    GFp_curve_algebra_ctx_free(ctx);
}

TEST_CASE( "secp256k1_algebra_add_points", "zkp") {
    GFp_curve_algebra_ctx_t* ctx = secp256k1_algebra_ctx_new();

    SECTION("basic") {
        REQUIRE(ctx);
        elliptic_curve256_point_t pa, pb, sum, res;
        uint32_t a = 7, b = 5;
        elliptic_curve_algebra_status status = GFp_curve_algebra_generator_mul_data(ctx, (uint8_t*)&a, sizeof(a), &pa);
        REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);    
        status = GFp_curve_algebra_generator_mul_data(ctx, (uint8_t*)&b, sizeof(b), &pb);
        REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        
        status = GFp_curve_algebra_add_points(ctx, &res, &pa, &pb);
        REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);

        uint32_t val = __bswap_32(__bswap_32(a)+__bswap_32(b)); // sum in big endian
        status = GFp_curve_algebra_generator_mul_data(ctx, (uint8_t*)&val, sizeof(val), &sum);
        REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);

        REQUIRE(memcmp(sum, res, sizeof(sum)) == 0);
    }

    SECTION("zero") {
        REQUIRE(ctx);
        elliptic_curve256_point_t pa, pb, sum, res;
        uint32_t a = 7, b = 0;
        elliptic_curve_algebra_status status = GFp_curve_algebra_generator_mul_data(ctx, (uint8_t*)&a, sizeof(a), &pa);
        REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);    
        status = GFp_curve_algebra_generator_mul_data(ctx, (uint8_t*)&b, sizeof(b), &pb);
        REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        
        status = GFp_curve_algebra_add_points(ctx, &res, &pa, &pb);
        REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE(memcmp(pa, res, sizeof(elliptic_curve256_point_t)) == 0);

        uint32_t val = __bswap_32(__bswap_32(a)+__bswap_32(b)); // sum in big endian
        status = GFp_curve_algebra_generator_mul_data(ctx, (uint8_t*)&val, sizeof(val), &sum);
        REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);

        REQUIRE(memcmp(sum, res, sizeof(sum)) == 0);
    }

    GFp_curve_algebra_ctx_free(ctx);
}

TEST_CASE( "secp256k1_algebra_add_scalars", "zkp") {
    GFp_curve_algebra_ctx_t* ctx = secp256k1_algebra_ctx_new();

    SECTION("basic") {
        REQUIRE(ctx);
        elliptic_curve256_scalar_t a, b, sum;
        REQUIRE(RAND_bytes(a, sizeof(a)));
        REQUIRE(RAND_bytes(b, sizeof(b)));

        auto status = GFp_curve_algebra_add_scalars(ctx, &sum, a, sizeof(a), b, sizeof(b));
        REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);

        BN_CTX* bn_ctx = BN_CTX_new();
        BN_CTX_start(bn_ctx);
        BIGNUM* bn_a = BN_CTX_get(bn_ctx);
        BIGNUM* bn_b = BN_CTX_get(bn_ctx);
        BIGNUM* bn_sum = BN_CTX_get(bn_ctx);
        BIGNUM* bn_field = BN_CTX_get(bn_ctx);
        REQUIRE(bn_a);
        REQUIRE(bn_b);
        REQUIRE(bn_sum);
        REQUIRE(bn_field);
        REQUIRE(BN_bin2bn(a, sizeof(a), bn_a));
        REQUIRE(BN_bin2bn(b, sizeof(b), bn_b));
        REQUIRE(BN_bin2bn(sum, sizeof(sum), bn_sum));
        REQUIRE(BN_bin2bn(SECP256K1_FIELD, ELLIPTIC_CURVE_FIELD_SIZE, bn_field));
        REQUIRE(BN_mod_add(bn_a, bn_a, bn_b, bn_field, bn_ctx));
        REQUIRE(BN_cmp(bn_a, bn_sum) == 0);

        BN_CTX_end(bn_ctx);
        BN_CTX_free(bn_ctx);
    }

    SECTION("long num") {
        REQUIRE(ctx);
        elliptic_curve256_scalar_t a, sum;
        uint8_t b[64];
        REQUIRE(RAND_bytes(a, sizeof(a)));
        REQUIRE(RAND_bytes(b, sizeof(b)));

        auto status = GFp_curve_algebra_add_scalars(ctx, &sum, a, sizeof(a), b, sizeof(b));
        REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);

        BN_CTX* bn_ctx = BN_CTX_new();
        BN_CTX_start(bn_ctx);
        BIGNUM* bn_a = BN_CTX_get(bn_ctx);
        BIGNUM* bn_b = BN_CTX_get(bn_ctx);
        BIGNUM* bn_sum = BN_CTX_get(bn_ctx);
        BIGNUM* bn_field = BN_CTX_get(bn_ctx);
        REQUIRE(bn_a);
        REQUIRE(bn_b);
        REQUIRE(bn_sum);
        REQUIRE(bn_field);
        REQUIRE(BN_bin2bn(a, sizeof(a), bn_a));
        REQUIRE(BN_bin2bn(b, sizeof(b), bn_b));
        REQUIRE(BN_bin2bn(sum, sizeof(sum), bn_sum));
        REQUIRE(BN_bin2bn(SECP256K1_FIELD, ELLIPTIC_CURVE_FIELD_SIZE, bn_field));
        REQUIRE(BN_mod_add(bn_a, bn_a, bn_b, bn_field, bn_ctx));
        REQUIRE(BN_cmp(bn_a, bn_sum) == 0);

        BN_CTX_end(bn_ctx);
        BN_CTX_free(bn_ctx);
    }

    SECTION("short num") {
        REQUIRE(ctx);
        elliptic_curve256_scalar_t a, sum;
        uint8_t b[20];
        REQUIRE(RAND_bytes(a, sizeof(a)));
        REQUIRE(RAND_bytes(b, sizeof(b)));

        auto status = GFp_curve_algebra_add_scalars(ctx, &sum, a, sizeof(a), b, sizeof(b));
        REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);

        BN_CTX* bn_ctx = BN_CTX_new();
        BN_CTX_start(bn_ctx);
        BIGNUM* bn_a = BN_CTX_get(bn_ctx);
        BIGNUM* bn_b = BN_CTX_get(bn_ctx);
        BIGNUM* bn_sum = BN_CTX_get(bn_ctx);
        BIGNUM* bn_field = BN_CTX_get(bn_ctx);
        REQUIRE(bn_a);
        REQUIRE(bn_b);
        REQUIRE(bn_sum);
        REQUIRE(bn_field);
        REQUIRE(BN_bin2bn(a, sizeof(a), bn_a));
        REQUIRE(BN_bin2bn(b, sizeof(b), bn_b));
        REQUIRE(BN_bin2bn(sum, sizeof(sum), bn_sum));
        REQUIRE(BN_bin2bn(SECP256K1_FIELD, ELLIPTIC_CURVE_FIELD_SIZE, bn_field));
        REQUIRE(BN_mod_add(bn_a, bn_a, bn_b, bn_field, bn_ctx));
        REQUIRE(BN_cmp(bn_a, bn_sum) == 0);

        BN_CTX_end(bn_ctx);
        BN_CTX_free(bn_ctx);
    }

    GFp_curve_algebra_ctx_free(ctx);
}

TEST_CASE( "reduce" ) {
    elliptic_curve256_algebra_ctx_t* secp256k1 = elliptic_curve256_new_secp256k1_algebra();
    
    SECTION("basic") {
        REQUIRE(secp256k1);
        elliptic_curve256_scalar_t a;
        REQUIRE(RAND_bytes(a, sizeof(a)));
        REQUIRE(secp256k1->reduce(secp256k1, &a, &a) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
    }

    SECTION("stark") {
        elliptic_curve256_algebra_ctx_t* stark = elliptic_curve256_new_stark_algebra();
        elliptic_curve256_scalar_t a;
        REQUIRE(stark);
        BN_CTX* bn_ctx = BN_CTX_new();
        BN_CTX_start(bn_ctx);
        BIGNUM* bn_a = BN_CTX_get(bn_ctx);
        
        for (size_t i = 0; i < 1024; i++)
        {
            REQUIRE(RAND_bytes(a, sizeof(a)));

            REQUIRE(bn_a);
            REQUIRE(BN_bin2bn(a, sizeof(a), bn_a));
            BN_clear_bit(bn_a, 255);
            BN_clear_bit(bn_a, 254);
            BN_clear_bit(bn_a, 253);
            BN_clear_bit(bn_a, 252);

            elliptic_curve256_scalar_t b;
            bool a_in_field = stark->reduce(stark, &b, &a) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS;
            bool bn_in_field = BN_cmp(bn_a, stark->order_internal(stark)) < 0;
            REQUIRE(a_in_field == bn_in_field);
        }
        BN_CTX_end(bn_ctx);
        BN_CTX_free(bn_ctx);

        memcpy(a, stark->order(stark), sizeof(a));
        REQUIRE(stark->reduce(stark, &a, &a) == ELLIPTIC_CURVE_ALGEBRA_INVALID_SCALAR);
        ++a[31];
        REQUIRE(stark->reduce(stark, &a, &a) == ELLIPTIC_CURVE_ALGEBRA_INVALID_SCALAR);
        a[31] -= 2;
        REQUIRE(stark->reduce(stark, &a, &a) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        elliptic_curve256_algebra_ctx_free(stark);
    }

    elliptic_curve256_algebra_ctx_free(secp256k1);
}

TEST_CASE( "point_projection" ) {
    // apparently x = q + 2 is a valid point
    elliptic_curve256_point_t point = {2, 0};
    memcpy(&point[1], SECP256K1_FIELD, 32);
    point[32] += 2;

    GFp_curve_algebra_ctx_t* secp256k1 = secp256k1_algebra_ctx_new();
    uint8_t overflow = 0;
    elliptic_curve256_scalar_t x_val;
    elliptic_curve256_scalar_t two = {0};
    two[31] = 2;
    REQUIRE(GFp_curve_algebra_get_point_projection(secp256k1, &x_val, &point, &overflow) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
    REQUIRE(overflow == 1);
    REQUIRE(memcmp(x_val, two, sizeof(elliptic_curve256_scalar_t)) == 0);
    GFp_curve_algebra_ctx_free(secp256k1);
}