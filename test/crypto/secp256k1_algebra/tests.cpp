#include "crypto/GFp_curve_algebra/GFp_curve_algebra.h"

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/objects.h>
#include <openssl/rand.h>

#include "crypto/common/byteswap.h"
#include <string.h>

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
        elliptic_curve256_scalar_t coeff[3] = {{0}};
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
        elliptic_curve256_scalar_t coeff[3] = {{0}};
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
        elliptic_curve256_scalar_t coeff[2] = {{0}};
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

        uint32_t val = bswap_32(bswap_32(a)+bswap_32(b)); // sum in big endian
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

        uint32_t val = bswap_32(bswap_32(a)+bswap_32(b)); // sum in big endian
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

TEST_CASE( "hash_on_curve" ) {
    elliptic_curve256_point_t res;
    elliptic_curve256_point_t res2;
    uint8_t msg[] = "Some example message";

    SECTION("secp256k1") {
        elliptic_curve256_algebra_ctx_t* secp256k1 = elliptic_curve256_new_secp256k1_algebra();
        REQUIRE(secp256k1);
        REQUIRE(secp256k1->hash_on_curve(secp256k1, &res, msg, sizeof(msg)) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE(secp256k1->add_points(secp256k1, &res2, &res, &res) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE(secp256k1->hash_on_curve(secp256k1, &res2, msg, sizeof(msg)) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE(memcmp(res, res2, sizeof(elliptic_curve256_point_t)) == 0);

        REQUIRE(secp256k1->hash_on_curve(secp256k1, &res2, NULL, 0) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE(secp256k1->hash_on_curve(secp256k1, &res, NULL, 0) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE(memcmp(res, res2, sizeof(elliptic_curve256_point_t)) == 0);
        elliptic_curve256_algebra_ctx_free(secp256k1);
    }

    SECTION("secp256r1") {
        elliptic_curve256_algebra_ctx_t* secp256r1 = elliptic_curve256_new_secp256r1_algebra();
        REQUIRE(secp256r1);
        REQUIRE(secp256r1->hash_on_curve(secp256r1, &res, msg, sizeof(msg)) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE(secp256r1->add_points(secp256r1, &res2, &res, &res) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE(secp256r1->hash_on_curve(secp256r1, &res2, msg, sizeof(msg)) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE(memcmp(res, res2, sizeof(elliptic_curve256_point_t)) == 0);

        REQUIRE(secp256r1->hash_on_curve(secp256r1, &res2, NULL, 0) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE(secp256r1->hash_on_curve(secp256r1, &res, NULL, 0) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE(memcmp(res, res2, sizeof(elliptic_curve256_point_t)) == 0);
        elliptic_curve256_algebra_ctx_free(secp256r1);
    }

    SECTION("stark") {
        elliptic_curve256_algebra_ctx_t* stark = elliptic_curve256_new_stark_algebra();
        REQUIRE(stark);
        REQUIRE(stark->hash_on_curve(stark, &res, msg, sizeof(msg)) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE(stark->add_points(stark, &res2, &res, &res) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE(stark->hash_on_curve(stark, &res2, msg, sizeof(msg)) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE(memcmp(res, res2, sizeof(elliptic_curve256_point_t)) == 0);

        REQUIRE(stark->hash_on_curve(stark, &res2, NULL, 0) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE(stark->hash_on_curve(stark, &res, NULL, 0) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE(memcmp(res, res2, sizeof(elliptic_curve256_point_t)) == 0);
        elliptic_curve256_algebra_ctx_free(stark);
    }

}

TEST_CASE("hash_on_curve_test_vectors") {
    /* 11 precomputed test vectors per curve.
     * If any hash-to-curve implementation changes, these will fail — that is
     * intentional.  Update the vectors only after reviewing the change. */

    struct test_input {
        const uint8_t *data;
        uint32_t len;
        const char *label;
    };

    const uint8_t byte_00 = 0x00;
    const uint8_t byte_01 = 0x01;
    const uint8_t byte_ff = 0xff;
    const uint8_t abc[] = "abc";
    const uint8_t test_msg[] = "test";
    const uint8_t example[] = "Some example message";
    uint8_t zeros32[32]; memset(zeros32, 0x00, 32);
    uint8_t ffs32[32];   memset(ffs32,   0xff, 32);
    uint8_t incr32[32];  for (int i = 0; i < 32; i++) incr32[i] = (uint8_t)i;
    const uint8_t fox[] = "The quick brown fox jumps over the lazy dog";

    const test_input inputs[] = {
        { NULL,     0,                "NULL_empty"     },
        { &byte_00, 1,                "byte_0x00"      },
        { &byte_01, 1,                "byte_0x01"      },
        { &byte_ff, 1,                "byte_0xFF"      },
        { abc,      sizeof(abc),      "abc_with_null"  },
        { test_msg, sizeof(test_msg), "test_with_null" },
        { example,  sizeof(example),  "example_msg"    },
        { zeros32,  32,               "32_zero_bytes"  },
        { ffs32,    32,               "32_0xFF_bytes"  },
        { incr32,   32,               "32_incr_bytes"  },
        { fox,      sizeof(fox),      "fox_with_null"  },
    };
    const int N = sizeof(inputs) / sizeof(inputs[0]);

    SECTION("secp256k1") {
        static const elliptic_curve256_point_t expected[] = {
            {0x03, 0xbd, 0x0f, 0x07, 0x23, 0xbf, 0xba, 0x27, 0xe7, 0xd8, 0x1e,
             0x75, 0x5c, 0xb5, 0x85, 0x6e, 0x1c, 0xa2, 0x96, 0x7e, 0xda, 0x12,
             0x90, 0x92, 0x37, 0xe0, 0xe2, 0x7d, 0xc5, 0xd2, 0x2a, 0x6f, 0x49},
            {0x02, 0x14, 0x29, 0xa2, 0xce, 0x8f, 0x50, 0x03, 0xa2, 0x5b, 0x12,
             0x51, 0x0f, 0xdf, 0x2a, 0x40, 0x25, 0x5e, 0x7b, 0x28, 0xb9, 0xcf,
             0xdd, 0xb0, 0x5d, 0x95, 0xd0, 0x6d, 0xc4, 0x33, 0x95, 0x06, 0xbf},
            {0x03, 0xcb, 0xe4, 0xde, 0x92, 0x50, 0x1a, 0x04, 0x38, 0x83, 0x44,
             0xd0, 0x07, 0x12, 0x7a, 0x7e, 0xab, 0xe1, 0x95, 0x39, 0x24, 0xd8,
             0x6f, 0x03, 0x9d, 0x27, 0x26, 0xe1, 0xcf, 0x16, 0xf5, 0xef, 0x5d},
            {0x02, 0x4d, 0xd1, 0x5a, 0x49, 0x91, 0x44, 0x0f, 0x30, 0x76, 0x6d,
             0xbe, 0x08, 0x4e, 0x0a, 0xbb, 0x61, 0x58, 0x38, 0x77, 0xb0, 0x7c,
             0x44, 0xa3, 0x25, 0xb3, 0x3c, 0xb8, 0x6e, 0x5e, 0x7f, 0xa9, 0x32},
            {0x02, 0x3c, 0x2d, 0xd0, 0x34, 0xcf, 0x14, 0xf7, 0x8f, 0xa9, 0xbd,
             0x18, 0xc6, 0x58, 0x52, 0x2e, 0x7a, 0xc1, 0x65, 0xd4, 0x0c, 0xfa,
             0x50, 0x60, 0xae, 0x64, 0x7b, 0x60, 0x0c, 0x65, 0xbd, 0xa8, 0x17},
            {0x02, 0x4d, 0x4f, 0xbb, 0x70, 0x45, 0xc5, 0x63, 0x2d, 0xa2, 0x3c,
             0xae, 0xe7, 0x30, 0xa9, 0x28, 0x4f, 0xa2, 0xf9, 0x72, 0xaa, 0x5a,
             0xd1, 0xc6, 0x61, 0x01, 0xa4, 0xcb, 0x7c, 0xae, 0x6f, 0xc9, 0xa1},
            {0x02, 0x19, 0x2e, 0x28, 0xdf, 0x0d, 0xb5, 0xee, 0xec, 0xea, 0x7e,
             0x5b, 0x21, 0xf9, 0x55, 0xf6, 0x38, 0x85, 0x23, 0x87, 0xf6, 0x5a,
             0x4d, 0xaf, 0x7f, 0x87, 0xe7, 0xb5, 0x3d, 0x75, 0xb6, 0x6e, 0x38},
            {0x02, 0x43, 0xcf, 0xdf, 0x48, 0x6e, 0x6e, 0x50, 0x02, 0x17, 0xee,
             0x01, 0x45, 0x8e, 0x72, 0xac, 0xdd, 0x41, 0xfb, 0x7e, 0x2e, 0xc1,
             0x2d, 0x8a, 0xf6, 0xee, 0x51, 0xb5, 0x2c, 0x10, 0x9e, 0x1c, 0x7d},
            {0x03, 0x08, 0x7a, 0xbe, 0x83, 0x9a, 0x59, 0xdb, 0x64, 0x9f, 0xa4,
             0xaa, 0x86, 0x7c, 0xb6, 0x69, 0x7f, 0x97, 0x7e, 0x67, 0x76, 0x4d,
             0x4a, 0x00, 0x2c, 0xba, 0xce, 0x0f, 0x98, 0x2b, 0x0b, 0xd5, 0x9e},
            {0x03, 0x4b, 0x91, 0xe5, 0x8a, 0xd1, 0x50, 0x65, 0xee, 0x65, 0x81,
             0x35, 0x24, 0x98, 0x14, 0xf8, 0x0e, 0xf3, 0x1d, 0x8d, 0x36, 0xb3,
             0xb8, 0x90, 0x6e, 0xbf, 0x41, 0xc7, 0x0b, 0xa8, 0x28, 0x90, 0x78},
            {0x02, 0xee, 0x70, 0x67, 0x41, 0x2e, 0x28, 0x30, 0x1a, 0x2a, 0x6c,
             0x15, 0x66, 0x33, 0x92, 0x61, 0xa4, 0xf1, 0x3f, 0x55, 0x4f, 0x8f,
             0xa2, 0x07, 0x14, 0xc5, 0x87, 0x78, 0xf5, 0x29, 0x2f, 0xc5, 0xfe},
        };

        elliptic_curve256_algebra_ctx_t *ctx = elliptic_curve256_new_secp256k1_algebra();
        REQUIRE(ctx);
        elliptic_curve256_point_t result;
        for (int i = 0; i < N; i++) {
            INFO("secp256k1 vector " << i << " (" << inputs[i].label << ")");
            REQUIRE(ctx->hash_on_curve(ctx, &result, inputs[i].data, inputs[i].len) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
            REQUIRE(memcmp(result, expected[i], sizeof(elliptic_curve256_point_t)) == 0);
        }
        elliptic_curve256_algebra_ctx_free(ctx);
    }

    SECTION("secp256r1") {
        static const elliptic_curve256_point_t expected[] = {
            {0x03, 0xe0, 0x8f, 0xbc, 0x74, 0x13, 0x4f, 0x74, 0xb5, 0xce, 0x16,
             0xc2, 0x44, 0x06, 0xa6, 0x36, 0x9f, 0x87, 0x44, 0xad, 0xff, 0xe8,
             0xf1, 0xb2, 0x1e, 0x1e, 0x4e, 0xaf, 0x2d, 0x33, 0xb7, 0x28, 0x14},
            {0x03, 0x8f, 0x03, 0xb3, 0x9e, 0x1d, 0x26, 0x7d, 0xd4, 0xd2, 0x07,
             0x74, 0x72, 0xee, 0x2d, 0xe9, 0x34, 0xc9, 0xbf, 0x1a, 0xb6, 0x25,
             0xb7, 0xee, 0x78, 0x6c, 0x26, 0xb1, 0xdb, 0x2b, 0xc8, 0xb9, 0xb5},
            {0x03, 0xdc, 0xfb, 0x2d, 0x45, 0xc0, 0x71, 0x58, 0xa1, 0xff, 0x68,
             0x26, 0xcc, 0x84, 0xd6, 0x08, 0x9f, 0x85, 0x6b, 0x79, 0xa9, 0x23,
             0x40, 0x60, 0xc3, 0x66, 0xf7, 0x64, 0x18, 0x34, 0x7b, 0x0f, 0x8e},
            {0x02, 0xc2, 0xfc, 0x30, 0x3f, 0x8f, 0xf4, 0x6b, 0x01, 0xf7, 0x41,
             0xd0, 0xbd, 0x16, 0x61, 0x34, 0x09, 0xd1, 0xc0, 0xdc, 0x19, 0xc1,
             0x78, 0x27, 0x1d, 0x76, 0xb7, 0x30, 0x06, 0xa5, 0x0e, 0xf9, 0x49},
            {0x02, 0x22, 0x7c, 0x47, 0x93, 0x68, 0xed, 0xa7, 0x10, 0x60, 0x53,
             0xd1, 0x38, 0x8f, 0x06, 0xd8, 0x14, 0xe8, 0x23, 0xb6, 0xa0, 0xd9,
             0x25, 0x98, 0x63, 0xdc, 0x14, 0x97, 0x80, 0x8e, 0xa5, 0x04, 0x58},
            {0x02, 0x41, 0x77, 0x62, 0x3e, 0xbc, 0x8e, 0x22, 0x13, 0x2a, 0x95,
             0x78, 0xb4, 0x0a, 0x92, 0xba, 0x32, 0xef, 0x5b, 0x20, 0x77, 0x59,
             0x2d, 0xe8, 0x11, 0xb1, 0xd7, 0x2b, 0x40, 0xcb, 0x65, 0x6e, 0x90},
            {0x03, 0xdf, 0x5a, 0xa7, 0x28, 0x32, 0xe5, 0x6b, 0x0b, 0x7e, 0x13,
             0x24, 0x15, 0xc9, 0x61, 0x37, 0x26, 0xb2, 0xbd, 0x63, 0x5e, 0x50,
             0x32, 0xa1, 0x17, 0x77, 0xef, 0x58, 0x30, 0x6a, 0x78, 0xa3, 0x59},
            {0x03, 0x8d, 0x43, 0xa2, 0x4e, 0xad, 0xf4, 0xd2, 0x84, 0x85, 0xc5,
             0x73, 0xf2, 0xe5, 0xc0, 0xcd, 0x92, 0xb2, 0x14, 0x04, 0x9f, 0x13,
             0x52, 0xac, 0x1f, 0xd6, 0xce, 0x09, 0x8c, 0xd6, 0x8f, 0x9f, 0xee},
            {0x03, 0xd3, 0xd4, 0x94, 0xfa, 0x32, 0x29, 0xe1, 0xc4, 0x06, 0x48,
             0x2a, 0x37, 0x5c, 0x0f, 0xf9, 0x86, 0x88, 0xb3, 0xb6, 0x7f, 0x9b,
             0x0f, 0x99, 0xca, 0xbe, 0xef, 0xa4, 0x76, 0xf4, 0xba, 0x9a, 0x46},
            {0x03, 0x59, 0x00, 0xcc, 0xcd, 0xb4, 0x5b, 0x28, 0x05, 0x53, 0xe8,
             0x2c, 0x19, 0xfe, 0x97, 0x08, 0x2c, 0x5c, 0x3e, 0xb0, 0xc7, 0xa6,
             0x01, 0x74, 0xda, 0x58, 0xac, 0x1a, 0xee, 0x5e, 0x8a, 0x98, 0x41},
            {0x02, 0xaf, 0xf7, 0xd7, 0x76, 0x2e, 0xc5, 0x38, 0xd9, 0xc8, 0x78,
             0xa9, 0x95, 0xe1, 0x85, 0xda, 0x8a, 0x92, 0xe7, 0xa6, 0xd6, 0xcf,
             0xc5, 0x3e, 0x7c, 0xef, 0x70, 0xe7, 0x29, 0x3d, 0x81, 0xbf, 0xca},
        };

        elliptic_curve256_algebra_ctx_t *ctx = elliptic_curve256_new_secp256r1_algebra();
        REQUIRE(ctx);
        elliptic_curve256_point_t result;
        for (int i = 0; i < N; i++) {
            INFO("secp256r1 vector " << i << " (" << inputs[i].label << ")");
            REQUIRE(ctx->hash_on_curve(ctx, &result, inputs[i].data, inputs[i].len) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
            REQUIRE(memcmp(result, expected[i], sizeof(elliptic_curve256_point_t)) == 0);
        }
        elliptic_curve256_algebra_ctx_free(ctx);
    }

    SECTION("stark") {
        static const elliptic_curve256_point_t expected[] = {
            {0x03, 0x01, 0xa6, 0xff, 0x5a, 0x5a, 0xfe, 0x6d, 0x00, 0x07, 0xb5,
             0x0a, 0xad, 0x43, 0x7f, 0x80, 0x69, 0x98, 0x18, 0x77, 0xb2, 0xdf,
             0x89, 0x3e, 0xa4, 0xfc, 0x1a, 0x31, 0xb4, 0xbe, 0xd9, 0x1b, 0xba},
            {0x02, 0x06, 0xd0, 0xde, 0x30, 0x93, 0x44, 0x30, 0x49, 0x18, 0x7c,
             0xdd, 0x74, 0x49, 0xcb, 0xec, 0xf6, 0xc9, 0x60, 0xe9, 0xc7, 0xcb,
             0xbd, 0xa0, 0xd2, 0xa9, 0xd0, 0x75, 0x14, 0x24, 0x74, 0x18, 0x18},
            {0x03, 0x07, 0xb0, 0x13, 0xac, 0xe3, 0x1f, 0x1d, 0xee, 0x0e, 0x6f,
             0xe2, 0xac, 0xcf, 0x37, 0x46, 0xc6, 0xbf, 0x3c, 0xc1, 0x70, 0x45,
             0x92, 0xb9, 0x0c, 0x12, 0x49, 0xac, 0x70, 0x1e, 0x6a, 0x84, 0xdf},
            {0x03, 0x06, 0x4c, 0xb9, 0xe1, 0x92, 0xb4, 0xca, 0x89, 0x8c, 0xbe,
             0xd9, 0x95, 0x64, 0x53, 0x9e, 0xe2, 0x8c, 0x68, 0x92, 0xcf, 0x8d,
             0x39, 0xd2, 0x07, 0x86, 0xec, 0xe0, 0xbd, 0xb5, 0x64, 0x18, 0x0b},
            {0x02, 0x07, 0xc6, 0xad, 0x8a, 0xd0, 0xd2, 0x94, 0xa1, 0x69, 0xa9,
             0xf8, 0x05, 0x74, 0xbd, 0x79, 0x5a, 0xb7, 0x52, 0x1e, 0x70, 0x76,
             0x82, 0xba, 0x8f, 0xea, 0x7e, 0x9e, 0x44, 0xc3, 0x1b, 0x1a, 0x2a},
            {0x02, 0x02, 0x6b, 0x77, 0x76, 0xc5, 0x06, 0x71, 0xba, 0xe2, 0x1b,
             0xe5, 0x6e, 0xa0, 0xa8, 0xfa, 0x98, 0xa3, 0xd8, 0xd3, 0x0c, 0xf9,
             0x7c, 0x66, 0x65, 0x6d, 0xa9, 0xd8, 0xdd, 0xa6, 0x67, 0x06, 0x19},
            {0x02, 0x07, 0xfc, 0x93, 0x46, 0xaf, 0x07, 0x50, 0x11, 0x07, 0x3c,
             0x8d, 0x16, 0xcd, 0xca, 0xda, 0x63, 0x91, 0x86, 0xb0, 0x47, 0x0d,
             0x6b, 0x60, 0xd4, 0xcc, 0x22, 0xeb, 0xf3, 0xcb, 0x8f, 0x6f, 0xe0},
            {0x03, 0x03, 0xef, 0x04, 0x67, 0xd0, 0xc0, 0x01, 0x93, 0xe1, 0xa1,
             0x04, 0x4c, 0x94, 0x85, 0x77, 0x2f, 0xec, 0x32, 0x91, 0xf1, 0xed,
             0xfb, 0xe0, 0x8a, 0x16, 0x95, 0xff, 0xd8, 0x28, 0xe7, 0x8a, 0xcb},
            {0x02, 0x00, 0x79, 0xe7, 0xec, 0xf8, 0x0f, 0xbb, 0x6e, 0x13, 0x36,
             0x0c, 0xa8, 0x42, 0x84, 0x3f, 0xab, 0xd6, 0xf8, 0x42, 0xd0, 0x0b,
             0xf6, 0x8a, 0xc2, 0x79, 0x98, 0xe4, 0xe5, 0x09, 0xc8, 0x5e, 0x31},
            {0x03, 0x04, 0x29, 0xaf, 0xe7, 0x57, 0x6e, 0x30, 0x79, 0xac, 0x22,
             0x81, 0x33, 0x81, 0x5a, 0xc7, 0x86, 0x43, 0x8b, 0xfe, 0x8e, 0x40,
             0xf3, 0xe9, 0x4c, 0x0d, 0x59, 0x11, 0x19, 0x77, 0x69, 0x6a, 0x65},
            {0x02, 0x05, 0xc6, 0xa2, 0x17, 0x18, 0x8b, 0x54, 0xac, 0xa5, 0xfd,
             0x4a, 0xe9, 0x5d, 0x7c, 0x94, 0xcb, 0xb0, 0xf4, 0x39, 0x9c, 0x0e,
             0xaf, 0x7a, 0x0f, 0x56, 0x49, 0x95, 0x55, 0xfe, 0x8a, 0x3f, 0xbc},
        };

        elliptic_curve256_algebra_ctx_t *ctx = elliptic_curve256_new_stark_algebra();
        REQUIRE(ctx);
        elliptic_curve256_point_t result;
        for (int i = 0; i < N; i++) {
            INFO("stark vector " << i << " (" << inputs[i].label << ")");
            REQUIRE(ctx->hash_on_curve(ctx, &result, inputs[i].data, inputs[i].len) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
            REQUIRE(memcmp(result, expected[i], sizeof(elliptic_curve256_point_t)) == 0);
        }
        elliptic_curve256_algebra_ctx_free(ctx);
    }
}

TEST_CASE("validate_non_infinity_point (GFp curves)", "secp256k1") {
    SECTION("secp256k1: rejects infinity encoding (0x00 + garbage)") {
        elliptic_curve256_algebra_ctx_t* secp256k1 = elliptic_curve256_new_secp256k1_algebra();
        REQUIRE(secp256k1);
        REQUIRE(secp256k1->validate_non_infinity_point);

        elliptic_curve256_point_t inf_garbage;
        memset(inf_garbage, 0xA5, sizeof(inf_garbage));
        inf_garbage[0] = 0x00;
        REQUIRE(secp256k1->validate_non_infinity_point(secp256k1, &inf_garbage) == ELLIPTIC_CURVE_ALGEBRA_INVALID_POINT);

        elliptic_curve256_point_t p;
        elliptic_curve256_scalar_t one = {0};
        one[31] = 1;
        REQUIRE(secp256k1->generator_mul(secp256k1, &p, &one) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);

        elliptic_curve256_point_t sum;
        REQUIRE(secp256k1->add_points(secp256k1, &sum, &inf_garbage, &p) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE(memcmp(sum, p, sizeof(elliptic_curve256_point_t)) == 0);

        elliptic_curve256_algebra_ctx_free(secp256k1);
    }

    SECTION("secp256k1: rejects invalid encodings (bad prefix / out-of-range X)") {
        elliptic_curve256_algebra_ctx_t* secp256k1 = elliptic_curve256_new_secp256k1_algebra();
        REQUIRE(secp256k1);
        REQUIRE(secp256k1->validate_non_infinity_point);

        elliptic_curve256_point_t bad_prefix;
        memset(bad_prefix, 0x11, sizeof(bad_prefix));
        bad_prefix[0] = 0x04; // uncompressed prefix but we only provide 33 bytes -> must be invalid
        REQUIRE(secp256k1->validate_non_infinity_point(secp256k1, &bad_prefix) == ELLIPTIC_CURVE_ALGEBRA_INVALID_POINT);

        elliptic_curve256_point_t x_too_large;
        memset(x_too_large, 0xFF, sizeof(x_too_large));
        x_too_large[0] = 0x02; // "compressed, even y" with X >= p -> invalid
        REQUIRE(secp256k1->validate_non_infinity_point(secp256k1, &x_too_large) == ELLIPTIC_CURVE_ALGEBRA_INVALID_POINT);

        elliptic_curve256_algebra_ctx_free(secp256k1);
    }

    SECTION("secp256r1: rejects infinity encoding (0x00 + garbage)") {
        elliptic_curve256_algebra_ctx_t* secp256r1 = elliptic_curve256_new_secp256r1_algebra();
        REQUIRE(secp256r1);
        REQUIRE(secp256r1->validate_non_infinity_point);

        elliptic_curve256_point_t inf_garbage;
        memset(inf_garbage, 0x5A, sizeof(inf_garbage));
        inf_garbage[0] = 0x00;
        REQUIRE(secp256r1->validate_non_infinity_point(secp256r1, &inf_garbage) == ELLIPTIC_CURVE_ALGEBRA_INVALID_POINT);

        elliptic_curve256_algebra_ctx_free(secp256r1);
    }

    SECTION("secp256r1: rejects invalid encodings (bad prefix / out-of-range X)") {
        elliptic_curve256_algebra_ctx_t* secp256r1 = elliptic_curve256_new_secp256r1_algebra();
        REQUIRE(secp256r1);
        REQUIRE(secp256r1->validate_non_infinity_point);

        elliptic_curve256_point_t bad_prefix;
        memset(bad_prefix, 0x22, sizeof(bad_prefix));
        bad_prefix[0] = 0x04;
        REQUIRE(secp256r1->validate_non_infinity_point(secp256r1, &bad_prefix) == ELLIPTIC_CURVE_ALGEBRA_INVALID_POINT);

        elliptic_curve256_point_t x_too_large;
        memset(x_too_large, 0xFF, sizeof(x_too_large));
        x_too_large[0] = 0x03;
        REQUIRE(secp256r1->validate_non_infinity_point(secp256r1, &x_too_large) == ELLIPTIC_CURVE_ALGEBRA_INVALID_POINT);

        elliptic_curve256_algebra_ctx_free(secp256r1);
    }

    SECTION("stark: rejects infinity encoding (0x00 + garbage)") {
        elliptic_curve256_algebra_ctx_t* stark = elliptic_curve256_new_stark_algebra();
        REQUIRE(stark);
        REQUIRE(stark->validate_non_infinity_point);

        elliptic_curve256_point_t inf_garbage;
        memset(inf_garbage, 0xFF, sizeof(inf_garbage));
        inf_garbage[0] = 0x00;
        REQUIRE(stark->validate_non_infinity_point(stark, &inf_garbage) == ELLIPTIC_CURVE_ALGEBRA_INVALID_POINT);

        elliptic_curve256_algebra_ctx_free(stark);
    }

    SECTION("stark: rejects invalid encodings (bad prefix / out-of-range X)") {
        elliptic_curve256_algebra_ctx_t* stark = elliptic_curve256_new_stark_algebra();
        REQUIRE(stark);
        REQUIRE(stark->validate_non_infinity_point);

        elliptic_curve256_point_t bad_prefix;
        memset(bad_prefix, 0x33, sizeof(bad_prefix));
        bad_prefix[0] = 0x04;
        REQUIRE(stark->validate_non_infinity_point(stark, &bad_prefix) == ELLIPTIC_CURVE_ALGEBRA_INVALID_POINT);

        elliptic_curve256_point_t x_too_large;
        memset(x_too_large, 0xFF, sizeof(x_too_large));
        x_too_large[0] = 0x02;
        REQUIRE(stark->validate_non_infinity_point(stark, &x_too_large) == ELLIPTIC_CURVE_ALGEBRA_INVALID_POINT);

        elliptic_curve256_algebra_ctx_free(stark);
    }
}

TEST_CASE("secp256k1_attacks", "[attack][secp256k1]") {
    elliptic_curve256_algebra_ctx_t* algebra = elliptic_curve256_new_secp256k1_algebra();
    REQUIRE(algebra);

    SECTION("generator_mul with zero scalar") {
        elliptic_curve256_scalar_t zero;
        memset(zero, 0, sizeof(zero));
        elliptic_curve256_point_t result;
        elliptic_curve_algebra_status status = algebra->generator_mul(algebra, &result, &zero);
        // G^0 should either fail or return the infinity point
        if (status == ELLIPTIC_CURVE_ALGEBRA_SUCCESS) {
            const elliptic_curve256_point_t* inf = algebra->infinity_point(algebra);
            REQUIRE(inf);
            REQUIRE(memcmp(result, *inf, sizeof(elliptic_curve256_point_t)) == 0);
        } else {
            REQUIRE((status == ELLIPTIC_CURVE_ALGEBRA_INVALID_SCALAR || status == ELLIPTIC_CURVE_ALGEBRA_UNKNOWN_ERROR));
        }
    }

    SECTION("generator_mul with order scalar") {
        elliptic_curve256_scalar_t order_scalar;
        const uint8_t* order_bytes = algebra->order(algebra);
        REQUIRE(order_bytes);
        memcpy(order_scalar, order_bytes, sizeof(elliptic_curve256_scalar_t));
        elliptic_curve256_point_t result;
        elliptic_curve_algebra_status status = algebra->generator_mul(algebra, &result, &order_scalar);
        // G^n = infinity, should either fail or return infinity
        if (status == ELLIPTIC_CURVE_ALGEBRA_SUCCESS) {
            const elliptic_curve256_point_t* inf = algebra->infinity_point(algebra);
            REQUIRE(inf);
            REQUIRE(memcmp(result, *inf, sizeof(elliptic_curve256_point_t)) == 0);
        } else {
            REQUIRE((status == ELLIPTIC_CURVE_ALGEBRA_INVALID_SCALAR || status == ELLIPTIC_CURVE_ALGEBRA_UNKNOWN_ERROR));
        }
    }

    SECTION("generator_mul with order-1") {
        // Compute order - 1
        elliptic_curve256_scalar_t order_minus_1;
        const uint8_t* order_bytes = algebra->order(algebra);
        REQUIRE(order_bytes);
        memcpy(order_minus_1, order_bytes, sizeof(elliptic_curve256_scalar_t));
        // Subtract 1 from big-endian value
        for (int i = ELLIPTIC_CURVE_FIELD_SIZE - 1; i >= 0; --i) {
            if (order_minus_1[i] > 0) {
                order_minus_1[i]--;
                break;
            }
            order_minus_1[i] = 0xFF;
        }
        elliptic_curve256_point_t result;
        elliptic_curve_algebra_status status = algebra->generator_mul(algebra, &result, &order_minus_1);
        REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        // The result should NOT be infinity (it is the negation of G)
        const elliptic_curve256_point_t* inf = algebra->infinity_point(algebra);
        REQUIRE(inf);
        REQUIRE(memcmp(result, *inf, sizeof(elliptic_curve256_point_t)) != 0);
        // Verify: result + G = infinity (i.e. result is -G)
        elliptic_curve256_scalar_t one = {0};
        one[ELLIPTIC_CURVE_FIELD_SIZE - 1] = 1;
        elliptic_curve256_point_t gen_point;
        REQUIRE(algebra->generator_mul(algebra, &gen_point, &one) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        elliptic_curve256_point_t sum;
        REQUIRE(algebra->add_points(algebra, &sum, &result, &gen_point) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE(memcmp(sum, *inf, sizeof(elliptic_curve256_point_t)) == 0);
    }

    SECTION("generator_mul with order+1") {
        // Compute order + 1
        elliptic_curve256_scalar_t order_plus_1;
        const uint8_t* order_bytes = algebra->order(algebra);
        REQUIRE(order_bytes);
        memcpy(order_plus_1, order_bytes, sizeof(elliptic_curve256_scalar_t));
        // Add 1 to big-endian value
        int carry = 1;
        for (int i = ELLIPTIC_CURVE_FIELD_SIZE - 1; i >= 0 && carry; --i) {
            int tmp = order_plus_1[i] + carry;
            order_plus_1[i] = (uint8_t)(tmp & 0xFF);
            carry = tmp >> 8;
        }
        elliptic_curve256_point_t result;
        elliptic_curve_algebra_status status = algebra->generator_mul(algebra, &result, &order_plus_1);
        // Should wrap modulo order, giving G^1
        if (status == ELLIPTIC_CURVE_ALGEBRA_SUCCESS) {
            elliptic_curve256_scalar_t one = {0};
            one[ELLIPTIC_CURVE_FIELD_SIZE - 1] = 1;
            elliptic_curve256_point_t g1;
            REQUIRE(algebra->generator_mul(algebra, &g1, &one) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
            REQUIRE(memcmp(result, g1, sizeof(elliptic_curve256_point_t)) == 0);
        } else {
            // Some implementations may reject scalars >= order
            REQUIRE((status == ELLIPTIC_CURVE_ALGEBRA_INVALID_SCALAR || status == ELLIPTIC_CURVE_ALGEBRA_UNKNOWN_ERROR));
        }
    }

    SECTION("generator_mul with max scalar 0xFF...") {
        elliptic_curve256_scalar_t max_scalar;
        memset(max_scalar, 0xFF, sizeof(max_scalar));
        elliptic_curve256_point_t result;
        elliptic_curve_algebra_status status = algebra->generator_mul(algebra, &result, &max_scalar);
        // 0xFF...FF is much larger than the order; should either reduce mod order or fail
        if (status == ELLIPTIC_CURVE_ALGEBRA_SUCCESS) {
            const elliptic_curve256_point_t* inf = algebra->infinity_point(algebra);
            REQUIRE(inf);
            // The result should be a valid non-infinity point (0xFF..FF mod n != 0)
            REQUIRE(memcmp(result, *inf, sizeof(elliptic_curve256_point_t)) != 0);
        } else {
            REQUIRE((status == ELLIPTIC_CURVE_ALGEBRA_INVALID_SCALAR || status == ELLIPTIC_CURVE_ALGEBRA_UNKNOWN_ERROR));
        }
    }

    SECTION("point_mul with infinity point") {
        const elliptic_curve256_point_t* inf = algebra->infinity_point(algebra);
        REQUIRE(inf);
        elliptic_curve256_scalar_t scalar = {0};
        scalar[ELLIPTIC_CURVE_FIELD_SIZE - 1] = 5;
        elliptic_curve256_point_t result;
        elliptic_curve_algebra_status status = algebra->point_mul(algebra, &result, inf, &scalar);
        // infinity * s should be infinity or error
        if (status == ELLIPTIC_CURVE_ALGEBRA_SUCCESS) {
            REQUIRE(memcmp(result, *inf, sizeof(elliptic_curve256_point_t)) == 0);
        } else {
            REQUIRE((status == ELLIPTIC_CURVE_ALGEBRA_INVALID_POINT ||
                     status == ELLIPTIC_CURVE_ALGEBRA_INVALID_PARAMETER ||
                     status == ELLIPTIC_CURVE_ALGEBRA_UNKNOWN_ERROR));
        }
    }

    SECTION("point_mul with zero scalar") {
        // Generate a valid point first
        elliptic_curve256_scalar_t three = {0};
        three[ELLIPTIC_CURVE_FIELD_SIZE - 1] = 3;
        elliptic_curve256_point_t point;
        REQUIRE(algebra->generator_mul(algebra, &point, &three) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);

        elliptic_curve256_scalar_t zero;
        memset(zero, 0, sizeof(zero));
        elliptic_curve256_point_t result;
        elliptic_curve_algebra_status status = algebra->point_mul(algebra, &result, &point, &zero);
        // P * 0 should be infinity or fail
        if (status == ELLIPTIC_CURVE_ALGEBRA_SUCCESS) {
            const elliptic_curve256_point_t* inf = algebra->infinity_point(algebra);
            REQUIRE(inf);
            REQUIRE(memcmp(result, *inf, sizeof(elliptic_curve256_point_t)) == 0);
        } else {
            REQUIRE((status == ELLIPTIC_CURVE_ALGEBRA_INVALID_SCALAR || status == ELLIPTIC_CURVE_ALGEBRA_UNKNOWN_ERROR));
        }
    }

    SECTION("add_points with infinity") {
        // P + infinity = P
        elliptic_curve256_scalar_t seven = {0};
        seven[ELLIPTIC_CURVE_FIELD_SIZE - 1] = 7;
        elliptic_curve256_point_t point;
        REQUIRE(algebra->generator_mul(algebra, &point, &seven) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);

        const elliptic_curve256_point_t* inf = algebra->infinity_point(algebra);
        REQUIRE(inf);
        elliptic_curve256_point_t result;
        elliptic_curve_algebra_status status = algebra->add_points(algebra, &result, &point, inf);
        REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE(memcmp(result, point, sizeof(elliptic_curve256_point_t)) == 0);

        // Also test infinity + P = P
        status = algebra->add_points(algebra, &result, inf, &point);
        REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE(memcmp(result, point, sizeof(elliptic_curve256_point_t)) == 0);
    }

    SECTION("add_points with P and -P") {
        // P + (-P) = infinity
        // -P is G^(order-1), P is G^1
        elliptic_curve256_scalar_t one = {0};
        one[ELLIPTIC_CURVE_FIELD_SIZE - 1] = 1;
        elliptic_curve256_point_t gen_point;
        REQUIRE(algebra->generator_mul(algebra, &gen_point, &one) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);

        elliptic_curve256_scalar_t order_minus_1;
        const uint8_t* order_bytes = algebra->order(algebra);
        REQUIRE(order_bytes);
        memcpy(order_minus_1, order_bytes, sizeof(elliptic_curve256_scalar_t));
        for (int i = ELLIPTIC_CURVE_FIELD_SIZE - 1; i >= 0; --i) {
            if (order_minus_1[i] > 0) {
                order_minus_1[i]--;
                break;
            }
            order_minus_1[i] = 0xFF;
        }
        elliptic_curve256_point_t neg_gen;
        REQUIRE(algebra->generator_mul(algebra, &neg_gen, &order_minus_1) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);

        elliptic_curve256_point_t sum;
        REQUIRE(algebra->add_points(algebra, &sum, &gen_point, &neg_gen) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        const elliptic_curve256_point_t* inf = algebra->infinity_point(algebra);
        REQUIRE(inf);
        REQUIRE(memcmp(sum, *inf, sizeof(elliptic_curve256_point_t)) == 0);
    }

    SECTION("add_scalars overflow - beyond order") {
        // Choose a = order - 1, b = 2 => a + b = order + 1 => should reduce to 1 mod order
        const uint8_t* order_bytes = algebra->order(algebra);
        REQUIRE(order_bytes);
        elliptic_curve256_scalar_t a;
        memcpy(a, order_bytes, sizeof(elliptic_curve256_scalar_t));
        for (int i = ELLIPTIC_CURVE_FIELD_SIZE - 1; i >= 0; --i) {
            if (a[i] > 0) {
                a[i]--;
                break;
            }
            a[i] = 0xFF;
        }
        elliptic_curve256_scalar_t b = {0};
        b[ELLIPTIC_CURVE_FIELD_SIZE - 1] = 2;

        elliptic_curve256_scalar_t result;
        elliptic_curve_algebra_status status = algebra->add_scalars(algebra, &result, a, sizeof(a), b, sizeof(b));
        REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        // (order - 1) + 2 = order + 1 = 1 mod order
        elliptic_curve256_scalar_t expected_one = {0};
        expected_one[ELLIPTIC_CURVE_FIELD_SIZE - 1] = 1;
        REQUIRE(memcmp(result, expected_one, sizeof(elliptic_curve256_scalar_t)) == 0);
    }

    SECTION("mul_scalars with zero") {
        elliptic_curve256_scalar_t a = {0};
        a[ELLIPTIC_CURVE_FIELD_SIZE - 1] = 42;
        elliptic_curve256_scalar_t zero;
        memset(zero, 0, sizeof(zero));

        elliptic_curve256_scalar_t result;
        elliptic_curve_algebra_status status = algebra->mul_scalars(algebra, &result, a, sizeof(a), zero, sizeof(zero));
        REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        elliptic_curve256_scalar_t expected_zero;
        memset(expected_zero, 0, sizeof(expected_zero));
        REQUIRE(memcmp(result, expected_zero, sizeof(elliptic_curve256_scalar_t)) == 0);
    }

    SECTION("inverse of zero") {
        elliptic_curve256_scalar_t zero;
        memset(zero, 0, sizeof(zero));
        elliptic_curve256_scalar_t result;
        elliptic_curve_algebra_status status = algebra->inverse(algebra, &result, &zero);
        // Inverse of zero is undefined; must fail
        REQUIRE(status != ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
    }

    SECTION("inverse of order") {
        // order mod order = 0, so inverse should fail
        elliptic_curve256_scalar_t order_scalar;
        const uint8_t* order_bytes = algebra->order(algebra);
        REQUIRE(order_bytes);
        memcpy(order_scalar, order_bytes, sizeof(elliptic_curve256_scalar_t));
        elliptic_curve256_scalar_t result;
        elliptic_curve_algebra_status status = algebra->inverse(algebra, &result, &order_scalar);
        // order = 0 mod order, so inverse is undefined; must fail
        REQUIRE(status != ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
    }

    elliptic_curve256_algebra_ctx_free(algebra);
}

TEST_CASE("multi_curve_attacks", "[attack][multi_curve]") {

    SECTION("secp256r1 generator_mul zero") {
        elliptic_curve256_algebra_ctx_t* r1 = elliptic_curve256_new_secp256r1_algebra();
        REQUIRE(r1);
        elliptic_curve256_scalar_t zero;
        memset(zero, 0, sizeof(zero));
        elliptic_curve256_point_t result;
        elliptic_curve_algebra_status status = r1->generator_mul(r1, &result, &zero);
        // G^0 should be infinity or fail
        if (status == ELLIPTIC_CURVE_ALGEBRA_SUCCESS) {
            const elliptic_curve256_point_t* inf = r1->infinity_point(r1);
            REQUIRE(inf);
            REQUIRE(memcmp(result, *inf, sizeof(elliptic_curve256_point_t)) == 0);
        } else {
            REQUIRE((status == ELLIPTIC_CURVE_ALGEBRA_INVALID_SCALAR || status == ELLIPTIC_CURVE_ALGEBRA_UNKNOWN_ERROR));
        }
        elliptic_curve256_algebra_ctx_free(r1);
    }

    SECTION("secp256r1 add_points self-inverse") {
        elliptic_curve256_algebra_ctx_t* r1 = elliptic_curve256_new_secp256r1_algebra();
        REQUIRE(r1);
        // Compute G and -G (= G^(order-1))
        elliptic_curve256_scalar_t one = {0};
        one[ELLIPTIC_CURVE_FIELD_SIZE - 1] = 1;
        elliptic_curve256_point_t gen_point;
        REQUIRE(r1->generator_mul(r1, &gen_point, &one) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);

        elliptic_curve256_scalar_t order_minus_1;
        const uint8_t* order_bytes = r1->order(r1);
        REQUIRE(order_bytes);
        memcpy(order_minus_1, order_bytes, sizeof(elliptic_curve256_scalar_t));
        for (int i = ELLIPTIC_CURVE_FIELD_SIZE - 1; i >= 0; --i) {
            if (order_minus_1[i] > 0) {
                order_minus_1[i]--;
                break;
            }
            order_minus_1[i] = 0xFF;
        }
        elliptic_curve256_point_t neg_gen;
        REQUIRE(r1->generator_mul(r1, &neg_gen, &order_minus_1) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);

        elliptic_curve256_point_t sum;
        REQUIRE(r1->add_points(r1, &sum, &gen_point, &neg_gen) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        const elliptic_curve256_point_t* inf = r1->infinity_point(r1);
        REQUIRE(inf);
        REQUIRE(memcmp(sum, *inf, sizeof(elliptic_curve256_point_t)) == 0);
        elliptic_curve256_algebra_ctx_free(r1);
    }

    SECTION("stark generator_mul zero") {
        elliptic_curve256_algebra_ctx_t* stark = elliptic_curve256_new_stark_algebra();
        REQUIRE(stark);
        elliptic_curve256_scalar_t zero;
        memset(zero, 0, sizeof(zero));
        elliptic_curve256_point_t result;
        elliptic_curve_algebra_status status = stark->generator_mul(stark, &result, &zero);
        // G^0 should be infinity or fail
        if (status == ELLIPTIC_CURVE_ALGEBRA_SUCCESS) {
            const elliptic_curve256_point_t* inf = stark->infinity_point(stark);
            REQUIRE(inf);
            REQUIRE(memcmp(result, *inf, sizeof(elliptic_curve256_point_t)) == 0);
        } else {
            REQUIRE((status == ELLIPTIC_CURVE_ALGEBRA_INVALID_SCALAR || status == ELLIPTIC_CURVE_ALGEBRA_UNKNOWN_ERROR));
        }
        elliptic_curve256_algebra_ctx_free(stark);
    }

    SECTION("stark point on wrong curve") {
        // Generate a point on secp256k1, then try to use it with STARK's point_mul
        elliptic_curve256_algebra_ctx_t* k1 = elliptic_curve256_new_secp256k1_algebra();
        elliptic_curve256_algebra_ctx_t* stark = elliptic_curve256_new_stark_algebra();
        REQUIRE(k1);
        REQUIRE(stark);

        elliptic_curve256_scalar_t three = {0};
        three[ELLIPTIC_CURVE_FIELD_SIZE - 1] = 3;
        elliptic_curve256_point_t k1_point;
        REQUIRE(k1->generator_mul(k1, &k1_point, &three) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);

        // Use the secp256k1 point in a STARK point_mul -- should fail or produce wrong result
        elliptic_curve256_scalar_t two = {0};
        two[ELLIPTIC_CURVE_FIELD_SIZE - 1] = 2;
        elliptic_curve256_point_t result;
        elliptic_curve_algebra_status status = stark->point_mul(stark, &result, &k1_point, &two);
        if (status == ELLIPTIC_CURVE_ALGEBRA_SUCCESS) {
            // If it somehow succeeded, the result must NOT match what secp256k1 would produce
            elliptic_curve256_point_t k1_result;
            REQUIRE(k1->point_mul(k1, &k1_result, &k1_point, &two) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
            // Points from different curves should differ (different generators and group structure)
            REQUIRE(memcmp(result, k1_result, sizeof(elliptic_curve256_point_t)) != 0);
        } else {
            // Expected: the library rejects a point not on the STARK curve
            REQUIRE((status == ELLIPTIC_CURVE_ALGEBRA_INVALID_POINT ||
                     status == ELLIPTIC_CURVE_ALGEBRA_INVALID_PARAMETER ||
                     status == ELLIPTIC_CURVE_ALGEBRA_UNKNOWN_ERROR));
        }

        elliptic_curve256_algebra_ctx_free(k1);
        elliptic_curve256_algebra_ctx_free(stark);
    }
}

// ============================================================================
// GFp Signature Verification Attack Tests
// Tests for GFp_curve_algebra_verify_signature and get_point_projection
// used in BAM signing flow.
// ============================================================================

TEST_CASE("GFp_verify_signature_attacks", "[attack][signature]") {
    GFp_curve_algebra_ctx_t* ctx = secp256k1_algebra_ctx_new();
    REQUIRE(ctx);

    // Create a valid signature for tampering tests
    // Generate keypair: private_key, public_key = G^private_key
    elliptic_curve256_scalar_t private_key = {0};
    private_key[ELLIPTIC_CURVE_FIELD_SIZE - 1] = 42;
    elliptic_curve256_point_t public_key;
    REQUIRE(GFp_curve_algebra_generator_mul_data(ctx, private_key, sizeof(private_key), &public_key) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);

    // Create a message hash
    elliptic_curve256_scalar_t message = {0};
    message[ELLIPTIC_CURVE_FIELD_SIZE - 1] = 0xAB;
    message[ELLIPTIC_CURVE_FIELD_SIZE - 2] = 0xCD;

    // Create a "signature" with known r and s values
    // Use k=7 as ephemeral nonce: R = G^7, r = R.x mod n
    elliptic_curve256_scalar_t k = {0};
    k[ELLIPTIC_CURVE_FIELD_SIZE - 1] = 7;
    elliptic_curve256_point_t R_point;
    REQUIRE(GFp_curve_algebra_generator_mul_data(ctx, k, sizeof(k), &R_point) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
    elliptic_curve256_scalar_t sig_r;
    REQUIRE(GFp_curve_algebra_get_point_projection(ctx, &sig_r, &R_point, NULL) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);

    SECTION("verify_signature with r = 0") {
        elliptic_curve256_scalar_t zero_r;
        memset(zero_r, 0, sizeof(zero_r));
        elliptic_curve256_scalar_t dummy_s = {0};
        dummy_s[ELLIPTIC_CURVE_FIELD_SIZE - 1] = 1;

        elliptic_curve_algebra_status status = GFp_curve_algebra_verify_signature(ctx, &public_key, &message, &zero_r, &dummy_s);
        // r = 0 is invalid for ECDSA — must reject
        REQUIRE(status != ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
    }

    SECTION("verify_signature with s = 0") {
        elliptic_curve256_scalar_t zero_s;
        memset(zero_s, 0, sizeof(zero_s));

        elliptic_curve_algebra_status status = GFp_curve_algebra_verify_signature(ctx, &public_key, &message, &sig_r, &zero_s);
        // s = 0 is invalid for ECDSA — must reject
        REQUIRE(status != ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
    }

    SECTION("verify_signature with r = group order") {
        // secp256k1 group order n (big-endian)
        elliptic_curve256_scalar_t order_r = {
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
            0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B,
            0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41
        };
        elliptic_curve256_scalar_t dummy_s = {0};
        dummy_s[ELLIPTIC_CURVE_FIELD_SIZE - 1] = 1;

        elliptic_curve_algebra_status status = GFp_curve_algebra_verify_signature(ctx, &public_key, &message, &order_r, &dummy_s);
        // r = n means r = 0 mod n — must reject
        REQUIRE(status != ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
    }

    SECTION("verify_signature with wrong public key") {
        // Generate a different public key
        elliptic_curve256_scalar_t wrong_priv = {0};
        wrong_priv[ELLIPTIC_CURVE_FIELD_SIZE - 1] = 99;
        elliptic_curve256_point_t wrong_pubkey;
        REQUIRE(GFp_curve_algebra_generator_mul_data(ctx, wrong_priv, sizeof(wrong_priv), &wrong_pubkey) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);

        // Use valid-looking r and s with wrong key — must fail verification
        elliptic_curve256_scalar_t dummy_s = {0};
        dummy_s[ELLIPTIC_CURVE_FIELD_SIZE - 1] = 1;
        elliptic_curve_algebra_status status = GFp_curve_algebra_verify_signature(ctx, &wrong_pubkey, &message, &sig_r, &dummy_s);
        // The signature was not produced with this key — verification should fail
        REQUIRE(status != ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
    }

    SECTION("verify_signature with infinity public key") {
        elliptic_curve256_point_t inf_key;
        memset(inf_key, 0, sizeof(inf_key)); // canonical infinity for GFp curves
        elliptic_curve256_scalar_t dummy_s = {0};
        dummy_s[ELLIPTIC_CURVE_FIELD_SIZE - 1] = 1;

        elliptic_curve_algebra_status status = GFp_curve_algebra_verify_signature(ctx, &inf_key, &message, &sig_r, &dummy_s);
        // Infinity is not a valid public key — must reject
        REQUIRE(status != ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
    }

    SECTION("get_point_projection with infinity point") {
        elliptic_curve256_point_t inf;
        memset(inf, 0, sizeof(inf));
        elliptic_curve256_scalar_t x_val;
        uint8_t overflow = 0;

        elliptic_curve_algebra_status status = GFp_curve_algebra_get_point_projection(ctx, &x_val, &inf, &overflow);
        // Projecting infinity should either fail or return zero
        if (status == ELLIPTIC_CURVE_ALGEBRA_SUCCESS) {
            elliptic_curve256_scalar_t zero;
            memset(zero, 0, sizeof(zero));
            REQUIRE(memcmp(x_val, zero, sizeof(x_val)) == 0);
        } else {
            REQUIRE((status == ELLIPTIC_CURVE_ALGEBRA_INVALID_POINT ||
                     status == ELLIPTIC_CURVE_ALGEBRA_INVALID_PARAMETER ||
                     status == ELLIPTIC_CURVE_ALGEBRA_UNKNOWN_ERROR));
        }
    }

    SECTION("verify_signature with both r and s equal to max (0xFF...)") {
        elliptic_curve256_scalar_t max_val;
        memset(max_val, 0xFF, sizeof(max_val));

        elliptic_curve_algebra_status status = GFp_curve_algebra_verify_signature(ctx, &public_key, &message, &max_val, &max_val);
        // Both r and s > order — must reject
        REQUIRE(status != ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
    }

    GFp_curve_algebra_ctx_free(ctx);
}

TEST_CASE("ec_scalar_point_consistency", "[correctness]")
{
    elliptic_curve256_algebra_ctx_t* algebra = elliptic_curve256_new_secp256k1_algebra();
    REQUIRE(algebra);

    SECTION("a*G + b*G = (a+b)*G for 10 random pairs")
    {
        for (int i = 0; i < 10; i++)
        {
            elliptic_curve256_scalar_t a, b, a_plus_b;
            REQUIRE(algebra->rand(algebra, &a) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
            REQUIRE(algebra->rand(algebra, &b) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);

            // Compute a*G and b*G separately
            elliptic_curve256_point_t aG, bG;
            REQUIRE(algebra->generator_mul(algebra, &aG, &a) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
            REQUIRE(algebra->generator_mul(algebra, &bG, &b) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);

            // Compute a*G + b*G via point addition
            elliptic_curve256_point_t sum_points;
            REQUIRE(algebra->add_points(algebra, &sum_points, &aG, &bG) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);

            // Compute (a+b)*G via scalar addition then generator_mul
            REQUIRE(algebra->add_scalars(algebra, &a_plus_b, a, sizeof(a), b, sizeof(b)) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
            elliptic_curve256_point_t sum_scalar;
            REQUIRE(algebra->generator_mul(algebra, &sum_scalar, &a_plus_b) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);

            REQUIRE(memcmp(sum_points, sum_scalar, sizeof(elliptic_curve256_point_t)) == 0);
        }
    }

    SECTION("a*(b*G) = (a*b)*G for 10 random pairs")
    {
        for (int i = 0; i < 10; i++)
        {
            elliptic_curve256_scalar_t a, b, ab;
            REQUIRE(algebra->rand(algebra, &a) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
            REQUIRE(algebra->rand(algebra, &b) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);

            // Compute b*G, then a*(b*G) via point_mul
            elliptic_curve256_point_t bG;
            REQUIRE(algebra->generator_mul(algebra, &bG, &b) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
            elliptic_curve256_point_t a_times_bG;
            REQUIRE(algebra->point_mul(algebra, &a_times_bG, &bG, &a) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);

            // Compute (a*b)*G via scalar multiplication then generator_mul
            REQUIRE(algebra->mul_scalars(algebra, &ab, a, sizeof(a), b, sizeof(b)) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
            elliptic_curve256_point_t ab_times_G;
            REQUIRE(algebra->generator_mul(algebra, &ab_times_G, &ab) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);

            REQUIRE(memcmp(a_times_bG, ab_times_G, sizeof(elliptic_curve256_point_t)) == 0);
        }
    }

    elliptic_curve256_algebra_ctx_free(algebra);
}

TEST_CASE("ec_known_test_vectors", "[correctness]")
{
    elliptic_curve256_algebra_ctx_t* algebra = elliptic_curve256_new_secp256k1_algebra();
    REQUIRE(algebra);

    SECTION("generator point matches secp256k1 specification")
    {
        // secp256k1 generator Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
        const uint8_t expected_gx[] = {
            0x79, 0xBE, 0x66, 0x7E, 0xF9, 0xDC, 0xBB, 0xAC,
            0x55, 0xA0, 0x62, 0x95, 0xCE, 0x87, 0x0B, 0x07,
            0x02, 0x9B, 0xFC, 0xDB, 0x2D, 0xCE, 0x28, 0xD9,
            0x59, 0xF2, 0x81, 0x5B, 0x16, 0xF8, 0x17, 0x98
        };

        elliptic_curve256_scalar_t one = {0};
        one[ELLIPTIC_CURVE_FIELD_SIZE - 1] = 1;
        elliptic_curve256_point_t gen;
        REQUIRE(algebra->generator_mul(algebra, &gen, &one) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);

        // Compressed point: prefix byte (02 or 03) + 32-byte x-coordinate
        REQUIRE(memcmp(&gen[1], expected_gx, 32) == 0);
    }

    SECTION("2*G matches known value")
    {
        // 2*G x-coordinate: 0xC6047F9441ED7D6D3045406E95C07CD85C778E4B8CEF3CA7ABAC09B95C709EE5
        const uint8_t expected_2gx[] = {
            0xC6, 0x04, 0x7F, 0x94, 0x41, 0xED, 0x7D, 0x6D,
            0x30, 0x45, 0x40, 0x6E, 0x95, 0xC0, 0x7C, 0xD8,
            0x5C, 0x77, 0x8E, 0x4B, 0x8C, 0xEF, 0x3C, 0xA7,
            0xAB, 0xAC, 0x09, 0xB9, 0x5C, 0x70, 0x9E, 0xE5
        };

        elliptic_curve256_scalar_t two = {0};
        two[ELLIPTIC_CURVE_FIELD_SIZE - 1] = 2;
        elliptic_curve256_point_t result;
        REQUIRE(algebra->generator_mul(algebra, &result, &two) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);

        REQUIRE(memcmp(&result[1], expected_2gx, 32) == 0);
    }

    SECTION("G + G = 2*G via point addition")
    {
        elliptic_curve256_scalar_t one = {0};
        one[ELLIPTIC_CURVE_FIELD_SIZE - 1] = 1;
        elliptic_curve256_point_t gen;
        REQUIRE(algebra->generator_mul(algebra, &gen, &one) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);

        elliptic_curve256_point_t sum;
        REQUIRE(algebra->add_points(algebra, &sum, &gen, &gen) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);

        elliptic_curve256_scalar_t two = {0};
        two[ELLIPTIC_CURVE_FIELD_SIZE - 1] = 2;
        elliptic_curve256_point_t double_g;
        REQUIRE(algebra->generator_mul(algebra, &double_g, &two) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);

        REQUIRE(memcmp(sum, double_g, sizeof(elliptic_curve256_point_t)) == 0);
    }

    elliptic_curve256_algebra_ctx_free(algebra);
}