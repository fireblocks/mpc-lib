#include "crypto/ed25519_algebra/ed25519_algebra.h"
#include "crypto/elliptic_curve_algebra/elliptic_curve256_algebra.h"

#include <openssl/rand.h>
#include <openssl/bn.h>

#define CATCH_CONFIG_MAIN  
#include <tests/catch.hpp>

TEST_CASE( "verify", "zkp") {
    ed25519_algebra_ctx_t* ctx = ed25519_algebra_ctx_new();

    SECTION("verify") {
        REQUIRE(ctx);
        ed25519_point_t proof;
        uint32_t val = 7;
        elliptic_curve_algebra_status status = ed25519_algebra_generator_mul_data(ctx, (uint8_t*)&val, sizeof(val), &proof);
        REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        uint8_t res = 0;
        status = ed25519_algebra_verify(ctx, (uint8_t*)&val, sizeof(val), &proof, &res);
        REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE(res);
    }

    SECTION("zero") {
        REQUIRE(ctx);
        ed25519_point_t proof;
        uint32_t val = 0;
        elliptic_curve_algebra_status status = ed25519_algebra_generator_mul_data(ctx, (uint8_t*)&val, sizeof(val), &proof);
        REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        uint8_t res = 0;
        status = ed25519_algebra_verify(ctx, (uint8_t*)&val, sizeof(val), &proof, &res);
        REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE(res);
    }

    SECTION("invalid order") {
        REQUIRE(ctx);
        ed25519_point_t proof;
        uint8_t val[32];
        memset(val, 0xff, sizeof(val));
        elliptic_curve_algebra_status status = ed25519_algebra_generator_mul_data(ctx, val, sizeof(val), &proof);
        REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        uint8_t res = 0;
        status = ed25519_algebra_verify(ctx, (uint8_t*)&val, sizeof(val), &proof, &res);
        REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE(res);
    }

    SECTION("wrong data") {
        REQUIRE(ctx);
        ed25519_point_t proof;
        uint32_t val = 7;
        elliptic_curve_algebra_status status = ed25519_algebra_generator_mul_data(ctx, (uint8_t*)&val, sizeof(val), &proof);
        REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        uint8_t res = 0;
        val = 8;
        status = ed25519_algebra_verify(ctx, (uint8_t*)&val, sizeof(val), &proof, &res);
        REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE_FALSE(res);
        val = 7;
        ++proof[3];
        status = ed25519_algebra_verify(ctx, (uint8_t*)&val, sizeof(val), &proof, &res);
        REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE_FALSE(res);
    }

    ed25519_algebra_ctx_free(ctx);
}

TEST_CASE( "verify_mul_sum", "zkp") {
    ed25519_algebra_ctx_t* ctx = ed25519_algebra_ctx_new();

    SECTION("verify_mul_sum") {
        REQUIRE(ctx);
        ed25519_point_t proof;
        uint8_t val = 2*3 + 4*5 + 6*7;
        elliptic_curve_algebra_status status = ed25519_algebra_generator_mul_data(ctx, (uint8_t*)&val, sizeof(val), &proof);
        REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        
        ed25519_point_t proofs[3];
        ed25519_scalar_t coeff[3] = {0};
        val = 2;
        coeff[0][31] = 3;
        status = ed25519_algebra_generator_mul_data(ctx, (uint8_t*)&val, sizeof(val), proofs);
        REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        val = 4;
        coeff[1][31] = 5;
        status = ed25519_algebra_generator_mul_data(ctx, (uint8_t*)&val, sizeof(val), proofs + 1);
        REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        val = 6;
        coeff[2][31] = 7;
        status = ed25519_algebra_generator_mul_data(ctx, (uint8_t*)&val, sizeof(val), proofs + 2);
        REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);

        uint8_t res = 0;
        status = ed25519_algebra_verify_linear_combination(ctx, &proof, proofs, coeff, 3, &res);
        REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE(res);
    }

    SECTION("wrong data") {
        REQUIRE(ctx);
        ed25519_point_t proof;
        uint8_t val = 2*3 + 4*5 + 6*7;
        elliptic_curve_algebra_status status = ed25519_algebra_generator_mul_data(ctx, (uint8_t*)&val, sizeof(val), &proof);
        REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        
        ed25519_point_t proofs[3];
        ed25519_scalar_t coeff[3] = {0};
        val = 2;
        coeff[0][31] = 3;
        status = ed25519_algebra_generator_mul_data(ctx, (uint8_t*)&val, sizeof(val), proofs);
        REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        val = 4;
        coeff[1][31] = 5;
        status = ed25519_algebra_generator_mul_data(ctx, (uint8_t*)&val, sizeof(val), proofs + 1);
        REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        val = 6;
        coeff[2][31] = 7;
        status = ed25519_algebra_generator_mul_data(ctx, (uint8_t*)&val, sizeof(val), proofs + 2);
        REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);

        uint8_t res = 0;
        status = ed25519_algebra_verify_linear_combination(ctx, &proof, proofs, coeff, 2, &res);
        REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE_FALSE(res);

        ++proof[4];
        status = ed25519_algebra_verify_linear_combination(ctx, &proof, proofs, coeff, 3, &res);
        REQUIRE((status == ELLIPTIC_CURVE_ALGEBRA_SUCCESS || status == ELLIPTIC_CURVE_ALGEBRA_INVALID_POINT));
        REQUIRE_FALSE(res);

        --proof[4];
        ++coeff[0][31];
        status = ed25519_algebra_verify_linear_combination(ctx, &proof, proofs, coeff, 3, &res);
        REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE_FALSE(res);

        --coeff[0][31];
        ++proofs[0][7];
        status = ed25519_algebra_verify_linear_combination(ctx, &proof, proofs, coeff, 3, &res);
        REQUIRE((status == ELLIPTIC_CURVE_ALGEBRA_SUCCESS || status == ELLIPTIC_CURVE_ALGEBRA_INVALID_POINT));
        REQUIRE_FALSE(res);
    }

    ed25519_algebra_ctx_free(ctx);
}

TEST_CASE( "invalid param", "zkp") {
    ed25519_algebra_ctx_t* ctx = ed25519_algebra_ctx_new();

    SECTION("verify") {
        REQUIRE(ctx);
        ed25519_point_t proof;
        uint32_t val = 7;
        elliptic_curve_algebra_status status = ed25519_algebra_generator_mul_data(NULL, (uint8_t*)&val, sizeof(val), &proof);
        REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_INVALID_PARAMETER);
        status = ed25519_algebra_generator_mul_data(ctx, NULL, sizeof(val), &proof);
        REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_INVALID_PARAMETER);
        status = ed25519_algebra_generator_mul_data(ctx, (uint8_t*)&val, 0, &proof);
        REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_INVALID_PARAMETER);
        status = ed25519_algebra_generator_mul_data(ctx, (uint8_t*)&val, sizeof(val), NULL);
        REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_INVALID_PARAMETER);
        uint8_t res = 0;
        status = ed25519_algebra_verify(NULL, (uint8_t*)&val, sizeof(val), &proof, &res);
        REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_INVALID_PARAMETER);
        status = ed25519_algebra_verify(ctx, NULL, sizeof(val), &proof, &res);
        REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_INVALID_PARAMETER);
        status = ed25519_algebra_verify(ctx, (uint8_t*)&val, 0, &proof, &res);
        REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_INVALID_PARAMETER);
        status = ed25519_algebra_verify(ctx, (uint8_t*)&val, sizeof(val), NULL, &res);
        REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_INVALID_PARAMETER);
        status = ed25519_algebra_verify(ctx, (uint8_t*)&val, sizeof(val), &proof, NULL);
        REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_INVALID_PARAMETER);
    }

    SECTION("verify mul sum") {
        REQUIRE(ctx);
        ed25519_point_t proof;
        uint32_t val = 7;
        elliptic_curve_algebra_status status = ed25519_algebra_generator_mul_data(ctx, (uint8_t*)&val, sizeof(val), &proof);
        REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        
        ed25519_point_t proofs[2];
        ed25519_scalar_t coeff[2] = {0};
        coeff[0][31] = 3;
        coeff[1][31] = 7;
        val = 5;
        status = ed25519_algebra_generator_mul_data(ctx, (uint8_t*)&val, sizeof(val), proofs);
        REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        val = 2;
        status = ed25519_algebra_generator_mul_data(ctx, (uint8_t*)&val, sizeof(val), proofs + 1);
        REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        
        uint8_t res = 0;
        status = ed25519_algebra_verify_linear_combination(NULL, &proof, proofs, coeff, 2, &res);
        REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_INVALID_PARAMETER);
        status = ed25519_algebra_verify_linear_combination(ctx, NULL, proofs, coeff, 2, &res);
        REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_INVALID_PARAMETER);
        status = ed25519_algebra_verify_linear_combination(ctx, &proof, NULL, coeff, 2, &res);
        REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_INVALID_PARAMETER);
        status = ed25519_algebra_verify_linear_combination(ctx, &proof, proofs, NULL, 2, &res);
        REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_INVALID_PARAMETER);
        status = ed25519_algebra_verify_linear_combination(ctx, &proof, proofs, coeff, 0, &res);
        REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_INVALID_PARAMETER);
        status = ed25519_algebra_verify_linear_combination(ctx, &proof, proofs, coeff, 2, NULL);
        REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_INVALID_PARAMETER);
    }

    SECTION("add points") {
        REQUIRE(ctx);
        ed25519_point_t pa, pb;
        uint32_t a = 7, b = 5;
        elliptic_curve_algebra_status status = ed25519_algebra_generator_mul_data(ctx, (uint8_t*)&a, sizeof(a), &pa);
        REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);    
        status = ed25519_algebra_generator_mul_data(ctx, (uint8_t*)&b, sizeof(b), &pb);
        REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        
        status = ed25519_algebra_add_points(NULL, &pa, &pa, &pb);
        REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_INVALID_PARAMETER);
        status = ed25519_algebra_add_points(ctx, NULL, &pa, &pb);
        REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_INVALID_PARAMETER);
        status = ed25519_algebra_add_points(ctx, &pa, NULL, &pb);
        REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_INVALID_PARAMETER);
        status = ed25519_algebra_add_points(ctx, &pa, &pa, NULL);
        REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_INVALID_PARAMETER);
    }

    SECTION("add scalars") {
        REQUIRE(ctx);
        uint32_t a = 7, b = 5;
        
        ed25519_scalar_t res;
        elliptic_curve_algebra_status status = ed25519_algebra_add_scalars(NULL, &res, (uint8_t*)&a, sizeof(a), (uint8_t*)&b, sizeof(b));
        REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_INVALID_PARAMETER);
        status = ed25519_algebra_add_scalars(ctx, NULL, (uint8_t*)&a, sizeof(a), (uint8_t*)&b, sizeof(b));
        REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_INVALID_PARAMETER);
        status = ed25519_algebra_add_scalars(ctx, &res, NULL, sizeof(a), (uint8_t*)&b, sizeof(b));
        REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_INVALID_PARAMETER);
        status = ed25519_algebra_add_scalars(ctx, &res, (uint8_t*)&a, 0, (uint8_t*)&b, sizeof(b));
        REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_INVALID_PARAMETER);
        status = ed25519_algebra_add_scalars(ctx, &res, (uint8_t*)&a, sizeof(a), NULL, sizeof(b));
        REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_INVALID_PARAMETER);
        status = ed25519_algebra_add_scalars(ctx, &res, (uint8_t*)&a, sizeof(a), (uint8_t*)&b, 0);
        REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_INVALID_PARAMETER);
    }

    ed25519_algebra_ctx_free(ctx);
}

TEST_CASE( "ed25519_algebra_add_points", "zkp") {
    ed25519_algebra_ctx_t* ctx = ed25519_algebra_ctx_new();

    SECTION("basic") {
        REQUIRE(ctx);
        ed25519_point_t pa, pb, sum, res;
        uint32_t a = 7, b = 5;
        elliptic_curve_algebra_status status = ed25519_algebra_generator_mul_data(ctx, (uint8_t*)&a, sizeof(a), &pa);
        REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);    
        status = ed25519_algebra_generator_mul_data(ctx, (uint8_t*)&b, sizeof(b), &pb);
        REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        
        status = ed25519_algebra_add_points(ctx, &res, &pa, &pb);
        REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);

        uint32_t val = __bswap_32(__bswap_32(a)+__bswap_32(b)); // sum in big endian
        status = ed25519_algebra_generator_mul_data(ctx, (uint8_t*)&val, sizeof(val), &sum);
        REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);

        REQUIRE(memcmp(sum, res, sizeof(sum)) == 0);
    }

    SECTION("zero") {
        REQUIRE(ctx);
        ed25519_point_t pa, pb, sum, res;
        uint32_t a = 7, b = 0;
        elliptic_curve_algebra_status status = ed25519_algebra_generator_mul_data(ctx, (uint8_t*)&a, sizeof(a), &pa);
        REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);    
        status = ed25519_algebra_generator_mul_data(ctx, (uint8_t*)&b, sizeof(b), &pb);
        REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        
        status = ed25519_algebra_add_points(ctx, &res, &pa, &pb);
        REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE(memcmp(pa, res, sizeof(ed25519_point_t)) == 0);

        uint32_t val = __bswap_32(__bswap_32(a)+__bswap_32(b)); // sum in big endian
        status = ed25519_algebra_generator_mul_data(ctx, (uint8_t*)&val, sizeof(val), &sum);
        REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);

        REQUIRE(memcmp(sum, res, sizeof(sum)) == 0);
    }

    SECTION("zero point") {
        REQUIRE(ctx);
        ed25519_point_t pa, pb = {0}, res;
        uint32_t a = 7;
        elliptic_curve_algebra_status status = ed25519_algebra_generator_mul_data(ctx, (uint8_t*)&a, sizeof(a), &pa);
        REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);    
        
        status = ed25519_algebra_add_points(ctx, &res, &pa, &pb); //invalid encoding
        REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_INVALID_POINT);
        pb[0] = 1;
        status = ed25519_algebra_add_points(ctx, &res, &pa, &pb);
        REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE(memcmp(pa, res, sizeof(ed25519_point_t)) == 0);
    }

    ed25519_algebra_ctx_free(ctx);
}

TEST_CASE( "ed25519_algebra_point_mul", "zkp") {
    ed25519_algebra_ctx_t* ctx = ed25519_algebra_ctx_new();

    SECTION("basic") {
        REQUIRE(ctx);
        ed25519_point_t pa, sum, res;
        uint8_t a = 7;
        ed25519_scalar_t exp = {0};
        exp[sizeof(ed25519_scalar_t) - 1] = 5;
        elliptic_curve_algebra_status status = ed25519_algebra_generator_mul_data(ctx, (uint8_t*)&a, sizeof(a), &pa);
        REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);    
        status = ed25519_algebra_point_mul(ctx, &res, &pa, &exp);
        REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        
        uint8_t val = 35;
        status = ed25519_algebra_generator_mul_data(ctx, (uint8_t*)&val, sizeof(val), &sum);
        REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);

        REQUIRE(memcmp(sum, res, sizeof(sum)) == 0);
    }

    SECTION("zero") {
        REQUIRE(ctx);
        ed25519_point_t pa, sum, res;
        uint8_t a = 7;
        ed25519_scalar_t exp = {0};
        elliptic_curve_algebra_status status = ed25519_algebra_generator_mul_data(ctx, (uint8_t*)&a, sizeof(a), &pa);
        REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);    
        
        status = ed25519_algebra_point_mul(ctx, &res, &pa, &exp);
        REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        
        uint32_t val = 0;
        status = ed25519_algebra_generator_mul_data(ctx, (uint8_t*)&val, sizeof(val), &sum);
        REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);

        REQUIRE(memcmp(sum, res, sizeof(sum)) == 0);
    }

    SECTION("one") {
        REQUIRE(ctx);
        ed25519_point_t pa, res;
        uint8_t a = 7;
        ed25519_scalar_t exp = {0};
        exp[sizeof(ed25519_scalar_t) - 1] = 1;
        elliptic_curve_algebra_status status = ed25519_algebra_generator_mul_data(ctx, (uint8_t*)&a, sizeof(a), &pa);
        REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);    
        
        status = ed25519_algebra_point_mul(ctx, &res, &pa, &exp);
        REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        
        REQUIRE(memcmp(pa, res, sizeof(pa)) == 0);
    }

    SECTION("invalid point") {
        REQUIRE(ctx);
        ed25519_point_t p = {0xb8, 0x62, 0x40, 0x9f, 0xb5, 0xc4, 0xc4, 0x12, 0x3d, 0xf2, 0xab, 0xf7, 0x46, 0x2b, 0x88, 0xf0, 0x41, 0xad, 0x36, 0xdd, 0x68, 0x64, 0xce, 0x87, 0x2f, 0xd5, 0x47, 0x2b, 0xe3, 0x63, 0xc5, 0xb2};
        ed25519_point_t res;
        ed25519_scalar_t exp = {0};
        exp[sizeof(ed25519_scalar_t) - 1] = 1;
        
        elliptic_curve_algebra_status status = ed25519_algebra_point_mul(ctx, &res, &p, &exp);
        REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_INVALID_POINT);
    }

    SECTION("invalid exp") {
        REQUIRE(ctx);
        ed25519_point_t pa, res;
        uint8_t a = 7;
        ed25519_scalar_t exp = {0};
        exp[0] = 0x81;
        elliptic_curve_algebra_status status = ed25519_algebra_generator_mul_data(ctx, (uint8_t*)&a, sizeof(a), &pa);
        REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);    
        
        status = ed25519_algebra_point_mul(ctx, &res, &pa, &exp);
        REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_INVALID_SCALAR);
    }

    ed25519_algebra_ctx_free(ctx);
}

TEST_CASE( "ed25519_algebra_generator_mul", "zkp") {
    ed25519_algebra_ctx_t* ctx = ed25519_algebra_ctx_new();

    SECTION("basic") {
        REQUIRE(ctx);
        ed25519_point_t pa, res;
        uint8_t a = 7;
        ed25519_scalar_t exp = {0};
        exp[sizeof(ed25519_scalar_t) - 1] = 7;
        elliptic_curve_algebra_status status = ed25519_algebra_generator_mul(ctx, &res, &exp);
        REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        status = ed25519_algebra_generator_mul_data(ctx, (uint8_t*)&a, sizeof(a), &pa);
        REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);    
        
        REQUIRE(memcmp(pa, res, sizeof(pa)) == 0);
    }

    SECTION("large number") {
        REQUIRE(ctx);
        ed25519_point_t pa, res;
        uint8_t a[sizeof(ed25519_scalar_t)];
        ed25519_scalar_t exp;
        REQUIRE(ed25519_algebra_rand(ctx, &exp) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        memcpy(a, exp, sizeof(exp));
        elliptic_curve_algebra_status status = ed25519_algebra_generator_mul(ctx, &res, &exp);
        REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        status = ed25519_algebra_generator_mul_data(ctx, (uint8_t*)&a, sizeof(a), &pa);
        REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);    
        
        REQUIRE(memcmp(pa, res, sizeof(pa)) == 0);
    }

    SECTION("65537") {
        REQUIRE(ctx);
        uint8_t expected[] = {0x60, 0x18, 0xed, 0x66, 0xc2, 0x76, 0x71, 0x82, 0x4c, 0x55, 0x02, 0x9b, 0x8e, 0xec, 0xf4, 0xbf, 0xfd, 0xa0, 0x59, 0x60, 0xb9, 0x14, 0x4a, 0x9e, 0xe5, 0xa9, 0xbe, 0xcd, 0xae, 0x9c, 0xc8, 0x21};
        ed25519_point_t res;
        ed25519_scalar_t exp = {0};
        exp[sizeof(ed25519_scalar_t) - 1] = 1;
        exp[sizeof(ed25519_scalar_t) - 3] = 1;
        elliptic_curve_algebra_status status = ed25519_algebra_generator_mul(ctx, &res, &exp);
        REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
                
        REQUIRE(memcmp(expected, res, sizeof(expected)) == 0);
    }

    SECTION("invalid exp") {
        REQUIRE(ctx);
        ed25519_point_t res;
        ed25519_scalar_t exp = {0};
        exp[0] = 0x81;
        elliptic_curve_algebra_status status = ed25519_algebra_generator_mul(ctx, &res, &exp);
        REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_INVALID_SCALAR);
    }

    ed25519_algebra_ctx_free(ctx);
}

TEST_CASE( "ed25519_algebra_add_scalars", "zkp") {
    ed25519_algebra_ctx_t* ctx = ed25519_algebra_ctx_new();

    SECTION("basic") {
        REQUIRE(ctx);
        ed25519_scalar_t a, b, sum;
        REQUIRE(RAND_bytes(a, sizeof(a)));
        REQUIRE(RAND_bytes(b, sizeof(b)));

        auto status = ed25519_algebra_add_scalars(ctx, &sum, a, sizeof(a), b, sizeof(b));
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
        REQUIRE(BN_bin2bn(ED25519_FIELD, ED25519_FIELD_SIZE, bn_field));
        REQUIRE(BN_mod_add(bn_a, bn_a, bn_b, bn_field, bn_ctx));
        REQUIRE(BN_cmp(bn_a, bn_sum) == 0);

        BN_CTX_end(bn_ctx);
        BN_CTX_free(bn_ctx);
    }

    SECTION("long num") {
        REQUIRE(ctx);
        ed25519_scalar_t a, sum;
        uint8_t b[64];
        REQUIRE(RAND_bytes(a, sizeof(a)));
        REQUIRE(RAND_bytes(b, sizeof(b)));

        auto status = ed25519_algebra_add_scalars(ctx, &sum, a, sizeof(a), b, sizeof(b));
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
        REQUIRE(BN_bin2bn(ED25519_FIELD, ED25519_FIELD_SIZE, bn_field));
        REQUIRE(BN_mod_add(bn_a, bn_a, bn_b, bn_field, bn_ctx));
        REQUIRE(BN_cmp(bn_a, bn_sum) == 0);

        BN_CTX_end(bn_ctx);
        BN_CTX_free(bn_ctx);
    }

    SECTION("short num") {
        REQUIRE(ctx);
        ed25519_scalar_t a, sum;
        uint8_t b[20];
        REQUIRE(RAND_bytes(a, sizeof(a)));
        REQUIRE(RAND_bytes(b, sizeof(b)));

        auto status = ed25519_algebra_add_scalars(ctx, &sum, a, sizeof(a), b, sizeof(b));
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
        REQUIRE(BN_bin2bn(ED25519_FIELD, ED25519_FIELD_SIZE, bn_field));
        REQUIRE(BN_mod_add(bn_a, bn_a, bn_b, bn_field, bn_ctx));
        REQUIRE(BN_cmp(bn_a, bn_sum) == 0);

        BN_CTX_end(bn_ctx);
        BN_CTX_free(bn_ctx);
    }

    ed25519_algebra_ctx_free(ctx);
}

TEST_CASE( "sign", "ed25519") {
    ed25519_algebra_ctx_t* ctx = ed25519_algebra_ctx_new();

    SECTION("short num") {
        ed25519_scalar_t priv;
        ed25519_point_t pub;
        uint8_t msg[] = "00000000000000000000000000000000";
        uint8_t sig[64];

        REQUIRE(ed25519_algebra_rand(ctx, &priv) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE(ed25519_algebra_generator_mul(ctx, &pub, &priv) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE(ed25519_algebra_sign(ctx, &priv, msg, 32, 0, sig) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);

        REQUIRE(ED25519_verify(msg, 32, sig, pub));
    }

    SECTION("keccac") {
        ed25519_scalar_t priv;
        ed25519_point_t pub;
        uint8_t msg[] = "00000000000000000000000000000000";
        uint8_t sig[64];

        REQUIRE(ed25519_algebra_rand(ctx, &priv) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE(ed25519_algebra_generator_mul(ctx, &pub, &priv) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE(ed25519_algebra_sign(ctx, &priv, msg, 32, 1, sig) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE(ed25519_verify(ctx, msg, 32, sig, pub, 1));
    }

    ed25519_algebra_ctx_free(ctx);
}


TEST_CASE( "reduce" ) {
    elliptic_curve256_algebra_ctx_t* ed25519 = elliptic_curve256_new_ed25519_algebra();
    
    elliptic_curve256_scalar_t a;
    elliptic_curve256_scalar_t b;
    REQUIRE(ed25519);
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

        bool a_in_field = ed25519->reduce(ed25519, &b, &a) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS;
        bool bn_in_field = BN_cmp(bn_a, ed25519->order_internal(ed25519)) < 0;
        REQUIRE(a_in_field == bn_in_field);
    }
    BN_CTX_end(bn_ctx);
    BN_CTX_free(bn_ctx);

    memcpy(a, ed25519->order(ed25519), sizeof(a));
    REQUIRE(ed25519->reduce(ed25519, &b, &a) == ELLIPTIC_CURVE_ALGEBRA_INVALID_SCALAR);
    ++a[31];
    REQUIRE(ed25519->reduce(ed25519, &b, &a) == ELLIPTIC_CURVE_ALGEBRA_INVALID_SCALAR);
    a[31] -= 2;
    REQUIRE(ed25519->reduce(ed25519, &b, &a) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
    elliptic_curve256_algebra_ctx_free(ed25519);
}