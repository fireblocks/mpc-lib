#include "crypto/ed25519_algebra/ed25519_algebra.h"
#include "crypto/elliptic_curve_algebra/elliptic_curve256_algebra.h"

#include <openssl/rand.h>
#include <openssl/bn.h>

#include "crypto/common/byteswap.h"
#include <string.h>

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
        ed25519_scalar_t coeff[3] = {{0}};
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
        ed25519_scalar_t coeff[3] = {{0}};
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
        ed25519_scalar_t coeff[2] = {{0}};
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

        uint32_t val = bswap_32(bswap_32(a)+bswap_32(b)); // sum in big endian
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

        uint32_t val = bswap_32(bswap_32(a)+bswap_32(b)); // sum in big endian
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

    SECTION("keccak") {
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

TEST_CASE( "calc_hram", "ed25519") {
    ed25519_algebra_ctx_t* ctx = ed25519_algebra_ctx_new();
    SECTION("param check") {
        ed25519_le_scalar_t hram;
        ed25519_point_t R, public_key;
        const uint8_t message[2] = {0xde, 0xad};

        REQUIRE(ed25519_calc_hram(ctx, &hram, &R, &public_key, message, sizeof(message), 0) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE(ed25519_calc_hram(NULL, &hram, &R, &public_key, message, sizeof(message), 0) == ELLIPTIC_CURVE_ALGEBRA_INVALID_PARAMETER);
        REQUIRE(ed25519_calc_hram(ctx, NULL, &R, &public_key, message, sizeof(message), 0) == ELLIPTIC_CURVE_ALGEBRA_INVALID_PARAMETER);
        REQUIRE(ed25519_calc_hram(ctx, &hram, NULL, &public_key, message, sizeof(message), 0) == ELLIPTIC_CURVE_ALGEBRA_INVALID_PARAMETER);
        REQUIRE(ed25519_calc_hram(ctx, &hram, &R, NULL, message, sizeof(message), 0) == ELLIPTIC_CURVE_ALGEBRA_INVALID_PARAMETER);
        REQUIRE(ed25519_calc_hram(ctx, &hram, &R, &public_key, NULL, sizeof(message), 0) == ELLIPTIC_CURVE_ALGEBRA_INVALID_PARAMETER);
        REQUIRE(ed25519_calc_hram(ctx, &hram, &R, &public_key, message, 0, 0) == ELLIPTIC_CURVE_ALGEBRA_INVALID_PARAMETER);
    }
    ed25519_algebra_ctx_free(ctx);
}
TEST_CASE( "hash_on_curve" ) {
    elliptic_curve256_point_t res;
    elliptic_curve256_point_t res2;
    uint8_t msg[] = "Some example message";
    elliptic_curve256_algebra_ctx_t* ed25519 = elliptic_curve256_new_ed25519_algebra();
    REQUIRE(ed25519);
    SECTION("TestVector#1") {
        REQUIRE(ed25519->hash_on_curve(ed25519, &res, msg, sizeof(msg)) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE(ed25519->add_points(ed25519, &res2, &res, &res) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE(ed25519->hash_on_curve(ed25519, &res2, msg, sizeof(msg)) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE(memcmp(res, res2, sizeof(elliptic_curve256_point_t)) == 0);

        REQUIRE(ed25519->hash_on_curve(ed25519, &res2, NULL, 0) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE(ed25519->hash_on_curve(ed25519, &res, NULL, 0) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE(memcmp(res, res2, sizeof(elliptic_curve256_point_t)) == 0);
    }

    elliptic_curve256_algebra_ctx_free(ed25519);
}

TEST_CASE("hash_on_curve_test_vectors") {
    /* 11 precomputed test vectors for ed25519.
     * If the hash-to-curve implementation changes, these will fail — that is
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

    static const elliptic_curve256_point_t expected[] = {
        {0x97, 0x2f, 0x26, 0x99, 0x88, 0xd5, 0xf5, 0x3d, 0x96, 0xfa, 0xbb,
         0x04, 0xb0, 0x7c, 0x38, 0xb3, 0x5f, 0xb3, 0xaf, 0xa1, 0x8e, 0x34,
         0x94, 0x7a, 0x1d, 0x98, 0x2f, 0x1b, 0x9a, 0x57, 0xc9, 0x48, 0x00},
        {0xcb, 0x7c, 0xd9, 0xa7, 0x33, 0xe4, 0x88, 0x80, 0xa5, 0xc4, 0x69,
         0x31, 0x2d, 0x4c, 0x0e, 0x6d, 0xb2, 0xf8, 0xa2, 0x05, 0x6b, 0x89,
         0xb0, 0x8c, 0x60, 0x81, 0xd8, 0x80, 0x8c, 0xdb, 0x3d, 0xdb, 0x00},
        {0x62, 0x7e, 0x51, 0xd2, 0x13, 0x98, 0xf1, 0x9b, 0x33, 0x4d, 0x29,
         0xe2, 0x0b, 0x74, 0x90, 0x39, 0x26, 0xf9, 0xd2, 0x54, 0x29, 0x96,
         0x68, 0xf8, 0xb3, 0xf8, 0xb0, 0x48, 0xe7, 0xa6, 0x31, 0xd9, 0x00},
        {0xad, 0x02, 0xdb, 0x95, 0x51, 0xf7, 0x8a, 0x4f, 0x4c, 0xdb, 0x6b,
         0xdd, 0xb5, 0xa6, 0x42, 0x7a, 0x8a, 0xee, 0x12, 0x65, 0x2f, 0xe8,
         0xf2, 0xa7, 0x6b, 0x02, 0xf8, 0xb4, 0xb4, 0x3b, 0x63, 0x3d, 0x00},
        {0xe2, 0x18, 0xce, 0xff, 0xe4, 0x36, 0x67, 0x08, 0x2e, 0xfa, 0xb6,
         0x17, 0x1e, 0x95, 0xb5, 0xe3, 0x52, 0xc2, 0xc7, 0x9f, 0xe2, 0x19,
         0xc1, 0xf2, 0xe4, 0x6f, 0xf1, 0x4f, 0x5c, 0x39, 0xfd, 0x70, 0x00},
        {0x11, 0x8a, 0x9c, 0x8b, 0x57, 0x0f, 0x45, 0xb3, 0x27, 0x00, 0xc3,
         0x7e, 0x69, 0x1c, 0xef, 0x5d, 0x1a, 0x76, 0x49, 0x81, 0x2f, 0x02,
         0x47, 0x6c, 0xa8, 0x64, 0x00, 0x92, 0x94, 0x4e, 0x56, 0xbe, 0x00},
        {0x58, 0x9d, 0x77, 0x83, 0x19, 0xc6, 0x67, 0x84, 0x55, 0x0f, 0xc5,
         0x7c, 0x04, 0x0b, 0xb3, 0xa5, 0x18, 0x8a, 0x1b, 0x51, 0xb6, 0x8e,
         0xc4, 0x36, 0x6d, 0x7e, 0xe5, 0xd1, 0xaa, 0x15, 0x37, 0x06, 0x00},
        {0x6d, 0x78, 0xa6, 0x2a, 0x93, 0x62, 0xb6, 0x17, 0x00, 0x1a, 0xcb,
         0x6d, 0x28, 0x0a, 0xd5, 0xba, 0x7a, 0xc4, 0xa2, 0x88, 0xa8, 0x7e,
         0xa2, 0x2b, 0x36, 0x59, 0x2d, 0x82, 0x52, 0xe7, 0x28, 0xa9, 0x00},
        {0x0f, 0xe1, 0xdd, 0xb7, 0xc1, 0xe5, 0x26, 0x0c, 0x5b, 0xa7, 0xa7,
         0xeb, 0xf2, 0xef, 0x87, 0x88, 0x49, 0xfc, 0x7b, 0xd5, 0x51, 0x36,
         0x02, 0x56, 0xee, 0xf3, 0xbb, 0xb7, 0xb1, 0x7f, 0xfe, 0x76, 0x00},
        {0xda, 0xdc, 0xe1, 0x20, 0xb6, 0xd5, 0x39, 0xb3, 0x87, 0xc7, 0xa3,
         0x96, 0xae, 0x96, 0x7d, 0x9d, 0x30, 0x13, 0x85, 0x05, 0x5a, 0x51,
         0x96, 0x17, 0xd6, 0x71, 0xa5, 0x53, 0x03, 0xc1, 0x4b, 0xd6, 0x00},
        {0xc2, 0xb5, 0x2e, 0xbb, 0x4e, 0x38, 0xa0, 0x73, 0x54, 0xf3, 0x20,
         0x8e, 0xa0, 0x36, 0xa7, 0x89, 0x25, 0x4a, 0x51, 0xc7, 0x4a, 0xab,
         0x89, 0x91, 0xf7, 0x8f, 0xf5, 0x08, 0x53, 0xf7, 0xe5, 0xba, 0x00},
    };

    elliptic_curve256_algebra_ctx_t *ctx = elliptic_curve256_new_ed25519_algebra();
    REQUIRE(ctx);
    elliptic_curve256_point_t result;
    for (int i = 0; i < N; i++) {
        INFO("ed25519 vector " << i << " (" << inputs[i].label << ")");
        REQUIRE(ctx->hash_on_curve(ctx, &result, inputs[i].data, inputs[i].len) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE(memcmp(result, expected[i], sizeof(elliptic_curve256_point_t)) == 0);
    }
    elliptic_curve256_algebra_ctx_free(ctx);
}

TEST_CASE("validate_non_infinity_point (ed25519)", "ed25519") {
    elliptic_curve256_algebra_ctx_t* ed25519 = elliptic_curve256_new_ed25519_algebra();
    REQUIRE(ed25519);
    REQUIRE(ed25519->validate_non_infinity_point);

    SECTION("infinity (canonical + tail variations) is rejected") {
        const elliptic_curve256_point_t* inf = ed25519->infinity_point(ed25519);
        REQUIRE(inf);
        REQUIRE(ed25519->validate_non_infinity_point(ed25519, inf) == ELLIPTIC_CURVE_ALGEBRA_INVALID_POINT);

        elliptic_curve256_point_t p;
        memcpy(p, *inf, sizeof(p));
        p[32] = 0xAA; // tail byte is ignored by Ed25519 operations
        REQUIRE(ed25519->validate_non_infinity_point(ed25519, &p) == ELLIPTIC_CURVE_ALGEBRA_INVALID_POINT);
    }

    SECTION("valid non-infinity point is accepted") {
        elliptic_curve256_point_t p;
        elliptic_curve256_scalar_t one = {0};
        one[31] = 1;
        REQUIRE(ed25519->generator_mul(ed25519, &p, &one) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE(ed25519->validate_non_infinity_point(ed25519, &p) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
    }

    SECTION("generator_mul by zero returns infinity (rejected)") {
        elliptic_curve256_point_t p;
        elliptic_curve256_scalar_t zero = {0};
        REQUIRE(ed25519->generator_mul(ed25519, &p, &zero) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE(ed25519->validate_non_infinity_point(ed25519, &p) == ELLIPTIC_CURVE_ALGEBRA_INVALID_POINT);
    }

    SECTION("sign-bit-toggled identity encoding is invalid (rejected)") {
        const elliptic_curve256_point_t* inf = ed25519->infinity_point(ed25519);
        REQUIRE(inf);
        elliptic_curve256_point_t p;
        memcpy(p, *inf, sizeof(p));
        p[31] |= 0x80; // invalid encoding (x sign bit set for x=0)
        REQUIRE(ed25519->validate_non_infinity_point(ed25519, &p) == ELLIPTIC_CURVE_ALGEBRA_INVALID_POINT);
    }

    SECTION("obviously invalid encoding (y = 2^255-1) is rejected") {
        elliptic_curve256_point_t p;
        memset(p, 0xFF, sizeof(p));
        p[31] &= 0x7F; // clear x sign bit, keep y as 2^255-1 (not a valid field element for Ed25519)
        REQUIRE(ed25519->validate_non_infinity_point(ed25519, &p) == ELLIPTIC_CURVE_ALGEBRA_INVALID_POINT);
    }

    elliptic_curve256_algebra_ctx_free(ed25519);
}

// ============================================================================
// Ed25519 Attack Tests via Generic Interface
// Tests boundary conditions used by EdDSA BAM variant through the
// elliptic_curve256 abstraction layer.
// ============================================================================

TEST_CASE("ed25519_attacks", "[attack][ed25519]") {
    elliptic_curve256_algebra_ctx_t* ed25519 = elliptic_curve256_new_ed25519_algebra();
    REQUIRE(ed25519);

    SECTION("generator_mul with zero scalar") {
        elliptic_curve256_scalar_t zero;
        memset(zero, 0, sizeof(zero));
        elliptic_curve256_point_t result;
        elliptic_curve_algebra_status status = ed25519->generator_mul(ed25519, &result, &zero);
        // G^0 should return identity or fail
        if (status == ELLIPTIC_CURVE_ALGEBRA_SUCCESS) {
            const elliptic_curve256_point_t* inf = ed25519->infinity_point(ed25519);
            REQUIRE(inf);
            REQUIRE(ed25519->validate_non_infinity_point(ed25519, &result) == ELLIPTIC_CURVE_ALGEBRA_INVALID_POINT);
        } else {
            REQUIRE((status == ELLIPTIC_CURVE_ALGEBRA_INVALID_SCALAR || status == ELLIPTIC_CURVE_ALGEBRA_UNKNOWN_ERROR));
        }
    }

    SECTION("generator_mul with group order scalar") {
        elliptic_curve256_scalar_t order_scalar;
        const uint8_t* order_bytes = ed25519->order(ed25519);
        REQUIRE(order_bytes);
        memcpy(order_scalar, order_bytes, sizeof(elliptic_curve256_scalar_t));
        elliptic_curve256_point_t result;
        elliptic_curve_algebra_status status = ed25519->generator_mul(ed25519, &result, &order_scalar);
        // G^n = identity, should either fail or return identity
        if (status == ELLIPTIC_CURVE_ALGEBRA_SUCCESS) {
            REQUIRE(ed25519->validate_non_infinity_point(ed25519, &result) == ELLIPTIC_CURVE_ALGEBRA_INVALID_POINT);
        } else {
            REQUIRE((status == ELLIPTIC_CURVE_ALGEBRA_INVALID_SCALAR || status == ELLIPTIC_CURVE_ALGEBRA_UNKNOWN_ERROR));
        }
    }

    SECTION("point_mul with identity point") {
        // Get identity point by multiplying by zero
        elliptic_curve256_scalar_t zero;
        memset(zero, 0, sizeof(zero));
        elliptic_curve256_point_t identity;
        elliptic_curve_algebra_status status = ed25519->generator_mul(ed25519, &identity, &zero);
        if (status != ELLIPTIC_CURVE_ALGEBRA_SUCCESS) {
            // If we can't get identity this way, use the infinity_point function
            const elliptic_curve256_point_t* inf = ed25519->infinity_point(ed25519);
            REQUIRE(inf);
            memcpy(identity, *inf, sizeof(identity));
        }

        elliptic_curve256_scalar_t five = {0};
        five[sizeof(five) - 1] = 5;
        elliptic_curve256_point_t result;
        status = ed25519->point_mul(ed25519, &result, &identity, &five);
        // identity * 5 should be identity or error
        if (status == ELLIPTIC_CURVE_ALGEBRA_SUCCESS) {
            REQUIRE(ed25519->validate_non_infinity_point(ed25519, &result) == ELLIPTIC_CURVE_ALGEBRA_INVALID_POINT);
        } else {
            REQUIRE((status == ELLIPTIC_CURVE_ALGEBRA_INVALID_POINT ||
                     status == ELLIPTIC_CURVE_ALGEBRA_INVALID_PARAMETER ||
                     status == ELLIPTIC_CURVE_ALGEBRA_UNKNOWN_ERROR));
        }
    }

    SECTION("add_points P + (-P) = identity") {
        // Compute G and -G
        elliptic_curve256_scalar_t one = {0};
        one[sizeof(one) - 1] = 1;
        elliptic_curve256_point_t gen_point;
        REQUIRE(ed25519->generator_mul(ed25519, &gen_point, &one) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);

        // -G = G^(order-1)
        elliptic_curve256_scalar_t order_minus_1;
        const uint8_t* order_bytes = ed25519->order(ed25519);
        REQUIRE(order_bytes);
        memcpy(order_minus_1, order_bytes, sizeof(elliptic_curve256_scalar_t));
        // Subtract 1 from big-endian
        for (int i = sizeof(order_minus_1) - 1; i >= 0; --i) {
            if (order_minus_1[i] > 0) {
                order_minus_1[i]--;
                break;
            }
            order_minus_1[i] = 0xFF;
        }
        elliptic_curve256_point_t neg_gen;
        REQUIRE(ed25519->generator_mul(ed25519, &neg_gen, &order_minus_1) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);

        elliptic_curve256_point_t sum;
        REQUIRE(ed25519->add_points(ed25519, &sum, &gen_point, &neg_gen) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        // Result should be identity
        REQUIRE(ed25519->validate_non_infinity_point(ed25519, &sum) == ELLIPTIC_CURVE_ALGEBRA_INVALID_POINT);
    }

    SECTION("inverse of zero scalar") {
        elliptic_curve256_scalar_t zero;
        memset(zero, 0, sizeof(zero));
        elliptic_curve256_scalar_t result;
        elliptic_curve_algebra_status status = ed25519->inverse(ed25519, &result, &zero);
        // Inverse of zero is undefined — must fail
        REQUIRE(status != ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
    }

    // NOTE: cross-curve test (secp256k1 point in ed25519 context) lives in
    // secp256k1_algebra/main.cpp TEST_CASE("multi_curve_attacks") because that
    // test binary links both curve libraries.

    elliptic_curve256_algebra_ctx_free(ed25519);
}