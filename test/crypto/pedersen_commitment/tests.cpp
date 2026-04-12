#include "crypto/commitments/pedersen.h"
#include "crypto/commitments/ring_pedersen.h"
#include "../../../src/common/crypto/commitments/ring_pedersen_internal.h"
#include "crypto/elliptic_curve_algebra/elliptic_curve256_algebra.h"
#include <cstring>
#include <openssl/rand.h>
#include <openssl/bn.h>

#include <tests/catch.hpp>


TEST_CASE("test_pedersen_commitment")
{
    const uint8_t aad[] = "SOME RANDOM AAD";
    const uint32_t aad_len = sizeof(aad);
    pedersen_commitment_two_generators_t base;
    struct elliptic_curve256_algebra_ctx *ctx = NULL;
    elliptic_curve256_scalar_t a;
    elliptic_curve256_scalar_t b;
    elliptic_curve256_scalar_t c;
    elliptic_curve_commitment_t commitment;
    SECTION("test secp256k1") 
    {
        ctx = elliptic_curve256_new_secp256k1_algebra();
        REQUIRE(COMMITMENTS_SUCCESS == pedersen_commitment_two_generators_base_generate(&base, aad, aad_len, ctx));
        REQUIRE(ELLIPTIC_CURVE_ALGEBRA_SUCCESS == ctx->rand(ctx, &a));
        REQUIRE(ELLIPTIC_CURVE_ALGEBRA_SUCCESS == ctx->rand(ctx, &b));
        REQUIRE(ELLIPTIC_CURVE_ALGEBRA_SUCCESS == ctx->rand(ctx, &c));

        REQUIRE(COMMITMENTS_SUCCESS == pedersen_commitment_two_generators_create_commitment(&commitment, &base, a, sizeof(a), b, sizeof(b), c, sizeof(c), ctx));
        REQUIRE(COMMITMENTS_SUCCESS == pedersen_commitment_two_generators_verify_commitment(&commitment, &base, a, sizeof(a), b, sizeof(b), c, sizeof(c), ctx));
    }

    SECTION("test secp256r1") 
    {
        ctx = elliptic_curve256_new_secp256r1_algebra();
        REQUIRE(COMMITMENTS_SUCCESS == pedersen_commitment_two_generators_base_generate(&base, aad, aad_len, ctx));
        REQUIRE(ELLIPTIC_CURVE_ALGEBRA_SUCCESS == ctx->rand(ctx, &a));
        REQUIRE(ELLIPTIC_CURVE_ALGEBRA_SUCCESS == ctx->rand(ctx, &b));
        REQUIRE(ELLIPTIC_CURVE_ALGEBRA_SUCCESS == ctx->rand(ctx, &c));

        REQUIRE(COMMITMENTS_SUCCESS == pedersen_commitment_two_generators_create_commitment(&commitment, &base, a, sizeof(a), b, sizeof(b), c, sizeof(c), ctx));
        REQUIRE(COMMITMENTS_SUCCESS == pedersen_commitment_two_generators_verify_commitment(&commitment, &base, a, sizeof(a), b, sizeof(b), c, sizeof(c), ctx));
    }


    SECTION("test stark") 
    {
        ctx = elliptic_curve256_new_stark_algebra();
        REQUIRE(COMMITMENTS_SUCCESS == pedersen_commitment_two_generators_base_generate(&base, aad, aad_len, ctx));
        REQUIRE(ELLIPTIC_CURVE_ALGEBRA_SUCCESS == ctx->rand(ctx, &a));
        REQUIRE(ELLIPTIC_CURVE_ALGEBRA_SUCCESS == ctx->rand(ctx, &b));
        REQUIRE(ELLIPTIC_CURVE_ALGEBRA_SUCCESS == ctx->rand(ctx, &c));

        REQUIRE(COMMITMENTS_SUCCESS == pedersen_commitment_two_generators_create_commitment(&commitment, &base, a, sizeof(a), b, sizeof(b), c, sizeof(c), ctx));
        REQUIRE(COMMITMENTS_SUCCESS == pedersen_commitment_two_generators_verify_commitment(&commitment, &base, a, sizeof(a), b, sizeof(b), c, sizeof(c), ctx));
    }

    SECTION("test ed25519") 
    {
        ctx = elliptic_curve256_new_ed25519_algebra();
        REQUIRE(COMMITMENTS_SUCCESS == pedersen_commitment_two_generators_base_generate(&base, aad, aad_len, ctx));
        REQUIRE(ELLIPTIC_CURVE_ALGEBRA_SUCCESS == ctx->rand(ctx, &a));
        REQUIRE(ELLIPTIC_CURVE_ALGEBRA_SUCCESS == ctx->rand(ctx, &b));
        REQUIRE(ELLIPTIC_CURVE_ALGEBRA_SUCCESS == ctx->rand(ctx, &c));

        REQUIRE(COMMITMENTS_SUCCESS == pedersen_commitment_two_generators_create_commitment(&commitment, &base, a, sizeof(a), b, sizeof(b), c, sizeof(c), ctx));
        REQUIRE(COMMITMENTS_SUCCESS == pedersen_commitment_two_generators_verify_commitment(&commitment, &base, a, sizeof(a), b, sizeof(b), c, sizeof(c), ctx));
    }


    SECTION("negative test1") 
    {
        ctx = elliptic_curve256_new_secp256k1_algebra();
        REQUIRE(COMMITMENTS_SUCCESS == pedersen_commitment_two_generators_base_generate(&base, aad, aad_len, ctx));
        REQUIRE(ELLIPTIC_CURVE_ALGEBRA_SUCCESS == ctx->rand(ctx, &a));
        REQUIRE(ELLIPTIC_CURVE_ALGEBRA_SUCCESS == ctx->rand(ctx, &b));
        REQUIRE(ELLIPTIC_CURVE_ALGEBRA_SUCCESS == ctx->rand(ctx, &c));

        REQUIRE(COMMITMENTS_SUCCESS == pedersen_commitment_two_generators_create_commitment(&commitment, &base, a, sizeof(a), b, sizeof(b), c, sizeof(c), ctx));
        for (int i = 0; i < ctx->point_size(ctx) * 8; ++i)
        {
            commitment[i / 8] ^=  (0x1 << (i % 8)); //flip bit
            REQUIRE(COMMITMENTS_INVALID_COMMITMENT == pedersen_commitment_two_generators_verify_commitment(&commitment, &base, a, sizeof(a), b, sizeof(b), c, sizeof(c), ctx));
            commitment[i / 8] ^=  (0x1 << (i % 8)); //flip bit back
        }
        REQUIRE(COMMITMENTS_SUCCESS == pedersen_commitment_two_generators_verify_commitment(&commitment, &base, a, sizeof(a), b, sizeof(b), c, sizeof(c), ctx));
    }

    SECTION("negative test2") 
    {
        const uint8_t another_aad[] = "ANOTHER AAD";
        const uint32_t another_aad_len = sizeof(another_aad);
        pedersen_commitment_two_generators_t another_base;
        ctx = elliptic_curve256_new_secp256k1_algebra();
        REQUIRE(COMMITMENTS_SUCCESS == pedersen_commitment_two_generators_base_generate(&base, aad, aad_len, ctx));
        
        REQUIRE(ELLIPTIC_CURVE_ALGEBRA_SUCCESS == ctx->rand(ctx, &a));
        REQUIRE(ELLIPTIC_CURVE_ALGEBRA_SUCCESS == ctx->rand(ctx, &b));
        REQUIRE(ELLIPTIC_CURVE_ALGEBRA_SUCCESS == ctx->rand(ctx, &c));

        REQUIRE(COMMITMENTS_SUCCESS == pedersen_commitment_two_generators_create_commitment(&commitment, &base, a, sizeof(a), b, sizeof(b), c, sizeof(c), ctx));

        REQUIRE(COMMITMENTS_SUCCESS == pedersen_commitment_two_generators_base_generate(&another_base, another_aad, another_aad_len, ctx));

        REQUIRE(COMMITMENTS_INVALID_COMMITMENT == pedersen_commitment_two_generators_verify_commitment(&commitment, &another_base, a, sizeof(a), b, sizeof(b), c, sizeof(c), ctx));
    }


    if (ctx)
    {
        ctx->release(ctx);
    }
}

TEST_CASE("pedersen_commitment_attacks")
{
    const uint8_t aad[] = "SOME RANDOM AAD";
    const uint32_t aad_len = sizeof(aad);

    SECTION("zero scalar a")
    {
        elliptic_curve256_algebra_ctx_t *ctx = elliptic_curve256_new_secp256k1_algebra();
        REQUIRE(ctx != NULL);

        pedersen_commitment_two_generators_t base;
        REQUIRE(COMMITMENTS_SUCCESS == pedersen_commitment_two_generators_base_generate(&base, aad, aad_len, ctx));

        elliptic_curve256_scalar_t a, b, c;
        memset(a, 0, sizeof(a));
        REQUIRE(ELLIPTIC_CURVE_ALGEBRA_SUCCESS == ctx->rand(ctx, &b));
        REQUIRE(ELLIPTIC_CURVE_ALGEBRA_SUCCESS == ctx->rand(ctx, &c));

        elliptic_curve_commitment_t commitment;
        commitments_status create_ret = pedersen_commitment_two_generators_create_commitment(&commitment, &base, a, sizeof(a), b, sizeof(b), c, sizeof(c), ctx);
        if (create_ret == COMMITMENTS_SUCCESS)
        {
            REQUIRE(COMMITMENTS_SUCCESS == pedersen_commitment_two_generators_verify_commitment(&commitment, &base, a, sizeof(a), b, sizeof(b), c, sizeof(c), ctx));
        }

        elliptic_curve256_algebra_ctx_free(ctx);
    }

    SECTION("zero scalar b")
    {
        elliptic_curve256_algebra_ctx_t *ctx = elliptic_curve256_new_secp256k1_algebra();
        REQUIRE(ctx != NULL);

        pedersen_commitment_two_generators_t base;
        REQUIRE(COMMITMENTS_SUCCESS == pedersen_commitment_two_generators_base_generate(&base, aad, aad_len, ctx));

        elliptic_curve256_scalar_t a, b, c;
        REQUIRE(ELLIPTIC_CURVE_ALGEBRA_SUCCESS == ctx->rand(ctx, &a));
        memset(b, 0, sizeof(b));
        REQUIRE(ELLIPTIC_CURVE_ALGEBRA_SUCCESS == ctx->rand(ctx, &c));

        elliptic_curve_commitment_t commitment;
        commitments_status create_ret = pedersen_commitment_two_generators_create_commitment(&commitment, &base, a, sizeof(a), b, sizeof(b), c, sizeof(c), ctx);
        if (create_ret == COMMITMENTS_SUCCESS)
        {
            REQUIRE(COMMITMENTS_SUCCESS == pedersen_commitment_two_generators_verify_commitment(&commitment, &base, a, sizeof(a), b, sizeof(b), c, sizeof(c), ctx));
        }

        elliptic_curve256_algebra_ctx_free(ctx);
    }

    SECTION("both zero scalars")
    {
        elliptic_curve256_algebra_ctx_t *ctx = elliptic_curve256_new_secp256k1_algebra();
        REQUIRE(ctx != NULL);

        pedersen_commitment_two_generators_t base;
        REQUIRE(COMMITMENTS_SUCCESS == pedersen_commitment_two_generators_base_generate(&base, aad, aad_len, ctx));

        elliptic_curve256_scalar_t a, b, c;
        memset(a, 0, sizeof(a));
        memset(b, 0, sizeof(b));
        memset(c, 0, sizeof(c));

        elliptic_curve_commitment_t commitment;
        commitments_status create_ret = pedersen_commitment_two_generators_create_commitment(&commitment, &base, a, sizeof(a), b, sizeof(b), c, sizeof(c), ctx);
        if (create_ret == COMMITMENTS_SUCCESS)
        {
            REQUIRE(COMMITMENTS_SUCCESS == pedersen_commitment_two_generators_verify_commitment(&commitment, &base, a, sizeof(a), b, sizeof(b), c, sizeof(c), ctx));
        }

        elliptic_curve256_algebra_ctx_free(ctx);
    }

    SECTION("order scalar a")
    {
        elliptic_curve256_algebra_ctx_t *ctx = elliptic_curve256_new_secp256k1_algebra();
        REQUIRE(ctx != NULL);

        pedersen_commitment_two_generators_t base;
        REQUIRE(COMMITMENTS_SUCCESS == pedersen_commitment_two_generators_base_generate(&base, aad, aad_len, ctx));

        elliptic_curve256_scalar_t a, b, c;
        const uint8_t *order = ctx->order(ctx);
        memcpy(a, order, sizeof(a));
        REQUIRE(ELLIPTIC_CURVE_ALGEBRA_SUCCESS == ctx->rand(ctx, &b));
        REQUIRE(ELLIPTIC_CURVE_ALGEBRA_SUCCESS == ctx->rand(ctx, &c));

        elliptic_curve_commitment_t commitment;
        commitments_status create_ret = pedersen_commitment_two_generators_create_commitment(&commitment, &base, a, sizeof(a), b, sizeof(b), c, sizeof(c), ctx);
        // Scalar equal to the curve order is equivalent to zero mod n.
        // Either the implementation rejects it or it produces a valid commitment for zero.
        if (create_ret == COMMITMENTS_SUCCESS)
        {
            REQUIRE(COMMITMENTS_SUCCESS == pedersen_commitment_two_generators_verify_commitment(&commitment, &base, a, sizeof(a), b, sizeof(b), c, sizeof(c), ctx));
        }

        elliptic_curve256_algebra_ctx_free(ctx);
    }

    SECTION("infinity point in base h")
    {
        elliptic_curve256_algebra_ctx_t *ctx = elliptic_curve256_new_secp256k1_algebra();
        REQUIRE(ctx != NULL);

        pedersen_commitment_two_generators_t base;
        REQUIRE(COMMITMENTS_SUCCESS == pedersen_commitment_two_generators_base_generate(&base, aad, aad_len, ctx));

        elliptic_curve256_scalar_t a, b, c;
        REQUIRE(ELLIPTIC_CURVE_ALGEBRA_SUCCESS == ctx->rand(ctx, &a));
        REQUIRE(ELLIPTIC_CURVE_ALGEBRA_SUCCESS == ctx->rand(ctx, &b));
        REQUIRE(ELLIPTIC_CURVE_ALGEBRA_SUCCESS == ctx->rand(ctx, &c));

        // Create a valid commitment first
        elliptic_curve_commitment_t commitment;
        REQUIRE(COMMITMENTS_SUCCESS == pedersen_commitment_two_generators_create_commitment(&commitment, &base, a, sizeof(a), b, sizeof(b), c, sizeof(c), ctx));

        // Tamper base.h with the infinity point
        pedersen_commitment_two_generators_t tampered_base;
        memcpy(&tampered_base, &base, sizeof(base));
        const elliptic_curve256_point_t *inf = ctx->infinity_point(ctx);
        memcpy(tampered_base.h, *inf, sizeof(elliptic_curve256_point_t));

        // Verification with tampered base must fail
        REQUIRE(COMMITMENTS_SUCCESS != pedersen_commitment_two_generators_verify_commitment(&commitment, &tampered_base, a, sizeof(a), b, sizeof(b), c, sizeof(c), ctx));

        elliptic_curve256_algebra_ctx_free(ctx);
    }

    SECTION("infinity point in base f")
    {
        elliptic_curve256_algebra_ctx_t *ctx = elliptic_curve256_new_secp256k1_algebra();
        REQUIRE(ctx != NULL);

        pedersen_commitment_two_generators_t base;
        REQUIRE(COMMITMENTS_SUCCESS == pedersen_commitment_two_generators_base_generate(&base, aad, aad_len, ctx));

        elliptic_curve256_scalar_t a, b, c;
        REQUIRE(ELLIPTIC_CURVE_ALGEBRA_SUCCESS == ctx->rand(ctx, &a));
        REQUIRE(ELLIPTIC_CURVE_ALGEBRA_SUCCESS == ctx->rand(ctx, &b));
        REQUIRE(ELLIPTIC_CURVE_ALGEBRA_SUCCESS == ctx->rand(ctx, &c));

        // Create a valid commitment first
        elliptic_curve_commitment_t commitment;
        REQUIRE(COMMITMENTS_SUCCESS == pedersen_commitment_two_generators_create_commitment(&commitment, &base, a, sizeof(a), b, sizeof(b), c, sizeof(c), ctx));

        // Tamper base.f with the infinity point
        pedersen_commitment_two_generators_t tampered_base;
        memcpy(&tampered_base, &base, sizeof(base));
        const elliptic_curve256_point_t *inf = ctx->infinity_point(ctx);
        memcpy(tampered_base.f, *inf, sizeof(elliptic_curve256_point_t));

        // Verification with tampered base must fail
        REQUIRE(COMMITMENTS_SUCCESS != pedersen_commitment_two_generators_verify_commitment(&commitment, &tampered_base, a, sizeof(a), b, sizeof(b), c, sizeof(c), ctx));

        elliptic_curve256_algebra_ctx_free(ctx);
    }

    SECTION("negated commitment")
    {
        elliptic_curve256_algebra_ctx_t *ctx = elliptic_curve256_new_secp256k1_algebra();
        REQUIRE(ctx != NULL);

        pedersen_commitment_two_generators_t base;
        REQUIRE(COMMITMENTS_SUCCESS == pedersen_commitment_two_generators_base_generate(&base, aad, aad_len, ctx));

        elliptic_curve256_scalar_t a, b, c;
        REQUIRE(ELLIPTIC_CURVE_ALGEBRA_SUCCESS == ctx->rand(ctx, &a));
        REQUIRE(ELLIPTIC_CURVE_ALGEBRA_SUCCESS == ctx->rand(ctx, &b));
        REQUIRE(ELLIPTIC_CURVE_ALGEBRA_SUCCESS == ctx->rand(ctx, &c));

        elliptic_curve_commitment_t commitment;
        REQUIRE(COMMITMENTS_SUCCESS == pedersen_commitment_two_generators_create_commitment(&commitment, &base, a, sizeof(a), b, sizeof(b), c, sizeof(c), ctx));

        // Verify the original commitment is valid
        REQUIRE(COMMITMENTS_SUCCESS == pedersen_commitment_two_generators_verify_commitment(&commitment, &base, a, sizeof(a), b, sizeof(b), c, sizeof(c), ctx));

        // Flip the parity byte (0x02 <-> 0x03) to negate the point
        elliptic_curve_commitment_t negated_commitment;
        memcpy(negated_commitment, commitment, sizeof(negated_commitment));
        if (negated_commitment[0] == 0x02)
            negated_commitment[0] = 0x03;
        else if (negated_commitment[0] == 0x03)
            negated_commitment[0] = 0x02;

        REQUIRE(COMMITMENTS_SUCCESS != pedersen_commitment_two_generators_verify_commitment(&negated_commitment, &base, a, sizeof(a), b, sizeof(b), c, sizeof(c), ctx));

        elliptic_curve256_algebra_ctx_free(ctx);
    }

    SECTION("cross-curve verification")
    {
        elliptic_curve256_algebra_ctx_t *ctx_k1 = elliptic_curve256_new_secp256k1_algebra();
        REQUIRE(ctx_k1 != NULL);
        elliptic_curve256_algebra_ctx_t *ctx_r1 = elliptic_curve256_new_secp256r1_algebra();
        REQUIRE(ctx_r1 != NULL);

        pedersen_commitment_two_generators_t base_k1;
        REQUIRE(COMMITMENTS_SUCCESS == pedersen_commitment_two_generators_base_generate(&base_k1, aad, aad_len, ctx_k1));

        elliptic_curve256_scalar_t a, b, c;
        REQUIRE(ELLIPTIC_CURVE_ALGEBRA_SUCCESS == ctx_k1->rand(ctx_k1, &a));
        REQUIRE(ELLIPTIC_CURVE_ALGEBRA_SUCCESS == ctx_k1->rand(ctx_k1, &b));
        REQUIRE(ELLIPTIC_CURVE_ALGEBRA_SUCCESS == ctx_k1->rand(ctx_k1, &c));

        elliptic_curve_commitment_t commitment;
        REQUIRE(COMMITMENTS_SUCCESS == pedersen_commitment_two_generators_create_commitment(&commitment, &base_k1, a, sizeof(a), b, sizeof(b), c, sizeof(c), ctx_k1));

        // Generate base on secp256r1 with the same AAD
        pedersen_commitment_two_generators_t base_r1;
        REQUIRE(COMMITMENTS_SUCCESS == pedersen_commitment_two_generators_base_generate(&base_r1, aad, aad_len, ctx_r1));

        // Verification on a different curve must fail
        REQUIRE(COMMITMENTS_SUCCESS != pedersen_commitment_two_generators_verify_commitment(&commitment, &base_r1, a, sizeof(a), b, sizeof(b), c, sizeof(c), ctx_r1));

        elliptic_curve256_algebra_ctx_free(ctx_k1);
        elliptic_curve256_algebra_ctx_free(ctx_r1);
    }

    SECTION("random byte corruption in commitment")
    {
        elliptic_curve256_algebra_ctx_t *ctx = elliptic_curve256_new_secp256k1_algebra();
        REQUIRE(ctx != NULL);

        pedersen_commitment_two_generators_t base;
        REQUIRE(COMMITMENTS_SUCCESS == pedersen_commitment_two_generators_base_generate(&base, aad, aad_len, ctx));

        elliptic_curve256_scalar_t a, b, c;
        REQUIRE(ELLIPTIC_CURVE_ALGEBRA_SUCCESS == ctx->rand(ctx, &a));
        REQUIRE(ELLIPTIC_CURVE_ALGEBRA_SUCCESS == ctx->rand(ctx, &b));
        REQUIRE(ELLIPTIC_CURVE_ALGEBRA_SUCCESS == ctx->rand(ctx, &c));

        elliptic_curve_commitment_t commitment;
        REQUIRE(COMMITMENTS_SUCCESS == pedersen_commitment_two_generators_create_commitment(&commitment, &base, a, sizeof(a), b, sizeof(b), c, sizeof(c), ctx));
        REQUIRE(COMMITMENTS_SUCCESS == pedersen_commitment_two_generators_verify_commitment(&commitment, &base, a, sizeof(a), b, sizeof(b), c, sizeof(c), ctx));

        // Corrupt multiple random bytes and check each time
        uint8_t point_size = ctx->point_size(ctx);
        for (int trial = 0; trial < 10; trial++)
        {
            elliptic_curve_commitment_t corrupted;
            memcpy(corrupted, commitment, sizeof(corrupted));

            // Pick a random byte position within the point and XOR with a non-zero value
            uint32_t pos;
            RAND_bytes((uint8_t *)&pos, sizeof(pos));
            pos %= point_size;
            uint8_t xor_val = 0;
            while (xor_val == 0)
            {
                RAND_bytes(&xor_val, 1);
            }
            corrupted[pos] ^= xor_val;

            REQUIRE(COMMITMENTS_SUCCESS != pedersen_commitment_two_generators_verify_commitment(&corrupted, &base, a, sizeof(a), b, sizeof(b), c, sizeof(c), ctx));
        }

        elliptic_curve256_algebra_ctx_free(ctx);
    }

    SECTION("STARK curve zero scalar")
    {
        elliptic_curve256_algebra_ctx_t *ctx = elliptic_curve256_new_stark_algebra();
        REQUIRE(ctx != NULL);

        pedersen_commitment_two_generators_t base;
        REQUIRE(COMMITMENTS_SUCCESS == pedersen_commitment_two_generators_base_generate(&base, aad, aad_len, ctx));

        elliptic_curve256_scalar_t a, b, c;
        memset(a, 0, sizeof(a));
        REQUIRE(ELLIPTIC_CURVE_ALGEBRA_SUCCESS == ctx->rand(ctx, &b));
        REQUIRE(ELLIPTIC_CURVE_ALGEBRA_SUCCESS == ctx->rand(ctx, &c));

        elliptic_curve_commitment_t commitment;
        commitments_status create_ret = pedersen_commitment_two_generators_create_commitment(&commitment, &base, a, sizeof(a), b, sizeof(b), c, sizeof(c), ctx);
        if (create_ret == COMMITMENTS_SUCCESS)
        {
            REQUIRE(COMMITMENTS_SUCCESS == pedersen_commitment_two_generators_verify_commitment(&commitment, &base, a, sizeof(a), b, sizeof(b), c, sizeof(c), ctx));
        }

        elliptic_curve256_algebra_ctx_free(ctx);
    }
}

TEST_CASE("ring_pedersen_key_validity", "[correctness]")
{
    ring_pedersen_public_t* pub = NULL;
    ring_pedersen_private_t* priv = NULL;
    auto status = ring_pedersen_generate_key_pair(1024, &pub, &priv);
    REQUIRE(status == RING_PEDERSEN_SUCCESS);

    SECTION("N is the product of two factors via phi_n consistency")
    {
        // phi_n should be (p-1)*(q-1) for some p, q where N = p*q
        // We verify: N > phi_n (since N = p*q > (p-1)*(q-1))
        // and phi_n > 0
        REQUIRE(!BN_is_zero(priv->phi_n));
        REQUIRE(BN_cmp(pub->n, priv->phi_n) > 0);
    }

    SECTION("N has requested bit size")
    {
        int n_bits = BN_num_bits(pub->n);
        // key_len=1024 means N is ~1024 bits (p and q are each ~512 bits)
        REQUIRE(n_bits >= 1023);
        REQUIRE(n_bits <= 1024);
    }

    SECTION("s is not 1 mod N")
    {
        REQUIRE(!BN_is_one(pub->s));
    }

    SECTION("t is not 1 mod N")
    {
        REQUIRE(!BN_is_one(pub->t));
    }

    SECTION("s != t")
    {
        REQUIRE(BN_cmp(pub->s, pub->t) != 0);
    }

    SECTION("lambda is nonzero")
    {
        REQUIRE(!BN_is_zero(priv->lambda));
    }

    SECTION("t^lambda = s mod N")
    {
        // The Ring-Pedersen relation: s = t^lambda mod N
        BN_CTX* ctx = BN_CTX_new();
        BIGNUM* computed_s = BN_new();
        BN_mod_exp(computed_s, pub->t, priv->lambda, pub->n, ctx);
        REQUIRE(BN_cmp(computed_s, pub->s) == 0);
        BN_free(computed_s);
        BN_CTX_free(ctx);
    }

    ring_pedersen_free_public(pub);
    ring_pedersen_free_private(priv);
}

TEST_CASE("ring_pedersen_homomorphic", "[correctness]")
{
    ring_pedersen_public_t* pub = NULL;
    ring_pedersen_private_t* priv = NULL;
    auto status = ring_pedersen_generate_key_pair(1024, &pub, &priv);
    REQUIRE(status == RING_PEDERSEN_SUCCESS);

    SECTION("Commit(x1,r1) * Commit(x2,r2) = Commit(x1+x2, r1+r2) mod N")
    {
        BN_CTX* ctx = BN_CTX_new();

        // Generate random x1, r1, x2, r2
        BIGNUM* x1 = BN_new();
        BIGNUM* r1 = BN_new();
        BIGNUM* x2 = BN_new();
        BIGNUM* r2 = BN_new();
        BN_rand(x1, 256, -1, 0);
        BN_rand(r1, 256, -1, 0);
        BN_rand(x2, 256, -1, 0);
        BN_rand(r2, 256, -1, 0);

        // Commit(x1, r1) = s^x1 * t^r1 mod N
        BIGNUM* c1 = BN_new();
        REQUIRE(ring_pedersen_create_commitment_internal(pub, x1, r1, c1, ctx) == RING_PEDERSEN_SUCCESS);

        // Commit(x2, r2) = s^x2 * t^r2 mod N
        BIGNUM* c2 = BN_new();
        REQUIRE(ring_pedersen_create_commitment_internal(pub, x2, r2, c2, ctx) == RING_PEDERSEN_SUCCESS);

        // Product: c1 * c2 mod N
        BIGNUM* product = BN_new();
        BN_mod_mul(product, c1, c2, pub->n, ctx);

        // Commit(x1+x2, r1+r2)
        BIGNUM* x_sum = BN_new();
        BIGNUM* r_sum = BN_new();
        BN_add(x_sum, x1, x2);
        BN_add(r_sum, r1, r2);
        BIGNUM* c_sum = BN_new();
        REQUIRE(ring_pedersen_create_commitment_internal(pub, x_sum, r_sum, c_sum, ctx) == RING_PEDERSEN_SUCCESS);

        REQUIRE(BN_cmp(product, c_sum) == 0);

        BN_free(x1);
        BN_free(r1);
        BN_free(x2);
        BN_free(r2);
        BN_free(c1);
        BN_free(c2);
        BN_free(product);
        BN_free(x_sum);
        BN_free(r_sum);
        BN_free(c_sum);
        BN_CTX_free(ctx);
    }

    ring_pedersen_free_public(pub);
    ring_pedersen_free_private(priv);
}

TEST_CASE("ring_pedersen_keys_no_common_factors", "[statistical]")
{
    // Generate multiple Ring-Pedersen keys and verify GCD(N_i, N_j) == 1 for all pairs.
    const int NUM_KEYS = 50;

    SECTION("50 keys have pairwise coprime moduli")
    {
        BIGNUM* moduli[50];

        for (int i = 0; i < NUM_KEYS; i++)
        {
            ring_pedersen_public_t* pub_i = NULL;
            ring_pedersen_private_t* s = NULL;
            REQUIRE(ring_pedersen_generate_key_pair(1024, &pub_i, &s) == RING_PEDERSEN_SUCCESS);
            moduli[i] = BN_dup(pub_i->n);
            REQUIRE(moduli[i] != NULL);
            ring_pedersen_free_public(pub_i);
            ring_pedersen_free_private(s);
        }

        BN_CTX* ctx = BN_CTX_new();
        BIGNUM* gcd = BN_new();

        for (int i = 0; i < NUM_KEYS; i++)
        {
            for (int j = i + 1; j < NUM_KEYS; j++)
            {
                BN_gcd(gcd, moduli[i], moduli[j], ctx);
                REQUIRE(BN_is_one(gcd));
            }
        }

        BN_free(gcd);
        BN_CTX_free(ctx);
        for (int i = 0; i < NUM_KEYS; i++)
        {
            BN_free(moduli[i]);
        }
    }
}
