#include "crypto/zero_knowledge_proof/schnorr.h"
#include "crypto/zero_knowledge_proof/range_proofs.h"
#include "crypto/zero_knowledge_proof/diffie_hellman_log.h"
#include "crypto/commitments/damgard_fujisaki.h"
#include "crypto/paillier_commitment/paillier_commitment.h"
#include "../../../src/common/crypto/paillier/paillier_internal.h"
#include "crypto/GFp_curve_algebra/GFp_curve_algebra.h"
#include "crypto/commitments/damgard_fujisaki.h"
#include "crypto/paillier_commitment/paillier_commitment.h"
#include "../../../src/common/crypto/paillier/paillier_internal.h"

#include "attack_helpers.h"

#include <openssl/rand.h>
#include <openssl/bn.h>

#include <iostream>
#include <vector>

#include <string.h>

#include <tests/catch.hpp>

using namespace attack_helpers;

TEST_CASE("schnorr", "[default]") 
{
    GFp_curve_algebra_ctx_t* ctx = secp256k1_algebra_ctx_new();
    elliptic_curve256_algebra_ctx_t* secp256k1_algebra = elliptic_curve256_new_secp256k1_algebra();

    SECTION("verify") 
    {
        elliptic_curve256_scalar_t a;
        elliptic_curve256_point_t A;
        REQUIRE(ctx);
        elliptic_curve_algebra_status status = GFp_curve_algebra_rand(ctx, &a);
        REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        status = GFp_curve_algebra_generator_mul_data(ctx, (uint8_t*)a, sizeof(a), &A);
        REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);

        schnorr_zkp_t zkp;
        zero_knowledge_proof_status status2 = schnorr_zkp_generate(secp256k1_algebra, a, sizeof(a), &a, &A, &zkp);
        REQUIRE(status2 == ZKP_SUCCESS);
        status2 = schnorr_zkp_verify(secp256k1_algebra, a, sizeof(a), &A, &zkp);
        REQUIRE(status2 == ZKP_SUCCESS);
    }

    SECTION("verify raw data") 
    {
        uint8_t a[32];
        elliptic_curve256_point_t A;
        REQUIRE(ctx);
        REQUIRE(RAND_bytes(a, sizeof(a)));

        schnorr_zkp_t zkp;
        zero_knowledge_proof_status status2 = schnorr_zkp_generate_for_data(secp256k1_algebra, a, sizeof(a), a, sizeof(a), &A, &zkp);
        REQUIRE(status2 == ZKP_SUCCESS);
        status2 = schnorr_zkp_verify(secp256k1_algebra, a, sizeof(a), &A, &zkp);
        REQUIRE(status2 == ZKP_SUCCESS);
    }

    SECTION("verify large raw data") 
    {
        uint8_t a[80];
        elliptic_curve256_point_t A;
        REQUIRE(ctx);
        REQUIRE(RAND_bytes(a, sizeof(a)));

        schnorr_zkp_t zkp;
        zero_knowledge_proof_status status2 = schnorr_zkp_generate_for_data(secp256k1_algebra, a, sizeof(a), a, sizeof(a), &A, &zkp);
        REQUIRE(status2 == ZKP_SUCCESS);
        status2 = schnorr_zkp_verify(secp256k1_algebra, a, sizeof(a), &A, &zkp);
        REQUIRE(status2 == ZKP_SUCCESS);
    }

    SECTION("invalid public") 
    {
        elliptic_curve256_scalar_t a;
        elliptic_curve256_point_t A;
        REQUIRE(ctx);
        elliptic_curve_algebra_status status = GFp_curve_algebra_rand(ctx, &a);
        REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        elliptic_curve256_scalar_t a2;
        memcpy(a2, a, sizeof(a));
        a2[sizeof(a2) - 1]++;
        status = GFp_curve_algebra_generator_mul_data(ctx, (uint8_t*)a2, sizeof(a2), &A);
        REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);

        schnorr_zkp_t zkp;
        zero_knowledge_proof_status status2 = schnorr_zkp_generate(secp256k1_algebra, a, sizeof(a), &a, &A, &zkp);
        REQUIRE(status2 == ZKP_SUCCESS);
        status2 = schnorr_zkp_verify(secp256k1_algebra, a, sizeof(a), &A, &zkp);
        REQUIRE(status2 == ZKP_VERIFICATION_FAILED);
    }

    SECTION("invalid secret") 
    {
        elliptic_curve256_scalar_t a;
        elliptic_curve256_point_t A;
        REQUIRE(ctx);
        elliptic_curve_algebra_status status = GFp_curve_algebra_rand(ctx, &a);
        REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        status = GFp_curve_algebra_generator_mul_data(ctx, (uint8_t*)a, sizeof(a), &A);
        REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        a[sizeof(a) - 1]++;

        schnorr_zkp_t zkp;
        zero_knowledge_proof_status status2 = schnorr_zkp_generate(secp256k1_algebra, a, sizeof(a), &a, &A, &zkp);
        REQUIRE(status2 == ZKP_SUCCESS);
        status2 = schnorr_zkp_verify(secp256k1_algebra, a, sizeof(a), &A, &zkp);
        REQUIRE(status2 == ZKP_VERIFICATION_FAILED);
    }

    SECTION("invalid id") 
    {
        elliptic_curve256_scalar_t a;
        elliptic_curve256_point_t A;
        REQUIRE(ctx);
        elliptic_curve_algebra_status status = GFp_curve_algebra_rand(ctx, &a);
        REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        status = GFp_curve_algebra_generator_mul_data(ctx, (uint8_t*)a, sizeof(a), &A);
        REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);

        schnorr_zkp_t zkp;
        zero_knowledge_proof_status status2 = schnorr_zkp_generate(secp256k1_algebra, a, sizeof(a), &a, &A, &zkp);
        REQUIRE(status2 == ZKP_SUCCESS);
        a[sizeof(a) - 1]++;
        status2 = schnorr_zkp_verify(secp256k1_algebra, a, sizeof(a), &A, &zkp);
        REQUIRE(status2 == ZKP_VERIFICATION_FAILED);
    }

    SECTION("invalid proof") 
    {
        elliptic_curve256_scalar_t a;
        elliptic_curve256_point_t A;
        REQUIRE(ctx);
        elliptic_curve_algebra_status status = GFp_curve_algebra_rand(ctx, &a);
        REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        status = GFp_curve_algebra_generator_mul_data(ctx, (uint8_t*)a, sizeof(a), &A);
        REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        
        schnorr_zkp_t zkp;
        zero_knowledge_proof_status status2 = schnorr_zkp_generate(secp256k1_algebra, a, sizeof(a), &a, &A, &zkp);
        REQUIRE(status2 == ZKP_SUCCESS);
        zkp.R[sizeof(elliptic_curve256_point_t) - 1]++;
        status2 = schnorr_zkp_verify(secp256k1_algebra, a, sizeof(a), &A, &zkp);
        REQUIRE((status2 == ZKP_VERIFICATION_FAILED || status2 == ZKP_INVALID_PARAMETER));
        zkp.R[sizeof(elliptic_curve256_point_t) - 1]--;
        zkp.s[sizeof(elliptic_curve256_scalar_t) - 1]++;
        status2 = schnorr_zkp_verify(secp256k1_algebra, a, sizeof(a), &A, &zkp);
        REQUIRE(status2 == ZKP_VERIFICATION_FAILED);

        zkp.R[sizeof(elliptic_curve256_point_t) - 1] += 11;
        status2 = schnorr_zkp_verify(secp256k1_algebra, a, sizeof(a), &A, &zkp);
        REQUIRE((status2 == ZKP_VERIFICATION_FAILED || status2 == ZKP_INVALID_PARAMETER));
    }

    SECTION("custom k") 
    {
        elliptic_curve256_scalar_t a;
        elliptic_curve256_point_t A;
        elliptic_curve256_scalar_t k;
        elliptic_curve256_point_t R;
        REQUIRE(ctx);
        elliptic_curve_algebra_status status = GFp_curve_algebra_rand(ctx, &a);
        REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        status = GFp_curve_algebra_generator_mul_data(ctx, (uint8_t*)a, sizeof(a), &A);
        REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        status = GFp_curve_algebra_rand(ctx, &k);
        REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        status = GFp_curve_algebra_generator_mul_data(ctx, (uint8_t*)k, sizeof(k), &R);
        REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        
        schnorr_zkp_t zkp;
        zero_knowledge_proof_status status2 = schnorr_zkp_generate_with_custom_randomness(secp256k1_algebra, a, sizeof(a), &a, &A, &k, &zkp);
        REQUIRE(status2 == ZKP_SUCCESS);
        status2 = schnorr_zkp_verify(secp256k1_algebra, a, sizeof(a), &A, &zkp);
        REQUIRE(status2 == ZKP_SUCCESS);
        REQUIRE(memcmp(zkp.R, R, sizeof(R)) == 0);

        k[sizeof(k) - 1]++;
        status2 = schnorr_zkp_generate_with_custom_randomness(secp256k1_algebra, a, sizeof(a), &a, &A, &k, &zkp);
        REQUIRE(status2 == ZKP_SUCCESS);
        status2 = schnorr_zkp_verify(secp256k1_algebra, a, sizeof(a), &A, &zkp);
        REQUIRE(status2 == ZKP_SUCCESS);
        REQUIRE(memcmp(zkp.R, R, sizeof(R)) != 0);

        memcpy(zkp.R, R, sizeof(R));
        status2 = schnorr_zkp_verify(secp256k1_algebra, a, sizeof(a), &A, &zkp);
        REQUIRE(status2 == ZKP_VERIFICATION_FAILED);

        memset(k, 0, sizeof(k));
        status2 = schnorr_zkp_generate_with_custom_randomness(secp256k1_algebra, a, sizeof(a), &a, &A, &k, &zkp);
        REQUIRE(status2 == ZKP_INVALID_PARAMETER);
    }

    SECTION("invalid param") 
    {
        elliptic_curve256_scalar_t a;
        elliptic_curve256_point_t A;
        REQUIRE(ctx);
        elliptic_curve_algebra_status status = GFp_curve_algebra_rand(ctx, &a);
        REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        status = GFp_curve_algebra_generator_mul_data(ctx, (uint8_t*)a, sizeof(a), &A);
        REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        
        schnorr_zkp_t zkp;
        zero_knowledge_proof_status status2 = schnorr_zkp_generate(secp256k1_algebra, NULL, sizeof(a), &a, &A, &zkp);
        REQUIRE(status2 == ZKP_INVALID_PARAMETER);
        status2 = schnorr_zkp_generate(secp256k1_algebra, a, 0, &a, &A, &zkp);
        REQUIRE(status2 == ZKP_INVALID_PARAMETER);
        status2 = schnorr_zkp_generate(secp256k1_algebra, a, sizeof(a), NULL, &A, &zkp);
        REQUIRE(status2 == ZKP_INVALID_PARAMETER);
        status2 = schnorr_zkp_generate(secp256k1_algebra, a, sizeof(a), &a, NULL, &zkp);
        REQUIRE(status2 == ZKP_INVALID_PARAMETER);
        status2 = schnorr_zkp_generate(secp256k1_algebra, a, sizeof(a), &a, &A, NULL);
        REQUIRE(status2 == ZKP_INVALID_PARAMETER);

        status2 = schnorr_zkp_generate_for_data(secp256k1_algebra, NULL, sizeof(a), a, sizeof(a), &A, &zkp);
        REQUIRE(status2 == ZKP_INVALID_PARAMETER);
        status2 = schnorr_zkp_generate_for_data(secp256k1_algebra, a, 0, a, sizeof(a), &A, &zkp);
        REQUIRE(status2 == ZKP_INVALID_PARAMETER);
        status2 = schnorr_zkp_generate_for_data(secp256k1_algebra, a, sizeof(a), NULL, sizeof(a), &A, &zkp);
        REQUIRE(status2 == ZKP_INVALID_PARAMETER);
        status2 = schnorr_zkp_generate_for_data(secp256k1_algebra, a, sizeof(a), a, 0, &A, &zkp);
        REQUIRE(status2 == ZKP_INVALID_PARAMETER);
        status2 = schnorr_zkp_generate_for_data(secp256k1_algebra, a, sizeof(a), a, sizeof(a), NULL, &zkp);
        REQUIRE(status2 == ZKP_INVALID_PARAMETER);
        status2 = schnorr_zkp_generate_for_data(secp256k1_algebra, a, sizeof(a), a, sizeof(a), &A, NULL);
        REQUIRE(status2 == ZKP_INVALID_PARAMETER);

        elliptic_curve256_scalar_t k;
        status = GFp_curve_algebra_rand(ctx, &k);
        REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        status2 = schnorr_zkp_generate_with_custom_randomness(secp256k1_algebra, NULL, sizeof(a), &a, &A, &k, &zkp);
        REQUIRE(status2 == ZKP_INVALID_PARAMETER);
        status2 = schnorr_zkp_generate_with_custom_randomness(secp256k1_algebra, a, 0, &a, &A, &k, &zkp);
        REQUIRE(status2 == ZKP_INVALID_PARAMETER);
        status2 = schnorr_zkp_generate_with_custom_randomness(secp256k1_algebra, a, sizeof(a), NULL, &A, &k, &zkp);
        REQUIRE(status2 == ZKP_INVALID_PARAMETER);
        status2 = schnorr_zkp_generate_with_custom_randomness(secp256k1_algebra, a, sizeof(a), &a, NULL, &k, &zkp);
        REQUIRE(status2 == ZKP_INVALID_PARAMETER);
        status2 = schnorr_zkp_generate_with_custom_randomness(secp256k1_algebra, a, sizeof(a), &a, &A, NULL, &zkp);
        REQUIRE(status2 == ZKP_INVALID_PARAMETER);
        status2 = schnorr_zkp_generate_with_custom_randomness(secp256k1_algebra, a, sizeof(a), &a, &A, &k, NULL);
        REQUIRE(status2 == ZKP_INVALID_PARAMETER);

        status2 = schnorr_zkp_verify(secp256k1_algebra, NULL, sizeof(a), &A, &zkp);
        REQUIRE(status2 == ZKP_INVALID_PARAMETER);
        status2 = schnorr_zkp_verify(secp256k1_algebra, a, 0, &A, &zkp);
        REQUIRE(status2 == ZKP_INVALID_PARAMETER);
        status2 = schnorr_zkp_verify(secp256k1_algebra, a, sizeof(a), NULL, &zkp);
        REQUIRE(status2 == ZKP_INVALID_PARAMETER);
        status2 = schnorr_zkp_verify(secp256k1_algebra, a, sizeof(a), &A, NULL);
        REQUIRE(status2 == ZKP_INVALID_PARAMETER);
    }

    SECTION("secp256r1") 
    {
        elliptic_curve256_algebra_ctx_t* secp256r1 = elliptic_curve256_new_secp256r1_algebra();
        elliptic_curve256_scalar_t a;
        elliptic_curve256_point_t A;
        REQUIRE(ctx);
        elliptic_curve_algebra_status status = secp256r1->rand(secp256r1, &a);
        REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        status = secp256r1->generator_mul(secp256r1, &A, &a);
        REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);

        schnorr_zkp_t zkp;
        zero_knowledge_proof_status status2 = schnorr_zkp_generate(secp256r1, a, sizeof(a), &a, &A, &zkp);
        REQUIRE(status2 == ZKP_SUCCESS);
        status2 = schnorr_zkp_verify(secp256r1, a, sizeof(a), &A, &zkp);
        REQUIRE(status2 == ZKP_SUCCESS);

        uint8_t b[80];
        elliptic_curve256_point_t B;
        REQUIRE(RAND_bytes(b, sizeof(b)));
        status2 = schnorr_zkp_generate_for_data(secp256r1, b, sizeof(b), b, sizeof(b), &B, &zkp);
        REQUIRE(status2 == ZKP_SUCCESS);
        status2 = schnorr_zkp_verify(secp256r1, b, sizeof(b), &B, &zkp);
        REQUIRE(status2 == ZKP_SUCCESS);
        secp256r1->release(secp256r1);
    }

    SECTION("ed25519") 
    {
        elliptic_curve256_algebra_ctx_t* ed25519 = elliptic_curve256_new_ed25519_algebra();
        elliptic_curve256_scalar_t a;
        elliptic_curve256_point_t A;
        REQUIRE(ctx);
        elliptic_curve_algebra_status status = ed25519->rand(ed25519, &a);
        REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        status = ed25519->generator_mul(ed25519, &A, &a);
        REQUIRE(status == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);

        schnorr_zkp_t zkp;
        zero_knowledge_proof_status status2 = schnorr_zkp_generate(ed25519, a, sizeof(a), &a, &A, &zkp);
        REQUIRE(status2 == ZKP_SUCCESS);
        status2 = schnorr_zkp_verify(ed25519, a, sizeof(a), &A, &zkp);
        REQUIRE(status2 == ZKP_SUCCESS);

        uint8_t b[80];
        elliptic_curve256_point_t B;
        REQUIRE(RAND_bytes(b, sizeof(b)));
        status2 = schnorr_zkp_generate_for_data(ed25519, b, sizeof(b), b, sizeof(b), &B, &zkp);
        REQUIRE(status2 == ZKP_SUCCESS);
        status2 = schnorr_zkp_verify(ed25519, b, sizeof(b), &B, &zkp);
        REQUIRE(status2 == ZKP_SUCCESS);
        ed25519->release(ed25519);
    }

    GFp_curve_algebra_ctx_free(ctx);
    secp256k1_algebra->release(secp256k1_algebra);
}

TEST_CASE("ring_pedersen", "[default]") 
{
    ring_pedersen_private_t* priv;
    ring_pedersen_public_t* pub;
    auto status = ring_pedersen_generate_key_pair(1024, &pub, &priv);

    SECTION("valid") 
    {
        REQUIRE(status == RING_PEDERSEN_SUCCESS);
        uint32_t proof_len;
        auto res = ring_pedersen_parameters_zkp_generate(priv, (const unsigned char*)"hello world", sizeof("hello world") - 1, NULL, 0, &proof_len);
        REQUIRE(res == ZKP_INSUFFICIENT_BUFFER);
        std::unique_ptr<uint8_t[]> proof(new uint8_t[proof_len]);
        res = ring_pedersen_parameters_zkp_generate(priv, (const unsigned char*)"hello world", sizeof("hello world") - 1, proof.get(), proof_len -1, &proof_len);
        REQUIRE(res == ZKP_INSUFFICIENT_BUFFER);
        res = ring_pedersen_parameters_zkp_generate(priv, (const unsigned char*)"hello world", sizeof("hello world") - 1, proof.get(), proof_len, &proof_len);
        REQUIRE(res == ZKP_SUCCESS);
        res = ring_pedersen_parameters_zkp_verify(pub, (const unsigned char*)"hello world", sizeof("hello world") - 1, proof.get(), proof_len);
        REQUIRE(res == ZKP_SUCCESS);
    }

    SECTION("invalid aad") 
    {
        REQUIRE(status == RING_PEDERSEN_SUCCESS);
        uint32_t proof_len;
        auto res = ring_pedersen_parameters_zkp_generate(priv, (const unsigned char*)"hello world", sizeof("hello world") - 1, NULL, 0, &proof_len);
        REQUIRE(res == ZKP_INSUFFICIENT_BUFFER);
        std::unique_ptr<uint8_t[]> proof(new uint8_t[proof_len]);
        res = ring_pedersen_parameters_zkp_generate(priv, (const unsigned char*)"hello world", sizeof("hello world") - 1, proof.get(), proof_len, &proof_len);
        REQUIRE(res == ZKP_SUCCESS);
        res = ring_pedersen_parameters_zkp_verify(pub, (const unsigned char*)"gello world", sizeof("hello world") - 1, proof.get(), proof_len);
        REQUIRE(res == ZKP_VERIFICATION_FAILED);
    }

    SECTION("invalid proof") 
    {
        REQUIRE(status == RING_PEDERSEN_SUCCESS);
        uint32_t proof_len;
        auto res = ring_pedersen_parameters_zkp_generate(priv, (const unsigned char*)"hello world", sizeof("hello world") - 1, NULL, 0, &proof_len);
        REQUIRE(res == ZKP_INSUFFICIENT_BUFFER);
        std::unique_ptr<uint8_t[]> proof(new uint8_t[proof_len]);
        res = ring_pedersen_parameters_zkp_generate(priv, (const unsigned char*)"hello world", sizeof("hello world") - 1, proof.get(), proof_len, &proof_len);
        REQUIRE(res == ZKP_SUCCESS);
        (*(uint32_t*)proof.get())++;
        res = ring_pedersen_parameters_zkp_verify(pub, (const unsigned char*)"hello world", sizeof("hello world") - 1, proof.get(), proof_len);
        REQUIRE(res == ZKP_VERIFICATION_FAILED);
        (*(uint32_t*)proof.get())--;
        proof.get()[32]++;
        res = ring_pedersen_parameters_zkp_verify(pub, (const unsigned char*)"hello world", sizeof("hello world") - 1, proof.get(), proof_len);
        REQUIRE(res == ZKP_VERIFICATION_FAILED);
    }

    SECTION("commitment") 
    {
        REQUIRE(status == RING_PEDERSEN_SUCCESS);
        uint8_t x[32];
        REQUIRE(RAND_bytes(x, sizeof(x)));
        uint8_t r[32];
        REQUIRE(RAND_bytes(r, sizeof(r)));
        uint32_t commitment_len;
        auto res = ring_pedersen_create_commitment(pub, x, sizeof(x), r, sizeof(r), NULL, 0, &commitment_len);
        REQUIRE(res == RING_PEDERSEN_BUFFER_TOO_SHORT);
        std::unique_ptr<uint8_t[]> commitment(new uint8_t[commitment_len]);
        res = ring_pedersen_create_commitment(pub, x, sizeof(x), r, sizeof(r), commitment.get(), commitment_len, &commitment_len);
        REQUIRE(res == RING_PEDERSEN_SUCCESS);
        res = ring_pedersen_verify_commitment(priv, x, sizeof(x), r, sizeof(r), commitment.get(), commitment_len);
        REQUIRE(res == RING_PEDERSEN_SUCCESS);
    }

    SECTION("invalid commitment") 
    {
        REQUIRE(status == RING_PEDERSEN_SUCCESS);
        uint8_t x[32];
        REQUIRE(RAND_bytes(x, sizeof(x)));
        uint8_t r[32];
        REQUIRE(RAND_bytes(r, sizeof(r)));
        uint32_t commitment_len;
        auto res = ring_pedersen_create_commitment(pub, x, sizeof(x), r, sizeof(r), NULL, 0, &commitment_len);
        REQUIRE(res == RING_PEDERSEN_BUFFER_TOO_SHORT);
        std::unique_ptr<uint8_t[]> commitment(new uint8_t[commitment_len]);
        res = ring_pedersen_create_commitment(pub, x, sizeof(x), r, sizeof(r), commitment.get(), commitment_len, &commitment_len);
        REQUIRE(res == RING_PEDERSEN_SUCCESS);
        x[5]++;
        res = ring_pedersen_verify_commitment(priv, x, sizeof(x), r, sizeof(r), commitment.get(), commitment_len);
        REQUIRE(res == RING_PEDERSEN_INVALID_COMMITMENT);
        x[5]--;
        r[8]++;
        res = ring_pedersen_verify_commitment(priv, x, sizeof(x), r, sizeof(r), commitment.get(), commitment_len);
        REQUIRE(res == RING_PEDERSEN_INVALID_COMMITMENT);
        r[8]--;
        commitment[15]++;
        res = ring_pedersen_verify_commitment(priv, x, sizeof(x), r, sizeof(r), commitment.get(), commitment_len);
        REQUIRE(res == RING_PEDERSEN_INVALID_COMMITMENT);
    }

    SECTION("batch verification") 
    {
        REQUIRE(status == RING_PEDERSEN_SUCCESS);
        const uint32_t BATCH_SIZE = 1000;
        const uint32_t SCALAR_SIZE = 100;
        ring_pedersen_batch_data_t x[BATCH_SIZE];
        ring_pedersen_batch_data_t r[BATCH_SIZE];
        ring_pedersen_batch_data_t commits[BATCH_SIZE];
        uint32_t commitment_len;
        const uint8_t ZERO = 0;
        auto res = ring_pedersen_create_commitment(pub, &ZERO, sizeof(ZERO), &ZERO, sizeof(ZERO), NULL, 0, &commitment_len);

        for (size_t i = 0; i < BATCH_SIZE; i++)
        {
            x[i].size = SCALAR_SIZE;
            r[i].size = SCALAR_SIZE;
            commits[i].size = commitment_len;
            x[i].data = new uint8_t[SCALAR_SIZE];
            REQUIRE(x[i].data);
            REQUIRE(RAND_bytes(x[i].data, SCALAR_SIZE));
            r[i].data = new uint8_t[SCALAR_SIZE];
            REQUIRE(r[i].data);
            REQUIRE(RAND_bytes(r[i].data, SCALAR_SIZE));
            commits[i].data = new uint8_t[commitment_len];
            REQUIRE(commits[i].data);

            res = ring_pedersen_create_commitment(pub, x[i].data, SCALAR_SIZE, r[i].data, SCALAR_SIZE, commits[i].data, commits[i].size, &commitment_len);
            REQUIRE(res == RING_PEDERSEN_SUCCESS);
        }

        clock_t start = clock();
        for (size_t i = 0; i < BATCH_SIZE; i++)
            REQUIRE(ring_pedersen_verify_commitment(priv, x[i].data, x[i].size, r[i].data, r[i].size, commits[i].data, commits[i].size) == RING_PEDERSEN_SUCCESS);
        size_t diff = clock() - start;
        std::cout << "single verifications done in " << std::dec << diff << " " << diff / CLOCKS_PER_SEC << "s" << std::endl;

        start = clock();
        REQUIRE(ring_pedersen_verify_batch_commitments(priv, BATCH_SIZE, x, r, commits) == RING_PEDERSEN_SUCCESS);
        diff = clock() - start;
        std::cout << "batch verification done in " << std::dec << diff << " " << diff / CLOCKS_PER_SEC << "s" << std::endl;

        for (size_t i = 0; i < BATCH_SIZE; i++)
        {
            delete[] x[i].data;
            delete[] r[i].data;
            delete[] commits[i].data;
        }
    }

    SECTION("invalid param") 
    {
        uint32_t proof_len;
        auto res = ring_pedersen_parameters_zkp_generate(priv, (const unsigned char*)"hello world", sizeof("hello world") - 1, NULL, 0, &proof_len);
        REQUIRE(res == ZKP_INSUFFICIENT_BUFFER);
        std::unique_ptr<uint8_t[]> proof(new uint8_t[proof_len]);
        res = ring_pedersen_parameters_zkp_generate(NULL, (const unsigned char*)"hello world", sizeof("hello world") - 1, proof.get(), proof_len, NULL);
        REQUIRE(res == ZKP_INVALID_PARAMETER);
        res = ring_pedersen_parameters_zkp_generate(priv, NULL, sizeof("hello world") - 1, proof.get(), proof_len, NULL);
        REQUIRE(res == ZKP_INVALID_PARAMETER);
        res = ring_pedersen_parameters_zkp_generate(priv, (const unsigned char*)"hello world", sizeof("hello world") - 1, NULL, proof_len, NULL);
        REQUIRE(res == ZKP_INVALID_PARAMETER);
        res = ring_pedersen_parameters_zkp_generate(priv, (const unsigned char*)"hello world", sizeof("hello world") - 1, proof.get(), 0, NULL);
        REQUIRE(res == ZKP_INSUFFICIENT_BUFFER);
        
        res = ring_pedersen_parameters_zkp_verify(NULL, (const unsigned char*)"hello world", sizeof("hello world") - 1, proof.get(), proof_len);
        REQUIRE(res == ZKP_INVALID_PARAMETER);
        res = ring_pedersen_parameters_zkp_verify(pub, 0, sizeof("hello world") - 1, proof.get(), proof_len);
        REQUIRE(res == ZKP_INVALID_PARAMETER);
        res = ring_pedersen_parameters_zkp_verify(pub, (const unsigned char*)"hello world", sizeof("hello world") - 1, NULL, proof_len);
        REQUIRE(res == ZKP_INVALID_PARAMETER);
        res = ring_pedersen_parameters_zkp_verify(pub, (const unsigned char*)"hello world", sizeof("hello world") - 1, proof.get(), 7);
        REQUIRE(res == ZKP_INVALID_PARAMETER);
    }

    SECTION("serialization") 
    {
        REQUIRE(status == RING_PEDERSEN_SUCCESS);
        uint32_t needed_len = 0;
        ring_pedersen_public_serialize(pub, NULL, 0, &needed_len);
        uint8_t* buff = (uint8_t*)malloc(needed_len);
        ring_pedersen_public_serialize(pub, buff, needed_len, &needed_len);
        ring_pedersen_public_t* pub2 = ring_pedersen_public_deserialize(buff, needed_len);
        REQUIRE(pub2);
        uint32_t proof_len;
        auto res = ring_pedersen_parameters_zkp_generate(priv, (const unsigned char*)"hello world", sizeof("hello world") - 1, NULL, 0, &proof_len);
        REQUIRE(res == ZKP_INSUFFICIENT_BUFFER);
        std::unique_ptr<uint8_t[]> proof(new uint8_t[proof_len]);
        res = ring_pedersen_parameters_zkp_generate(priv, (const unsigned char*)"hello world", sizeof("hello world") - 1, proof.get(), proof_len, &proof_len);
        REQUIRE(res == ZKP_SUCCESS);
        res = ring_pedersen_parameters_zkp_verify(pub2, (const unsigned char*)"hello world", sizeof("hello world") - 1, proof.get(), proof_len);
        REQUIRE(res == ZKP_SUCCESS);
        
        ring_pedersen_private_serialize(priv, NULL, 0, &needed_len);
        buff = (uint8_t*)realloc(buff, needed_len);
        ring_pedersen_private_serialize(priv, buff, needed_len, &needed_len);
        ring_pedersen_private_t* priv2 = ring_pedersen_private_deserialize(buff, needed_len);
        REQUIRE(priv2);
        free(buff);
        res = ring_pedersen_parameters_zkp_generate(priv2, (const unsigned char*)"hello world", sizeof("hello world") - 1, proof.get(), proof_len, &proof_len);
        REQUIRE(res == ZKP_SUCCESS);
        res = ring_pedersen_parameters_zkp_verify(pub, (const unsigned char*)"hello world", sizeof("hello world") - 1, proof.get(), proof_len);
        REQUIRE(res == ZKP_SUCCESS);
        ring_pedersen_free_public(pub2);
        ring_pedersen_free_private(priv2);
    }

    ring_pedersen_free_public(pub);
    ring_pedersen_free_private(priv);
}

TEST_CASE("exp_range_proof", "[default]") 
{
    ring_pedersen_public_t*  ring_pedersen_pub;
    ring_pedersen_private_t* ring_pedersen_priv;
    auto status = ring_pedersen_generate_key_pair(1024, &ring_pedersen_pub, &ring_pedersen_priv);
    paillier_public_key_t*  paillier_pub = NULL;
    paillier_private_key_t* paillier_priv = NULL;
    long res = paillier_generate_key_pair(2048, &paillier_pub, &paillier_priv);
    auto algebra = elliptic_curve256_new_secp256k1_algebra();
    
    SECTION("valid") 
    {
        REQUIRE(status == RING_PEDERSEN_SUCCESS);
        REQUIRE(res == PAILLIER_SUCCESS);
        for (const uint8_t use_extended_seed : { (uint8_t)0, (uint8_t)1 })
        {
            elliptic_curve256_scalar_t x;
            elliptic_curve256_point_t X;
            paillier_with_range_proof_t *proof;
            REQUIRE(algebra->rand(algebra, &x) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
            REQUIRE(algebra->generator_mul(algebra, &X, &x) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);

            REQUIRE(range_proof_paillier_encrypt_with_exponent_zkpok_generate(ring_pedersen_pub, paillier_pub, algebra, (const unsigned char*)"hello world", sizeof("hello world") - 1, &x, use_extended_seed, &proof) == ZKP_SUCCESS);

            // IMPORTANT: verify must use the same use_extended_seed that was used in generate.
            REQUIRE(range_proof_exponent_zkpok_verify(ring_pedersen_priv, paillier_pub, algebra, (const unsigned char*)"hello world", sizeof("hello world") - 1, &X, proof, 1, use_extended_seed) == ZKP_SUCCESS);
            REQUIRE(range_proof_exponent_zkpok_verify(ring_pedersen_priv, paillier_pub, algebra, (const unsigned char*)"hello world", sizeof("hello world") - 1, &X, proof, 0, use_extended_seed) == ZKP_SUCCESS);

            range_proof_free_paillier_with_range_proof(proof);
        }
    }

    SECTION("multiple proofs") 
    {
        REQUIRE(status == RING_PEDERSEN_SUCCESS);
        REQUIRE(res == PAILLIER_SUCCESS);
        for (const uint8_t use_extended_seed : { (uint8_t)0, (uint8_t)1 })
        {
            elliptic_curve256_scalar_t x;
            elliptic_curve256_point_t X;
            paillier_with_range_proof_t proof[2];
            REQUIRE(algebra->rand(algebra, &x) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
            REQUIRE(algebra->generator_mul(algebra, &X, &x) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);

            paillier_ciphertext_t* ciphertext = NULL;
            REQUIRE(paillier_encrypt_to_ciphertext(paillier_pub, x, sizeof(elliptic_curve256_scalar_t), &ciphertext) == PAILLIER_SUCCESS);
            paillier_get_ciphertext(ciphertext, NULL, 0, &proof[0].ciphertext_len);
            proof[0].ciphertext = proof[1].ciphertext = new uint8_t[proof[0].ciphertext_len];
            REQUIRE(paillier_get_ciphertext(ciphertext, proof[0].ciphertext, proof[0].ciphertext_len, &proof[1].ciphertext_len) == PAILLIER_SUCCESS);
            REQUIRE(proof[0].ciphertext_len == proof[1].ciphertext_len);

            range_proof_paillier_exponent_zkpok_generate(ring_pedersen_pub, paillier_pub, algebra, (const unsigned char*)"hello world", sizeof("hello world") - 1, &x, ciphertext, use_extended_seed, NULL, 0, &proof[0].proof_len);
            proof[0].serialized_proof = new uint8_t[proof[0].proof_len];
            proof[1].serialized_proof = new uint8_t[proof[0].proof_len];
            REQUIRE(range_proof_paillier_exponent_zkpok_generate(ring_pedersen_pub, paillier_pub, algebra, (const unsigned char*)"hello world", sizeof("hello world") - 1, &x, ciphertext, use_extended_seed, proof[0].serialized_proof, proof[0].proof_len, &proof[1].proof_len) == ZKP_SUCCESS);
            REQUIRE(proof[0].proof_len == proof[1].proof_len);
            REQUIRE(range_proof_paillier_exponent_zkpok_generate(ring_pedersen_pub, paillier_pub, algebra, (const unsigned char*)"hello world", sizeof("hello world") - 1, &x, ciphertext, use_extended_seed, proof[1].serialized_proof, proof[0].proof_len, &proof[1].proof_len) == ZKP_SUCCESS);
            REQUIRE(memcmp(proof[0].serialized_proof, proof[1].serialized_proof, proof[0].proof_len) != 0);
            REQUIRE(range_proof_exponent_zkpok_verify(ring_pedersen_priv, paillier_pub, algebra, (const unsigned char*)"hello world", sizeof("hello world") - 1, &X, &proof[0], 1, use_extended_seed) == ZKP_SUCCESS);
            REQUIRE(range_proof_exponent_zkpok_verify(ring_pedersen_priv, paillier_pub, algebra, (const unsigned char*)"hello world", sizeof("hello world") - 1, &X, &proof[1], 1, use_extended_seed) == ZKP_SUCCESS);
            paillier_free_ciphertext(ciphertext);
            delete[] proof[0].ciphertext;
            delete[] proof[0].serialized_proof;
            delete[] proof[1].serialized_proof;
        }
    }

    SECTION("invalid aad") 
    {
        REQUIRE(status == RING_PEDERSEN_SUCCESS);
        REQUIRE(res == PAILLIER_SUCCESS);
        for (const uint8_t use_extended_seed : { (uint8_t)0, (uint8_t)1 })
        {
            elliptic_curve256_scalar_t x;
            elliptic_curve256_point_t X;
            paillier_with_range_proof_t *proof;
            REQUIRE(algebra->rand(algebra, &x) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
            REQUIRE(algebra->generator_mul(algebra, &X, &x) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
            REQUIRE(range_proof_paillier_encrypt_with_exponent_zkpok_generate(ring_pedersen_pub, paillier_pub, algebra, (const unsigned char*)"hello world", sizeof("hello world") - 1, &x, use_extended_seed, &proof) == ZKP_SUCCESS);

            // IMPORTANT: verify must use the same use_extended_seed that was used in generate.
            REQUIRE(range_proof_exponent_zkpok_verify(ring_pedersen_priv, paillier_pub, algebra, (const unsigned char*)"gello world", sizeof("hello world") - 1, &X, proof, 1, use_extended_seed) == ZKP_VERIFICATION_FAILED);
            REQUIRE(range_proof_exponent_zkpok_verify(ring_pedersen_priv, paillier_pub, algebra, (const unsigned char*)"gello world", sizeof("hello world") - 1, &X, proof, 0, use_extended_seed) == ZKP_VERIFICATION_FAILED);

            range_proof_free_paillier_with_range_proof(proof);
        }
    }

    SECTION("invalid proof") 
    {
        REQUIRE(status == RING_PEDERSEN_SUCCESS);
        REQUIRE(res == PAILLIER_SUCCESS);
        for (const uint8_t use_extended_seed : { (uint8_t)0, (uint8_t)1 })
        {
            elliptic_curve256_scalar_t x;
            elliptic_curve256_point_t X;
            paillier_with_range_proof_t *proof;
            REQUIRE(algebra->rand(algebra, &x) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
            REQUIRE(algebra->generator_mul(algebra, &X, &x) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
            REQUIRE(range_proof_paillier_encrypt_with_exponent_zkpok_generate(ring_pedersen_pub, paillier_pub, algebra, (const unsigned char*)"hello world", sizeof("hello world") - 1, &x, use_extended_seed, &proof) == ZKP_SUCCESS);

            proof->ciphertext[123]++;
            REQUIRE(range_proof_exponent_zkpok_verify(ring_pedersen_priv, paillier_pub, algebra, (const unsigned char*)"hello world", sizeof("hello world") - 1, &X, proof, 1, use_extended_seed) == ZKP_VERIFICATION_FAILED);
            REQUIRE(range_proof_exponent_zkpok_verify(ring_pedersen_priv, paillier_pub, algebra, (const unsigned char*)"hello world", sizeof("hello world") - 1, &X, proof, 0, use_extended_seed) == ZKP_VERIFICATION_FAILED);
            proof->ciphertext[123]--;

            proof->serialized_proof[55]++;
            REQUIRE(range_proof_exponent_zkpok_verify(ring_pedersen_priv, paillier_pub, algebra, (const unsigned char*)"hello world", sizeof("hello world") - 1, &X, proof, 1, use_extended_seed) == ZKP_VERIFICATION_FAILED);
            REQUIRE(range_proof_exponent_zkpok_verify(ring_pedersen_priv, paillier_pub, algebra, (const unsigned char*)"hello world", sizeof("hello world") - 1, &X, proof, 0, use_extended_seed) == ZKP_VERIFICATION_FAILED);

            range_proof_free_paillier_with_range_proof(proof);
        }
    }

    SECTION("ed25519") 
    {
        REQUIRE(status == RING_PEDERSEN_SUCCESS);
        REQUIRE(res == PAILLIER_SUCCESS);
        auto ed25519 = elliptic_curve256_new_ed25519_algebra();
        for (const uint8_t use_extended_seed : { (uint8_t)0, (uint8_t)1 })
        {
            elliptic_curve256_scalar_t x;
            elliptic_curve256_point_t X;
            paillier_with_range_proof_t *proof;
            REQUIRE(ed25519->rand(ed25519, &x) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
            REQUIRE(ed25519->generator_mul(ed25519, &X, &x) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);

            REQUIRE(range_proof_paillier_encrypt_with_exponent_zkpok_generate(ring_pedersen_pub, paillier_pub, ed25519, (const unsigned char*)"hello world", sizeof("hello world") - 1, &x, use_extended_seed, &proof) == ZKP_SUCCESS);
            REQUIRE(range_proof_exponent_zkpok_verify(ring_pedersen_priv, paillier_pub, ed25519, (const unsigned char*)"hello world", sizeof("hello world") - 1, &X, proof, 1, use_extended_seed) == ZKP_SUCCESS);
            range_proof_free_paillier_with_range_proof(proof);
        }
        ed25519->release(ed25519);
    }

    ring_pedersen_free_public(ring_pedersen_pub);
    ring_pedersen_free_private(ring_pedersen_priv);
    paillier_free_public_key(paillier_pub);
    paillier_free_private_key(paillier_priv);
    algebra->release(algebra);
}

TEST_CASE("exp_range_proof_small_group", "[default]") 
{
    damgard_fujisaki_public*  damgard_fujisaki_pub;
    damgard_fujisaki_private* damgard_fujisaki_priv;
    auto status = damgard_fujisaki_generate_key_pair(1024, 2, &damgard_fujisaki_pub, &damgard_fujisaki_priv);
    REQUIRE(status == RING_PEDERSEN_SUCCESS);
    paillier_commitment_private_key_t* paillier_priv = NULL;
    
    long res = paillier_commitment_generate_private_key(2048, &paillier_priv);
    REQUIRE(res == PAILLIER_SUCCESS);

    auto algebra = elliptic_curve256_new_secp256k1_algebra();
    
    SECTION("valid") 
    {
        for (const uint8_t use_extended_seed : { (uint8_t)0, (uint8_t)1 })
        {
            elliptic_curve256_scalar_t x;
            elliptic_curve256_point_t X;
            paillier_with_range_proof_t *proof;
            REQUIRE(algebra->rand(algebra, &x) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
            REQUIRE(algebra->generator_mul(algebra, &X, &x) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);

            REQUIRE(paillier_commitment_encrypt_with_exponent_zkpok_generate(damgard_fujisaki_pub, 
                                                                             paillier_priv, 
                                                                             algebra, 
                                                                             (const unsigned char*)"hello world", 
                                                                             sizeof("hello world") - 1, 
                                                                             x, 
                                                                             sizeof(x), 
                                                                             use_extended_seed,
                                                                             &proof) == ZKP_SUCCESS);

            // IMPORTANT: verify must use the same use_extended_seed that was used in generate.
            REQUIRE(paillier_commitment_exponent_zkpok_verify(damgard_fujisaki_priv, 
                                                              paillier_commitment_private_cast_to_public(paillier_priv), 
                                                              algebra, 
                                                              (const unsigned char*)"hello world", 
                                                              sizeof("hello world") - 1, 
                                                              &X, 
                                                              reinterpret_cast<const const_paillier_with_range_proof_t*>(proof),
                                                              use_extended_seed) == ZKP_SUCCESS);
            range_proof_free_paillier_with_range_proof(proof);
        }
    }

    SECTION("invalid aad") 
    {
        for (const uint8_t use_extended_seed : { (uint8_t)0, (uint8_t)1 })
        {
            elliptic_curve256_scalar_t x;
            elliptic_curve256_point_t X;
            paillier_with_range_proof_t *proof;
            REQUIRE(algebra->rand(algebra, &x) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
            REQUIRE(algebra->generator_mul(algebra, &X, &x) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);

            REQUIRE(paillier_commitment_encrypt_with_exponent_zkpok_generate(damgard_fujisaki_pub, 
                                                                             paillier_priv, 
                                                                             algebra, 
                                                                             (const unsigned char*)"hello world", 
                                                                             sizeof("hello world") - 1, 
                                                                             x, 
                                                                             sizeof(x), 
                                                                             use_extended_seed,
                                                                             &proof) == ZKP_SUCCESS);

            REQUIRE(paillier_commitment_exponent_zkpok_verify(damgard_fujisaki_priv, 
                                                              paillier_commitment_private_cast_to_public(paillier_priv), 
                                                              algebra, 
                                                              (const unsigned char*)"gello world", 
                                                              sizeof("gello world") - 1, 
                                                              &X, 
                                                              reinterpret_cast<const const_paillier_with_range_proof_t*>(proof),
                                                              use_extended_seed) == ZKP_VERIFICATION_FAILED);
            range_proof_free_paillier_with_range_proof(proof);
        }
    }

    SECTION("invalid proof") 
    {
        for (const uint8_t use_extended_seed : { (uint8_t)0, (uint8_t)1 })
        {
            elliptic_curve256_scalar_t x;
            elliptic_curve256_point_t X;
            paillier_with_range_proof_t *proof;
            REQUIRE(algebra->rand(algebra, &x) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
            REQUIRE(algebra->generator_mul(algebra, &X, &x) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
            REQUIRE(paillier_commitment_encrypt_with_exponent_zkpok_generate(damgard_fujisaki_pub, 
                                                                             paillier_priv, 
                                                                             algebra, 
                                                                             (const unsigned char*)"hello world", 
                                                                             sizeof("hello world") - 1, 
                                                                             x, 
                                                                             sizeof(x), 
                                                                             use_extended_seed,
                                                                             &proof) == ZKP_SUCCESS);
            proof->ciphertext[123]++;
            REQUIRE(paillier_commitment_exponent_zkpok_verify(damgard_fujisaki_priv, 
                                                              paillier_commitment_private_cast_to_public(paillier_priv), 
                                                              algebra, 
                                                              (const unsigned char*)"hello world", 
                                                              sizeof("hello world") - 1, 
                                                              &X, 
                                                              reinterpret_cast<const const_paillier_with_range_proof_t*>(proof),
                                                              use_extended_seed) == ZKP_VERIFICATION_FAILED);
            proof->ciphertext[123]--;
            proof->serialized_proof[55]++;
            REQUIRE(paillier_commitment_exponent_zkpok_verify(damgard_fujisaki_priv, 
                                                              paillier_commitment_private_cast_to_public(paillier_priv), 
                                                              algebra, 
                                                              (const unsigned char*)"hello world", 
                                                              sizeof("hello world") - 1, 
                                                              &X, 
                                                              reinterpret_cast<const const_paillier_with_range_proof_t*>(proof),
                                                              use_extended_seed) == ZKP_VERIFICATION_FAILED);
            range_proof_free_paillier_with_range_proof(proof);
        }
    }

    SECTION("secp256r1") 
    {
        auto secp256r1 = elliptic_curve256_new_secp256r1_algebra();
        for (const uint8_t use_extended_seed : { (uint8_t)0, (uint8_t)1 })
        {
            elliptic_curve256_scalar_t x;
            elliptic_curve256_point_t X;
            paillier_with_range_proof_t *proof;
            REQUIRE(secp256r1->rand(secp256r1, &x) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
            REQUIRE(secp256r1->generator_mul(secp256r1, &X, &x) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);

            REQUIRE(paillier_commitment_encrypt_with_exponent_zkpok_generate(damgard_fujisaki_pub, 
                                                                             paillier_priv, 
                                                                             secp256r1, 
                                                                             (const unsigned char*)"hello world", 
                                                                             sizeof("hello world") - 1, 
                                                                             x, 
                                                                             sizeof(x), 
                                                                             use_extended_seed,
                                                                             &proof) == ZKP_SUCCESS);

            REQUIRE(paillier_commitment_exponent_zkpok_verify(damgard_fujisaki_priv, 
                                                              paillier_commitment_private_cast_to_public(paillier_priv), 
                                                              secp256r1, 
                                                              (const unsigned char*)"hello world", 
                                                              sizeof("hello world") - 1, 
                                                              &X, 
                                                              reinterpret_cast<const const_paillier_with_range_proof_t*>(proof),
                                                              use_extended_seed) == ZKP_SUCCESS);
            range_proof_free_paillier_with_range_proof(proof);
        }
        secp256r1->release(secp256r1);
    }

    SECTION("ed25519") 
    {
        auto ed25519 = elliptic_curve256_new_ed25519_algebra();
        for (const uint8_t use_extended_seed : { (uint8_t)0, (uint8_t)1 })
        {
            elliptic_curve256_scalar_t x;
            elliptic_curve256_point_t X;
            paillier_with_range_proof_t *proof;
            REQUIRE(ed25519->rand(ed25519, &x) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
            REQUIRE(ed25519->generator_mul(ed25519, &X, &x) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);

            REQUIRE(paillier_commitment_encrypt_with_exponent_zkpok_generate(damgard_fujisaki_pub, 
                                                                             paillier_priv, 
                                                                             ed25519, 
                                                                             (const unsigned char*)"hello world", 
                                                                             sizeof("hello world") - 1, 
                                                                             x, 
                                                                             sizeof(x), 
                                                                             use_extended_seed,
                                                                             &proof) == ZKP_SUCCESS);

            REQUIRE(paillier_commitment_exponent_zkpok_verify(damgard_fujisaki_priv, 
                                                              paillier_commitment_private_cast_to_public(paillier_priv), 
                                                              ed25519, 
                                                              (const unsigned char*)"hello world", 
                                                              sizeof("hello world") - 1, 
                                                              &X, 
                                                              reinterpret_cast<const const_paillier_with_range_proof_t*>(proof),
                                                              use_extended_seed) == ZKP_SUCCESS);
            range_proof_free_paillier_with_range_proof(proof);
        }
        ed25519->release(ed25519);
    }

    damgard_fujisaki_free_public(damgard_fujisaki_pub);
    damgard_fujisaki_free_private(damgard_fujisaki_priv);
    paillier_commitment_free_private_key(paillier_priv);
    algebra->release(algebra);
}

TEST_CASE("rddh", "[default]") 
{
    ring_pedersen_public_t*  ring_pedersen_pub;
    ring_pedersen_private_t* ring_pedersen_priv;
    auto status = ring_pedersen_generate_key_pair(1024, &ring_pedersen_pub, &ring_pedersen_priv);
    paillier_public_key_t*  paillier_pub = NULL;
    paillier_private_key_t* paillier_priv = NULL;
    long res = paillier_generate_key_pair(2048, &paillier_pub, &paillier_priv);
    auto algebra = elliptic_curve256_new_secp256k1_algebra();
    
    SECTION("valid") 
    {
        REQUIRE(status == RING_PEDERSEN_SUCCESS);
        REQUIRE(res == PAILLIER_SUCCESS);
        for (const uint8_t use_extended_seed : { (uint8_t)0, (uint8_t)1 })
        {
            elliptic_curve256_scalar_t x, a, b;
            elliptic_curve256_point_t X, A, B;
            paillier_with_range_proof_t *proof = NULL;
        
            REQUIRE(algebra->rand(algebra, &x) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
            REQUIRE(algebra->rand(algebra, &a) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
            REQUIRE(algebra->generator_mul(algebra, &A, &a) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
            REQUIRE(algebra->rand(algebra, &b) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
            REQUIRE(algebra->generator_mul(algebra, &B, &b) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
            
            REQUIRE(range_proof_paillier_encrypt_with_diffie_hellman_zkpok_generate(ring_pedersen_pub,
                                                                                    paillier_pub,
                                                                                    algebra,
                                                                                    (const unsigned char*)"test aad",
                                                                                    sizeof("test aad") - 1,
                                                                                    &x,
                                                                                    &a,
                                                                                    &b,
                                                                                    use_extended_seed,
                                                                                    &proof) == ZKP_SUCCESS);
        
            elliptic_curve256_scalar_t tmp;
            REQUIRE(algebra->mul_scalars(algebra, &tmp, a, sizeof(elliptic_curve256_scalar_t), b, sizeof(elliptic_curve256_scalar_t)) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
            REQUIRE(algebra->add_scalars(algebra, &tmp, tmp, sizeof(elliptic_curve256_scalar_t), x, sizeof(elliptic_curve256_scalar_t)) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
            REQUIRE(algebra->generator_mul(algebra, &X, &tmp) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        
            // IMPORTANT: verify must use the same use_extended_seed that was used in generate.
            // strict_ciphertext_length = 1 (strict)
            REQUIRE(range_proof_diffie_hellman_zkpok_verify(ring_pedersen_priv, paillier_pub, algebra, (const unsigned char*)"test aad", sizeof("test aad") - 1, &X, &A, &B, proof, 1, use_extended_seed) == ZKP_SUCCESS);
            
            // strict_ciphertext_length = 0 (non-strict)
            REQUIRE(range_proof_diffie_hellman_zkpok_verify(ring_pedersen_priv, paillier_pub, algebra, (const unsigned char*)"test aad", sizeof("test aad") - 1, &X, &A, &B, proof, 0, use_extended_seed) == ZKP_SUCCESS);
            
            range_proof_free_paillier_with_range_proof(proof);
        }
    }

    SECTION("invalid aad") 
    {
        REQUIRE(status == RING_PEDERSEN_SUCCESS);
        REQUIRE(res == PAILLIER_SUCCESS);
        for (const uint8_t use_extended_seed : { (uint8_t)0, (uint8_t)1 })
        {
            elliptic_curve256_scalar_t x, a, b;
            elliptic_curve256_point_t X, A, B;
            paillier_with_range_proof_t *proof = NULL;
            REQUIRE(algebra->rand(algebra, &x) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
            REQUIRE(algebra->rand(algebra, &a) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
            REQUIRE(algebra->generator_mul(algebra, &A, &a) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
            REQUIRE(algebra->rand(algebra, &b) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
            REQUIRE(algebra->generator_mul(algebra, &B, &b) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);

            REQUIRE(range_proof_paillier_encrypt_with_diffie_hellman_zkpok_generate(ring_pedersen_pub,
                                                                                    paillier_pub,
                                                                                    algebra,
                                                                                    (const unsigned char*)"hello world",
                                                                                    sizeof("hello world") - 1,
                                                                                    &x,
                                                                                    &a,
                                                                                    &b,
                                                                                    use_extended_seed,
                                                                                    &proof) == ZKP_SUCCESS);

            elliptic_curve256_scalar_t tmp;
            REQUIRE(algebra->mul_scalars(algebra, &tmp, a, sizeof(elliptic_curve256_scalar_t), b, sizeof(elliptic_curve256_scalar_t)) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
            REQUIRE(algebra->add_scalars(algebra, &tmp, tmp, sizeof(elliptic_curve256_scalar_t), x, sizeof(elliptic_curve256_scalar_t)) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
            REQUIRE(algebra->generator_mul(algebra, &X, &tmp) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);

            REQUIRE(range_proof_diffie_hellman_zkpok_verify(ring_pedersen_priv, paillier_pub, algebra, (const unsigned char*)"gello world", sizeof("hello world") - 1, &X, &A, &B, proof, 0, use_extended_seed) == ZKP_VERIFICATION_FAILED);
            REQUIRE(range_proof_diffie_hellman_zkpok_verify(ring_pedersen_priv, paillier_pub, algebra, (const unsigned char*)"gello world", sizeof("hello world") - 1, &X, &A, &B, proof, 1, use_extended_seed) == ZKP_VERIFICATION_FAILED);

            range_proof_free_paillier_with_range_proof(proof);
        }
    }

    SECTION("invalid proof") 
    {
        REQUIRE(status == RING_PEDERSEN_SUCCESS);
        REQUIRE(res == PAILLIER_SUCCESS);
        for (const uint8_t use_extended_seed : { (uint8_t)0, (uint8_t)1 })
        {
            elliptic_curve256_scalar_t x, a, b;
            elliptic_curve256_point_t X, A, B;
            paillier_with_range_proof_t *proof = NULL;
            REQUIRE(algebra->rand(algebra, &x) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
            REQUIRE(algebra->rand(algebra, &a) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
            REQUIRE(algebra->generator_mul(algebra, &A, &a) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
            REQUIRE(algebra->rand(algebra, &b) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
            REQUIRE(algebra->generator_mul(algebra, &B, &b) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);

            REQUIRE(range_proof_paillier_encrypt_with_diffie_hellman_zkpok_generate(ring_pedersen_pub,
                                                                                    paillier_pub,
                                                                                    algebra,
                                                                                    (const unsigned char*)"hello world",
                                                                                    sizeof("hello world") - 1,
                                                                                    &x,
                                                                                    &a,
                                                                                    &b,
                                                                                    use_extended_seed,
                                                                                    &proof) == ZKP_SUCCESS);

            elliptic_curve256_scalar_t tmp;
            REQUIRE(algebra->mul_scalars(algebra, &tmp, a, sizeof(elliptic_curve256_scalar_t), b, sizeof(elliptic_curve256_scalar_t)) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
            REQUIRE(algebra->add_scalars(algebra, &tmp, tmp, sizeof(elliptic_curve256_scalar_t), x, sizeof(elliptic_curve256_scalar_t)) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
            REQUIRE(algebra->generator_mul(algebra, &X, &tmp) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
            
            proof->ciphertext[123]++;
            REQUIRE(range_proof_diffie_hellman_zkpok_verify(ring_pedersen_priv, paillier_pub, algebra, (const unsigned char*)"hello world", sizeof("hello world") - 1, &X, &A, &B, proof, 0, use_extended_seed) == ZKP_VERIFICATION_FAILED);
            REQUIRE(range_proof_diffie_hellman_zkpok_verify(ring_pedersen_priv, paillier_pub, algebra, (const unsigned char*)"hello world", sizeof("hello world") - 1, &X, &A, &B, proof, 1, use_extended_seed) == ZKP_VERIFICATION_FAILED);
            proof->ciphertext[123]--;
            proof->serialized_proof[55]++;
            REQUIRE(range_proof_diffie_hellman_zkpok_verify(ring_pedersen_priv, paillier_pub, algebra, (const unsigned char*)"hello world", sizeof("hello world") - 1, &X, &A, &B, proof, 0, use_extended_seed) == ZKP_VERIFICATION_FAILED);
            REQUIRE(range_proof_diffie_hellman_zkpok_verify(ring_pedersen_priv, paillier_pub, algebra, (const unsigned char*)"hello world", sizeof("hello world") - 1, &X, &A, &B, proof, 1, use_extended_seed) == ZKP_VERIFICATION_FAILED);
            A[12]++;
            REQUIRE(range_proof_diffie_hellman_zkpok_verify(ring_pedersen_priv, paillier_pub, algebra, (const unsigned char*)"hello world", sizeof("hello world") - 1, &X, &A, &B, proof, 0, use_extended_seed) == ZKP_VERIFICATION_FAILED);
            REQUIRE(range_proof_diffie_hellman_zkpok_verify(ring_pedersen_priv, paillier_pub, algebra, (const unsigned char*)"hello world", sizeof("hello world") - 1, &X, &A, &B, proof, 1, use_extended_seed) == ZKP_VERIFICATION_FAILED);
            A[12]--;
            B[11]++;
            REQUIRE(range_proof_diffie_hellman_zkpok_verify(ring_pedersen_priv, paillier_pub, algebra, (const unsigned char*)"hello world", sizeof("hello world") - 1, &X, &A, &B, proof, 0, use_extended_seed) == ZKP_VERIFICATION_FAILED);
            REQUIRE(range_proof_diffie_hellman_zkpok_verify(ring_pedersen_priv, paillier_pub, algebra, (const unsigned char*)"hello world", sizeof("hello world") - 1, &X, &A, &B, proof, 1, use_extended_seed) == ZKP_VERIFICATION_FAILED);
            B[11]--;
            X[10]++;
            REQUIRE(range_proof_diffie_hellman_zkpok_verify(ring_pedersen_priv, paillier_pub, algebra, (const unsigned char*)"hello world", sizeof("hello world") - 1, &X, &A, &B, proof, 0, use_extended_seed) == ZKP_VERIFICATION_FAILED);
            REQUIRE(range_proof_diffie_hellman_zkpok_verify(ring_pedersen_priv, paillier_pub, algebra, (const unsigned char*)"hello world", sizeof("hello world") - 1, &X, &A, &B, proof, 1, use_extended_seed) == ZKP_VERIFICATION_FAILED);
            tmp[31]++;
            REQUIRE(algebra->generator_mul(algebra, &X, &tmp) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
            REQUIRE(range_proof_diffie_hellman_zkpok_verify(ring_pedersen_priv, paillier_pub, algebra, (const unsigned char*)"hello world", sizeof("hello world") - 1, &X, &A, &B, proof, 0, use_extended_seed) == ZKP_VERIFICATION_FAILED);
            REQUIRE(range_proof_diffie_hellman_zkpok_verify(ring_pedersen_priv, paillier_pub, algebra, (const unsigned char*)"hello world", sizeof("hello world") - 1, &X, &A, &B, proof, 1, use_extended_seed) == ZKP_VERIFICATION_FAILED);

            range_proof_free_paillier_with_range_proof(proof);
        }
    }

    SECTION("ed25519") 
    {
        REQUIRE(status == RING_PEDERSEN_SUCCESS);
        REQUIRE(res == PAILLIER_SUCCESS);
        auto ed25519 = elliptic_curve256_new_ed25519_algebra();
        for (const uint8_t use_extended_seed : { (uint8_t)0, (uint8_t)1 })
        {
            elliptic_curve256_scalar_t x, a, b;
            elliptic_curve256_point_t X, A, B;
            paillier_with_range_proof_t *proof = NULL;
            REQUIRE(ed25519->rand(ed25519, &x) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
            REQUIRE(ed25519->rand(ed25519, &a) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
            REQUIRE(ed25519->generator_mul(ed25519, &A, &a) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
            REQUIRE(ed25519->rand(ed25519, &b) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
            REQUIRE(ed25519->generator_mul(ed25519, &B, &b) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);

            REQUIRE(range_proof_paillier_encrypt_with_diffie_hellman_zkpok_generate(ring_pedersen_pub,
                                                                                    paillier_pub,
                                                                                    ed25519,
                                                                                    (const unsigned char*)"hello world",
                                                                                    sizeof("hello world") - 1,
                                                                                    &x,
                                                                                    &a,
                                                                                    &b,
                                                                                    use_extended_seed,
                                                                                    &proof) == ZKP_SUCCESS);

            elliptic_curve256_scalar_t tmp;
            REQUIRE(ed25519->mul_scalars(ed25519, &tmp, a, sizeof(elliptic_curve256_scalar_t), b, sizeof(elliptic_curve256_scalar_t)) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
            REQUIRE(ed25519->add_scalars(ed25519, &tmp, tmp, sizeof(elliptic_curve256_scalar_t), x, sizeof(elliptic_curve256_scalar_t)) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
            REQUIRE(ed25519->generator_mul(ed25519, &X, &tmp) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
            REQUIRE(range_proof_diffie_hellman_zkpok_verify(ring_pedersen_priv, paillier_pub, ed25519, (const unsigned char*)"hello world", sizeof("hello world") - 1, &X, &A, &B, proof, 1, use_extended_seed) == ZKP_SUCCESS);

            range_proof_free_paillier_with_range_proof(proof);
        }
        ed25519->release(ed25519);
    }

    ring_pedersen_free_public(ring_pedersen_pub);
    ring_pedersen_free_private(ring_pedersen_priv);
    paillier_free_public_key(paillier_pub);
    paillier_free_private_key(paillier_priv);
    algebra->release(algebra);
}

TEST_CASE("ddh", "[default]") 
{
    auto algebra = elliptic_curve256_new_secp256k1_algebra();
    
    SECTION("valid") 
    {
        elliptic_curve256_scalar_t x, a, b;
        elliptic_curve256_point_t base_point, tmp;
        diffie_hellman_log_public_data_t pub;
        diffie_hellman_log_zkp_t proof;

        REQUIRE(algebra->rand(algebra, &x) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE(algebra->generator_mul(algebra, &base_point, &x) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE(algebra->rand(algebra, &x) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE(algebra->point_mul(algebra, &pub.X, &base_point, &x) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE(algebra->rand(algebra, &a) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE(algebra->generator_mul(algebra, &pub.A, &a) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE(algebra->rand(algebra, &b) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE(algebra->generator_mul(algebra, &pub.B, &b) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE(algebra->generator_mul(algebra, &pub.C, &x) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE(algebra->point_mul(algebra, &tmp, &pub.A, &b) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE(algebra->add_points(algebra, &pub.C, &pub.C, &tmp) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        
        REQUIRE(diffie_hellman_log_zkp_generate(algebra, (const unsigned char*)"hello world", sizeof("hello world") - 1, &base_point, &x, &a, &b, &pub, &proof) == ZKP_SUCCESS);
        REQUIRE(diffie_hellman_log_zkp_verify(algebra, (const unsigned char*)"hello world", sizeof("hello world") - 1, &base_point, &pub, &proof) == ZKP_SUCCESS);
    }

    SECTION("invalid aad") 
    {
        elliptic_curve256_scalar_t x, a, b;
        elliptic_curve256_point_t base_point, tmp;
        diffie_hellman_log_public_data_t pub;
        diffie_hellman_log_zkp_t proof;

        REQUIRE(algebra->rand(algebra, &x) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE(algebra->generator_mul(algebra, &base_point, &x) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE(algebra->rand(algebra, &x) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE(algebra->point_mul(algebra, &pub.X, &base_point, &x) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE(algebra->rand(algebra, &a) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE(algebra->generator_mul(algebra, &pub.A, &a) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE(algebra->rand(algebra, &b) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE(algebra->generator_mul(algebra, &pub.B, &b) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE(algebra->generator_mul(algebra, &pub.C, &x) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE(algebra->point_mul(algebra, &tmp, &pub.A, &b) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE(algebra->add_points(algebra, &pub.C, &pub.C, &tmp) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        
        REQUIRE(diffie_hellman_log_zkp_generate(algebra, (const unsigned char*)"hello world", sizeof("hello world") - 1, &base_point, &x, &a, &b, &pub, &proof) == ZKP_SUCCESS);
        REQUIRE(diffie_hellman_log_zkp_verify(algebra, (const unsigned char*)"gello world", sizeof("hello world") - 1, &base_point, &pub, &proof) == ZKP_VERIFICATION_FAILED);
    }

    SECTION("invalid proof") 
    {
        elliptic_curve256_scalar_t x, a, b;
        elliptic_curve256_point_t base_point, tmp;
        diffie_hellman_log_public_data_t pub;
        diffie_hellman_log_zkp_t proof;

        REQUIRE(algebra->rand(algebra, &x) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE(algebra->generator_mul(algebra, &base_point, &x) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE(algebra->rand(algebra, &x) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE(algebra->point_mul(algebra, &pub.X, &base_point, &x) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE(algebra->rand(algebra, &a) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE(algebra->generator_mul(algebra, &pub.A, &a) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE(algebra->rand(algebra, &b) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE(algebra->generator_mul(algebra, &pub.B, &b) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE(algebra->generator_mul(algebra, &pub.C, &x) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE(algebra->point_mul(algebra, &tmp, &pub.A, &b) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE(algebra->add_points(algebra, &pub.C, &pub.C, &tmp) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        
        REQUIRE(diffie_hellman_log_zkp_generate(algebra, (const unsigned char*)"hello world", sizeof("hello world") - 1, &base_point, &x, &a, &b, &pub, &proof) == ZKP_SUCCESS);
        base_point[0] ^= 1;
        REQUIRE(diffie_hellman_log_zkp_verify(algebra, (const unsigned char*)"hello world", sizeof("hello world") - 1, &base_point, &pub, &proof) == ZKP_VERIFICATION_FAILED);
        base_point[0] ^= 1;
        pub.A[12]++;
        REQUIRE(diffie_hellman_log_zkp_verify(algebra, (const unsigned char*)"hello world", sizeof("hello world") - 1, &base_point, &pub, &proof) == ZKP_VERIFICATION_FAILED);
        pub.A[12]--;
        pub.B[11]++;
        REQUIRE(diffie_hellman_log_zkp_verify(algebra, (const unsigned char*)"hello world", sizeof("hello world") - 1, &base_point, &pub, &proof) == ZKP_VERIFICATION_FAILED);
        pub.B[11]--;
        pub.C[10]++;
        REQUIRE(diffie_hellman_log_zkp_verify(algebra, (const unsigned char*)"hello world", sizeof("hello world") - 1, &base_point, &pub, &proof) == ZKP_VERIFICATION_FAILED);
        pub.C[10]--;
        pub.X[10]++;
        REQUIRE(diffie_hellman_log_zkp_verify(algebra, (const unsigned char*)"hello world", sizeof("hello world") - 1, &base_point, &pub, &proof) == ZKP_VERIFICATION_FAILED);
        pub.X[10]--;
        
        proof.D[22]++;
        REQUIRE(diffie_hellman_log_zkp_verify(algebra, (const unsigned char*)"hello world", sizeof("hello world") - 1, &base_point, &pub, &proof) == ZKP_VERIFICATION_FAILED);
        proof.D[22]--;
        proof.Y[21]++;
        REQUIRE(diffie_hellman_log_zkp_verify(algebra, (const unsigned char*)"hello world", sizeof("hello world") - 1, &base_point, &pub, &proof) == ZKP_VERIFICATION_FAILED);
        proof.Y[21]--;
        proof.V[20]++;
        REQUIRE(diffie_hellman_log_zkp_verify(algebra, (const unsigned char*)"hello world", sizeof("hello world") - 1, &base_point, &pub, &proof) == ZKP_VERIFICATION_FAILED);
        proof.V[20]--;
        proof.w[30]++;
        REQUIRE(diffie_hellman_log_zkp_verify(algebra, (const unsigned char*)"hello world", sizeof("hello world") - 1, &base_point, &pub, &proof) == ZKP_VERIFICATION_FAILED);
        proof.w[30]--;
        proof.z[31]++;
        REQUIRE(diffie_hellman_log_zkp_verify(algebra, (const unsigned char*)"hello world", sizeof("hello world") - 1, &base_point, &pub, &proof) == ZKP_VERIFICATION_FAILED);
    }

    SECTION("ed25519") 
    {
        elliptic_curve256_scalar_t x, a, b;
        elliptic_curve256_point_t base_point, tmp;
        diffie_hellman_log_public_data_t pub;
        diffie_hellman_log_zkp_t proof;
        auto ed25519 = elliptic_curve256_new_ed25519_algebra();

        REQUIRE(ed25519->rand(ed25519, &x) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE(ed25519->generator_mul(ed25519, &base_point, &x) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE(ed25519->rand(ed25519, &x) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE(ed25519->point_mul(ed25519, &pub.X, &base_point, &x) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE(ed25519->rand(ed25519, &a) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE(ed25519->generator_mul(ed25519, &pub.A, &a) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE(ed25519->rand(ed25519, &b) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE(ed25519->generator_mul(ed25519, &pub.B, &b) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE(ed25519->generator_mul(ed25519, &pub.C, &x) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE(ed25519->point_mul(ed25519, &tmp, &pub.A, &b) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE(ed25519->add_points(ed25519, &pub.C, &pub.C, &tmp) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        
        REQUIRE(diffie_hellman_log_zkp_generate(ed25519, (const unsigned char*)"hello world", sizeof("hello world") - 1, &base_point, &x, &a, &b, &pub, &proof) == ZKP_SUCCESS);
        REQUIRE(diffie_hellman_log_zkp_verify(ed25519, (const unsigned char*)"hello world", sizeof("hello world") - 1, &base_point, &pub, &proof) == ZKP_SUCCESS);
        ed25519->release(ed25519);
    }

    algebra->release(algebra);
}

TEST_CASE("paillier_large_factors", "[default]") 
{
    ring_pedersen_public_t*  ring_pedersen_pub;
    ring_pedersen_private_t* ring_pedersen_priv;
    auto status = ring_pedersen_generate_key_pair(1024, &ring_pedersen_pub, &ring_pedersen_priv);
    paillier_public_key_t*  paillier_pub = NULL;
    paillier_private_key_t* paillier_priv = NULL;
    long res = paillier_generate_key_pair(2048, &paillier_pub, &paillier_priv);
    
    SECTION("valid-extended-hash") 
    {
        REQUIRE(status == RING_PEDERSEN_SUCCESS);
        REQUIRE(res == PAILLIER_SUCCESS);
        
        uint32_t len = 0;
        REQUIRE(range_proof_paillier_large_factors_zkp_generate(paillier_priv, ring_pedersen_pub, (const unsigned char*)"hello world", sizeof("hello world") - 1, 1, NULL, 0, &len) == ZKP_INSUFFICIENT_BUFFER);
        uint8_t* proof = new uint8_t[len];
        REQUIRE(range_proof_paillier_large_factors_zkp_generate(paillier_priv, ring_pedersen_pub, (const unsigned char*)"hello world", sizeof("hello world") - 1, 1, proof, len, &len) == ZKP_SUCCESS);
        REQUIRE(range_proof_paillier_large_factors_zkp_verify(paillier_pub, ring_pedersen_priv, (const unsigned char*)"hello world", sizeof("hello world") - 1, 1, proof, len) == ZKP_SUCCESS);
        delete[] proof;
    }

    SECTION("valid-reduced-hash") 
    {
        REQUIRE(status == RING_PEDERSEN_SUCCESS);
        REQUIRE(res == PAILLIER_SUCCESS);
        
        uint32_t len = 0;
        REQUIRE(range_proof_paillier_large_factors_zkp_generate(paillier_priv, ring_pedersen_pub, (const unsigned char*)"hello world", sizeof("hello world") - 1, 0, NULL, 0, &len) == ZKP_INSUFFICIENT_BUFFER);
        uint8_t* proof = new uint8_t[len];
        REQUIRE(range_proof_paillier_large_factors_zkp_generate(paillier_priv, ring_pedersen_pub, (const unsigned char*)"hello world", sizeof("hello world") - 1, 0, proof, len, &len) == ZKP_SUCCESS);
        REQUIRE(range_proof_paillier_large_factors_zkp_verify(paillier_pub, ring_pedersen_priv, (const unsigned char*)"hello world", sizeof("hello world") - 1, 0, proof, len) == ZKP_SUCCESS);
        delete[] proof;
    }

    SECTION("valid large keys-extended") 
    {
        ring_pedersen_public_t*  large_ring_pedersen_pub;
        ring_pedersen_private_t* large_ring_pedersen_priv;
        auto status = ring_pedersen_generate_key_pair(2048, &large_ring_pedersen_pub, &large_ring_pedersen_priv);
        paillier_public_key_t*  large_paillier_pub = NULL;
        paillier_private_key_t* large_paillier_priv = NULL;
        long res = paillier_generate_key_pair(3072, &large_paillier_pub, &large_paillier_priv);
        REQUIRE(status == RING_PEDERSEN_SUCCESS);
        REQUIRE(res == PAILLIER_SUCCESS);
        
        uint32_t len = 0;
        REQUIRE(range_proof_paillier_large_factors_zkp_generate(large_paillier_priv, large_ring_pedersen_pub, (const unsigned char*)"hello world", sizeof("hello world") - 1, 1, NULL, 0, &len) == ZKP_INSUFFICIENT_BUFFER);
        uint8_t* proof = new uint8_t[len];
        REQUIRE(range_proof_paillier_large_factors_zkp_generate(large_paillier_priv, large_ring_pedersen_pub, (const unsigned char*)"hello world", sizeof("hello world") - 1, 1, proof, len, &len) == ZKP_SUCCESS);
        REQUIRE(range_proof_paillier_large_factors_zkp_verify(large_paillier_pub, large_ring_pedersen_priv, (const unsigned char*)"hello world", sizeof("hello world") - 1, 1, proof, len) == ZKP_SUCCESS);
        delete[] proof;
    
        paillier_free_private_key(large_paillier_priv);
        paillier_free_public_key(large_paillier_pub);
        ring_pedersen_free_private(large_ring_pedersen_priv);
        ring_pedersen_free_public(large_ring_pedersen_pub);
    }

    SECTION("valid large keys reduced") 
    {
        ring_pedersen_public_t*  large_ring_pedersen_pub;
        ring_pedersen_private_t* large_ring_pedersen_priv;
        auto status = ring_pedersen_generate_key_pair(2048, &large_ring_pedersen_pub, &large_ring_pedersen_priv);
        paillier_public_key_t*  large_paillier_pub = NULL;
        paillier_private_key_t* large_paillier_priv = NULL;
        long res = paillier_generate_key_pair(3072, &large_paillier_pub, &large_paillier_priv);
        REQUIRE(status == RING_PEDERSEN_SUCCESS);
        REQUIRE(res == PAILLIER_SUCCESS);
        
        uint32_t len = 0;
        REQUIRE(range_proof_paillier_large_factors_zkp_generate(large_paillier_priv, large_ring_pedersen_pub, (const unsigned char*)"hello world", sizeof("hello world") - 1, 0, NULL, 0, &len) == ZKP_INSUFFICIENT_BUFFER);
        uint8_t* proof = new uint8_t[len];
        REQUIRE(range_proof_paillier_large_factors_zkp_generate(large_paillier_priv, large_ring_pedersen_pub, (const unsigned char*)"hello world", sizeof("hello world") - 1, 0, proof, len, &len) == ZKP_SUCCESS);
        REQUIRE(range_proof_paillier_large_factors_zkp_verify(large_paillier_pub, large_ring_pedersen_priv, (const unsigned char*)"hello world", sizeof("hello world") - 1, 0, proof, len) == ZKP_SUCCESS);
        delete[] proof;
    
        paillier_free_private_key(large_paillier_priv);
        paillier_free_public_key(large_paillier_pub);
        ring_pedersen_free_private(large_ring_pedersen_priv);
        ring_pedersen_free_public(large_ring_pedersen_pub);
    }

    SECTION("invalid aad extended") 
    {
        REQUIRE(status == RING_PEDERSEN_SUCCESS);
        REQUIRE(res == PAILLIER_SUCCESS);
        
        uint32_t len = 0;
        REQUIRE(range_proof_paillier_large_factors_zkp_generate(paillier_priv, ring_pedersen_pub, (const unsigned char*)"hello world", sizeof("hello world") - 1, 1, NULL, 0, &len) == ZKP_INSUFFICIENT_BUFFER);
        uint8_t* proof = new uint8_t[len];
        REQUIRE(range_proof_paillier_large_factors_zkp_generate(paillier_priv, ring_pedersen_pub, (const unsigned char*)"hello world", sizeof("hello world") - 1, 1, proof, len, &len) == ZKP_SUCCESS);
        REQUIRE(range_proof_paillier_large_factors_zkp_verify(paillier_pub, ring_pedersen_priv, (const unsigned char*)"gello world", sizeof("hello world") - 1, 1, proof, len) == ZKP_VERIFICATION_FAILED);
        delete[] proof;
    }

    SECTION("invalid aad reduced") 
    {
        REQUIRE(status == RING_PEDERSEN_SUCCESS);
        REQUIRE(res == PAILLIER_SUCCESS);
        
        uint32_t len = 0;
        REQUIRE(range_proof_paillier_large_factors_zkp_generate(paillier_priv, ring_pedersen_pub, (const unsigned char*)"hello world", sizeof("hello world") - 1, 0, NULL, 0, &len) == ZKP_INSUFFICIENT_BUFFER);
        uint8_t* proof = new uint8_t[len];
        REQUIRE(range_proof_paillier_large_factors_zkp_generate(paillier_priv, ring_pedersen_pub, (const unsigned char*)"hello world", sizeof("hello world") - 1, 0, proof, len, &len) == ZKP_SUCCESS);
        REQUIRE(range_proof_paillier_large_factors_zkp_verify(paillier_pub, ring_pedersen_priv, (const unsigned char*)"gello world", sizeof("hello world") - 1, 0, proof, len) == ZKP_VERIFICATION_FAILED);
        delete[] proof;
    }

    SECTION("invalid proof - extended") 
    {
        REQUIRE(status == RING_PEDERSEN_SUCCESS);
        uint32_t len = 0;
        BN_CTX* ctx = BN_CTX_new();
        BN_CTX_start(ctx);
        paillier_private_key priv = {};
        priv.p = BN_CTX_get(ctx);
        priv.q = BN_CTX_get(ctx);
        priv.pub.n = BN_CTX_get(ctx);
        REQUIRE(BN_generate_prime_ex(priv.p, 256, 0, NULL, NULL, NULL));
        REQUIRE(BN_generate_prime_ex(priv.q, 2048 - 256, 0, NULL, NULL, NULL));
        REQUIRE(BN_mul(priv.pub.n, priv.p, priv.q, ctx));

        REQUIRE(range_proof_paillier_large_factors_zkp_generate((paillier_private_key_t*)&priv, ring_pedersen_pub, (const unsigned char*)"hello world", sizeof("hello world") - 1, 1, NULL, 0, &len) == ZKP_INSUFFICIENT_BUFFER);
        uint8_t* proof = new uint8_t[len];
        range_proof_paillier_large_factors_zkp_generate((paillier_private_key_t*)&priv, ring_pedersen_pub, (const unsigned char*)"hello world", sizeof("hello world") - 1, 1, proof, len, &len);
        REQUIRE(range_proof_paillier_large_factors_zkp_verify((paillier_public_key_t*)&priv.pub, ring_pedersen_priv, (const unsigned char*)"hello world", sizeof("hello world") - 1, 1, proof, len) == ZKP_VERIFICATION_FAILED);
        delete[] proof;
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
    }


    SECTION("invalid proof - reduced") 
    {
        REQUIRE(status == RING_PEDERSEN_SUCCESS);
        uint32_t len = 0;
        BN_CTX* ctx = BN_CTX_new();
        BN_CTX_start(ctx);
        paillier_private_key priv = {};
        priv.p = BN_CTX_get(ctx);
        priv.q = BN_CTX_get(ctx);
        priv.pub.n = BN_CTX_get(ctx);
        REQUIRE(BN_generate_prime_ex(priv.p, 256, 0, NULL, NULL, NULL));
        REQUIRE(BN_generate_prime_ex(priv.q, 2048 - 256, 0, NULL, NULL, NULL));
        REQUIRE(BN_mul(priv.pub.n, priv.p, priv.q, ctx));

        REQUIRE(range_proof_paillier_large_factors_zkp_generate((paillier_private_key_t*)&priv, ring_pedersen_pub, (const unsigned char*)"hello world", sizeof("hello world") - 1, 0, NULL, 0, &len) == ZKP_INSUFFICIENT_BUFFER);
        uint8_t* proof = new uint8_t[len];
        range_proof_paillier_large_factors_zkp_generate((paillier_private_key_t*)&priv, ring_pedersen_pub, (const unsigned char*)"hello world", sizeof("hello world") - 1, 0, proof, len, &len);
        REQUIRE(range_proof_paillier_large_factors_zkp_verify((paillier_public_key_t*)&priv.pub, ring_pedersen_priv, (const unsigned char*)"hello world", sizeof("hello world") - 1, 0, proof, len) == ZKP_VERIFICATION_FAILED);
        delete[] proof;
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
    }

    paillier_free_private_key(paillier_priv);
    paillier_free_public_key(paillier_pub);
    ring_pedersen_free_private(ring_pedersen_priv);
    ring_pedersen_free_public(ring_pedersen_pub);
}

// We fix the prime 'd' once and for all without impacting the
// security, since its generation takes a very long time.
// To avoid any malicious intent, we took the smallest safe prime of
// PAILLIER_LARGE_FACTOR_QUADRATIC_MAX_BITSIZE_FOR_HARCODED_D bitsize
// this is 2^3460 + 1169115 - first prime to have 3460 digits. 
// found by iterating over i where p = 2^3460 + 2*i + 1
static const uint8_t hardcoded_d[] = 
{
    0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x11, 0xd6,
    0xdb
};

TEST_CASE("paillier_large_factors_quadratic", "[default][large_factors_quadratic]") 
{
    paillier_public_key* pub;
    paillier_private_key* priv;
    long res = paillier_generate_key_pair(3072, &pub, &priv);
    REQUIRE(res == PAILLIER_SUCCESS);
    uint32_t proof_len = 0;

    SECTION("valid") 
    {
        REQUIRE(range_proof_paillier_large_factors_quadratic_zkp_generate(priv, (const uint8_t*) "Test AAD", 8, hardcoded_d, sizeof(hardcoded_d), NULL, 0, &proof_len) == ZKP_INSUFFICIENT_BUFFER);
        REQUIRE(proof_len > 0);
        std::vector<uint8_t> serialized_proof(proof_len);
        REQUIRE(range_proof_paillier_large_factors_quadratic_zkp_generate(priv, (const uint8_t*) "Test AAD", 8, hardcoded_d, sizeof(hardcoded_d), serialized_proof.data(), proof_len, NULL) == ZKP_SUCCESS);
        REQUIRE(range_proof_paillier_large_factors_quadratic_zkp_verify(pub, (const uint8_t*) "Test AAD", 8, serialized_proof.data(), proof_len) == ZKP_SUCCESS);
    }

    SECTION("invalid aad") 
    {
        REQUIRE(range_proof_paillier_large_factors_quadratic_zkp_generate(priv, (const uint8_t*) "Test AAD", 8, hardcoded_d, sizeof(hardcoded_d), NULL, 0, &proof_len) == ZKP_INSUFFICIENT_BUFFER);
        REQUIRE(proof_len > 0);
        std::vector<uint8_t> serialized_proof(proof_len);
        REQUIRE(range_proof_paillier_large_factors_quadratic_zkp_generate(priv, (const uint8_t*) "Test AAD", 8, hardcoded_d, sizeof(hardcoded_d), serialized_proof.data(), proof_len, NULL) == ZKP_SUCCESS);
        REQUIRE(range_proof_paillier_large_factors_quadratic_zkp_verify(pub, (const uint8_t*) "test AAD", 8, serialized_proof.data(), proof_len) == ZKP_VERIFICATION_FAILED);
    }

    SECTION("auto generated d") 
    {   
        paillier_public_key_t* local_pub;
        paillier_private_key_t* local_priv;
        long res = paillier_generate_key_pair(512, &local_pub, &local_priv);
        REQUIRE(res == PAILLIER_SUCCESS);

        REQUIRE(range_proof_paillier_large_factors_quadratic_zkp_generate(local_priv, (const uint8_t*) "Test AAD", 8, NULL, 0, NULL, 0, &proof_len) == ZKP_INSUFFICIENT_BUFFER);
        REQUIRE(proof_len > 0);
        std::vector<uint8_t> serialized_proof(proof_len);
        REQUIRE(range_proof_paillier_large_factors_quadratic_zkp_generate(local_priv, (const uint8_t*) "Test AAD", 8, NULL, 0, serialized_proof.data(), proof_len, NULL) == ZKP_SUCCESS);
        REQUIRE(range_proof_paillier_large_factors_quadratic_zkp_verify(local_pub, (const uint8_t*) "test AAD", 8, serialized_proof.data(), proof_len) == ZKP_VERIFICATION_FAILED);
        paillier_free_private_key(local_priv);
        paillier_free_public_key(local_pub);
    }

    SECTION("non-safe prime d") 
    {   
        paillier_public_key_t* local_pub;
        paillier_private_key_t* local_priv;
        long res = paillier_generate_key_pair(512, &local_pub, &local_priv);
        REQUIRE(res == PAILLIER_SUCCESS);
        const uint32_t d_bitsize = range_proof_paillier_large_factors_quadratic_zkp_compute_d_bitsize(local_pub);
        BN_CTX *ctx = BN_CTX_new();
        REQUIRE(ctx);
        BN_CTX_start(ctx);

        BIGNUM* p = BN_CTX_get(ctx);
        BIGNUM* tmp = BN_CTX_get(ctx);
        REQUIRE((p && tmp));
        //generate not a safe prime p
        do
        {
            REQUIRE(BN_generate_prime_ex(p, d_bitsize, 0, NULL, NULL, NULL));
            REQUIRE(BN_rshift1(tmp, p));
            
        } while ( BN_is_prime_ex(tmp, BN_prime_checks, ctx, NULL));
        std::vector<uint8_t> d_buffer(BN_num_bytes(p));
        BN_bn2bin(p, &d_buffer[0]);
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);

        REQUIRE(range_proof_paillier_large_factors_quadratic_zkp_generate(local_priv, (const uint8_t*) "Test AAD", 8, d_buffer.data(), (uint32_t)d_buffer.size(), NULL, 0, &proof_len) == ZKP_INSUFFICIENT_BUFFER);
        REQUIRE(proof_len > 0);
        std::vector<uint8_t> serialized_proof(proof_len);
        REQUIRE(range_proof_paillier_large_factors_quadratic_zkp_generate(local_priv, (const uint8_t*) "Test AAD", 8, d_buffer.data(), (uint32_t)d_buffer.size(), serialized_proof.data(), proof_len, NULL) == ZKP_INVALID_PARAMETER);
        paillier_free_private_key(local_priv);
        paillier_free_public_key(local_pub);
    }


    SECTION("too small d") 
    {   
        paillier_public_key_t* local_pub;
        paillier_private_key_t* local_priv;
        long res = paillier_generate_key_pair(512, &local_pub, &local_priv);
        REQUIRE(res == PAILLIER_SUCCESS);
        const uint32_t d_bitsize = range_proof_paillier_large_factors_quadratic_zkp_compute_d_bitsize(local_pub);
        BN_CTX *ctx = BN_CTX_new();
        REQUIRE(ctx);
        BN_CTX_start(ctx);
        BIGNUM* p = BN_CTX_get(ctx);
        REQUIRE(p);
        REQUIRE(BN_generate_prime_ex(p, d_bitsize - 1, 1, NULL, NULL, NULL));
        std::vector<uint8_t> d_buffer(BN_num_bytes(p));
        BN_bn2bin(p, &d_buffer[0]);
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);

        REQUIRE(range_proof_paillier_large_factors_quadratic_zkp_generate(local_priv, (const uint8_t*) "Test AAD", 8, d_buffer.data(), (uint32_t)d_buffer.size(), NULL, 0, &proof_len) == ZKP_INSUFFICIENT_BUFFER);
        REQUIRE(proof_len > 0);
        std::vector<uint8_t> serialized_proof(proof_len);
        REQUIRE(range_proof_paillier_large_factors_quadratic_zkp_generate(local_priv, (const uint8_t*) "Test AAD", 8, d_buffer.data(), (uint32_t)d_buffer.size(), serialized_proof.data(), proof_len, NULL) == ZKP_INVALID_PARAMETER);
        paillier_free_private_key(local_priv);
        paillier_free_public_key(local_pub);
    }

    //Cannot add test that will fail the range proof without failing the sizes of z1 and z2 that depends on the half of the size of n

    paillier_free_private_key(priv);
    paillier_free_public_key(pub);
}

TEST_CASE("paillier_large_factors_quadratic-slow", "[.][slow]") 
{
    //very slow test - disable by default
    SECTION("valid bigger size") 
    {
        uint32_t proof_len = 0;
        paillier_public_key_t* local_pub;
        paillier_private_key_t* local_priv;
        long res = paillier_generate_key_pair(3100, &local_pub, &local_priv);
        REQUIRE(res == PAILLIER_SUCCESS);
        REQUIRE(range_proof_paillier_large_factors_quadratic_zkp_generate(local_priv, (const uint8_t*) "Test AAD", 8, hardcoded_d, sizeof(hardcoded_d), NULL, 0, &proof_len) == ZKP_INSUFFICIENT_BUFFER);
        REQUIRE(proof_len > 0);
        std::vector<uint8_t> serialized_proof(proof_len);
        REQUIRE(range_proof_paillier_large_factors_quadratic_zkp_generate(local_priv, (const uint8_t*) "Test AAD", 8, hardcoded_d, sizeof(hardcoded_d), serialized_proof.data(), proof_len, NULL) == ZKP_SUCCESS);
        REQUIRE(range_proof_paillier_large_factors_quadratic_zkp_verify(local_pub, (const uint8_t*) "Test AAD", 8, serialized_proof.data(), proof_len) == ZKP_SUCCESS);
        paillier_free_private_key(local_priv);
        paillier_free_public_key(local_pub);
    }
}

TEST_CASE("damgard_fujisaki", "[default]") 
{
    damgard_fujisaki_private* priv;
    damgard_fujisaki_public* pub;
    auto status = damgard_fujisaki_generate_key_pair(1024, 2, &pub, &priv);

    SECTION("valid") 
    {
        REQUIRE(status == RING_PEDERSEN_SUCCESS);
        uint32_t proof_len;
        auto res = damgard_fujisaki_parameters_zkp_generate(priv, (const unsigned char*)"hello world", sizeof("hello world") - 1, 1, NULL, 0, &proof_len);
        REQUIRE(res == ZKP_INSUFFICIENT_BUFFER);
        std::unique_ptr<uint8_t[]> proof(new uint8_t[proof_len]);
        res = damgard_fujisaki_parameters_zkp_generate(priv, (const unsigned char*)"hello world", sizeof("hello world") - 1, 1, proof.get(), proof_len -1, &proof_len);
        REQUIRE(res == ZKP_INSUFFICIENT_BUFFER);
        res = damgard_fujisaki_parameters_zkp_generate(priv, (const unsigned char*)"hello world", sizeof("hello world") - 1, 1, proof.get(), proof_len, &proof_len);
        REQUIRE(res == ZKP_SUCCESS);
        res = damgard_fujisaki_parameters_zkp_verify(pub, (const unsigned char*)"hello world", sizeof("hello world") - 1, 1, proof.get(), proof_len);
        REQUIRE(res == ZKP_SUCCESS);
    }

    SECTION("valid_bigger_challenge") 
    {
        REQUIRE(status == RING_PEDERSEN_SUCCESS);
        uint32_t proof_len;
        auto res = damgard_fujisaki_parameters_zkp_generate(priv, (const unsigned char*)"hello world", sizeof("hello world") - 1, 25, NULL, 0, &proof_len);
        REQUIRE(res == ZKP_INSUFFICIENT_BUFFER);
        std::unique_ptr<uint8_t[]> proof(new uint8_t[proof_len]);
        res = damgard_fujisaki_parameters_zkp_generate(priv, (const unsigned char*)"hello world", sizeof("hello world") - 1, 25, proof.get(), proof_len -1, &proof_len);
        REQUIRE(res == ZKP_INSUFFICIENT_BUFFER);
        res = damgard_fujisaki_parameters_zkp_generate(priv, (const unsigned char*)"hello world", sizeof("hello world") - 1, 25, proof.get(), proof_len, &proof_len);
        REQUIRE(res == ZKP_SUCCESS);
        res = damgard_fujisaki_parameters_zkp_verify(pub, (const unsigned char*)"hello world", sizeof("hello world") - 1, 25, proof.get(), proof_len);
        REQUIRE(res == ZKP_SUCCESS);
    }

    SECTION("invalid aad") 
    {
        REQUIRE(status == RING_PEDERSEN_SUCCESS);
        uint32_t proof_len;
        auto res = damgard_fujisaki_parameters_zkp_generate(priv, (const unsigned char*)"hello world", sizeof("hello world") - 1, 1, NULL, 0, &proof_len);
        REQUIRE(res == ZKP_INSUFFICIENT_BUFFER);
        std::unique_ptr<uint8_t[]> proof(new uint8_t[proof_len]);
        res = damgard_fujisaki_parameters_zkp_generate(priv, (const unsigned char*)"hello world", sizeof("hello world") - 1, 1, proof.get(), proof_len, &proof_len);
        REQUIRE(res == ZKP_SUCCESS);
        res = damgard_fujisaki_parameters_zkp_verify(pub, (const unsigned char*)"gello world", sizeof("hello world") - 1, 1, proof.get(), proof_len);
        REQUIRE(res == ZKP_VERIFICATION_FAILED);
    }

    SECTION("invalid proof") 
    {
        REQUIRE(status == RING_PEDERSEN_SUCCESS);
        uint32_t proof_len;
        auto res = damgard_fujisaki_parameters_zkp_generate(priv, (const unsigned char*)"hello world", sizeof("hello world") - 1, 1, NULL, 0, &proof_len);
        REQUIRE(res == ZKP_INSUFFICIENT_BUFFER);
        std::unique_ptr<uint8_t[]> proof(new uint8_t[proof_len]);
        res = damgard_fujisaki_parameters_zkp_generate(priv, (const unsigned char*)"hello world", sizeof("hello world") - 1, 1, proof.get(), proof_len, &proof_len);
        REQUIRE(res == ZKP_SUCCESS);
        (*(uint32_t*)proof.get())++;
        res = damgard_fujisaki_parameters_zkp_verify(pub, (const unsigned char*)"hello world", sizeof("hello world") - 1, 1, proof.get(), proof_len);
        REQUIRE(res == ZKP_VERIFICATION_FAILED);
        (*(uint32_t*)proof.get())--;
        proof.get()[32]++;
        res = damgard_fujisaki_parameters_zkp_verify(pub, (const unsigned char*)"hello world", sizeof("hello world") - 1, 1, proof.get(), proof_len);
        REQUIRE(res == ZKP_VERIFICATION_FAILED);
    }

    SECTION("invalid param") 
    {
        uint32_t proof_len;
        auto res = damgard_fujisaki_parameters_zkp_generate(priv, (const unsigned char*)"hello world", sizeof("hello world") - 1, 1, NULL, 0, &proof_len);
        REQUIRE(res == ZKP_INSUFFICIENT_BUFFER);
        std::unique_ptr<uint8_t[]> proof(new uint8_t[proof_len]);
        res = damgard_fujisaki_parameters_zkp_generate(NULL, (const unsigned char*)"hello world", sizeof("hello world") - 1, 1, proof.get(), proof_len, NULL);
        REQUIRE(res == ZKP_INVALID_PARAMETER);
        res = damgard_fujisaki_parameters_zkp_generate(priv, NULL, sizeof("hello world") - 1, 1, proof.get(), proof_len, NULL);
        REQUIRE(res == ZKP_INVALID_PARAMETER);
        res = damgard_fujisaki_parameters_zkp_generate(priv, (const unsigned char*)"hello world", sizeof("hello world") - 1, 1, NULL, proof_len, NULL);
        REQUIRE(res == ZKP_INVALID_PARAMETER);
        res = damgard_fujisaki_parameters_zkp_generate(priv, (const unsigned char*)"hello world", sizeof("hello world") - 1, 1, proof.get(), 0, NULL);
        REQUIRE(res == ZKP_INSUFFICIENT_BUFFER);
        res = damgard_fujisaki_parameters_zkp_verify(NULL, (const unsigned char*)"hello world", sizeof("hello world") - 1, 1, proof.get(), proof_len);
        REQUIRE(res == ZKP_INVALID_PARAMETER);
        res = damgard_fujisaki_parameters_zkp_verify(pub, 0, sizeof("hello world") - 1, 1, proof.get(), proof_len);
        REQUIRE(res == ZKP_INVALID_PARAMETER);
        res = damgard_fujisaki_parameters_zkp_verify(pub, (const unsigned char*)"hello world", sizeof("hello world") - 1, 1, NULL, proof_len);
        REQUIRE(res == ZKP_INVALID_PARAMETER);
        res = damgard_fujisaki_parameters_zkp_verify(pub, (const unsigned char*)"hello world", sizeof("hello world") - 1, 1, proof.get(), 7);
        REQUIRE(res == ZKP_INVALID_PARAMETER);
    }

    SECTION("serialization") 
    {
        REQUIRE(status == RING_PEDERSEN_SUCCESS);
        uint32_t needed_len = 0;
        damgard_fujisaki_public_serialize(pub, NULL, 0, &needed_len);
        uint8_t* buff = (uint8_t*)malloc(needed_len);
        damgard_fujisaki_public_serialize(pub, buff, needed_len, &needed_len);
        damgard_fujisaki_public* pub2 = damgard_fujisaki_public_deserialize(buff, needed_len);
        REQUIRE(pub2);
        uint32_t proof_len;
        auto res = damgard_fujisaki_parameters_zkp_generate(priv, (const unsigned char*)"hello world", sizeof("hello world") - 1, 1, NULL, 0, &proof_len);
        REQUIRE(res == ZKP_INSUFFICIENT_BUFFER);
        std::unique_ptr<uint8_t[]> proof(new uint8_t[proof_len]);
        res = damgard_fujisaki_parameters_zkp_generate(priv, (const unsigned char*)"hello world", sizeof("hello world") - 1, 1, proof.get(), proof_len, &proof_len);
        REQUIRE(res == ZKP_SUCCESS);
        res = damgard_fujisaki_parameters_zkp_verify(pub2, (const unsigned char*)"hello world", sizeof("hello world") - 1, 1, proof.get(), proof_len);
        REQUIRE(res == ZKP_SUCCESS);
        damgard_fujisaki_private_serialize(priv, NULL, 0, &needed_len);
        buff = (uint8_t*)realloc(buff, needed_len);
        damgard_fujisaki_private_serialize(priv, buff, needed_len, &needed_len);
        damgard_fujisaki_private* priv2 = damgard_fujisaki_private_deserialize(buff, needed_len);
        REQUIRE(priv2);
        free(buff);
        res = damgard_fujisaki_parameters_zkp_generate(priv2, 
                                                       (const unsigned char*)"hello world", 
                                                       sizeof("hello world") - 1, 
                                                       1, 
                                                       proof.get(), 
                                                       proof_len, 
                                                       &proof_len);
        REQUIRE(res == ZKP_SUCCESS);
        res = damgard_fujisaki_parameters_zkp_verify(pub, (const unsigned char*)"hello world", sizeof("hello world") - 1, 1, proof.get(), proof_len);
        REQUIRE(res == ZKP_SUCCESS);
        damgard_fujisaki_free_public(pub2);
        damgard_fujisaki_free_private(priv2);
    }

    damgard_fujisaki_free_public(pub);
    damgard_fujisaki_free_private(priv);
}

// ============================================================================
// Schnorr ZKP Attack Tests
// ============================================================================
TEST_CASE("schnorr_attacks", "[attacks][schnorr]")
{
    elliptic_curve256_algebra_ctx_t* algebra = elliptic_curve256_new_secp256k1_algebra();
    REQUIRE(algebra != nullptr);

    // Generate a valid proof for reuse in attack tests
    elliptic_curve256_scalar_t secret;
    elliptic_curve256_point_t pub_key;
    schnorr_zkp_t valid_proof;
    uint8_t prover_id[] = "test_prover";

    REQUIRE(algebra->rand(algebra, &secret) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
    REQUIRE(algebra->generator_mul(algebra, &pub_key, &secret) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
    REQUIRE(schnorr_zkp_generate(algebra, prover_id, sizeof(prover_id) - 1, &secret, &pub_key, &valid_proof) == ZKP_SUCCESS);

    SECTION("zero secret") {
        elliptic_curve256_scalar_t zero;
        zero_scalar(&zero);
        elliptic_curve256_point_t zero_pub;
        // G^0 = infinity, generator_mul may fail or return infinity
        auto status = algebra->generator_mul(algebra, &zero_pub, &zero);
        if (status == ELLIPTIC_CURVE_ALGEBRA_SUCCESS) {
            schnorr_zkp_t proof;
            auto zkp_status = schnorr_zkp_generate(algebra, prover_id, sizeof(prover_id) - 1, &zero, &zero_pub, &proof);
            // Either generate fails (good) or verify should still work for zero
            if (zkp_status == ZKP_SUCCESS) {
                auto verify_status = schnorr_zkp_verify(algebra, prover_id, sizeof(prover_id) - 1, &zero_pub, &proof);
                // If zero is a valid scalar, proof should verify
                REQUIRE(verify_status == ZKP_SUCCESS);
            }
        }
    }

    SECTION("order scalar") {
        elliptic_curve256_scalar_t order_s;
        order_scalar(algebra, &order_s);
        // n mod n = 0, so G^n = infinity
        elliptic_curve256_point_t order_pub;
        auto status = algebra->generator_mul(algebra, &order_pub, &order_s);
        if (status == ELLIPTIC_CURVE_ALGEBRA_SUCCESS) {
            schnorr_zkp_t proof;
            auto zkp_status = schnorr_zkp_generate(algebra, prover_id, sizeof(prover_id) - 1, &order_s, &order_pub, &proof);
            // Should either fail or produce a valid proof for the identity
            REQUIRE(zkp_status == ZKP_SUCCESS);
        }
    }

    SECTION("infinity public key") {
        elliptic_curve256_point_t inf;
        infinity_point(algebra, &inf);
        schnorr_zkp_t proof;
        auto status = schnorr_zkp_generate(algebra, prover_id, sizeof(prover_id) - 1, &secret, &inf, &proof);
        // Should fail: proof for wrong public key
        if (status == ZKP_SUCCESS) {
            auto verify_status = schnorr_zkp_verify(algebra, prover_id, sizeof(prover_id) - 1, &inf, &proof);
            REQUIRE(verify_status != ZKP_SUCCESS);
        }
    }

    SECTION("generator as public key") {
        elliptic_curve256_point_t G;
        generator_point(algebra, &G);
        // G is the public key for secret=1, but we're using a different secret
        schnorr_zkp_t proof;
        auto status = schnorr_zkp_generate(algebra, prover_id, sizeof(prover_id) - 1, &secret, &G, &proof);
        if (status == ZKP_SUCCESS) {
            auto verify_status = schnorr_zkp_verify(algebra, prover_id, sizeof(prover_id) - 1, &G, &proof);
            REQUIRE(verify_status == ZKP_VERIFICATION_FAILED);
        }
    }

    SECTION("negated public key") {
        elliptic_curve256_point_t neg_pub;
        memcpy(neg_pub, pub_key, sizeof(elliptic_curve256_point_t));
        negate_point(&neg_pub);
        // Verify with negated public key should fail
        auto status = schnorr_zkp_verify(algebra, prover_id, sizeof(prover_id) - 1, &neg_pub, &valid_proof);
        REQUIRE(status == ZKP_VERIFICATION_FAILED);
    }

    SECTION("single bit flip in R") {
        schnorr_zkp_t tampered = valid_proof;
        flip_bit(tampered.R, 16, 3); // Flip bit 3 of byte 16 in R
        auto status = schnorr_zkp_verify(algebra, prover_id, sizeof(prover_id) - 1, &pub_key, &tampered);
        // Non-deterministic: bit flip in compressed point R may produce an invalid encoding
        // (INVALID_PARAMETER) or a valid but wrong point (VERIFICATION_FAILED), depending
        // on the random key generated for this run.
        REQUIRE((status == ZKP_VERIFICATION_FAILED || status == ZKP_INVALID_PARAMETER));
    }

    SECTION("single bit flip in s") {
        schnorr_zkp_t tampered = valid_proof;
        flip_bit(tampered.s, 16, 3);
        auto status = schnorr_zkp_verify(algebra, prover_id, sizeof(prover_id) - 1, &pub_key, &tampered);
        REQUIRE(status == ZKP_VERIFICATION_FAILED);
    }

    SECTION("all-zeros R") {
        schnorr_zkp_t tampered = valid_proof;
        fill_zeros(tampered.R, sizeof(elliptic_curve256_point_t));
        auto status = schnorr_zkp_verify(algebra, prover_id, sizeof(prover_id) - 1, &pub_key, &tampered);
        REQUIRE(status == ZKP_VERIFICATION_FAILED);
    }

    SECTION("all-ones R") {
        schnorr_zkp_t tampered = valid_proof;
        fill_ones(tampered.R, sizeof(elliptic_curve256_point_t));
        auto status = schnorr_zkp_verify(algebra, prover_id, sizeof(prover_id) - 1, &pub_key, &tampered);
        REQUIRE(status == ZKP_INVALID_PARAMETER);
    }

    SECTION("all-zeros s") {
        schnorr_zkp_t tampered = valid_proof;
        fill_zeros(tampered.s, sizeof(elliptic_curve256_scalar_t));
        auto status = schnorr_zkp_verify(algebra, prover_id, sizeof(prover_id) - 1, &pub_key, &tampered);
        REQUIRE(status == ZKP_VERIFICATION_FAILED);
    }

    SECTION("all-ones s") {
        schnorr_zkp_t tampered = valid_proof;
        fill_ones(tampered.s, sizeof(elliptic_curve256_scalar_t));
        auto status = schnorr_zkp_verify(algebra, prover_id, sizeof(prover_id) - 1, &pub_key, &tampered);
        REQUIRE(status == ZKP_VERIFICATION_FAILED);
    }

    SECTION("swapped R and s") {
        schnorr_zkp_t tampered = valid_proof;
        // R is 33 bytes, s is 32 bytes - swap first 32 bytes
        swap_fields(tampered.R, tampered.s, sizeof(elliptic_curve256_scalar_t));
        auto status = schnorr_zkp_verify(algebra, prover_id, sizeof(prover_id) - 1, &pub_key, &tampered);
        REQUIRE(status == ZKP_INVALID_PARAMETER);
    }

    SECTION("scalar overflow - order value in s") {
        schnorr_zkp_t tampered = valid_proof;
        order_scalar(algebra, &tampered.s);
        auto status = schnorr_zkp_verify(algebra, prover_id, sizeof(prover_id) - 1, &pub_key, &tampered);
        REQUIRE(status == ZKP_VERIFICATION_FAILED);
    }

    SECTION("scalar overflow - max value in s") {
        schnorr_zkp_t tampered = valid_proof;
        max_scalar(&tampered.s);
        auto status = schnorr_zkp_verify(algebra, prover_id, sizeof(prover_id) - 1, &pub_key, &tampered);
        REQUIRE(status == ZKP_VERIFICATION_FAILED);
    }

    SECTION("proof replay - valid proof for different public key") {
        elliptic_curve256_scalar_t secret2;
        elliptic_curve256_point_t pub2;
        REQUIRE(algebra->rand(algebra, &secret2) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE(algebra->generator_mul(algebra, &pub2, &secret2) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        // Use valid_proof (for pub_key) against pub2
        auto status = schnorr_zkp_verify(algebra, prover_id, sizeof(prover_id) - 1, &pub2, &valid_proof);
        REQUIRE(status == ZKP_VERIFICATION_FAILED);
    }

    SECTION("proof replay - valid proof with different prover_id") {
        uint8_t other_id[] = "other_prover";
        auto status = schnorr_zkp_verify(algebra, other_id, sizeof(other_id) - 1, &pub_key, &valid_proof);
        REQUIRE(status == ZKP_VERIFICATION_FAILED);
    }

    SECTION("alternative infinity encodings in R") {
        schnorr_zkp_t tampered = valid_proof;

        // Alt infinity type 1: 0x00 prefix with non-zero trailing
        alt_infinity_nonzero_trailing(&tampered.R);
        auto status = schnorr_zkp_verify(algebra, prover_id, sizeof(prover_id) - 1, &pub_key, &tampered);
        REQUIRE(status == ZKP_VERIFICATION_FAILED);

        // Alt infinity type 2: 0x04 uncompressed zeros
        tampered = valid_proof;
        alt_infinity_uncompressed_zeros(&tampered.R);
        status = schnorr_zkp_verify(algebra, prover_id, sizeof(prover_id) - 1, &pub_key, &tampered);
        REQUIRE(status == ZKP_INVALID_PARAMETER);

        // Alt infinity type 3: valid prefix, zero x
        tampered = valid_proof;
        alt_infinity_valid_prefix_zero_x(&tampered.R);
        status = schnorr_zkp_verify(algebra, prover_id, sizeof(prover_id) - 1, &pub_key, &tampered);
        REQUIRE(status == ZKP_INVALID_PARAMETER);
    }

    SECTION("alternative infinity encodings in public key") {
        elliptic_curve256_point_t bad_pub;

        alt_infinity_nonzero_trailing(&bad_pub);
        auto status = schnorr_zkp_verify(algebra, prover_id, sizeof(prover_id) - 1, &bad_pub, &valid_proof);
        REQUIRE(status == ZKP_VERIFICATION_FAILED);

        alt_infinity_valid_prefix_zero_x(&bad_pub);
        status = schnorr_zkp_verify(algebra, prover_id, sizeof(prover_id) - 1, &bad_pub, &valid_proof);
        REQUIRE(status == ZKP_INVALID_PARAMETER);
    }

    SECTION("empty prover_id") {
        auto status = schnorr_zkp_verify(algebra, prover_id, 0, &pub_key, &valid_proof);
        // With zero-length ID, should either fail or produce different result
        REQUIRE(status == ZKP_INVALID_PARAMETER);
    }

    SECTION("multi-curve: secp256r1 proof verified on secp256k1") {
        elliptic_curve256_algebra_ctx_t* r1_algebra = elliptic_curve256_new_secp256r1_algebra();
        REQUIRE(r1_algebra != nullptr);

        // Generate proof on secp256r1
        elliptic_curve256_scalar_t r1_secret;
        elliptic_curve256_point_t r1_pub;
        schnorr_zkp_t r1_proof;
        REQUIRE(r1_algebra->rand(r1_algebra, &r1_secret) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE(r1_algebra->generator_mul(r1_algebra, &r1_pub, &r1_secret) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE(schnorr_zkp_generate(r1_algebra, prover_id, sizeof(prover_id) - 1, &r1_secret, &r1_pub, &r1_proof) == ZKP_SUCCESS);

        // Verify on secp256k1 - should fail
        auto status = schnorr_zkp_verify(algebra, prover_id, sizeof(prover_id) - 1, &r1_pub, &r1_proof);
        // Non-deterministic: secp256r1 point may or may not be valid on secp256k1.
        // If valid point on wrong curve -> VERIFICATION_FAILED; if invalid encoding -> INVALID_PARAMETER.
        REQUIRE((status == ZKP_VERIFICATION_FAILED || status == ZKP_INVALID_PARAMETER));

        elliptic_curve256_algebra_ctx_free(r1_algebra);
    }

    elliptic_curve256_algebra_ctx_free(algebra);
}

// ============================================================================
// Ring Pedersen Attack Tests
// ============================================================================
TEST_CASE("ring_pedersen_attacks", "[attacks][ring_pedersen]")
{
    ring_pedersen_public_t* pub;
    ring_pedersen_private_t* priv;
    auto status = ring_pedersen_generate_key_pair(1024, &pub, &priv);
    REQUIRE(status == RING_PEDERSEN_SUCCESS);

    // Generate a valid ZKP
    uint32_t proof_len = 0;
    auto res = ring_pedersen_parameters_zkp_generate(priv, (const uint8_t*)"Test AAD", 8, NULL, 0, &proof_len);
    REQUIRE(res == ZKP_INSUFFICIENT_BUFFER);
    REQUIRE(proof_len > 0);
    std::vector<uint8_t> valid_proof(proof_len);
    res = ring_pedersen_parameters_zkp_generate(priv, (const uint8_t*)"Test AAD", 8, valid_proof.data(), proof_len, NULL);
    REQUIRE(res == ZKP_SUCCESS);

    SECTION("single bit flip in proof") {
        for (size_t byte_pos = 0; byte_pos < proof_len; byte_pos += proof_len / 10) {
            std::vector<uint8_t> tampered = valid_proof;
            flip_bit(tampered.data(), byte_pos, 0);
            auto verify_res = ring_pedersen_parameters_zkp_verify(pub, (const uint8_t*)"Test AAD", 8, tampered.data(), proof_len);
            REQUIRE(verify_res == ZKP_VERIFICATION_FAILED);
        }
    }

    SECTION("truncated proof") {
        for (size_t remove = 1; remove <= 32; remove *= 2) {
            if (remove >= proof_len) continue;
            auto tampered = truncate(valid_proof.data(), proof_len, remove);
            auto verify_res = ring_pedersen_parameters_zkp_verify(pub, (const uint8_t*)"Test AAD", 8, tampered.data(), (uint32_t)tampered.size());
            REQUIRE(verify_res == ZKP_INVALID_PARAMETER);
        }
    }

    SECTION("extended proof") {
        auto tampered = extend(valid_proof.data(), proof_len, 32);
        auto verify_res = ring_pedersen_parameters_zkp_verify(pub, (const uint8_t*)"Test AAD", 8, tampered.data(), (uint32_t)tampered.size());
        REQUIRE(verify_res == ZKP_INVALID_PARAMETER);
    }

    SECTION("all-zeros proof") {
        std::vector<uint8_t> tampered(proof_len, 0);
        auto verify_res = ring_pedersen_parameters_zkp_verify(pub, (const uint8_t*)"Test AAD", 8, tampered.data(), proof_len);
        REQUIRE(verify_res == ZKP_VERIFICATION_FAILED);
    }

    SECTION("all-ones proof") {
        std::vector<uint8_t> tampered(proof_len, 0xFF);
        auto verify_res = ring_pedersen_parameters_zkp_verify(pub, (const uint8_t*)"Test AAD", 8, tampered.data(), proof_len);
        REQUIRE(verify_res == ZKP_VERIFICATION_FAILED);
    }

    SECTION("random bytes as proof") {
        std::vector<uint8_t> tampered(proof_len);
        RAND_bytes(tampered.data(), (int)proof_len);
        auto verify_res = ring_pedersen_parameters_zkp_verify(pub, (const uint8_t*)"Test AAD", 8, tampered.data(), proof_len);
        REQUIRE(verify_res == ZKP_VERIFICATION_FAILED);
    }

    SECTION("commitment with tampered x") {
        // Create a valid commitment first
        uint8_t x[32], r[32];
        RAND_bytes(x, sizeof(x));
        RAND_bytes(r, sizeof(r));

        uint32_t commitment_len = 0;
        ring_pedersen_create_commitment(pub, x, sizeof(x), r, sizeof(r), NULL, 0, &commitment_len);
        REQUIRE(commitment_len > 0);
        std::vector<uint8_t> commitment(commitment_len);
        REQUIRE(ring_pedersen_create_commitment(pub, x, sizeof(x), r, sizeof(r),
                commitment.data(), commitment_len, &commitment_len) == RING_PEDERSEN_SUCCESS);

        // Tamper with x
        x[0] ^= 1;
        REQUIRE(ring_pedersen_verify_commitment(priv, x, sizeof(x), r, sizeof(r),
                commitment.data(), commitment_len) == RING_PEDERSEN_INVALID_COMMITMENT);
    }

    SECTION("commitment with tampered r") {
        uint8_t x[32], r[32];
        RAND_bytes(x, sizeof(x));
        RAND_bytes(r, sizeof(r));

        uint32_t commitment_len = 0;
        ring_pedersen_create_commitment(pub, x, sizeof(x), r, sizeof(r), NULL, 0, &commitment_len);
        std::vector<uint8_t> commitment(commitment_len);
        REQUIRE(ring_pedersen_create_commitment(pub, x, sizeof(x), r, sizeof(r),
                commitment.data(), commitment_len, &commitment_len) == RING_PEDERSEN_SUCCESS);

        r[0] ^= 1;
        REQUIRE(ring_pedersen_verify_commitment(priv, x, sizeof(x), r, sizeof(r),
                commitment.data(), commitment_len) == RING_PEDERSEN_INVALID_COMMITMENT);
    }

    SECTION("zero-length x in commitment") {
        uint8_t r[32];
        RAND_bytes(r, sizeof(r));
        uint32_t commitment_len = 0;
        auto cstatus = ring_pedersen_create_commitment(pub, NULL, 0, r, sizeof(r), NULL, 0, &commitment_len);
        REQUIRE(cstatus == RING_PEDERSEN_INVALID_PARAMETER);
    }

    SECTION("deserialization of corrupted key") {
        // Serialize the public key
        uint32_t key_len = 0;
        ring_pedersen_public_serialize(pub, NULL, 0, &key_len);
        REQUIRE(key_len > 0);
        std::vector<uint8_t> key_data(key_len);
        ring_pedersen_public_serialize(pub, key_data.data(), key_len, &key_len);

        // Corrupt and attempt to deserialize
        key_data[key_len / 2] ^= 0xFF;
        auto* bad_pub = ring_pedersen_public_deserialize(key_data.data(), key_len);
        // Either returns NULL or returns an invalid key
        if (bad_pub) {
            // If it deserializes, proofs should still fail with the corrupted key
            auto verify_res = ring_pedersen_parameters_zkp_verify(bad_pub, (const uint8_t*)"Test AAD", 8,
                    valid_proof.data(), proof_len);
            REQUIRE(verify_res == ZKP_VERIFICATION_FAILED);
            ring_pedersen_free_public(bad_pub);
        }
    }

    SECTION("cross-key verification") {
        // Generate a second key pair and try to verify key A's proof with key B
        ring_pedersen_public_t* pub2;
        ring_pedersen_private_t* priv2;
        REQUIRE(ring_pedersen_generate_key_pair(1024, &pub2, &priv2) == RING_PEDERSEN_SUCCESS);

        auto verify_res = ring_pedersen_parameters_zkp_verify(pub2, (const uint8_t*)"Test AAD", 8,
                valid_proof.data(), proof_len);
        REQUIRE(verify_res == ZKP_VERIFICATION_FAILED);

        ring_pedersen_free_public(pub2);
        ring_pedersen_free_private(priv2);
    }

    ring_pedersen_free_public(pub);
    ring_pedersen_free_private(priv);
}

// ============================================================================
// DDH (Diffie-Hellman Log) Attack Tests
// ============================================================================
TEST_CASE("ddh_attacks", "[attacks][ddh]")
{
    elliptic_curve256_algebra_ctx_t* algebra = elliptic_curve256_new_secp256k1_algebra();
    REQUIRE(algebra != nullptr);

    // Setup valid DDH proof: A = g^a, B = g^b, X = g^secret, C = g^(ab + secret)
    elliptic_curve256_scalar_t secret, a, b;
    REQUIRE(algebra->rand(algebra, &secret) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
    REQUIRE(algebra->rand(algebra, &a) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
    REQUIRE(algebra->rand(algebra, &b) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);

    elliptic_curve256_point_t base_point;
    generator_point(algebra, &base_point);

    diffie_hellman_log_public_data_t pub_data;
    REQUIRE(algebra->generator_mul(algebra, &pub_data.A, &a) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
    REQUIRE(algebra->generator_mul(algebra, &pub_data.B, &b) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
    REQUIRE(algebra->generator_mul(algebra, &pub_data.X, &secret) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);

    // C = g^(a*b + secret)
    elliptic_curve256_scalar_t ab;
    REQUIRE(algebra->mul_scalars(algebra, &ab, a, sizeof(a), b, sizeof(b)) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
    elliptic_curve256_scalar_t ab_plus_secret;
    REQUIRE(algebra->add_scalars(algebra, &ab_plus_secret, ab, sizeof(ab), secret, sizeof(secret)) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
    REQUIRE(algebra->generator_mul(algebra, &pub_data.C, &ab_plus_secret) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);

    diffie_hellman_log_zkp_t valid_proof;
    REQUIRE(diffie_hellman_log_zkp_generate(algebra, (const uint8_t*)"DDH AAD", 7, &base_point,
            &secret, &a, &b, &pub_data, &valid_proof) == ZKP_SUCCESS);
    REQUIRE(diffie_hellman_log_zkp_verify(algebra, (const uint8_t*)"DDH AAD", 7, &base_point,
            &pub_data, &valid_proof) == ZKP_SUCCESS);

    SECTION("infinity point as A") {
        diffie_hellman_log_public_data_t bad_data = pub_data;
        infinity_point(algebra, &bad_data.A);
        auto status = diffie_hellman_log_zkp_verify(algebra, (const uint8_t*)"DDH AAD", 7, &base_point,
                &bad_data, &valid_proof);
        REQUIRE(status == ZKP_VERIFICATION_FAILED);
    }

    SECTION("infinity point as base_point") {
        elliptic_curve256_point_t inf;
        infinity_point(algebra, &inf);
        auto status = diffie_hellman_log_zkp_verify(algebra, (const uint8_t*)"DDH AAD", 7, &inf,
                &pub_data, &valid_proof);
        REQUIRE(status == ZKP_VERIFICATION_FAILED);
    }

    SECTION("all-zeros in proof D") {
        diffie_hellman_log_zkp_t tampered = valid_proof;
        fill_zeros(tampered.D, sizeof(elliptic_curve256_point_t));
        auto status = diffie_hellman_log_zkp_verify(algebra, (const uint8_t*)"DDH AAD", 7, &base_point,
                &pub_data, &tampered);
        REQUIRE(status == ZKP_VERIFICATION_FAILED);
    }

    SECTION("all-ones in proof w") {
        diffie_hellman_log_zkp_t tampered = valid_proof;
        fill_ones(tampered.w, sizeof(elliptic_curve256_scalar_t));
        auto status = diffie_hellman_log_zkp_verify(algebra, (const uint8_t*)"DDH AAD", 7, &base_point,
                &pub_data, &tampered);
        REQUIRE(status == ZKP_VERIFICATION_FAILED);
    }

    SECTION("swapped w and z") {
        diffie_hellman_log_zkp_t tampered = valid_proof;
        swap_fields(tampered.w, tampered.z, sizeof(elliptic_curve256_scalar_t));
        auto status = diffie_hellman_log_zkp_verify(algebra, (const uint8_t*)"DDH AAD", 7, &base_point,
                &pub_data, &tampered);
        REQUIRE(status == ZKP_VERIFICATION_FAILED);
    }

    SECTION("random byte corruption") {
        for (int trial = 0; trial < 5; trial++) {
            diffie_hellman_log_zkp_t tampered = valid_proof;
            corrupt_random_bytes((uint8_t*)&tampered, sizeof(diffie_hellman_log_zkp_t), 1);
            auto status = diffie_hellman_log_zkp_verify(algebra, (const uint8_t*)"DDH AAD", 7, &base_point,
                    &pub_data, &tampered);
            REQUIRE(status == ZKP_VERIFICATION_FAILED);
        }
    }

    SECTION("negated A point") {
        diffie_hellman_log_public_data_t bad_data = pub_data;
        negate_point(&bad_data.A);
        auto status = diffie_hellman_log_zkp_verify(algebra, (const uint8_t*)"DDH AAD", 7, &base_point,
                &bad_data, &valid_proof);
        REQUIRE(status == ZKP_VERIFICATION_FAILED);
    }

    SECTION("swapped A and B") {
        diffie_hellman_log_public_data_t bad_data = pub_data;
        swap_fields(bad_data.A, bad_data.B, sizeof(elliptic_curve256_point_t));
        auto status = diffie_hellman_log_zkp_verify(algebra, (const uint8_t*)"DDH AAD", 7, &base_point,
                &bad_data, &valid_proof);
        REQUIRE(status == ZKP_VERIFICATION_FAILED);
    }

    SECTION("cross-curve: ed25519 proof verified on secp256k1") {
        elliptic_curve256_algebra_ctx_t* ed_algebra = elliptic_curve256_new_ed25519_algebra();
        REQUIRE(ed_algebra != nullptr);

        // Generate valid DDH proof on ed25519
        elliptic_curve256_scalar_t ed_secret, ed_a, ed_b;
        REQUIRE(ed_algebra->rand(ed_algebra, &ed_secret) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE(ed_algebra->rand(ed_algebra, &ed_a) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE(ed_algebra->rand(ed_algebra, &ed_b) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);

        elliptic_curve256_point_t ed_base;
        elliptic_curve256_scalar_t one_s;
        one_scalar(&one_s);
        REQUIRE(ed_algebra->generator_mul(ed_algebra, &ed_base, &one_s) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);

        diffie_hellman_log_public_data_t ed_pub;
        REQUIRE(ed_algebra->generator_mul(ed_algebra, &ed_pub.A, &ed_a) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE(ed_algebra->generator_mul(ed_algebra, &ed_pub.B, &ed_b) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE(ed_algebra->generator_mul(ed_algebra, &ed_pub.X, &ed_secret) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        elliptic_curve256_scalar_t ed_ab, ed_abs;
        REQUIRE(ed_algebra->mul_scalars(ed_algebra, &ed_ab, ed_a, sizeof(ed_a), ed_b, sizeof(ed_b)) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE(ed_algebra->add_scalars(ed_algebra, &ed_abs, ed_ab, sizeof(ed_ab), ed_secret, sizeof(ed_secret)) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE(ed_algebra->generator_mul(ed_algebra, &ed_pub.C, &ed_abs) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);

        diffie_hellman_log_zkp_t ed_proof;
        REQUIRE(diffie_hellman_log_zkp_generate(ed_algebra, (const uint8_t*)"DDH AAD", 7, &ed_base,
                &ed_secret, &ed_a, &ed_b, &ed_pub, &ed_proof) == ZKP_SUCCESS);

        // Verify ed25519 proof on secp256k1 - should fail
        auto status = diffie_hellman_log_zkp_verify(algebra, (const uint8_t*)"DDH AAD", 7, &base_point,
                &ed_pub, &ed_proof);
        REQUIRE(status == ZKP_VERIFICATION_FAILED);

        elliptic_curve256_algebra_ctx_free(ed_algebra);
    }

    SECTION("cross-key: proof from key set A verified with key set B") {
        // Generate a completely independent set of keys and public data
        elliptic_curve256_scalar_t secret2, a2, b2;
        REQUIRE(algebra->rand(algebra, &secret2) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE(algebra->rand(algebra, &a2) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE(algebra->rand(algebra, &b2) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);

        diffie_hellman_log_public_data_t pub_data2;
        REQUIRE(algebra->generator_mul(algebra, &pub_data2.A, &a2) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE(algebra->generator_mul(algebra, &pub_data2.B, &b2) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE(algebra->generator_mul(algebra, &pub_data2.X, &secret2) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        elliptic_curve256_scalar_t ab2, abs2;
        REQUIRE(algebra->mul_scalars(algebra, &ab2, a2, sizeof(a2), b2, sizeof(b2)) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE(algebra->add_scalars(algebra, &abs2, ab2, sizeof(ab2), secret2, sizeof(secret2)) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE(algebra->generator_mul(algebra, &pub_data2.C, &abs2) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);

        // Verify proof from key A with public data from key B - should fail
        auto status = diffie_hellman_log_zkp_verify(algebra, (const uint8_t*)"DDH AAD", 7, &base_point,
                &pub_data2, &valid_proof);
        REQUIRE(status == ZKP_VERIFICATION_FAILED);
    }

    elliptic_curve256_algebra_ctx_free(algebra);
}

// ============================================================================
// Damgard-Fujisaki Attack Tests
// ============================================================================
TEST_CASE("damgard_fujisaki_attacks", "[attacks][damgard_fujisaki]")
{
    damgard_fujisaki_private_t* priv;
    damgard_fujisaki_public_t* pub;
    auto key_status = damgard_fujisaki_generate_key_pair(1024, 2, &pub, &priv);
    REQUIRE(key_status == RING_PEDERSEN_SUCCESS);

    // Generate a valid proof
    uint32_t proof_len = 0;
    auto res = damgard_fujisaki_parameters_zkp_generate(priv, (const unsigned char*)"Test AAD", 8, 1, NULL, 0, &proof_len);
    REQUIRE(res == ZKP_INSUFFICIENT_BUFFER);
    std::vector<uint8_t> valid_proof(proof_len);
    res = damgard_fujisaki_parameters_zkp_generate(priv, (const unsigned char*)"Test AAD", 8, 1, valid_proof.data(), proof_len, &proof_len);
    REQUIRE(res == ZKP_SUCCESS);

    SECTION("truncated proof - remove 1 byte") {
        auto tampered = truncate(valid_proof.data(), proof_len, 1);
        auto verify_res = damgard_fujisaki_parameters_zkp_verify(pub, (const unsigned char*)"Test AAD", 8, 1, tampered.data(), (uint32_t)tampered.size());
        REQUIRE(verify_res == ZKP_INVALID_PARAMETER);
    }

    SECTION("truncated proof - remove 16 bytes") {
        auto tampered = truncate(valid_proof.data(), proof_len, 16);
        auto verify_res = damgard_fujisaki_parameters_zkp_verify(pub, (const unsigned char*)"Test AAD", 8, 1, tampered.data(), (uint32_t)tampered.size());
        REQUIRE(verify_res == ZKP_INVALID_PARAMETER);
    }

    SECTION("extended proof") {
        auto tampered = extend(valid_proof.data(), proof_len, 32);
        auto verify_res = damgard_fujisaki_parameters_zkp_verify(pub, (const unsigned char*)"Test AAD", 8, 1, tampered.data(), (uint32_t)tampered.size());
        REQUIRE(verify_res == ZKP_INVALID_PARAMETER);
    }

    SECTION("all-zeros proof") {
        std::vector<uint8_t> tampered(proof_len, 0);
        auto verify_res = damgard_fujisaki_parameters_zkp_verify(pub, (const unsigned char*)"Test AAD", 8, 1, tampered.data(), proof_len);
        REQUIRE(verify_res == ZKP_VERIFICATION_FAILED);
    }

    SECTION("random garbage as proof") {
        std::vector<uint8_t> tampered(proof_len);
        RAND_bytes(tampered.data(), (int)proof_len);
        auto verify_res = damgard_fujisaki_parameters_zkp_verify(pub, (const unsigned char*)"Test AAD", 8, 1, tampered.data(), proof_len);
        REQUIRE(verify_res == ZKP_VERIFICATION_FAILED);
    }

    SECTION("mismatched challenge_bitlength") {
        // Proof generated with challenge_bitlength=1, verify with challenge_bitlength=25
        auto verify_res = damgard_fujisaki_parameters_zkp_verify(pub, (const unsigned char*)"Test AAD", 8, 25, valid_proof.data(), proof_len);
        REQUIRE(verify_res == ZKP_INVALID_PARAMETER);
    }

    SECTION("cross-key verification") {
        // Generate a second key pair and try to verify with it
        damgard_fujisaki_private_t* priv2;
        damgard_fujisaki_public_t* pub2;
        REQUIRE(damgard_fujisaki_generate_key_pair(1024, 2, &pub2, &priv2) == RING_PEDERSEN_SUCCESS);

        auto verify_res = damgard_fujisaki_parameters_zkp_verify(pub2, (const unsigned char*)"Test AAD", 8, 1, valid_proof.data(), proof_len);
        REQUIRE(verify_res == ZKP_VERIFICATION_FAILED);

        damgard_fujisaki_free_public(pub2);
        damgard_fujisaki_free_private(priv2);
    }

    SECTION("deserialization with corrupted data") {
        uint32_t key_len = 0;
        damgard_fujisaki_public_serialize(pub, NULL, 0, &key_len);
        std::vector<uint8_t> key_data(key_len);
        damgard_fujisaki_public_serialize(pub, key_data.data(), key_len, &key_len);

        // Corrupt middle bytes
        key_data[key_len / 2] ^= 0xFF;
        key_data[key_len / 2 + 1] ^= 0xAA;

        auto* bad_pub = damgard_fujisaki_public_deserialize(key_data.data(), key_len);
        if (bad_pub) {
            auto verify_res = damgard_fujisaki_parameters_zkp_verify(bad_pub, (const unsigned char*)"Test AAD", 8, 1, valid_proof.data(), proof_len);
            REQUIRE(verify_res == ZKP_VERIFICATION_FAILED);
            damgard_fujisaki_free_public(bad_pub);
        }
    }

    // damgard_fujisaki_public_deserialize returns NULL gracefully on invalid input.
    SECTION("deserialization with truncated data") {
        uint32_t key_len = 0;
        damgard_fujisaki_public_serialize(pub, NULL, 0, &key_len);
        std::vector<uint8_t> key_data(key_len);
        damgard_fujisaki_public_serialize(pub, key_data.data(), key_len, &key_len);
        auto* bad_pub = damgard_fujisaki_public_deserialize(key_data.data(), key_len / 2);
        REQUIRE(bad_pub == nullptr);
    }
    SECTION("deserialization with zero-length data") {
        auto* bad_pub = damgard_fujisaki_public_deserialize(NULL, 0);
        REQUIRE(bad_pub == nullptr);
    }

    damgard_fujisaki_free_public(pub);
    damgard_fujisaki_free_private(priv);
}

// ============================================================================
// Proof Randomization Tests
// Two proofs of the same statement must differ - verifies randomization.
// ============================================================================
TEST_CASE("zkp_proof_randomization", "[correctness]")
{
    SECTION("schnorr: two proofs of same statement differ")
    {
        auto* algebra = elliptic_curve256_new_secp256k1_algebra();
        REQUIRE(algebra);
        auto* gfp_ctx = secp256k1_algebra_ctx_new();
        REQUIRE(gfp_ctx);

        elliptic_curve256_scalar_t secret;
        elliptic_curve256_point_t pub_point;
        REQUIRE(GFp_curve_algebra_rand(gfp_ctx, &secret) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE(GFp_curve_algebra_generator_mul_data(gfp_ctx, (uint8_t*)secret, sizeof(secret), &pub_point) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);

        schnorr_zkp_t proof1, proof2;
        REQUIRE(schnorr_zkp_generate(algebra, secret, sizeof(secret), &secret, &pub_point, &proof1) == ZKP_SUCCESS);
        REQUIRE(schnorr_zkp_generate(algebra, secret, sizeof(secret), &secret, &pub_point, &proof2) == ZKP_SUCCESS);

        // Both proofs must verify
        REQUIRE(schnorr_zkp_verify(algebra, secret, sizeof(secret), &pub_point, &proof1) == ZKP_SUCCESS);
        REQUIRE(schnorr_zkp_verify(algebra, secret, sizeof(secret), &pub_point, &proof2) == ZKP_SUCCESS);

        // But they must differ (randomized commitment)
        REQUIRE(memcmp(&proof1, &proof2, sizeof(schnorr_zkp_t)) != 0);

        GFp_curve_algebra_ctx_free(gfp_ctx);
        elliptic_curve256_algebra_ctx_free(algebra);
    }

    SECTION("ring_pedersen: two proofs of same key differ")
    {
        ring_pedersen_public_t* pub;
        ring_pedersen_private_t* priv;
        REQUIRE(ring_pedersen_generate_key_pair(1024, &pub, &priv) == RING_PEDERSEN_SUCCESS);

        // Generate two proofs for the same key
        uint32_t proof_len = 0;
        ring_pedersen_parameters_zkp_generate(priv, (const uint8_t*)"AAD", 3, NULL, 0, &proof_len);
        REQUIRE(proof_len > 0);

        std::vector<uint8_t> p1(proof_len), p2(proof_len);
        REQUIRE(ring_pedersen_parameters_zkp_generate(priv, (const uint8_t*)"AAD", 3, p1.data(), proof_len, NULL) == ZKP_SUCCESS);
        REQUIRE(ring_pedersen_parameters_zkp_generate(priv, (const uint8_t*)"AAD", 3, p2.data(), proof_len, NULL) == ZKP_SUCCESS);

        // Both must verify
        REQUIRE(ring_pedersen_parameters_zkp_verify(pub, (const uint8_t*)"AAD", 3, p1.data(), proof_len) == ZKP_SUCCESS);
        REQUIRE(ring_pedersen_parameters_zkp_verify(pub, (const uint8_t*)"AAD", 3, p2.data(), proof_len) == ZKP_SUCCESS);

        // But they must differ
        REQUIRE(memcmp(p1.data(), p2.data(), proof_len) != 0);

        ring_pedersen_free_public(pub);
        ring_pedersen_free_private(priv);
    }

    SECTION("damgard_fujisaki: two proofs of same key differ")
    {
        damgard_fujisaki_private_t* df_priv;
        damgard_fujisaki_public_t* df_pub;
        REQUIRE(damgard_fujisaki_generate_key_pair(1024, 2, &df_pub, &df_priv) == RING_PEDERSEN_SUCCESS);

        uint32_t proof_len = 0;
        damgard_fujisaki_parameters_zkp_generate(df_priv, (const unsigned char*)"AAD", 3, 1, NULL, 0, &proof_len);
        REQUIRE(proof_len > 0);

        std::vector<uint8_t> p1(proof_len), p2(proof_len);
        REQUIRE(damgard_fujisaki_parameters_zkp_generate(df_priv, (const unsigned char*)"AAD", 3, 1, p1.data(), proof_len, &proof_len) == ZKP_SUCCESS);
        REQUIRE(damgard_fujisaki_parameters_zkp_generate(df_priv, (const unsigned char*)"AAD", 3, 1, p2.data(), proof_len, &proof_len) == ZKP_SUCCESS);

        // Both must verify
        REQUIRE(damgard_fujisaki_parameters_zkp_verify(df_pub, (const unsigned char*)"AAD", 3, 1, p1.data(), proof_len) == ZKP_SUCCESS);
        REQUIRE(damgard_fujisaki_parameters_zkp_verify(df_pub, (const unsigned char*)"AAD", 3, 1, p2.data(), proof_len) == ZKP_SUCCESS);

        // But they must differ
        REQUIRE(memcmp(p1.data(), p2.data(), proof_len) != 0);

        damgard_fujisaki_free_public(df_pub);
        damgard_fujisaki_free_private(df_priv);
    }
}

// ============================================================================
// ZKP Element Size Validation
// Verify proof byte lengths are consistent and within expected bounds.
// ============================================================================
TEST_CASE("zkp_element_size_validation", "[correctness]")
{
    SECTION("ring_pedersen proof size is consistent across multiple generations")
    {
        ring_pedersen_public_t* pub;
        ring_pedersen_private_t* priv;
        REQUIRE(ring_pedersen_generate_key_pair(1024, &pub, &priv) == RING_PEDERSEN_SUCCESS);

        uint32_t proof_len1 = 0, proof_len2 = 0;
        ring_pedersen_parameters_zkp_generate(priv, (const uint8_t*)"AAD", 3, NULL, 0, &proof_len1);
        REQUIRE(proof_len1 > 0);

        std::vector<uint8_t> p1(proof_len1);
        uint32_t real_len1 = 0;
        REQUIRE(ring_pedersen_parameters_zkp_generate(priv, (const uint8_t*)"AAD", 3, p1.data(), proof_len1, &real_len1) == ZKP_SUCCESS);

        // Generate a second proof and check size consistency
        ring_pedersen_parameters_zkp_generate(priv, (const uint8_t*)"BBB", 3, NULL, 0, &proof_len2);
        REQUIRE(proof_len2 == proof_len1);

        ring_pedersen_free_public(pub);
        ring_pedersen_free_private(priv);
    }

    SECTION("schnorr proof has non-zero fields")
    {
        auto* algebra = elliptic_curve256_new_secp256k1_algebra();
        auto* gfp_ctx = secp256k1_algebra_ctx_new();
        REQUIRE(algebra);
        REQUIRE(gfp_ctx);

        elliptic_curve256_scalar_t secret;
        elliptic_curve256_point_t pub_point;
        REQUIRE(GFp_curve_algebra_rand(gfp_ctx, &secret) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE(GFp_curve_algebra_generator_mul_data(gfp_ctx, (uint8_t*)secret, sizeof(secret), &pub_point) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);

        schnorr_zkp_t proof;
        REQUIRE(schnorr_zkp_generate(algebra, secret, sizeof(secret), &secret, &pub_point, &proof) == ZKP_SUCCESS);

        // R (commitment point) must not be all-zeros
        uint8_t zeros[sizeof(elliptic_curve256_point_t)] = {0};
        REQUIRE(memcmp(proof.R, zeros, sizeof(elliptic_curve256_point_t)) != 0);

        // s (response scalar) must not be all-zeros
        uint8_t scalar_zeros[sizeof(elliptic_curve256_scalar_t)] = {0};
        REQUIRE(memcmp(proof.s, scalar_zeros, sizeof(elliptic_curve256_scalar_t)) != 0);

        GFp_curve_algebra_ctx_free(gfp_ctx);
        elliptic_curve256_algebra_ctx_free(algebra);
    }

    SECTION("ddh proof has non-zero fields")
    {
        auto* algebra = elliptic_curve256_new_secp256k1_algebra();
        REQUIRE(algebra);

        elliptic_curve256_scalar_t secret, a, b;
        REQUIRE(algebra->rand(algebra, &secret) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE(algebra->rand(algebra, &a) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE(algebra->rand(algebra, &b) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);

        elliptic_curve256_scalar_t one_s = {0};
        one_s[ELLIPTIC_CURVE_FIELD_SIZE - 1] = 1;
        elliptic_curve256_point_t base_point;
        REQUIRE(algebra->generator_mul(algebra, &base_point, &one_s) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);

        diffie_hellman_log_public_data_t pub_data;
        REQUIRE(algebra->generator_mul(algebra, &pub_data.A, &a) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE(algebra->generator_mul(algebra, &pub_data.B, &b) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE(algebra->generator_mul(algebra, &pub_data.X, &secret) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        elliptic_curve256_scalar_t ab, abs_val;
        REQUIRE(algebra->mul_scalars(algebra, &ab, a, sizeof(a), b, sizeof(b)) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE(algebra->add_scalars(algebra, &abs_val, ab, sizeof(ab), secret, sizeof(secret)) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE(algebra->generator_mul(algebra, &pub_data.C, &abs_val) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);

        diffie_hellman_log_zkp_t proof;
        REQUIRE(diffie_hellman_log_zkp_generate(algebra, (const uint8_t*)"DDH", 3, &base_point,
                &secret, &a, &b, &pub_data, &proof) == ZKP_SUCCESS);

        // All proof fields must be non-zero
        uint8_t point_zeros[sizeof(elliptic_curve256_point_t)] = {0};
        uint8_t scalar_zeros[sizeof(elliptic_curve256_scalar_t)] = {0};
        REQUIRE(memcmp(proof.D, point_zeros, sizeof(elliptic_curve256_point_t)) != 0);
        REQUIRE(memcmp(proof.Y, point_zeros, sizeof(elliptic_curve256_point_t)) != 0);
        REQUIRE(memcmp(proof.V, point_zeros, sizeof(elliptic_curve256_point_t)) != 0);
        REQUIRE(memcmp(proof.w, scalar_zeros, sizeof(elliptic_curve256_scalar_t)) != 0);
        REQUIRE(memcmp(proof.z, scalar_zeros, sizeof(elliptic_curve256_scalar_t)) != 0);

        elliptic_curve256_algebra_ctx_free(algebra);
    }
}

// Verify that coprimality check failures on S and T fields return
// ZKP_VERIFICATION_FAILED (not ZKP_UNKNOWN_ERROR). Before the fix, the
// is_coprime_fast checks for S and T did not set status before goto cleanup.
TEST_CASE("exp_range_proof_coprime_status", "[attacks][range_proof]")
{
    ring_pedersen_public_t*  ring_pedersen_pub;
    ring_pedersen_private_t* ring_pedersen_priv;
    auto rp_status = ring_pedersen_generate_key_pair(1024, &ring_pedersen_pub, &ring_pedersen_priv);
    REQUIRE(rp_status == RING_PEDERSEN_SUCCESS);

    paillier_public_key_t*  paillier_pub = NULL;
    paillier_private_key_t* paillier_priv = NULL;
    long pail_res = paillier_generate_key_pair(2048, &paillier_pub, &paillier_priv);
    REQUIRE(pail_res == PAILLIER_SUCCESS);

    auto algebra = elliptic_curve256_new_secp256k1_algebra();
    REQUIRE(algebra);

    const uint8_t* aad = (const uint8_t*)"test_coprime_status";
    const uint32_t aad_len = 19;

    SECTION("zeroed S must return ZKP_VERIFICATION_FAILED in verify")
    {
        for (const uint8_t use_extended_seed : { (uint8_t)0, (uint8_t)1 })
        {
            elliptic_curve256_scalar_t x;
            elliptic_curve256_point_t X;
            REQUIRE(algebra->rand(algebra, &x) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
            REQUIRE(algebra->generator_mul(algebra, &X, &x) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);

            paillier_with_range_proof_t* valid_proof;
            REQUIRE(range_proof_paillier_encrypt_with_exponent_zkpok_generate(
                ring_pedersen_pub, paillier_pub, algebra,
                aad, aad_len, &x, use_extended_seed, &valid_proof) == ZKP_SUCCESS);

            REQUIRE(range_proof_exponent_zkpok_verify(
                ring_pedersen_priv, paillier_pub, algebra,
                aad, aad_len, &X, valid_proof, 1, use_extended_seed) == ZKP_SUCCESS);

            uint32_t rp_n_size = *(uint32_t*)valid_proof->serialized_proof;

            std::vector<uint8_t> tampered(valid_proof->serialized_proof,
                                          valid_proof->serialized_proof + valid_proof->proof_len);
            memset(tampered.data() + 8, 0, rp_n_size);

            paillier_with_range_proof_t bad_proof;
            bad_proof.ciphertext = valid_proof->ciphertext;
            bad_proof.ciphertext_len = valid_proof->ciphertext_len;
            bad_proof.serialized_proof = tampered.data();
            bad_proof.proof_len = valid_proof->proof_len;

            auto result = range_proof_exponent_zkpok_verify(
                ring_pedersen_priv, paillier_pub, algebra,
                aad, aad_len, &X, &bad_proof, 1, use_extended_seed);

            REQUIRE(result == ZKP_VERIFICATION_FAILED);

            range_proof_free_paillier_with_range_proof(valid_proof);
        }
    }

    SECTION("zeroed T must return ZKP_VERIFICATION_FAILED in verify")
    {
        for (const uint8_t use_extended_seed : { (uint8_t)0, (uint8_t)1 })
        {
            elliptic_curve256_scalar_t x;
            elliptic_curve256_point_t X;
            REQUIRE(algebra->rand(algebra, &x) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
            REQUIRE(algebra->generator_mul(algebra, &X, &x) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);

            paillier_with_range_proof_t* valid_proof;
            REQUIRE(range_proof_paillier_encrypt_with_exponent_zkpok_generate(
                ring_pedersen_pub, paillier_pub, algebra,
                aad, aad_len, &x, use_extended_seed, &valid_proof) == ZKP_SUCCESS);

            uint32_t rp_n_size = *(uint32_t*)valid_proof->serialized_proof;
            uint32_t pail_n_size = *(uint32_t*)(valid_proof->serialized_proof + 4);
            uint32_t t_offset = 8 + rp_n_size + 2 * pail_n_size + sizeof(elliptic_curve256_point_t);

            std::vector<uint8_t> tampered(valid_proof->serialized_proof,
                                          valid_proof->serialized_proof + valid_proof->proof_len);
            memset(tampered.data() + t_offset, 0, rp_n_size);

            paillier_with_range_proof_t bad_proof;
            bad_proof.ciphertext = valid_proof->ciphertext;
            bad_proof.ciphertext_len = valid_proof->ciphertext_len;
            bad_proof.serialized_proof = tampered.data();
            bad_proof.proof_len = valid_proof->proof_len;

            auto result = range_proof_exponent_zkpok_verify(
                ring_pedersen_priv, paillier_pub, algebra,
                aad, aad_len, &X, &bad_proof, 1, use_extended_seed);

            REQUIRE(result == ZKP_VERIFICATION_FAILED);

            range_proof_free_paillier_with_range_proof(valid_proof);
        }
    }

    ring_pedersen_free_public(ring_pedersen_pub);
    ring_pedersen_free_private(ring_pedersen_priv);
    paillier_free_public_key(paillier_pub);
    paillier_free_private_key(paillier_priv);
    algebra->release(algebra);
}

// Tests that zeroed S/T in the paillier commitment exponent proof returns
// ZKP_VERIFICATION_FAILED (not ZKP_UNKNOWN_ERROR).
TEST_CASE("paillier_commitment_coprime_status", "[attacks][range_proof]")
{
    damgard_fujisaki_public*  damgard_fujisaki_pub;
    damgard_fujisaki_private* damgard_fujisaki_priv;
    REQUIRE(damgard_fujisaki_generate_key_pair(1024, 2, &damgard_fujisaki_pub, &damgard_fujisaki_priv) == RING_PEDERSEN_SUCCESS);

    paillier_commitment_private_key_t* paillier_priv = NULL;
    REQUIRE(paillier_commitment_generate_private_key(2048, &paillier_priv) == PAILLIER_SUCCESS);

    auto algebra = elliptic_curve256_new_secp256k1_algebra();
    REQUIRE(algebra);

    const uint8_t* aad = (const uint8_t*)"test_pc_coprime";
    const uint32_t aad_len = 15;

    SECTION("zeroed S must return ZKP_VERIFICATION_FAILED")
    {
        for (const uint8_t use_extended_seed : { (uint8_t)0, (uint8_t)1 })
        {
            elliptic_curve256_scalar_t x;
            elliptic_curve256_point_t X;
            paillier_with_range_proof_t* proof = NULL;
            REQUIRE(algebra->rand(algebra, &x) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
            REQUIRE(algebra->generator_mul(algebra, &X, &x) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);

            REQUIRE(paillier_commitment_encrypt_with_exponent_zkpok_generate(damgard_fujisaki_pub,
                paillier_priv, algebra, aad, aad_len, x, sizeof(x),
                use_extended_seed, &proof) == ZKP_SUCCESS);

            REQUIRE(paillier_commitment_exponent_zkpok_verify(damgard_fujisaki_priv,
                paillier_commitment_private_cast_to_public(paillier_priv), algebra,
                aad, aad_len, &X,
                reinterpret_cast<const const_paillier_with_range_proof_t*>(proof),
                use_extended_seed) == ZKP_SUCCESS);

            uint32_t rp_n_size = *(uint32_t*)proof->serialized_proof;

            std::vector<uint8_t> tampered(proof->serialized_proof,
                                          proof->serialized_proof + proof->proof_len);
            memset(tampered.data() + 8, 0, rp_n_size);

            paillier_with_range_proof_t bad_proof;
            bad_proof.ciphertext = proof->ciphertext;
            bad_proof.ciphertext_len = proof->ciphertext_len;
            bad_proof.serialized_proof = tampered.data();
            bad_proof.proof_len = proof->proof_len;

            auto result = paillier_commitment_exponent_zkpok_verify(damgard_fujisaki_priv,
                paillier_commitment_private_cast_to_public(paillier_priv), algebra,
                aad, aad_len, &X,
                reinterpret_cast<const const_paillier_with_range_proof_t*>(&bad_proof),
                use_extended_seed);

            REQUIRE(result == ZKP_VERIFICATION_FAILED);

            range_proof_free_paillier_with_range_proof(proof);
        }
    }

    SECTION("zeroed T must return ZKP_VERIFICATION_FAILED")
    {
        for (const uint8_t use_extended_seed : { (uint8_t)0, (uint8_t)1 })
        {
            elliptic_curve256_scalar_t x;
            elliptic_curve256_point_t X;
            paillier_with_range_proof_t* proof = NULL;
            REQUIRE(algebra->rand(algebra, &x) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
            REQUIRE(algebra->generator_mul(algebra, &X, &x) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);

            REQUIRE(paillier_commitment_encrypt_with_exponent_zkpok_generate(damgard_fujisaki_pub,
                paillier_priv, algebra, aad, aad_len, x, sizeof(x),
                use_extended_seed, &proof) == ZKP_SUCCESS);

            uint32_t rp_n_size = *(uint32_t*)proof->serialized_proof;
            uint32_t pail_n_size = *(uint32_t*)(proof->serialized_proof + 4);
            uint32_t t_offset = 8 + rp_n_size + 2 * pail_n_size
                + sizeof(elliptic_curve256_point_t);

            std::vector<uint8_t> tampered(proof->serialized_proof,
                                          proof->serialized_proof + proof->proof_len);
            memset(tampered.data() + t_offset, 0, rp_n_size);

            paillier_with_range_proof_t bad_proof;
            bad_proof.ciphertext = proof->ciphertext;
            bad_proof.ciphertext_len = proof->ciphertext_len;
            bad_proof.serialized_proof = tampered.data();
            bad_proof.proof_len = proof->proof_len;

            auto result = paillier_commitment_exponent_zkpok_verify(damgard_fujisaki_priv,
                paillier_commitment_private_cast_to_public(paillier_priv), algebra,
                aad, aad_len, &X,
                reinterpret_cast<const const_paillier_with_range_proof_t*>(&bad_proof),
                use_extended_seed);

            REQUIRE(result == ZKP_VERIFICATION_FAILED);

            range_proof_free_paillier_with_range_proof(proof);
        }
    }

    damgard_fujisaki_free_public(damgard_fujisaki_pub);
    damgard_fujisaki_free_private(damgard_fujisaki_priv);
    paillier_commitment_free_private_key(paillier_priv);
    algebra->release(algebra);
}

// Tests that zeroed S/T in the diffie-hellman range proof returns
// ZKP_VERIFICATION_FAILED (not ZKP_UNKNOWN_ERROR).
TEST_CASE("dh_range_proof_coprime_status", "[attacks][range_proof]")
{
    ring_pedersen_public_t*  ring_pedersen_pub;
    ring_pedersen_private_t* ring_pedersen_priv;
    REQUIRE(ring_pedersen_generate_key_pair(1024, &ring_pedersen_pub, &ring_pedersen_priv) == RING_PEDERSEN_SUCCESS);

    paillier_public_key_t*  paillier_pub = NULL;
    paillier_private_key_t* paillier_priv = NULL;
    REQUIRE(paillier_generate_key_pair(2048, &paillier_pub, &paillier_priv) == PAILLIER_SUCCESS);

    auto algebra = elliptic_curve256_new_secp256k1_algebra();
    REQUIRE(algebra);

    const uint8_t* aad = (const uint8_t*)"test_dh_coprime";
    const uint32_t aad_len = 15;

    SECTION("zeroed S must return ZKP_VERIFICATION_FAILED")
    {
        for (const uint8_t use_extended_seed : { (uint8_t)0, (uint8_t)1 })
        {
            elliptic_curve256_scalar_t x, a, b;
            elliptic_curve256_point_t X, A, B;
            REQUIRE(algebra->rand(algebra, &x) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
            REQUIRE(algebra->rand(algebra, &a) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
            REQUIRE(algebra->generator_mul(algebra, &A, &a) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
            REQUIRE(algebra->rand(algebra, &b) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
            REQUIRE(algebra->generator_mul(algebra, &B, &b) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);

            paillier_with_range_proof_t* valid_proof = NULL;
            REQUIRE(range_proof_paillier_encrypt_with_diffie_hellman_zkpok_generate(
                ring_pedersen_pub, paillier_pub, algebra,
                aad, aad_len, &x, &a, &b, use_extended_seed, &valid_proof) == ZKP_SUCCESS);

            elliptic_curve256_scalar_t tmp;
            REQUIRE(algebra->mul_scalars(algebra, &tmp, a, sizeof(a), b, sizeof(b)) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
            REQUIRE(algebra->add_scalars(algebra, &tmp, tmp, sizeof(tmp), x, sizeof(x)) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
            REQUIRE(algebra->generator_mul(algebra, &X, &tmp) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);

            REQUIRE(range_proof_diffie_hellman_zkpok_verify(
                ring_pedersen_priv, paillier_pub, algebra,
                aad, aad_len, &X, &A, &B, valid_proof, 0, use_extended_seed) == ZKP_SUCCESS);

            uint32_t rp_n_size = *(uint32_t*)valid_proof->serialized_proof;

            std::vector<uint8_t> tampered(valid_proof->serialized_proof,
                                          valid_proof->serialized_proof + valid_proof->proof_len);
            memset(tampered.data() + 8, 0, rp_n_size);

            paillier_with_range_proof_t bad_proof;
            bad_proof.ciphertext = valid_proof->ciphertext;
            bad_proof.ciphertext_len = valid_proof->ciphertext_len;
            bad_proof.serialized_proof = tampered.data();
            bad_proof.proof_len = valid_proof->proof_len;

            auto result = range_proof_diffie_hellman_zkpok_verify(
                ring_pedersen_priv, paillier_pub, algebra,
                aad, aad_len, &X, &A, &B, &bad_proof, 0, use_extended_seed);

            REQUIRE(result == ZKP_VERIFICATION_FAILED);

            range_proof_free_paillier_with_range_proof(valid_proof);
        }
    }

    SECTION("zeroed T must return ZKP_VERIFICATION_FAILED")
    {
        for (const uint8_t use_extended_seed : { (uint8_t)0, (uint8_t)1 })
        {
            elliptic_curve256_scalar_t x, a, b;
            elliptic_curve256_point_t X, A, B;
            REQUIRE(algebra->rand(algebra, &x) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
            REQUIRE(algebra->rand(algebra, &a) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
            REQUIRE(algebra->generator_mul(algebra, &A, &a) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
            REQUIRE(algebra->rand(algebra, &b) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
            REQUIRE(algebra->generator_mul(algebra, &B, &b) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);

            paillier_with_range_proof_t* valid_proof = NULL;
            REQUIRE(range_proof_paillier_encrypt_with_diffie_hellman_zkpok_generate(
                ring_pedersen_pub, paillier_pub, algebra,
                aad, aad_len, &x, &a, &b, use_extended_seed, &valid_proof) == ZKP_SUCCESS);

            elliptic_curve256_scalar_t tmp;
            REQUIRE(algebra->mul_scalars(algebra, &tmp, a, sizeof(a), b, sizeof(b)) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
            REQUIRE(algebra->add_scalars(algebra, &tmp, tmp, sizeof(tmp), x, sizeof(x)) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
            REQUIRE(algebra->generator_mul(algebra, &X, &tmp) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);

            uint32_t rp_n_size = *(uint32_t*)valid_proof->serialized_proof;
            uint32_t pail_n_size = *(uint32_t*)(valid_proof->serialized_proof + 4);
            uint32_t t_offset = 8 + rp_n_size + 2 * pail_n_size
                + sizeof(elliptic_curve256_point_t);

            std::vector<uint8_t> tampered(valid_proof->serialized_proof,
                                          valid_proof->serialized_proof + valid_proof->proof_len);
            memset(tampered.data() + t_offset, 0, rp_n_size);

            paillier_with_range_proof_t bad_proof;
            bad_proof.ciphertext = valid_proof->ciphertext;
            bad_proof.ciphertext_len = valid_proof->ciphertext_len;
            bad_proof.serialized_proof = tampered.data();
            bad_proof.proof_len = valid_proof->proof_len;

            auto result = range_proof_diffie_hellman_zkpok_verify(
                ring_pedersen_priv, paillier_pub, algebra,
                aad, aad_len, &X, &A, &B, &bad_proof, 0, use_extended_seed);

            REQUIRE(result == ZKP_VERIFICATION_FAILED);

            range_proof_free_paillier_with_range_proof(valid_proof);
        }
    }

    ring_pedersen_free_public(ring_pedersen_pub);
    ring_pedersen_free_private(ring_pedersen_priv);
    paillier_free_public_key(paillier_pub);
    paillier_free_private_key(paillier_priv);
    algebra->release(algebra);
}