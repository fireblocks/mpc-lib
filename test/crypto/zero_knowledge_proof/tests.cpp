#include "crypto/zero_knowledge_proof/schnorr.h"
#include "crypto/zero_knowledge_proof/range_proofs.h"
#include "crypto/zero_knowledge_proof/diffie_hellman_log.h"
#include "crypto/GFp_curve_algebra/GFp_curve_algebra.h"
#include <openssl/rand.h>
#include <openssl/bn.h>

#include <iostream>
#include <memory>
#include <string.h>
#include <tests/catch.hpp>

void secure_memset(void* ptr, size_t len) {
    volatile unsigned char* p = (volatile unsigned char*)ptr;
    while (len--) *p++ = 0;
}

TEST_CASE("schnorr", "verify") {
    auto ctx = secp256k1_algebra_ctx_new();
    auto secp256k1_algebra = elliptic_curve256_new_secp256k1_algebra();

    SECTION("verify") {
        elliptic_curve256_scalar_t a;
        elliptic_curve256_point_t A;
        REQUIRE(ctx);

        REQUIRE(GFp_curve_algebra_rand(ctx, &a) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE(GFp_curve_algebra_generator_mul_data(ctx, reinterpret_cast<uint8_t*>(a), sizeof(a), &A) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);

        schnorr_zkp_t zkp;
        REQUIRE(schnorr_zkp_generate(secp256k1_algebra, a, sizeof(a), &a, &A, &zkp) == ZKP_SUCCESS);
        REQUIRE(schnorr_zkp_verify(secp256k1_algebra, a, sizeof(a), &A, &zkp) == ZKP_SUCCESS);

        secure_memset(&a, sizeof(a));
    }

    SECTION("verify raw data") {
        uint8_t a[32];
        elliptic_curve256_point_t A;
        REQUIRE(ctx);
        REQUIRE(RAND_bytes(a, sizeof(a)));

        schnorr_zkp_t zkp;
        REQUIRE(schnorr_zkp_generate_for_data(secp256k1_algebra, a, sizeof(a), a, sizeof(a), &A, &zkp) == ZKP_SUCCESS);
        REQUIRE(schnorr_zkp_verify(secp256k1_algebra, a, sizeof(a), &A, &zkp) == ZKP_SUCCESS);

        secure_memset(a, sizeof(a));
    }

    SECTION("verify large raw data") {
        uint8_t a[80];
        elliptic_curve256_point_t A;
        REQUIRE(ctx);
        REQUIRE(RAND_bytes(a, sizeof(a)));

        schnorr_zkp_t zkp;
        REQUIRE(schnorr_zkp_generate_for_data(secp256k1_algebra, a, sizeof(a), a, sizeof(a), &A, &zkp) == ZKP_SUCCESS);
        REQUIRE(schnorr_zkp_verify(secp256k1_algebra, a, sizeof(a), &A, &zkp) == ZKP_SUCCESS);

        secure_memset(a, sizeof(a));
    }

    SECTION("invalid public") {
        elliptic_curve256_scalar_t a;
        elliptic_curve256_point_t A;
        REQUIRE(ctx);
        REQUIRE(GFp_curve_algebra_rand(ctx, &a) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        elliptic_curve256_scalar_t a2;
        memcpy(a2, a, sizeof(a));
        a2[sizeof(a2) - 1]++;
        REQUIRE(GFp_curve_algebra_generator_mul_data(ctx, reinterpret_cast<uint8_t*>(a2), sizeof(a2), &A) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);

        schnorr_zkp_t zkp;
        REQUIRE(schnorr_zkp_generate(secp256k1_algebra, a, sizeof(a), &a, &A, &zkp) == ZKP_SUCCESS);
        REQUIRE(schnorr_zkp_verify(secp256k1_algebra, a, sizeof(a), &A, &zkp) == ZKP_VERIFICATION_FAILED);

        secure_memset(&a, sizeof(a));
        secure_memset(&a2, sizeof(a2));
    }

    SECTION("invalid secret") {
        elliptic_curve256_scalar_t a;
        elliptic_curve256_point_t A;
        REQUIRE(ctx);
        REQUIRE(GFp_curve_algebra_rand(ctx, &a) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE(GFp_curve_algebra_generator_mul_data(ctx, reinterpret_cast<uint8_t*>(a), sizeof(a), &A) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        a[sizeof(a) - 1]++;

        schnorr_zkp_t zkp;
        REQUIRE(schnorr_zkp_generate(secp256k1_algebra, a, sizeof(a), &a, &A, &zkp) == ZKP_SUCCESS);
        REQUIRE(schnorr_zkp_verify(secp256k1_algebra, a, sizeof(a), &A, &zkp) == ZKP_VERIFICATION_FAILED);

        secure_memset(&a, sizeof(a));
    }

    SECTION("invalid id") {
        elliptic_curve256_scalar_t a;
        elliptic_curve256_point_t A;
        REQUIRE(ctx);
        REQUIRE(GFp_curve_algebra_rand(ctx, &a) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE(GFp_curve_algebra_generator_mul_data(ctx, reinterpret_cast<uint8_t*>(a), sizeof(a), &A) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);

        schnorr_zkp_t zkp;
        REQUIRE(schnorr_zkp_generate(secp256k1_algebra, a, sizeof(a), &a, &A, &zkp) == ZKP_SUCCESS);
        a[sizeof(a) - 1]++;
        REQUIRE(schnorr_zkp_verify(secp256k1_algebra, a, sizeof(a), &A, &zkp) == ZKP_VERIFICATION_FAILED);

        secure_memset(&a, sizeof(a));
    }

    SECTION("invalid proof") {
        elliptic_curve256_scalar_t a;
        elliptic_curve256_point_t A;
        REQUIRE(ctx);
        REQUIRE(GFp_curve_algebra_rand(ctx, &a) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE(GFp_curve_algebra_generator_mul_data(ctx, reinterpret_cast<uint8_t*>(a), sizeof(a), &A) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        
        schnorr_zkp_t zkp;
        REQUIRE(schnorr_zkp_generate(secp256k1_algebra, a, sizeof(a), &a, &A, &zkp) == ZKP_SUCCESS);
        zkp.R[sizeof(elliptic_curve256_point_t) - 1]++;
        REQUIRE(schnorr_zkp_verify(secp256k1_algebra, a, sizeof(a), &A, &zkp) == ZKP_VERIFICATION_FAILED);

        secure_memset(&a, sizeof(a));
    }

    SECTION("custom randomness") {
        uint8_t k[32];
        elliptic_curve256_scalar_t a;
        elliptic_curve256_point_t A;
        REQUIRE(ctx);
        REQUIRE(RAND_bytes(k, sizeof(k)));
        REQUIRE(GFp_curve_algebra_rand(ctx, &a) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        REQUIRE(GFp_curve_algebra_generator_mul_data(ctx, reinterpret_cast<uint8_t*>(a), sizeof(a), &A) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);

        schnorr_zkp_t zkp;
        REQUIRE(schnorr_zkp_generate_with_custom_randomness(secp256k1_algebra, k, sizeof(k), a, sizeof(a), &a, &A, &zkp) == ZKP_SUCCESS);
        REQUIRE(schnorr_zkp_verify(secp256k1_algebra, a, sizeof(a), &A, &zkp) == ZKP_SUCCESS);

        secure_memset(&a, sizeof(a));
        secure_memset(k, sizeof(k));
    }
}

TEST_CASE("ring_pedersen", "verify") {
    const int64_t COUNT = 100000;  // Reduced for practicality

    for (auto curve : {secp256k1, secp256r1, ed25519}) {
        ring_pedersen_public_key_t public_key;
        ring_pedersen_secret_key_t secret_key;
        ring_pedersen_parameter_zkp_t parameter_zkp;
        std::vector<ring_pedersen_commitment_t> commitments;

        REQUIRE(ring_pedersen_generate_key_pair(curve, &secret_key, &public_key) == RING_PEDERSEN_SUCCESS);
        REQUIRE(ring_pedersen_generate_parameter_zkp(curve, &parameter_zkp, &secret_key, &public_key) == RING_PEDERSEN_SUCCESS);
        REQUIRE(ring_pedersen_verify_parameter_zkp(curve, &parameter_zkp, &public_key) == RING_PEDERSEN_SUCCESS);
        
        auto invalid_parameter_zkp = parameter_zkp;
        invalid_parameter_zkp.additional_authenticated_data[0]++;
        REQUIRE(ring_pedersen_verify_parameter_zkp(curve, &invalid_parameter_zkp, &public_key) == RING_PEDERSEN_VERIFICATION_FAILED);

        for (int64_t i = 0; i < COUNT; i++) {
            ring_pedersen_commitment_t commitment;
            uint8_t data[32];
            REQUIRE(RAND_bytes(data, sizeof(data)));
            REQUIRE(ring_pedersen_commit(curve, &commitment, data, sizeof(data), &secret_key, &public_key) == RING_PEDERSEN_SUCCESS);
            commitments.push_back(commitment);
        }

        auto start = std::chrono::steady_clock::now();
        REQUIRE(ring_pedersen_batch_verify(curve, commitments.data(), commitments.size(), &public_key) == RING_PEDERSEN_SUCCESS);
        auto end = std::chrono::steady_clock::now();
        std::cout << "Curve: " << curve << ", Verification time: " << std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count() << "ms\n";

        uint8_t aad[32];
        REQUIRE(RAND_bytes(aad, sizeof(aad)));
        ring_pedersen_zkp_t zkp;
        REQUIRE(ring_pedersen_generate_zkp(curve, &zkp, aad, sizeof(aad), &secret_key, &public_key) == RING_PEDERSEN_SUCCESS);
        REQUIRE(ring_pedersen_verify_zkp(curve, &zkp, aad, sizeof(aad), &public_key) == RING_PEDERSEN_SUCCESS);
        
        aad[0]++;
        REQUIRE(ring_pedersen_verify_zkp(curve, &zkp, aad, sizeof(aad), &public_key) == RING_PEDERSEN_VERIFICATION_FAILED);

        auto invalid_zkp = zkp;
        invalid_zkp.additional_authenticated_data[0]++;
        REQUIRE(ring_pedersen_verify_zkp(curve, &invalid_zkp, aad, sizeof(aad), &public_key) == RING_PEDERSEN_VERIFICATION_FAILED);
    }
}
