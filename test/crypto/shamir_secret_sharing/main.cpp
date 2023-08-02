#include "crypto/shamir_secret_sharing/verifiable_secret_sharing.h"
#include "crypto/elliptic_curve_algebra/elliptic_curve256_algebra.h"
#include <openssl/bn.h>

#include <memory>

#define CATCH_CONFIG_MAIN  
#include <tests/catch.hpp>

std::unique_ptr<elliptic_curve256_algebra_ctx_t, void (*)(elliptic_curve256_algebra_ctx_t*)> secp256k1(elliptic_curve256_new_secp256k1_algebra(), elliptic_curve256_algebra_ctx_free);

TEST_CASE( "basic", "secret_sharing") {
    SECTION("basic") {
        const unsigned char secret[33] = "01234567890123456789012345678912";
        unsigned char secret2[33] = {0};
        verifiable_secret_sharing_t *shamir;
        shamir_secret_share_t share[3];
        uint32_t size;
        
        REQUIRE(verifiable_secret_sharing_split(secp256k1.get(), secret, sizeof(secret) - 1, 3, 5, &shamir) == VERIFIABLE_SECRET_SHARING_SUCCESS);
        REQUIRE(verifiable_secret_sharing_get_share(shamir, 1, share) == VERIFIABLE_SECRET_SHARING_SUCCESS);
        REQUIRE(verifiable_secret_sharing_get_share(shamir, 3, share+1) == VERIFIABLE_SECRET_SHARING_SUCCESS);
        REQUIRE(verifiable_secret_sharing_get_share(shamir, 4, share+2) == VERIFIABLE_SECRET_SHARING_SUCCESS);
        verifiable_secret_sharing_free_shares(shamir);
        REQUIRE(verifiable_secret_sharing_reconstruct(secp256k1.get(), share, 3, secret2, 33, &size) == VERIFIABLE_SECRET_SHARING_SUCCESS);
        REQUIRE(size == sizeof(secret) - 1);
        REQUIRE(memcmp(secret, secret2, sizeof(secret) - 1) == 0);
        printf("%s\n", secret2);
    }

    SECTION("not enough") {
        const unsigned char secret[33] = "01234567890123456789012345678912";
        unsigned char secret2[33] = {0};
        verifiable_secret_sharing_t *shamir;
        shamir_secret_share_t share[3];
        uint32_t size;
        
        REQUIRE(verifiable_secret_sharing_split(secp256k1.get(), secret, sizeof(secret) - 1, 3, 5, &shamir) == VERIFIABLE_SECRET_SHARING_SUCCESS);
        REQUIRE(verifiable_secret_sharing_get_share(shamir, 1, share) == VERIFIABLE_SECRET_SHARING_SUCCESS);
        REQUIRE(verifiable_secret_sharing_get_share(shamir, 3, share+1) == VERIFIABLE_SECRET_SHARING_SUCCESS);
        verifiable_secret_sharing_free_shares(shamir);
        REQUIRE(verifiable_secret_sharing_reconstruct(secp256k1.get(), share, 2, secret2, 33, &size) == VERIFIABLE_SECRET_SHARING_SUCCESS);
        REQUIRE_FALSE(memcmp(secret, secret2, sizeof(secret) - 1) == 0);
    }

    SECTION("more then needed") {
        const unsigned char secret[33] = "01234567890123456789012345678912";
        unsigned char secret2[33] = {0};
        verifiable_secret_sharing_t *shamir;
        shamir_secret_share_t share[4];
        uint32_t size;
        
        REQUIRE(verifiable_secret_sharing_split(secp256k1.get(), secret, sizeof(secret) - 1, 3, 5, &shamir) == VERIFIABLE_SECRET_SHARING_SUCCESS);
        REQUIRE(verifiable_secret_sharing_get_share(shamir, 1, share) == VERIFIABLE_SECRET_SHARING_SUCCESS);
        REQUIRE(verifiable_secret_sharing_get_share(shamir, 3, share+1) == VERIFIABLE_SECRET_SHARING_SUCCESS);
        REQUIRE(verifiable_secret_sharing_get_share(shamir, 4, share+2) == VERIFIABLE_SECRET_SHARING_SUCCESS);
        REQUIRE(verifiable_secret_sharing_get_share(shamir, 0, share+3) == VERIFIABLE_SECRET_SHARING_SUCCESS);
        verifiable_secret_sharing_free_shares(shamir);
        REQUIRE(verifiable_secret_sharing_reconstruct(secp256k1.get(), share, 4, secret2, 33, &size) == VERIFIABLE_SECRET_SHARING_SUCCESS);
        REQUIRE(size == sizeof(secret) - 1);
        REQUIRE(memcmp(secret, secret2, sizeof(secret) - 1) == 0);
        printf("%s\n", secret2);
    }

    SECTION("more then needed with invalid share") {
        const unsigned char secret[33] = "01234567890123456789012345678912";
        unsigned char secret2[33] = {0};
        verifiable_secret_sharing_t *shamir;
        shamir_secret_share_t share[4];
        uint32_t size;
        
        REQUIRE(verifiable_secret_sharing_split(secp256k1.get(), secret, sizeof(secret) - 1, 3, 5, &shamir) == VERIFIABLE_SECRET_SHARING_SUCCESS);
        REQUIRE(verifiable_secret_sharing_get_share(shamir, 1, share) == VERIFIABLE_SECRET_SHARING_SUCCESS);
        REQUIRE(verifiable_secret_sharing_get_share(shamir, 3, share+1) == VERIFIABLE_SECRET_SHARING_SUCCESS);
        REQUIRE(verifiable_secret_sharing_get_share(shamir, 4, share+2) == VERIFIABLE_SECRET_SHARING_SUCCESS);
        REQUIRE(verifiable_secret_sharing_get_share(shamir, 0, share+3) == VERIFIABLE_SECRET_SHARING_SUCCESS);
        verifiable_secret_sharing_free_shares(shamir);
        ++share[2].data[25];
        REQUIRE(verifiable_secret_sharing_reconstruct(secp256k1.get(), share, 4, secret2, 33, &size) == VERIFIABLE_SECRET_SHARING_SUCCESS);
        REQUIRE(memcmp(secret, secret2, size) != 0);
    }

    SECTION("user_indexes") {
        const unsigned char secret[33] = "01234567890123456789012345678912";
        unsigned char secret2[33] = {0};
        verifiable_secret_sharing_t *shamir;
        shamir_secret_share_t share[3];
        uint64_t idx[5];
        uint32_t size;
        idx[0] = 11;
        idx[1] = 21;
        idx[2] = 31;
        idx[3] = 121;
        idx[4] = 257;
        REQUIRE(verifiable_secret_sharing_split_with_custom_ids(secp256k1.get(), secret, sizeof(secret) - 1, 3, 5, idx, &shamir) == VERIFIABLE_SECRET_SHARING_SUCCESS);
        REQUIRE(verifiable_secret_sharing_get_share(shamir, 1, share) == VERIFIABLE_SECRET_SHARING_SUCCESS);
        REQUIRE(verifiable_secret_sharing_get_share(shamir, 3, share+1) == VERIFIABLE_SECRET_SHARING_SUCCESS);
        REQUIRE(verifiable_secret_sharing_get_share(shamir, 4, share+2) == VERIFIABLE_SECRET_SHARING_SUCCESS);
        verifiable_secret_sharing_free_shares(shamir);
        REQUIRE(verifiable_secret_sharing_reconstruct(secp256k1.get(), share, 3, secret2, 33, &size) == VERIFIABLE_SECRET_SHARING_SUCCESS);
        REQUIRE(size == sizeof(secret) - 1);
        REQUIRE(memcmp(secret, secret2, sizeof(secret) - 1) == 0);
        printf("%s\n", secret2);
    }
}

TEST_CASE( "verify", "secret_sharing") {
    const uint8_t T = 3; 
    const uint8_t N = 5;

    SECTION("verify") {
        const unsigned char secret[33] = "01234567890123456789012345678912";
        unsigned char secret2[33] = {0};
        verifiable_secret_sharing_t *shamir;
        shamir_secret_share_t share[N];
        elliptic_curve256_point_t share_proof[N];
        commitments_commitment_t share_commitment;
        elliptic_curve256_point_t coeff_proof[T];
        commitments_commitment_t coeff_commitment;
        uint32_t size;
        
        REQUIRE(verifiable_secret_sharing_split(secp256k1.get(), secret, sizeof(secret) - 1, T, N, &shamir) == VERIFIABLE_SECRET_SHARING_SUCCESS);
        REQUIRE(verifiable_secret_sharing_get_threshold(shamir) == T);
        REQUIRE(verifiable_secret_sharing_get_polynom_proofs(shamir, coeff_proof, T) == VERIFIABLE_SECRET_SHARING_SUCCESS);
        REQUIRE(verifiable_secret_sharing_get_polynom_commitment(shamir, &coeff_commitment) == VERIFIABLE_SECRET_SHARING_SUCCESS);

        for (size_t i = 0; i < N; i++)
        {
            REQUIRE(verifiable_secret_sharing_get_share_and_proof(shamir, i, share + i, share_proof + i) == VERIFIABLE_SECRET_SHARING_SUCCESS);
        }
        REQUIRE(verifiable_secret_sharing_get_shares_commitment(shamir, &share_commitment) == VERIFIABLE_SECRET_SHARING_SUCCESS);
        verifiable_secret_sharing_free_shares(shamir);
        
        REQUIRE(verifiable_secret_sharing_verify_commitment(coeff_proof, T, &coeff_commitment) == VERIFIABLE_SECRET_SHARING_SUCCESS);
        REQUIRE(verifiable_secret_sharing_verify_commitment(share_proof, N, &share_commitment) == VERIFIABLE_SECRET_SHARING_SUCCESS);
        
        for (size_t i = 0; i < N; i++)
        {
            REQUIRE(verifiable_secret_sharing_verify_share(secp256k1.get(), share[i].id, share_proof + i, T, coeff_proof) == VERIFIABLE_SECRET_SHARING_SUCCESS);
        }
        
        REQUIRE(verifiable_secret_sharing_reconstruct(secp256k1.get(), share, 3, secret2, 33, &size) == VERIFIABLE_SECRET_SHARING_SUCCESS);
        REQUIRE(size == sizeof(secret) - 1);
        REQUIRE(memcmp(secret, secret2, sizeof(secret) - 1) == 0);
        printf("%s\n", secret2);
    }
}

TEST_CASE( "invalid", "secret_sharing") {
    const uint8_t T = 3; 
    const uint8_t N = 5;
    const unsigned char g_secret[33] = "01234567890123456789012345678912";
    verifiable_secret_sharing_t *g_shamir = NULL;
    auto status = verifiable_secret_sharing_split(secp256k1.get(), g_secret, sizeof(g_secret) - 1, T, N, &g_shamir);

    SECTION("verifiable_secret_sharing_split") {
        const unsigned char secret[33] = "01234567890123456789012345678912";
        verifiable_secret_sharing_t *shamir;
        REQUIRE(verifiable_secret_sharing_split(NULL, secret, sizeof(secret) - 1, T, N, &shamir) == VERIFIABLE_SECRET_SHARING_INVALID_PARAMETER);
        REQUIRE(verifiable_secret_sharing_split(secp256k1.get(), NULL, sizeof(secret) - 1, T, N, &shamir) == VERIFIABLE_SECRET_SHARING_INVALID_PARAMETER);
        REQUIRE(verifiable_secret_sharing_split(secp256k1.get(), secret, 0, T, N, &shamir) == VERIFIABLE_SECRET_SHARING_INVALID_PARAMETER);
        REQUIRE(verifiable_secret_sharing_split(secp256k1.get(), secret, sizeof(secret) - 1, 0, N, &shamir) == VERIFIABLE_SECRET_SHARING_INVALID_PARAMETER);
        REQUIRE(verifiable_secret_sharing_split(secp256k1.get(), secret, sizeof(secret) - 1, T, T - 1, &shamir) == VERIFIABLE_SECRET_SHARING_INVALID_PARAMETER);
        REQUIRE(verifiable_secret_sharing_split(secp256k1.get(), secret, sizeof(secret) - 1, T, N, NULL) == VERIFIABLE_SECRET_SHARING_INVALID_PARAMETER);
        unsigned char secret2[32];
        memset(secret2, 0xff, sizeof(secret2));
        REQUIRE(verifiable_secret_sharing_split(secp256k1.get(), secret2, sizeof(secret2), T, N, &shamir) == VERIFIABLE_SECRET_SHARING_INVALID_SECRET);
    }
    SECTION("verifiable_secret_sharing_split_with_custom_ids") {
        const unsigned char secret[33] = "01234567890123456789012345678912";
        verifiable_secret_sharing_t *shamir;
        uint64_t idx[5] = {11, 13, 19, 911, 823};
        REQUIRE(verifiable_secret_sharing_split_with_custom_ids(NULL, secret, sizeof(secret) - 1, T, N, idx, &shamir) == VERIFIABLE_SECRET_SHARING_INVALID_PARAMETER);
        REQUIRE(verifiable_secret_sharing_split_with_custom_ids(secp256k1.get(), NULL, sizeof(secret) - 1, T, N, idx, &shamir) == VERIFIABLE_SECRET_SHARING_INVALID_PARAMETER);
        REQUIRE(verifiable_secret_sharing_split_with_custom_ids(secp256k1.get(), secret, 0, T, N, idx, &shamir) == VERIFIABLE_SECRET_SHARING_INVALID_PARAMETER);
        REQUIRE(verifiable_secret_sharing_split_with_custom_ids(secp256k1.get(), secret, sizeof(secret) - 1, 0, N, idx, &shamir) == VERIFIABLE_SECRET_SHARING_INVALID_PARAMETER);
        REQUIRE(verifiable_secret_sharing_split_with_custom_ids(secp256k1.get(), secret, sizeof(secret) - 1, T, T - 1, idx, &shamir) == VERIFIABLE_SECRET_SHARING_INVALID_PARAMETER);
        REQUIRE(verifiable_secret_sharing_split_with_custom_ids(secp256k1.get(), secret, sizeof(secret) - 1, T, N, idx, NULL) == VERIFIABLE_SECRET_SHARING_INVALID_PARAMETER);
        REQUIRE(verifiable_secret_sharing_split_with_custom_ids(secp256k1.get(), secret, sizeof(secret) - 1, T, N, NULL, &shamir) == VERIFIABLE_SECRET_SHARING_INVALID_PARAMETER);
        unsigned char secret2[32];
        memset(secret2, 0xff, sizeof(secret2));
        REQUIRE(verifiable_secret_sharing_split_with_custom_ids(secp256k1.get(), secret2, sizeof(secret2), T, N, idx, &shamir) == VERIFIABLE_SECRET_SHARING_INVALID_SECRET);
        idx[1] = 0;
        REQUIRE(verifiable_secret_sharing_split_with_custom_ids(secp256k1.get(), secret, sizeof(secret) - 1, T, N, idx, &shamir) == VERIFIABLE_SECRET_SHARING_INVALID_SHARE_ID);
        idx[1] = 7;
        idx[4] = 7;
        REQUIRE(verifiable_secret_sharing_split_with_custom_ids(secp256k1.get(), secret, sizeof(secret) - 1, T, N, idx, &shamir) == VERIFIABLE_SECRET_SHARING_INVALID_SHARE_ID);
    }
    SECTION("verifiable_secret_sharing_get_share") {
        REQUIRE(status == VERIFIABLE_SECRET_SHARING_SUCCESS);
        shamir_secret_share_t share;
        REQUIRE(verifiable_secret_sharing_get_share(NULL, 0, &share) == VERIFIABLE_SECRET_SHARING_INVALID_PARAMETER);
        REQUIRE(verifiable_secret_sharing_get_share(g_shamir, N, &share) == VERIFIABLE_SECRET_SHARING_INVALID_INDEX);
        REQUIRE(verifiable_secret_sharing_get_share(g_shamir, 0, NULL) == VERIFIABLE_SECRET_SHARING_INVALID_PARAMETER);
    }
    SECTION("verifiable_secret_sharing_get_share_and_proof") {
        REQUIRE(status == VERIFIABLE_SECRET_SHARING_SUCCESS);
        shamir_secret_share_t share;
        elliptic_curve256_point_t proof;
        REQUIRE(verifiable_secret_sharing_get_share_and_proof(NULL, 0, &share, &proof) == VERIFIABLE_SECRET_SHARING_INVALID_PARAMETER);
        REQUIRE(verifiable_secret_sharing_get_share_and_proof(g_shamir, N, &share, &proof) == VERIFIABLE_SECRET_SHARING_INVALID_INDEX);
        REQUIRE(verifiable_secret_sharing_get_share_and_proof(g_shamir, 0, NULL, &proof) == VERIFIABLE_SECRET_SHARING_INVALID_PARAMETER);
        REQUIRE(verifiable_secret_sharing_get_share_and_proof(g_shamir, 0, &share, NULL) == VERIFIABLE_SECRET_SHARING_INVALID_PARAMETER);
    }
    SECTION("verifiable_secret_sharing_get_share_commitment") {
        REQUIRE(status == VERIFIABLE_SECRET_SHARING_SUCCESS);
        commitments_commitment_t commit;
        REQUIRE(verifiable_secret_sharing_get_shares_commitment(NULL, &commit) == VERIFIABLE_SECRET_SHARING_INVALID_PARAMETER);
        REQUIRE(verifiable_secret_sharing_get_shares_commitment(g_shamir, NULL) == VERIFIABLE_SECRET_SHARING_INVALID_PARAMETER);
    }
    SECTION("verifiable_secret_sharing_get_threshold") {
        REQUIRE(verifiable_secret_sharing_get_threshold(NULL) == -1);
    }
    SECTION("verifiable_secret_sharing_get_polynom_proofs") {
        REQUIRE(status == VERIFIABLE_SECRET_SHARING_SUCCESS);
        elliptic_curve256_point_t proof[N]; //only T needed
        REQUIRE(verifiable_secret_sharing_get_polynom_proofs(NULL, proof, T) == VERIFIABLE_SECRET_SHARING_INVALID_PARAMETER);
        REQUIRE(verifiable_secret_sharing_get_polynom_proofs(g_shamir, NULL, T) == VERIFIABLE_SECRET_SHARING_INVALID_PARAMETER);
        REQUIRE(verifiable_secret_sharing_get_polynom_proofs(g_shamir, proof, 0) == VERIFIABLE_SECRET_SHARING_INVALID_PARAMETER);
        REQUIRE(verifiable_secret_sharing_get_polynom_proofs(g_shamir, proof, T-1) == VERIFIABLE_SECRET_SHARING_INVALID_PARAMETER);
        REQUIRE(verifiable_secret_sharing_get_polynom_proofs(g_shamir, proof, N) == VERIFIABLE_SECRET_SHARING_SUCCESS);
    }
    SECTION("verifiable_secret_sharing_get_polynom_commitments") {
        REQUIRE(status == VERIFIABLE_SECRET_SHARING_SUCCESS);
        commitments_commitment_t commit; //only T needed
        REQUIRE(verifiable_secret_sharing_get_polynom_commitment(NULL, &commit) == VERIFIABLE_SECRET_SHARING_INVALID_PARAMETER);
        REQUIRE(verifiable_secret_sharing_get_polynom_commitment(g_shamir, NULL) == VERIFIABLE_SECRET_SHARING_INVALID_PARAMETER);
    }
    SECTION("verifiable_secret_sharing_verify_share") {
        REQUIRE(status == VERIFIABLE_SECRET_SHARING_SUCCESS);
        elliptic_curve256_point_t coeff_proof[T+1];
        shamir_secret_share_t share;
        elliptic_curve256_point_t share_proof;
        REQUIRE(verifiable_secret_sharing_get_polynom_proofs(g_shamir, coeff_proof, T) == VERIFIABLE_SECRET_SHARING_SUCCESS);
        REQUIRE(verifiable_secret_sharing_get_share_and_proof(g_shamir, 0, &share, &share_proof) == VERIFIABLE_SECRET_SHARING_SUCCESS);
        
        uint64_t val = 0x123456789abc;
        REQUIRE(secp256k1->generator_mul_data(secp256k1.get(), (uint8_t*)&val, sizeof(val), coeff_proof+T) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        
        
        REQUIRE(verifiable_secret_sharing_verify_share(secp256k1.get(), N, &share_proof, T, coeff_proof) == VERIFIABLE_SECRET_SHARING_INVALID_SHARE); // any id other then the share id (e.g. 1) should return invalid share
        REQUIRE(verifiable_secret_sharing_verify_share(secp256k1.get(), 2, &share_proof, T, coeff_proof) == VERIFIABLE_SECRET_SHARING_INVALID_SHARE);
        REQUIRE(verifiable_secret_sharing_verify_share(secp256k1.get(), 0, &share_proof, T, coeff_proof) == VERIFIABLE_SECRET_SHARING_INVALID_SHARE);

        REQUIRE(verifiable_secret_sharing_verify_share(NULL, 0, &share_proof, T, coeff_proof) == VERIFIABLE_SECRET_SHARING_INVALID_PARAMETER);
        REQUIRE(verifiable_secret_sharing_verify_share(secp256k1.get(), 0, NULL, T, coeff_proof) == VERIFIABLE_SECRET_SHARING_INVALID_PARAMETER);
        REQUIRE(verifiable_secret_sharing_verify_share(secp256k1.get(), 0, &share_proof, 0, coeff_proof) == VERIFIABLE_SECRET_SHARING_INVALID_PARAMETER);
        
        REQUIRE(verifiable_secret_sharing_verify_share(secp256k1.get(), 0, &share_proof, T-1, coeff_proof) == VERIFIABLE_SECRET_SHARING_INVALID_SHARE); // wrong polynom degree should return invalid share
        REQUIRE(verifiable_secret_sharing_verify_share(secp256k1.get(), 0, &share_proof, T+1, coeff_proof) == VERIFIABLE_SECRET_SHARING_INVALID_SHARE);
        
        REQUIRE(verifiable_secret_sharing_verify_share(secp256k1.get(), 0, &share_proof, T, NULL) == VERIFIABLE_SECRET_SHARING_INVALID_PARAMETER);
    }
    SECTION("verifiable_secret_sharing_verify_commitment") {
        REQUIRE(status == VERIFIABLE_SECRET_SHARING_SUCCESS);
        shamir_secret_share_t share;
        elliptic_curve256_point_t share_proof[N];
        for (size_t i = 0; i < N; i++)
            REQUIRE(verifiable_secret_sharing_get_share_and_proof(g_shamir, i, &share, share_proof + i) == VERIFIABLE_SECRET_SHARING_SUCCESS);
        commitments_commitment_t commit;
        REQUIRE(verifiable_secret_sharing_get_shares_commitment(g_shamir, &commit) == VERIFIABLE_SECRET_SHARING_SUCCESS);
        REQUIRE(verifiable_secret_sharing_verify_commitment(NULL, N, &commit) == VERIFIABLE_SECRET_SHARING_INVALID_PARAMETER);
        REQUIRE(verifiable_secret_sharing_verify_commitment(share_proof, N -1, &commit) == VERIFIABLE_SECRET_SHARING_INVALID_SHARE);
        REQUIRE(verifiable_secret_sharing_verify_commitment(share_proof, 0, &commit) == VERIFIABLE_SECRET_SHARING_INVALID_PARAMETER);
        REQUIRE(verifiable_secret_sharing_verify_commitment(share_proof, N, NULL) == VERIFIABLE_SECRET_SHARING_INVALID_PARAMETER);
    }
    SECTION("verifiable_secret_sharing_reconstruct") {
        REQUIRE(status == VERIFIABLE_SECRET_SHARING_SUCCESS);
        shamir_secret_share_t shares[T+1];
        for (size_t i = 0; i < T+1; i++)
        {
            REQUIRE(verifiable_secret_sharing_get_share(g_shamir, i, shares+i) == VERIFIABLE_SECRET_SHARING_SUCCESS);
        }
        uint8_t data[1024];
        uint32_t len = 0;
        REQUIRE(verifiable_secret_sharing_reconstruct(secp256k1.get(), NULL, T, data, sizeof(data), &len) == VERIFIABLE_SECRET_SHARING_INVALID_PARAMETER);
        REQUIRE(verifiable_secret_sharing_reconstruct(secp256k1.get(), shares, 0, data, sizeof(data), &len) == VERIFIABLE_SECRET_SHARING_INVALID_PARAMETER);
        REQUIRE(verifiable_secret_sharing_reconstruct(secp256k1.get(), shares, T, NULL, sizeof(data), &len) == VERIFIABLE_SECRET_SHARING_INVALID_PARAMETER);
        REQUIRE(verifiable_secret_sharing_reconstruct(secp256k1.get(), shares, T, data, 0, &len) == VERIFIABLE_SECRET_SHARING_INSUFFICIENT_BUFFER);
        REQUIRE(verifiable_secret_sharing_reconstruct(secp256k1.get(), shares, T, data, sizeof(data), NULL) == VERIFIABLE_SECRET_SHARING_SUCCESS);
        
        shares[0].id = 0;
        REQUIRE(verifiable_secret_sharing_reconstruct(secp256k1.get(), shares, T, data, sizeof(data), &len) == VERIFIABLE_SECRET_SHARING_INVALID_PARAMETER);
        shares[0].id = 2;
        REQUIRE(verifiable_secret_sharing_reconstruct(secp256k1.get(), shares, T, data, sizeof(data), &len) == VERIFIABLE_SECRET_SHARING_INVALID_PARAMETER);
        shares[0].id = 1;
        ++shares[T].data[22];
        REQUIRE(verifiable_secret_sharing_reconstruct(secp256k1.get(), shares, T+1, data, sizeof(data), &len) == VERIFIABLE_SECRET_SHARING_SUCCESS);
        REQUIRE(memcmp(data, g_secret, len) != 0);
    }

    verifiable_secret_sharing_free_shares(g_shamir);
}

TEST_CASE( "secp256r1", "secret_sharing") {
    const uint8_t T = 3; 
    const uint8_t N = 5;
    std::unique_ptr<elliptic_curve256_algebra_ctx_t, void (*)(elliptic_curve256_algebra_ctx_t*)> secp256r1(elliptic_curve256_new_secp256r1_algebra(), elliptic_curve256_algebra_ctx_free);

    SECTION("verify") {
        const unsigned char secret[33] = "01234567890123456789012345678912";
        unsigned char secret2[33] = {0};
        verifiable_secret_sharing_t *shamir;
        shamir_secret_share_t share[N];
        elliptic_curve256_point_t share_proof[N];
        commitments_commitment_t share_commitment;
        elliptic_curve256_point_t coeff_proof[T];
        commitments_commitment_t coeff_commitment;
        uint32_t size;
        
        REQUIRE(verifiable_secret_sharing_split(secp256r1.get(), secret, sizeof(secret) - 1, T, N, &shamir) == VERIFIABLE_SECRET_SHARING_SUCCESS);
        REQUIRE(verifiable_secret_sharing_get_threshold(shamir) == T);
        REQUIRE(verifiable_secret_sharing_get_polynom_proofs(shamir, coeff_proof, T) == VERIFIABLE_SECRET_SHARING_SUCCESS);
        REQUIRE(verifiable_secret_sharing_get_polynom_commitment(shamir, &coeff_commitment) == VERIFIABLE_SECRET_SHARING_SUCCESS);

        for (size_t i = 0; i < N; i++)
        {
            REQUIRE(verifiable_secret_sharing_get_share_and_proof(shamir, i, share + i, share_proof + i) == VERIFIABLE_SECRET_SHARING_SUCCESS);
        }
        REQUIRE(verifiable_secret_sharing_get_shares_commitment(shamir, &share_commitment) == VERIFIABLE_SECRET_SHARING_SUCCESS);
        verifiable_secret_sharing_free_shares(shamir);
        
        REQUIRE(verifiable_secret_sharing_verify_commitment(coeff_proof, T, &coeff_commitment) == VERIFIABLE_SECRET_SHARING_SUCCESS);
        REQUIRE(verifiable_secret_sharing_verify_commitment(share_proof, N, &share_commitment) == VERIFIABLE_SECRET_SHARING_SUCCESS);
        
        for (size_t i = 0; i < N; i++)
        {
            REQUIRE(verifiable_secret_sharing_verify_share(secp256r1.get(), share[i].id, share_proof + i, T, coeff_proof) == VERIFIABLE_SECRET_SHARING_SUCCESS);
        }
        
        REQUIRE(verifiable_secret_sharing_reconstruct(secp256r1.get(), share, 3, secret2, 33, &size) == VERIFIABLE_SECRET_SHARING_SUCCESS);
        REQUIRE(size == sizeof(secret) - 1);
        REQUIRE(memcmp(secret, secret2, sizeof(secret) - 1) == 0);
        printf("%s\n", secret2);
    }
}

TEST_CASE( "ed25519", "secret_sharing") {
    const uint8_t T = 3; 
    const uint8_t N = 5;
    std::unique_ptr<elliptic_curve256_algebra_ctx_t, void (*)(elliptic_curve256_algebra_ctx_t*)> ed25519(elliptic_curve256_new_ed25519_algebra(), elliptic_curve256_algebra_ctx_free);

    SECTION("verify") {
        unsigned char secret[33] = "01234567890123456789012345678912";
        secret[0] = 0;
        unsigned char secret2[33] = {0};
        verifiable_secret_sharing_t *shamir;
        shamir_secret_share_t share[N];
        elliptic_curve256_point_t share_proof[N];
        commitments_commitment_t share_commitment;
        elliptic_curve256_point_t coeff_proof[T];
        commitments_commitment_t coeff_commitment;
        uint32_t size;
        
        REQUIRE(verifiable_secret_sharing_split(ed25519.get(), secret, sizeof(secret) - 1, T, N, &shamir) == VERIFIABLE_SECRET_SHARING_SUCCESS);
        REQUIRE(verifiable_secret_sharing_get_threshold(shamir) == T);
        REQUIRE(verifiable_secret_sharing_get_polynom_proofs(shamir, coeff_proof, T) == VERIFIABLE_SECRET_SHARING_SUCCESS);
        REQUIRE(verifiable_secret_sharing_get_polynom_commitment(shamir, &coeff_commitment) == VERIFIABLE_SECRET_SHARING_SUCCESS);

        for (size_t i = 0; i < N; i++)
        {
            REQUIRE(verifiable_secret_sharing_get_share_and_proof(shamir, i, share + i, share_proof + i) == VERIFIABLE_SECRET_SHARING_SUCCESS);
        }
        REQUIRE(verifiable_secret_sharing_get_shares_commitment(shamir, &share_commitment) == VERIFIABLE_SECRET_SHARING_SUCCESS);
        verifiable_secret_sharing_free_shares(shamir);
        
        REQUIRE(verifiable_secret_sharing_verify_commitment(coeff_proof, T, &coeff_commitment) == VERIFIABLE_SECRET_SHARING_SUCCESS);
        REQUIRE(verifiable_secret_sharing_verify_commitment(share_proof, N, &share_commitment) == VERIFIABLE_SECRET_SHARING_SUCCESS);
        
        for (size_t i = 0; i < N; i++)
        {
            REQUIRE(verifiable_secret_sharing_verify_share(ed25519.get(), share[i].id, share_proof + i, T, coeff_proof) == VERIFIABLE_SECRET_SHARING_SUCCESS);
        }
        
        REQUIRE(verifiable_secret_sharing_reconstruct(ed25519.get(), share, 3, secret2, 33, &size) == VERIFIABLE_SECRET_SHARING_SUCCESS);
        REQUIRE(size == sizeof(secret) - 2);
        REQUIRE(memcmp(secret + 1, secret2, sizeof(secret) - 1) == 0);
        printf("%s\n", secret2);
    }
}
