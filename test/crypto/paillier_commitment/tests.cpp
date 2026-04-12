#include "crypto/paillier_commitment/paillier_commitment.h"
#include "../../../src/common/crypto/paillier_commitment/paillier_commitment_internal.h"
#include <openssl/bn.h>
#include <openssl/bio.h>
#include <cstring>
#include <tests/catch.hpp>


TEST_CASE( "gen_key", "paillier_commitment") 
{
    SECTION("gen_key") 
    {
        paillier_commitment_private_key_t* priv;
        long res = paillier_commitment_generate_private_key(3072, &priv);
        REQUIRE(res == PAILLIER_SUCCESS);
        paillier_commitment_free_private_key(priv);
    }

    // SECTION("large key") 
    // {
    //     paillier_commitment_private_key_t* priv;
    //     long res = paillier_commitment_generate_private_key(4 * 4096, &priv);
    //     REQUIRE(res == PAILLIER_SUCCESS);
    //     paillier_commitment_free_private_key(priv);
    // }

    SECTION("too small key") 
    {
        paillier_commitment_private_key_t* priv = NULL;
        long res = paillier_commitment_generate_private_key(64, &priv);
        REQUIRE(res == PAILLIER_ERROR_KEYLEN_TOO_SHORT);
        paillier_commitment_free_private_key(priv);
    }

    SECTION("strange key") 
    {
        paillier_commitment_private_key_t* priv;
        long res = paillier_commitment_generate_private_key(5099, &priv);
        REQUIRE(res == PAILLIER_ERROR_INVALID_PARAM);
        paillier_commitment_free_private_key(priv);
    }
}


TEST_CASE( "basic", "paillier_commitment") 
{
    paillier_commitment_private_key_t* priv;
    long res = paillier_commitment_generate_private_key(2048, &priv);
    REQUIRE(res == PAILLIER_SUCCESS);
    const paillier_commitment_public_key_t* pub = paillier_commitment_private_cast_to_public(priv);
    
    SECTION("enc") 
    {
        uint8_t* data = NULL;
        uint32_t data_len = 0;
        char* text = NULL;
        uint32_t text_len = 0;
        REQUIRE(res == PAILLIER_SUCCESS);
        char msg[] = "Hello World";
        uint32_t len = 0;
        res = paillier_commitment_encrypt(pub, (uint8_t*)msg, strlen(msg), data, 0, &len);
        REQUIRE(res == PAILLIER_ERROR_BUFFER_TOO_SHORT);
        data = new uint8_t[len];
        res = paillier_commitment_encrypt(pub, (uint8_t*)msg, strlen(msg), data, len, &data_len);
        REQUIRE(res == PAILLIER_SUCCESS);
        res = paillier_commitment_decrypt(priv, data, data_len, NULL, 0, &len);
        REQUIRE(res == PAILLIER_ERROR_BUFFER_TOO_SHORT);
        text = new char[len];
        memset(text, 0, len);
        res = paillier_commitment_decrypt(priv, data, data_len, (uint8_t*)text, len, &text_len);
        REQUIRE(res == PAILLIER_SUCCESS);
        REQUIRE(len == text_len);
        REQUIRE(text_len >= strlen(msg));
        REQUIRE(memcmp(msg, text + text_len - strlen(msg), strlen(msg)) == 0);
        for (uint32_t i = 0; i < text_len - strlen(msg); ++i)
        {
            REQUIRE(text[i] == 0);
        }
        delete[] data;
        delete[] text;
    }

    SECTION("pub_key_serialization") 
    {
        uint32_t len = 0;
        
        // Use is_reduced to cycle through 0 and 1
        int is_reduced = GENERATE(0, 1);

        auto res = paillier_commitment_public_key_serialize(pub, is_reduced, NULL, 0, &len);
        REQUIRE(res == PAILLIER_ERROR_BUFFER_TOO_SHORT);
        uint8_t* data = new uint8_t[len];
        uint32_t len1 = 0;
        res = paillier_commitment_public_key_serialize(pub, is_reduced, data, len, &len1);
        REQUIRE(res == PAILLIER_SUCCESS);
        REQUIRE(len1 == len);

        auto restored_key = paillier_commitment_public_key_deserialize(is_reduced, data, len);
        REQUIRE(NULL != restored_key);
        REQUIRE(BN_cmp(restored_key->n, pub->n) == 0);
        REQUIRE(BN_cmp(restored_key->t, pub->t) == 0);
        REQUIRE(BN_cmp(restored_key->s, pub->s) == 0);
        REQUIRE(BN_cmp(restored_key->n2, pub->n2) == 0);
        REQUIRE(BN_cmp(restored_key->rho, pub->rho) == 0);
        REQUIRE(BN_cmp(restored_key->sigma_0, pub->sigma_0) == 0);
        REQUIRE(restored_key->mont_n2 != NULL);
        delete[] data;

        uint32_t data_len = 0;
        char* text = NULL;
        uint32_t text_len = 0;
        REQUIRE(res == PAILLIER_SUCCESS);
        char msg[] = "Hello World";
        res = paillier_commitment_encrypt(restored_key, (uint8_t*)msg, strlen(msg), data, 0, &len);
        REQUIRE(res == PAILLIER_ERROR_BUFFER_TOO_SHORT);
        data = new uint8_t[len];
        res = paillier_commitment_encrypt(restored_key, (uint8_t*)msg, strlen(msg), data, len, &data_len);
        REQUIRE(res == PAILLIER_SUCCESS);
        res = paillier_commitment_decrypt(priv, data, data_len, NULL, 0, &len);
        REQUIRE(res == PAILLIER_ERROR_BUFFER_TOO_SHORT);
        text = new char[len];
        memset(text, 0, len);
        res = paillier_commitment_decrypt(priv, data, data_len, (uint8_t*)text, len, &text_len);
        REQUIRE(res == PAILLIER_SUCCESS);
        REQUIRE(text_len >= strlen(msg));
        REQUIRE(memcmp(msg, text + text_len - strlen(msg), strlen(msg)) == 0);
        for (uint32_t i = 0; i < text_len - strlen(msg); ++i)
        {
            REQUIRE(text[i] == 0);
        }
        delete[] data;
        delete[] text;
        paillier_commitment_free_public_key(restored_key);
    }


    SECTION("priv_key_serialization") 
    {
        uint32_t len = 0;

        auto res = paillier_commitment_private_key_serialize(priv, NULL, 0, &len);
        REQUIRE(res == PAILLIER_ERROR_BUFFER_TOO_SHORT);
        uint8_t* data = new uint8_t[len];
        uint32_t len1 = 0;
        res = paillier_commitment_private_key_serialize(priv, data, len, &len1);
        REQUIRE(res == PAILLIER_SUCCESS);
        REQUIRE(len1 == len);

        auto restored_key = paillier_commitment_private_key_deserialize(data, len);
        REQUIRE(NULL != restored_key);
        

        REQUIRE(BN_cmp(restored_key->p, priv->p) == 0);
        REQUIRE(BN_cmp(restored_key->q, priv->q) == 0);
        REQUIRE(BN_cmp(restored_key->lambda, priv->lambda) == 0);
        REQUIRE(BN_cmp(restored_key->p2, priv->p2) == 0);
        REQUIRE(BN_cmp(restored_key->q2, priv->q2) == 0);
        REQUIRE(BN_cmp(restored_key->phi_n, priv->phi_n) == 0);
        REQUIRE(BN_cmp(restored_key->phi_n_inv, priv->phi_n_inv) == 0);
        REQUIRE(BN_cmp(restored_key->q2_inv_p2, priv->q2_inv_p2) == 0);
        
        REQUIRE(BN_cmp(restored_key->pub.n, pub->n) == 0);
        REQUIRE(BN_cmp(restored_key->pub.t, pub->t) == 0);
        REQUIRE(BN_cmp(restored_key->pub.s, pub->s) == 0);
        REQUIRE(BN_cmp(restored_key->pub.n2, pub->n2) == 0);
        REQUIRE(BN_cmp(restored_key->pub.rho, pub->rho) == 0);
        REQUIRE(BN_cmp(restored_key->pub.sigma_0, pub->sigma_0) == 0);
        REQUIRE(restored_key->pub.mont_n2 != NULL);

        delete[] data;

        uint32_t data_len = 0;
        char* text = NULL;
        uint32_t text_len = 0;
        REQUIRE(res == PAILLIER_SUCCESS);
        char msg[] = "Hello World";
        res = paillier_commitment_encrypt(pub, (uint8_t*)msg, strlen(msg), data, 0, &len);
        REQUIRE(res == PAILLIER_ERROR_BUFFER_TOO_SHORT);
        data = new uint8_t[len];
        res = paillier_commitment_encrypt(pub, (uint8_t*)msg, strlen(msg), data, len, &data_len);
        REQUIRE(res == PAILLIER_SUCCESS);
        res = paillier_commitment_decrypt(restored_key, data, data_len, NULL, 0, &len);
        REQUIRE(res == PAILLIER_ERROR_BUFFER_TOO_SHORT);
        text = new char[len+1];
        memset(text, 0, len+1);
        res = paillier_commitment_decrypt(restored_key, data, data_len, (uint8_t*)text, len, &text_len);
        REQUIRE(res == PAILLIER_SUCCESS);
        REQUIRE(text_len >= strlen(msg));
        REQUIRE(strcmp(msg, text + text_len - strlen(msg)) == 0);
        for (uint32_t i = 0; i < text_len - strlen(msg); ++i)
        {
            REQUIRE(text[i] == 0);
        }
        delete[] data;
        delete[] text;
        paillier_commitment_free_private_key(restored_key);
    }

    SECTION("commitment")
    {
        uint8_t commited_value[] = "Hello World";
        const uint32_t randomizer_bitlength = 28;
        paillier_commitment_with_randomizer_power_t* commitment = NULL;

        res = paillier_commitment_commit(pub, commited_value, sizeof(commited_value) - 1, randomizer_bitlength, NULL, 0, NULL, 0, &commitment);
        REQUIRE(res == PAILLIER_SUCCESS);
        REQUIRE(commitment != NULL);
        uint32_t data_len = 0;

        res = paillier_commitment_commitment_serialize(commitment, NULL, 0, &data_len);
        REQUIRE(res == PAILLIER_ERROR_BUFFER_TOO_SHORT);

        uint8_t* data = new uint8_t[data_len];
        uint32_t data_len1 = 0;

        res = paillier_commitment_commitment_serialize(commitment, data, data_len, &data_len1);
        REQUIRE(res == PAILLIER_SUCCESS);
        REQUIRE(data_len1 == data_len);

        paillier_commitment_commitment_free(commitment);
        
        commitment = paillier_commitment_commitment_deserialize(data, data_len);

        res = paillier_commitment_verify(pub, commited_value, sizeof(commited_value) - 1, NULL, 0, NULL, 0, commitment);
        REQUIRE(res == PAILLIER_SUCCESS);

        paillier_commitment_commitment_free(commitment);
        delete[] data;
    } 


    SECTION("commitment_with_modifier")
    {
        uint8_t commited_value[] = "Hello World";
        const uint32_t randomizer_bitlength = 28;
        paillier_commitment_with_randomizer_power_t* commitment = NULL;

        res = paillier_commitment_commit(pub, commited_value, sizeof(commited_value) - 1, randomizer_bitlength, commited_value, sizeof(commited_value) - 1, commited_value, sizeof(commited_value) - 1, &commitment);
        REQUIRE(res == PAILLIER_SUCCESS);

        res = paillier_commitment_verify(pub, commited_value, sizeof(commited_value) - 1, commited_value, sizeof(commited_value) - 1, commited_value, sizeof(commited_value) - 1, commitment);
        REQUIRE(res == PAILLIER_SUCCESS);

        paillier_commitment_commitment_free(commitment);
    }

    paillier_commitment_free_private_key(priv);
}
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


TEST_CASE( "ZKP", "paillier_commitment") 
{
    paillier_commitment_private_key_t* priv;
    long res = paillier_commitment_generate_private_key(2048, &priv);
    REQUIRE(res == PAILLIER_SUCCESS);
    const paillier_commitment_public_key_t* pub = paillier_commitment_private_cast_to_public(priv);

    SECTION("large_factors_quadratic_zkp") 
    {
        const uint8_t aad[] = "SOME AAD";
        
        uint32_t real_proof_len = 0;
        auto res = range_proof_paillier_commitment_large_factors_zkp_generate(priv, aad,  sizeof(aad),  hardcoded_d, sizeof(hardcoded_d), NULL,  0,  &real_proof_len);
        REQUIRE(ZKP_INSUFFICIENT_BUFFER == res);

        uint8_t* serialized_proof = (uint8_t*)malloc(real_proof_len);
        memset(serialized_proof, 0xcd, real_proof_len);
        uint32_t actual_proff_len = 0;
        res = range_proof_paillier_commitment_large_factors_zkp_generate(priv, aad,  sizeof(aad), hardcoded_d, sizeof(hardcoded_d), serialized_proof,  real_proof_len, &actual_proff_len);
        REQUIRE(ZKP_SUCCESS == res);
        REQUIRE(actual_proff_len == real_proof_len);
        
        res = range_proof_paillier_commitment_large_factors_zkp_verify(pub, aad,  sizeof(aad),  serialized_proof,  real_proof_len);
        REQUIRE(ZKP_SUCCESS == res);
        free(serialized_proof);
    }

    SECTION("large_factors_quadratic_zkp - large d buffer") 
    {
        const uint8_t aad[] = "SOME AAD";
        std::vector<uint8_t> padded_d_buffer(2 * sizeof(hardcoded_d));
        
        for (uint32_t i =  sizeof(hardcoded_d); i < 2*sizeof(hardcoded_d); ++ i)
        {
            padded_d_buffer[i] = hardcoded_d[i - sizeof(hardcoded_d)];
        }

        uint32_t real_proof_len = 0;
        auto res = range_proof_paillier_commitment_large_factors_zkp_generate(priv, aad,  sizeof(aad),  padded_d_buffer.data(), 2 * sizeof(hardcoded_d), NULL,  0,  &real_proof_len);
        REQUIRE(ZKP_INSUFFICIENT_BUFFER == res);

        uint8_t* serialized_proof = (uint8_t*)malloc(real_proof_len);

        uint32_t actual_proff_len = 0;
        res = range_proof_paillier_commitment_large_factors_zkp_generate(priv, aad,  sizeof(aad), padded_d_buffer.data(), 2 *sizeof(hardcoded_d), serialized_proof,  real_proof_len, &actual_proff_len);
        REQUIRE(ZKP_SUCCESS == res);
        REQUIRE(actual_proff_len < real_proof_len);

        res = range_proof_paillier_commitment_large_factors_zkp_verify(pub, aad,  sizeof(aad),  serialized_proof,  real_proof_len);
        REQUIRE(ZKP_SUCCESS == res);
        free(serialized_proof);
    }

    SECTION("paillier_blum_zkp") 
    {
        const uint8_t aad[] = "SOME AAD";
        
        uint32_t real_proof_len = 0;
        auto res = paillier_commitment_paillier_blum_zkp_generate(priv, aad,  sizeof(aad),  NULL,  0, &real_proof_len);
        REQUIRE(PAILLIER_ERROR_BUFFER_TOO_SHORT == res);

        uint8_t* serialized_proof = (uint8_t*)malloc(real_proof_len);

        uint32_t actual_proff_len = 0;
        res = paillier_commitment_paillier_blum_zkp_generate(priv, aad,  sizeof(aad),  serialized_proof,  real_proof_len, &actual_proff_len);
        REQUIRE(PAILLIER_SUCCESS == res);
        REQUIRE(actual_proff_len == real_proof_len);

        res = paillier_commitment_paillier_blum_zkp_verify(pub, aad,  sizeof(aad),  serialized_proof,  real_proof_len);
        REQUIRE(PAILLIER_SUCCESS == res);
        free(serialized_proof);
    }


    SECTION("paillier_blum_zkp") 
    {
        const uint8_t aad[] = "SOME AAD";
        
        uint32_t real_proof_len = 0;
        auto res = paillier_commitment_damgard_fujisaki_parameters_zkp_generate(priv, aad,  sizeof(aad),  NULL,  0, &real_proof_len);
        REQUIRE(ZKP_INSUFFICIENT_BUFFER == res);

        uint8_t* serialized_proof = (uint8_t*)malloc(real_proof_len);

        uint32_t actual_proff_len = 0;
        res = paillier_commitment_damgard_fujisaki_parameters_zkp_generate(priv, aad,  sizeof(aad), serialized_proof,  real_proof_len, &actual_proff_len);
        REQUIRE(ZKP_SUCCESS == res);
        REQUIRE(actual_proff_len == real_proof_len);

        res = paillier_commitment_damgard_fujisaki_parameters_zkp_verify(pub, aad,  sizeof(aad),  serialized_proof,  real_proof_len);
        REQUIRE(ZKP_SUCCESS == res);
        free(serialized_proof);
    }

    paillier_commitment_free_private_key(priv);
    
}