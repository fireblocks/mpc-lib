#include "crypto/paillier/paillier.h"
#include <openssl/bn.h>
#include <openssl/bio.h>

#define CATCH_CONFIG_MAIN  
#include <tests/catch.hpp>


TEST_CASE( "gen_key", "paillier") {
    SECTION("gen_key") {
        paillier_public_key_t* pub;
        paillier_private_key_t* priv;
        long res = paillier_generate_key_pair(4096, &pub, &priv);
        REQUIRE(res == PAILLIER_SUCCESS);
        paillier_free_public_key(pub);
        paillier_free_private_key(priv);
    }

    // SECTION("large key") {
    //     paillier_public_key_t* pub;
    //     paillier_private_key_t* priv;
    //     long res = paillier_generate_key_pair(4096*4, &pub, &priv);
    //     REQUIRE(res == PAILLIER_SUCCESS);
    //     paillier_free_public_key(pub);
    //     paillier_free_private_key(priv);
    // }

    // SECTION("too large key") {
    //     paillier_public_key_t* pub;
    //     paillier_private_key_t* priv;
    //     long res = paillier_generate_key_pair(65536, &pub, &priv);
    //     REQUIRE(res == PAILLIER_SUCCESS);
    //     paillier_free_public_key(pub);
    //     paillier_free_private_key(priv);
    // }

    SECTION("too small key") {
        paillier_public_key_t* pub = NULL;
        paillier_private_key_t* priv = NULL;
        long res = paillier_generate_key_pair(64, &pub, &priv);
        REQUIRE(res == PAILLIER_ERROR_KEYLEN_TOO_SHORT);
    }

    SECTION("strange key") {
        paillier_public_key_t* pub;
        paillier_private_key_t* priv;
        long res = paillier_generate_key_pair(5099, &pub, &priv);
        REQUIRE(res == PAILLIER_SUCCESS);
        paillier_free_public_key(pub);
        paillier_free_private_key(priv);
    }

    SECTION("invalid") {
        paillier_public_key_t* pub;
        paillier_private_key_t* priv;
        long res = paillier_generate_key_pair(5099, NULL, &priv);
        REQUIRE(res == PAILLIER_ERROR_INVALID_PARAM);
        res = paillier_generate_key_pair(5099, &pub, NULL);
        REQUIRE(res == PAILLIER_ERROR_INVALID_PARAM);
    }
}


TEST_CASE( "basic", "paillier") {
    paillier_public_key_t* pub;
    paillier_private_key_t* priv;
    long res = paillier_generate_key_pair(2048, &pub, &priv);
    
    SECTION("enc") {
        uint8_t* data = NULL;
        uint32_t data_len = 0;
        char* text = NULL;
        uint32_t text_len = 0;
        REQUIRE(res == PAILLIER_SUCCESS);
        char msg[] = "Hello World";
        uint32_t len = 0;
        res = paillier_encrypt(pub, (uint8_t*)msg, strlen(msg), data, 0, &len);
        REQUIRE(res == PAILLIER_ERROR_INVALID_CIPHER_TEXT);
        data = new uint8_t[len];
        res = paillier_encrypt(pub, (uint8_t*)msg, strlen(msg), data, len, &data_len);
        REQUIRE(res == PAILLIER_SUCCESS);
        res = paillier_decrypt(priv, data, data_len, NULL, 0, &len);
        REQUIRE(res == PAILLIER_ERROR_INVALID_PLAIN_TEXT);
        text = new char[len];
        memset(text, 0, len);
        res = paillier_decrypt(priv, data, data_len, (uint8_t*)text, len, &text_len);
        REQUIRE(res == PAILLIER_SUCCESS);
        REQUIRE(strcmp(msg, text) == 0);
        delete[] data;
        delete[] text;
    }

    SECTION("enc int") {
        REQUIRE(res == PAILLIER_SUCCESS);
        uint64_t msg = 1234567;
        uint32_t len = 0;
        res = paillier_encrypt_integer(pub, msg, NULL, 0, &len);
        REQUIRE(res == PAILLIER_ERROR_INVALID_CIPHER_TEXT);
        uint8_t* data = new uint8_t[len];
        uint32_t data_len = 0;
        res = paillier_encrypt_integer(pub, msg, data, len, &data_len);
        REQUIRE(res == PAILLIER_SUCCESS);
        res = paillier_decrypt(priv, data, data_len, NULL, 0, &len);
        REQUIRE(res == PAILLIER_ERROR_INVALID_PLAIN_TEXT);
        uint8_t* plain = new uint8_t[len];
        memset(plain, 0, len);
        uint32_t plain_len = 0;
        res = paillier_decrypt(priv, data, data_len, plain, len, &plain_len);
        REQUIRE(res == PAILLIER_SUCCESS);
        REQUIRE(plain_len <= sizeof(msg));

        // byte swap as all numbers are represented in big endian
        for (uint32_t i = 0; i < plain_len/2; ++i)
        {
            uint8_t t = plain[i];
            plain[i] = plain[plain_len -1 - i];
            plain[plain_len -1 - i] = t;
        }
        REQUIRE(*(uint64_t*)plain == msg);
        uint64_t decrypted = 0;
        res = paillier_decrypt_integer(priv, data, data_len, &decrypted);
        REQUIRE(res == PAILLIER_SUCCESS);
        REQUIRE(decrypted == msg);
        delete[] data;
        delete[] plain;
    }

    paillier_free_public_key(pub);
    paillier_free_private_key(priv);
}

TEST_CASE( "serialize pub", "paillier") {
    paillier_public_key_t* pub = NULL;
    paillier_public_key_t* local_pub = NULL;
    paillier_private_key_t* priv = NULL;
    long res = paillier_generate_key_pair(2048, &pub, &priv);
    
    SECTION("enc") {
        uint8_t* data = NULL;
        uint32_t data_len = 0;
        char* text = NULL;
        uint32_t text_len = 0;
        REQUIRE(res == PAILLIER_SUCCESS);
        paillier_public_key_serialize(pub, NULL, 0, &data_len);
        REQUIRE(data_len > 0);
        uint8_t* key = new uint8_t[data_len];
        REQUIRE(paillier_public_key_serialize(pub, key, data_len, &data_len));
        local_pub = paillier_public_key_deserialize(key, data_len);
        REQUIRE(local_pub);
        char msg[] = "Hello World";
        uint32_t len = 0;
        res = paillier_encrypt(local_pub, (uint8_t*)msg, strlen(msg), data, 0, &len);
        REQUIRE(res == PAILLIER_ERROR_INVALID_CIPHER_TEXT);
        data = new uint8_t[len];
        res = paillier_encrypt(local_pub, (uint8_t*)msg, strlen(msg), data, len, &data_len);
        REQUIRE(res == PAILLIER_SUCCESS);
        res = paillier_decrypt(priv, data, data_len, NULL, 0, &len);
        REQUIRE(res == PAILLIER_ERROR_INVALID_PLAIN_TEXT);
        text = new char[len];
        memset(text, 0, len);
        res = paillier_decrypt(priv, data, data_len, (uint8_t*)text, len, &text_len);
        REQUIRE(res == PAILLIER_SUCCESS);
        REQUIRE(strcmp(msg, text) == 0);
        delete[] key;
        delete[] data;
        delete[] text;
    }

    SECTION("invalid buffer") {
        uint8_t* data = NULL;
        uint32_t data_len = 0;
        REQUIRE(res == PAILLIER_SUCCESS);
        paillier_public_key_serialize(pub, NULL, 0, &data_len);
        REQUIRE(data_len > 0);
        uint8_t* key = new uint8_t[data_len];
        REQUIRE(paillier_public_key_serialize(pub, key, data_len, &data_len));
        local_pub = paillier_public_key_deserialize(key, 16);
        REQUIRE(local_pub == NULL);
        delete[] key;
        delete[] data;
    }

    paillier_free_public_key(pub);
    paillier_free_public_key(local_pub);
    paillier_free_private_key(priv);
}

TEST_CASE( "serialize priv", "paillier") {
    paillier_public_key_t* pub = NULL;
    paillier_private_key_t* priv = NULL;
    paillier_private_key_t* local_priv = NULL;
    long res = paillier_generate_key_pair(2048, &pub, &priv);
    
    SECTION("enc") {
        uint8_t* data = NULL;
        uint32_t data_len = 0;
        char* text = NULL;
        uint32_t text_len = 0;
        REQUIRE(res == PAILLIER_SUCCESS);
        paillier_private_key_serialize(priv, NULL, 0, &data_len);
        REQUIRE(data_len > 0);
        uint8_t* key = new uint8_t[data_len];
        REQUIRE(paillier_private_key_serialize(priv, key, data_len, &data_len));
        local_priv = paillier_private_key_deserialize(key, data_len);
        REQUIRE(local_priv);
        char msg[] = "Hello World";
        uint32_t len = 0;
        res = paillier_encrypt(pub, (uint8_t*)msg, strlen(msg), data, 0, &len);
        REQUIRE(res == PAILLIER_ERROR_INVALID_CIPHER_TEXT);
        data = new uint8_t[len];
        res = paillier_encrypt(pub, (uint8_t*)msg, strlen(msg), data, len, &data_len);
        REQUIRE(res == PAILLIER_SUCCESS);
        res = paillier_decrypt(local_priv, data, data_len, NULL, 0, &len);
        REQUIRE(res == PAILLIER_ERROR_INVALID_PLAIN_TEXT);
        text = new char[len];
        memset(text, 0, len);
        res = paillier_decrypt(local_priv, data, data_len, (uint8_t*)text, len, &text_len);
        REQUIRE(res == PAILLIER_SUCCESS);
        REQUIRE(strcmp(msg, text) == 0);
        delete[] key;
        delete[] data;
        delete[] text;
    }

    SECTION("invalid buffer") {
        uint8_t* data = NULL;
        uint32_t data_len = 0;
        REQUIRE(res == PAILLIER_SUCCESS);
        paillier_private_key_serialize(priv, NULL, 0, &data_len);
        REQUIRE(data_len > 0);
        uint8_t* key = new uint8_t[data_len];
        REQUIRE(paillier_private_key_serialize(priv, key, data_len, &data_len));
        local_priv = paillier_private_key_deserialize(key, 16);
        REQUIRE(local_priv == NULL);
        delete[] key;
        delete[] data;
    }

    paillier_free_public_key(pub);
    paillier_free_private_key(priv);
    paillier_free_private_key(local_priv);
}

TEST_CASE( "add", "paillier") {
    paillier_public_key_t* pub;
    paillier_private_key_t* priv;
    long res = paillier_generate_key_pair(2048, &pub, &priv);

    SECTION("add") {
        REQUIRE(res == PAILLIER_SUCCESS);
        uint8_t msg[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 11, 12, 13, 14, 15, 16, 17, 18};
        uint32_t len = 0;
        res = paillier_encrypt(pub, msg, sizeof(msg), NULL, 0, &len);
        REQUIRE(res == PAILLIER_ERROR_INVALID_CIPHER_TEXT);
        uint8_t* data = new uint8_t[len];
        uint32_t data_len = 0;
        res = paillier_encrypt(pub, msg, sizeof(msg), data, len, &data_len);
        REQUIRE(res == PAILLIER_SUCCESS);
        res = paillier_encrypt(pub, msg, sizeof(msg), NULL, 0, &len);
        REQUIRE(res == PAILLIER_ERROR_INVALID_CIPHER_TEXT);
        uint8_t* data2 = new uint8_t[len];
        uint32_t data_len2 = 0;
        res = paillier_encrypt(pub, msg, sizeof(msg), data2, len, &data_len2);
        REQUIRE(res == PAILLIER_SUCCESS);
        
        res = paillier_add(pub, data, data_len, data2, data_len2, NULL, 0, &len);
        REQUIRE(res == PAILLIER_ERROR_INVALID_CIPHER_TEXT);
        uint8_t* data3 = new uint8_t[len];
        uint32_t data_len3 = 0;
        res = paillier_add(pub, data, data_len, data2, data_len2, data3, len, &data_len3);
        REQUIRE(res == PAILLIER_SUCCESS);
        
        
        res = paillier_decrypt(priv, data3, data_len3, NULL, 0, &len);
        REQUIRE(res == PAILLIER_ERROR_INVALID_PLAIN_TEXT);
        uint8_t* decrypted = new uint8_t[len];
        uint32_t decrypted_len;
        res = paillier_decrypt(priv, data3, data_len3, decrypted, len, &decrypted_len);
        REQUIRE(res == PAILLIER_SUCCESS);
        for (uint32_t i = 0; i < decrypted_len; i++)
            REQUIRE(decrypted[i] == 2*msg[i]);
        delete[] data;
        delete[] data2;
        delete[] data3;
        delete[] decrypted;
    }

    SECTION("add int") {
        REQUIRE(res == PAILLIER_SUCCESS);
        uint64_t msg = 1234567;
        uint32_t len = 0;
        res = paillier_encrypt_integer(pub, msg, NULL, 0, &len);
        REQUIRE(res == PAILLIER_ERROR_INVALID_CIPHER_TEXT);
        uint8_t* data = new uint8_t[len];
        uint32_t data_len = 0;
        res = paillier_encrypt_integer(pub, msg, data, len, &data_len);
        REQUIRE(res == PAILLIER_SUCCESS);
        uint64_t msg2 = 7654321;
        res = paillier_encrypt_integer(pub, msg2, NULL, 0, &len);
        REQUIRE(res == PAILLIER_ERROR_INVALID_CIPHER_TEXT);
        uint8_t* data2 = new uint8_t[len];
        uint32_t data_len2 = 0;
        res = paillier_encrypt_integer(pub, msg2, data2, len, &data_len2);
        REQUIRE(res == PAILLIER_SUCCESS);
        
        res = paillier_add(pub, data, data_len, data2, data_len2, NULL, 0, &len);
        REQUIRE(res == PAILLIER_ERROR_INVALID_CIPHER_TEXT);
        uint8_t* data3 = new uint8_t[len];
        uint32_t data_len3 = 0;
        res = paillier_add(pub, data, data_len, data2, data_len2, data3, len, &data_len3);
        REQUIRE(res == PAILLIER_SUCCESS);
        
        
        uint64_t decrypted = 0;
        res = paillier_decrypt_integer(priv, data3, data_len3, &decrypted);
        REQUIRE(res == PAILLIER_SUCCESS);
        REQUIRE(decrypted == msg+msg2);
        delete[] data;
        delete[] data2;
        delete[] data3;
    }

    SECTION("add int") {
        REQUIRE(res == PAILLIER_SUCCESS);
        uint64_t msg = 1234567;
        uint32_t len = 0;
        res = paillier_encrypt_integer(pub, msg, NULL, 0, &len);
        REQUIRE(res == PAILLIER_ERROR_INVALID_CIPHER_TEXT);
        uint8_t* data = new uint8_t[len];
        uint32_t data_len = 0;
        res = paillier_encrypt_integer(pub, msg, data, len, &data_len);
        REQUIRE(res == PAILLIER_SUCCESS);
        uint64_t msg2 = 7654321;
        
        res = paillier_add_integer(pub, data, data_len, msg2, NULL, 0, &len);
        REQUIRE(res == PAILLIER_ERROR_INVALID_CIPHER_TEXT);
        uint8_t* data2 = new uint8_t[len];
        uint32_t data_len2 = 0;
        res = paillier_add_integer(pub, data, data_len, msg2, data2, len, &data_len2);
        REQUIRE(res == PAILLIER_SUCCESS);
        
        
        uint64_t decrypted = 0;
        res = paillier_decrypt_integer(priv, data2, data_len2, &decrypted);
        REQUIRE(res == PAILLIER_SUCCESS);
        REQUIRE(decrypted == msg+msg2);
        delete[] data;
        delete[] data2;
    }
    
    paillier_free_public_key(pub);
    paillier_free_private_key(priv);
}

TEST_CASE( "sub", "paillier") {
    paillier_public_key_t* pub;
    paillier_private_key_t* priv;
    long res = paillier_generate_key_pair(2048, &pub, &priv);
    
    SECTION("sub") {
        REQUIRE(res == PAILLIER_SUCCESS);
        uint8_t msg[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 11, 12, 13, 14, 15, 16, 17, 18};
        uint32_t len = 0;
        res = paillier_encrypt(pub, msg, sizeof(msg), NULL, 0, &len);
        REQUIRE(res == PAILLIER_ERROR_INVALID_CIPHER_TEXT);
        uint8_t* data = new uint8_t[len];
        uint32_t data_len = 0;
        res = paillier_encrypt(pub, msg, sizeof(msg), data, len, &data_len);
        REQUIRE(res == PAILLIER_SUCCESS);
        uint8_t msg2[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 11, 12, 13, 14, 15, 16, 17};
        res = paillier_encrypt(pub, msg2, sizeof(msg2), NULL, 0, &len);
        REQUIRE(res == PAILLIER_ERROR_INVALID_CIPHER_TEXT);
        uint8_t* data2 = new uint8_t[len];
        uint32_t data_len2 = 0;
        res = paillier_encrypt(pub, msg2, sizeof(msg2), data2, len, &data_len2);
        REQUIRE(res == PAILLIER_SUCCESS);
        
        res = paillier_sub(pub, data, data_len, data2, data_len2, NULL, 0, &len);
        REQUIRE(res == PAILLIER_ERROR_INVALID_CIPHER_TEXT);
        uint8_t* data3 = new uint8_t[len];
        uint32_t data_len3 = 0;
        res = paillier_sub(pub, data, data_len, data2, data_len2, data3, len, &data_len3);
        REQUIRE(res == PAILLIER_SUCCESS);
        
        
        res = paillier_decrypt(priv, data3, data_len3, NULL, 0, &len);
        REQUIRE(res == PAILLIER_ERROR_INVALID_PLAIN_TEXT);
        uint8_t* decrypted = new uint8_t[len];
        uint32_t decrypted_len;
        res = paillier_decrypt(priv, data3, data_len3, decrypted, len, &decrypted_len);
        REQUIRE(res == PAILLIER_SUCCESS);
        BIGNUM* m1 = BN_bin2bn(msg, sizeof(msg), NULL);
        BIGNUM* m2 = BN_bin2bn(msg2, sizeof(msg2), NULL);
        BN_sub(m1, m1, m2);
        uint8_t sub_bin[sizeof(msg)];
        BN_bn2bin(m1, sub_bin);
        for (uint32_t i = 0; i < decrypted_len; i++)
            REQUIRE(decrypted[i] == sub_bin[i]);
        BN_free(m1);
        BN_free(m2);
        delete[] data;
        delete[] data2;
        delete[] data3;
        delete[] decrypted;
    }

    SECTION("sub int") {
        REQUIRE(res == PAILLIER_SUCCESS);
        uint64_t msg = 7654321;
        uint32_t len = 0;
        res = paillier_encrypt_integer(pub, msg, NULL, 0, &len);
        REQUIRE(res == PAILLIER_ERROR_INVALID_CIPHER_TEXT);
        uint8_t* data = new uint8_t[len];
        uint32_t data_len = 0;
        res = paillier_encrypt_integer(pub, msg, data, len, &data_len);
        REQUIRE(res == PAILLIER_SUCCESS);
        uint64_t msg2 = 1234567;
        res = paillier_encrypt_integer(pub, msg2, NULL, 0, &len);
        REQUIRE(res == PAILLIER_ERROR_INVALID_CIPHER_TEXT);
        uint8_t* data2 = new uint8_t[len];
        uint32_t data_len2 = 0;
        res = paillier_encrypt_integer(pub, msg2, data2, len, &data_len2);
        REQUIRE(res == PAILLIER_SUCCESS);
        
        res = paillier_sub(pub, data, data_len, data2, data_len2, NULL, 0, &len);
        REQUIRE(res == PAILLIER_ERROR_INVALID_CIPHER_TEXT);
        uint8_t* data3 = new uint8_t[len];
        uint32_t data_len3 = 0;
        res = paillier_sub(pub, data, data_len, data2, data_len2, data3, len, &data_len3);
        REQUIRE(res == PAILLIER_SUCCESS);
        
        
        uint64_t decrypted = 0;
        res = paillier_decrypt_integer(priv, data3, data_len3, &decrypted);
        REQUIRE(res == PAILLIER_SUCCESS);
        REQUIRE(decrypted == msg-msg2);
        delete[] data;
        delete[] data2;
        delete[] data3;
    }

    SECTION("sub int") {
        REQUIRE(res == PAILLIER_SUCCESS);
        uint64_t msg = 7654321;
        uint32_t len = 0;
        res = paillier_encrypt_integer(pub, msg, NULL, 0, &len);
        REQUIRE(res == PAILLIER_ERROR_INVALID_CIPHER_TEXT);
        uint8_t* data = new uint8_t[len];
        uint32_t data_len = 0;
        res = paillier_encrypt_integer(pub, msg, data, len, &data_len);
        REQUIRE(res == PAILLIER_SUCCESS);
        uint64_t msg2 = 1234567;
        
        res = paillier_sub_integer(pub, data, data_len, msg2, NULL, 0, &len);
        REQUIRE(res == PAILLIER_ERROR_INVALID_CIPHER_TEXT);
        uint8_t* data2 = new uint8_t[len];
        uint32_t data_len2 = 0;
        res = paillier_sub_integer(pub, data, data_len, msg2, data2, len, &data_len2);
        REQUIRE(res == PAILLIER_SUCCESS);
        
        
        uint64_t decrypted = 0;
        res = paillier_decrypt_integer(priv, data2, data_len2, &decrypted);
        REQUIRE(res == PAILLIER_SUCCESS);
        REQUIRE(decrypted == msg-msg2);
        delete[] data;
        delete[] data2;
    }
    
    paillier_free_public_key(pub);
    paillier_free_private_key(priv);
}

TEST_CASE( "mul", "paillier") {
    paillier_public_key_t* pub;
    paillier_private_key_t* priv;
    long res = paillier_generate_key_pair(2048, &pub, &priv);
    
    SECTION("mul") {
        REQUIRE(res == PAILLIER_SUCCESS);
        uint8_t msg[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 11, 12, 13, 14, 15, 16, 17, 18};
        uint32_t len = 0;
        res = paillier_encrypt(pub, msg, sizeof(msg), NULL, 0, &len);
        REQUIRE(res == PAILLIER_ERROR_INVALID_CIPHER_TEXT);
        uint8_t* data = new uint8_t[len];
        uint32_t data_len = 0;
        res = paillier_encrypt(pub, msg, sizeof(msg), data, len, &data_len);
        REQUIRE(res == PAILLIER_SUCCESS);
        
        res = paillier_mul(pub, data, data_len, msg, sizeof(msg), NULL, 0, &len);
        REQUIRE(res == PAILLIER_ERROR_INVALID_CIPHER_TEXT);
        uint8_t* data3 = new uint8_t[len];
        uint32_t data_len3 = 0;
        res = paillier_mul(pub, data, data_len, msg, sizeof(msg), data3, len, &data_len3);
        REQUIRE(res == PAILLIER_SUCCESS);
        
        
        res = paillier_decrypt(priv, data3, data_len3, NULL, 0, &len);
        REQUIRE(res == PAILLIER_ERROR_INVALID_PLAIN_TEXT);
        uint8_t* decrypted = new uint8_t[len];
        uint32_t decrypted_len;
        res = paillier_decrypt(priv, data3, data_len3, decrypted, len, &decrypted_len);
        REQUIRE(res == PAILLIER_SUCCESS);
        BIGNUM* m1 = BN_bin2bn(msg, sizeof(msg), NULL);
        BN_CTX* bn_ctx = BN_CTX_new();
        BN_sqr(m1, m1, bn_ctx);
        BN_CTX_free(bn_ctx);
        uint8_t* mul_bin = new uint8_t[BN_num_bytes(m1)];
        BN_bn2bin(m1, mul_bin);
        for (uint32_t i = 0; i < decrypted_len; i++)
            REQUIRE(decrypted[i] == mul_bin[i]);
        BN_free(m1);
        delete[] mul_bin;
        delete[] data;
        delete[] data3;
        delete[] decrypted;
    }

    SECTION("mul int") {
        REQUIRE(res == PAILLIER_SUCCESS);
        uint64_t msg = 1234567;
        uint32_t len = 0;
        res = paillier_encrypt_integer(pub, msg, NULL, 0, &len);
        REQUIRE(res == PAILLIER_ERROR_INVALID_CIPHER_TEXT);
        uint8_t* data = new uint8_t[len];
        uint32_t data_len = 0;
        res = paillier_encrypt_integer(pub, msg, data, len, &data_len);
        REQUIRE(res == PAILLIER_SUCCESS);
        uint64_t msg2 = 7654321;
        
        res = paillier_mul_integer(pub, data, data_len, msg2, NULL, 0, &len);
        REQUIRE(res == PAILLIER_ERROR_INVALID_CIPHER_TEXT);
        uint8_t* data2 = new uint8_t[len];
        uint32_t data_len2 = 0;
        res = paillier_mul_integer(pub, data, data_len, msg2, data2, len, &data_len2);
        REQUIRE(res == PAILLIER_SUCCESS);
        
        
        uint64_t decrypted = 0;
        res = paillier_decrypt_integer(priv, data2, data_len2, &decrypted);
        REQUIRE(res == PAILLIER_SUCCESS);
        REQUIRE(decrypted == msg*msg2);
        delete[] data;
        delete[] data2;
    }
    
    paillier_free_public_key(pub);
    paillier_free_private_key(priv);
}

TEST_CASE( "zkpok", "paillier") {
    paillier_public_key_t* pub;
    paillier_private_key_t* priv;
    long res = paillier_generate_key_pair(2048, &pub, &priv);
    
    SECTION("valid") {
        REQUIRE(res == PAILLIER_SUCCESS);
        unsigned char x[PAILLIER_SHA256_LEN];
        unsigned char y[256];
        
        res = paillier_generate_factorization_zkpok(priv, (const unsigned char*)"hello world", sizeof("hello world") - 1, x, y, 256, NULL);
        REQUIRE(res == PAILLIER_SUCCESS);
        res = paillier_verify_factorization_zkpok(pub, (const unsigned char*)"hello world", sizeof("hello world") - 1, x, y, 256);
        REQUIRE(res == PAILLIER_SUCCESS);
    }

    SECTION("invalid aad") {
        REQUIRE(res == PAILLIER_SUCCESS);
        unsigned char x[PAILLIER_SHA256_LEN];
        unsigned char y[256];
        
        res = paillier_generate_factorization_zkpok(priv, (const unsigned char*)"hello world", sizeof("hello world") - 1, x, y, 256, NULL);
        REQUIRE(res == PAILLIER_SUCCESS);
        res = paillier_verify_factorization_zkpok(pub, (const unsigned char*)"gello world", sizeof("hello world") - 1, x, y, 256);
        REQUIRE(res == PAILLIER_ERROR_INVALID_PROOF);
    }
    
    SECTION("invalid x") {
        REQUIRE(res == PAILLIER_SUCCESS);
        unsigned char x[PAILLIER_SHA256_LEN];
        unsigned char y[256];
        
        res = paillier_generate_factorization_zkpok(priv, (const unsigned char*)"hello world", sizeof("hello world") - 1, x, y, 256, NULL);
        REQUIRE(res == PAILLIER_SUCCESS);
        x[4]++;
        res = paillier_verify_factorization_zkpok(pub, (const unsigned char*)"hello world", sizeof("hello world") - 1, x, y, 256);
        REQUIRE(res == PAILLIER_ERROR_INVALID_PROOF);
    }

    SECTION("invalid y") {
        REQUIRE(res == PAILLIER_SUCCESS);
        unsigned char x[PAILLIER_SHA256_LEN];
        unsigned char y[256];
        
        res = paillier_generate_factorization_zkpok(priv, (const unsigned char*)"hello world", sizeof("hello world") - 1, x, y, 256, NULL);
        REQUIRE(res == PAILLIER_SUCCESS);
        y[4]++;
        res = paillier_verify_factorization_zkpok(pub, (const unsigned char*)"hello world", sizeof("hello world") - 1, x, y, 256);
        REQUIRE(res == PAILLIER_ERROR_INVALID_PROOF);
    }

    SECTION("invalid param") {
        unsigned char x[PAILLIER_SHA256_LEN];
        unsigned char y[256];
        res = paillier_generate_factorization_zkpok(NULL, (const unsigned char*)"hello world", sizeof("hello world") - 1, x, y, 256, NULL);
        REQUIRE(res == PAILLIER_ERROR_INVALID_KEY);
        res = paillier_generate_factorization_zkpok(priv, NULL, sizeof("hello world") - 1, x, y, 256, NULL);
        REQUIRE(res == PAILLIER_ERROR_INVALID_PARAM);
        res = paillier_generate_factorization_zkpok(priv, (const unsigned char*)"hello world", sizeof("hello world") - 1, NULL, y, 256, NULL);
        REQUIRE(res == PAILLIER_ERROR_INVALID_PARAM);
        res = paillier_generate_factorization_zkpok(priv, (const unsigned char*)"hello world", sizeof("hello world") - 1, x, NULL, 256, NULL);
        REQUIRE(res == PAILLIER_ERROR_INVALID_PARAM);
        res = paillier_generate_factorization_zkpok(priv, (const unsigned char*)"hello world", sizeof("hello world") - 1, x, y, 0, NULL);
        REQUIRE(res == PAILLIER_ERROR_BUFFER_TOO_SHORT);

        res = paillier_verify_factorization_zkpok(NULL, (const unsigned char*)"hello world", sizeof("hello world") - 1, x, y, 256);
        REQUIRE(res == PAILLIER_ERROR_INVALID_KEY);
        res = paillier_verify_factorization_zkpok(pub, 0, sizeof("hello world") - 1, x, y, 256);
        REQUIRE(res == PAILLIER_ERROR_INVALID_PARAM);
        res = paillier_verify_factorization_zkpok(pub, (const unsigned char*)"hello world", sizeof("hello world") - 1, NULL, y, 256);
        REQUIRE(res == PAILLIER_ERROR_INVALID_PARAM);
        res = paillier_verify_factorization_zkpok(pub, (const unsigned char*)"hello world", sizeof("hello world") - 1, x, NULL, 256);
        REQUIRE(res == PAILLIER_ERROR_INVALID_PARAM);
        res = paillier_verify_factorization_zkpok(pub, (const unsigned char*)"hello world", sizeof("hello world") - 1, x, y, 0);
        REQUIRE(res == PAILLIER_ERROR_INVALID_PARAM);
    }
    
    paillier_free_public_key(pub);
    paillier_free_private_key(priv);
}

TEST_CASE( "zkp", "paillier") {
    paillier_public_key_t* pub;
    paillier_private_key_t* priv;
    long res = paillier_generate_key_pair(2048, &pub, &priv);
    
    SECTION("valid") {
        REQUIRE(res == PAILLIER_SUCCESS);
        unsigned char y[4096];
        
        res = paillier_generate_coprime_zkp(priv, (const unsigned char*)"hello world", sizeof("hello world") - 1, y, sizeof(y), NULL);
        REQUIRE(res == PAILLIER_SUCCESS);
        res = paillier_verify_coprime_zkp(pub, (const unsigned char*)"hello world", sizeof("hello world") - 1, y, sizeof(y));
        REQUIRE(res == PAILLIER_SUCCESS);
    }

    SECTION("invalid aad") {
        REQUIRE(res == PAILLIER_SUCCESS);
        unsigned char y[4096];
        
        res = paillier_generate_coprime_zkp(priv, (const unsigned char*)"hello world", sizeof("hello world") - 1, y, sizeof(y), NULL);
        REQUIRE(res == PAILLIER_SUCCESS);
        res = paillier_verify_coprime_zkp(pub, (const unsigned char*)"gello world", sizeof("hello world") - 1, y, sizeof(y));
        REQUIRE(res == PAILLIER_ERROR_INVALID_PROOF);
    }
    
    SECTION("invalid y") {
        REQUIRE(res == PAILLIER_SUCCESS);
        unsigned char y[4096];
        
        res = paillier_generate_coprime_zkp(priv, (const unsigned char*)"hello world", sizeof("hello world") - 1, y, sizeof(y), NULL);
        REQUIRE(res == PAILLIER_SUCCESS);
        y[4]++;
        res = paillier_verify_coprime_zkp(pub, (const unsigned char*)"gello world", sizeof("hello world") - 1, y, sizeof(y));
        REQUIRE(res == PAILLIER_ERROR_INVALID_PROOF);
    }

    SECTION("invalid param") {
        unsigned char y[4096];
        unsigned int y_len;
        res = paillier_generate_coprime_zkp(NULL, (const unsigned char*)"hello world", sizeof("hello world") - 1, y, 4096, NULL);
        REQUIRE(res == PAILLIER_ERROR_INVALID_KEY);
        res = paillier_generate_coprime_zkp(priv, NULL, sizeof("hello world") - 1, y, 4096, NULL);
        REQUIRE(res == PAILLIER_ERROR_INVALID_PARAM);
        res = paillier_generate_coprime_zkp(priv, (const unsigned char*)"hello world", sizeof("hello world") - 1, NULL, 4096, NULL);
        REQUIRE(res == PAILLIER_ERROR_INVALID_PARAM);
        res = paillier_generate_coprime_zkp(priv, (const unsigned char*)"hello world", sizeof("hello world") - 1, y, 0, NULL);
        REQUIRE(res == PAILLIER_ERROR_BUFFER_TOO_SHORT);
        res = paillier_generate_coprime_zkp(priv, (const unsigned char*)"hello world", sizeof("hello world") - 1, NULL, 0, &y_len);
        REQUIRE(res == PAILLIER_ERROR_BUFFER_TOO_SHORT);
        REQUIRE(y_len == 2048/8*16);

        res = paillier_verify_coprime_zkp(NULL, (const unsigned char*)"hello world", sizeof("hello world") - 1, y, 4096);
        REQUIRE(res == PAILLIER_ERROR_INVALID_KEY);
        res = paillier_verify_coprime_zkp(pub, 0, sizeof("hello world") - 1, y, 4096);
        REQUIRE(res == PAILLIER_ERROR_INVALID_PARAM);
        res = paillier_verify_coprime_zkp(pub, (const unsigned char*)"hello world", sizeof("hello world") - 1, NULL, 4096);
        REQUIRE(res == PAILLIER_ERROR_INVALID_PARAM);
    }
    
    paillier_free_public_key(pub);
    paillier_free_private_key(priv);
}

TEST_CASE( "paillier_blum_zkp", "paillier") {
    paillier_public_key_t* pub;
    paillier_private_key_t* priv;
    long res = paillier_generate_key_pair(2048, &pub, &priv);
    
    SECTION("valid") {
        REQUIRE(res == PAILLIER_SUCCESS);
        uint32_t proof_len;
        res = paillier_generate_paillier_blum_zkp(priv, (const unsigned char*)"hello world", sizeof("hello world") - 1, NULL, 0, &proof_len);
        REQUIRE(res == PAILLIER_ERROR_BUFFER_TOO_SHORT);
        std::unique_ptr<uint8_t[]> proof(new uint8_t[proof_len]);
        res = paillier_generate_paillier_blum_zkp(priv, (const unsigned char*)"hello world", sizeof("hello world") - 1, proof.get(), proof_len -1, &proof_len);
        REQUIRE(res == PAILLIER_ERROR_BUFFER_TOO_SHORT);
        res = paillier_generate_paillier_blum_zkp(priv, (const unsigned char*)"hello world", sizeof("hello world") - 1, proof.get(), proof_len, &proof_len);
        REQUIRE(res == PAILLIER_SUCCESS);
        res = paillier_verify_paillier_blum_zkp(pub, (const unsigned char*)"hello world", sizeof("hello world") - 1, proof.get(), proof_len);
        REQUIRE(res == PAILLIER_SUCCESS);
    }

    SECTION("invalid aad") {
        REQUIRE(res == PAILLIER_SUCCESS);
        uint32_t proof_len;
        res = paillier_generate_paillier_blum_zkp(priv, (const unsigned char*)"hello world", sizeof("hello world") - 1, NULL, 0, &proof_len);
        REQUIRE(res == PAILLIER_ERROR_BUFFER_TOO_SHORT);
        std::unique_ptr<uint8_t[]> proof(new uint8_t[proof_len]);
        res = paillier_generate_paillier_blum_zkp(priv, (const unsigned char*)"hello world", sizeof("hello world") - 1, proof.get(), proof_len, &proof_len);
        REQUIRE(res == PAILLIER_SUCCESS);
        res = paillier_verify_paillier_blum_zkp(pub, (const unsigned char*)"gello world", sizeof("hello world") - 1, proof.get(), proof_len);
        REQUIRE(res == PAILLIER_ERROR_INVALID_PROOF);
    }
    
    SECTION("invalid proof") {
        REQUIRE(res == PAILLIER_SUCCESS);
        uint32_t proof_len;
        res = paillier_generate_paillier_blum_zkp(priv, (const unsigned char*)"hello world", sizeof("hello world") - 1, NULL, 0, &proof_len);
        REQUIRE(res == PAILLIER_ERROR_BUFFER_TOO_SHORT);
        std::unique_ptr<uint8_t[]> proof(new uint8_t[proof_len]);
        res = paillier_generate_paillier_blum_zkp(priv, (const unsigned char*)"hello world", sizeof("hello world") - 1, proof.get(), proof_len, &proof_len);
        REQUIRE(res == PAILLIER_SUCCESS);
        (*(uint32_t*)proof.get())++;
        res = paillier_verify_paillier_blum_zkp(pub, (const unsigned char*)"hello world", sizeof("hello world") - 1, proof.get(), proof_len);
        REQUIRE(res == PAILLIER_ERROR_INVALID_PROOF);
        (*(uint32_t*)proof.get())--;
        proof.get()[32]++;
        res = paillier_verify_paillier_blum_zkp(pub, (const unsigned char*)"hello world", sizeof("hello world") - 1, proof.get(), proof_len);
        REQUIRE(res == PAILLIER_ERROR_INVALID_PROOF);
    }

    SECTION("invalid param") {
        uint32_t proof_len;
        res = paillier_generate_paillier_blum_zkp(priv, (const unsigned char*)"hello world", sizeof("hello world") - 1, NULL, 0, &proof_len);
        REQUIRE(res == PAILLIER_ERROR_BUFFER_TOO_SHORT);
        std::unique_ptr<uint8_t[]> proof(new uint8_t[proof_len]);
        res = paillier_generate_paillier_blum_zkp(NULL, (const unsigned char*)"hello world", sizeof("hello world") - 1, proof.get(), proof_len, NULL);
        REQUIRE(res == PAILLIER_ERROR_INVALID_KEY);
        res = paillier_generate_paillier_blum_zkp(priv, NULL, sizeof("hello world") - 1, proof.get(), proof_len, NULL);
        REQUIRE(res == PAILLIER_ERROR_INVALID_PARAM);
        res = paillier_generate_paillier_blum_zkp(priv, (const unsigned char*)"hello world", sizeof("hello world") - 1, NULL, proof_len, NULL);
        REQUIRE(res == PAILLIER_ERROR_INVALID_PARAM);
        res = paillier_generate_paillier_blum_zkp(priv, (const unsigned char*)"hello world", sizeof("hello world") - 1, proof.get(), 0, NULL);
        REQUIRE(res == PAILLIER_ERROR_BUFFER_TOO_SHORT);
        
        res = paillier_verify_paillier_blum_zkp(NULL, (const unsigned char*)"hello world", sizeof("hello world") - 1, proof.get(), proof_len);
        REQUIRE(res == PAILLIER_ERROR_INVALID_KEY);
        res = paillier_verify_paillier_blum_zkp(pub, 0, sizeof("hello world") - 1, proof.get(), proof_len);
        REQUIRE(res == PAILLIER_ERROR_INVALID_PARAM);
        res = paillier_verify_paillier_blum_zkp(pub, (const unsigned char*)"hello world", sizeof("hello world") - 1, NULL, proof_len);
        REQUIRE(res == PAILLIER_ERROR_INVALID_PARAM);
        res = paillier_verify_paillier_blum_zkp(pub, (const unsigned char*)"hello world", sizeof("hello world") - 1, proof.get(), 7);
        REQUIRE(res == PAILLIER_ERROR_INVALID_PARAM);
    }
    
    paillier_free_public_key(pub);
    paillier_free_private_key(priv);
}
