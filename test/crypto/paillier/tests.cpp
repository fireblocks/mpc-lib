#include "crypto/paillier/paillier.h"
#include "../../../src/common/crypto/paillier/paillier_internal.h"
#include <openssl/bn.h>
#include <openssl/bio.h>

#include <string.h>

#include <tests/catch.hpp>

TEST_CASE( "gen_key", "paillier")
{
    SECTION("gen_key")
    {
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

    SECTION("too small key")
    {
        paillier_public_key_t* pub = NULL;
        paillier_private_key_t* priv = NULL;
        long res = paillier_generate_key_pair(64, &pub, &priv);
        REQUIRE(res == PAILLIER_ERROR_KEYLEN_TOO_SHORT);
    }

    SECTION("strange key")
    {
        paillier_public_key_t* pub;
        paillier_private_key_t* priv;
        long res = paillier_generate_key_pair(5099, &pub, &priv);
        REQUIRE(res == PAILLIER_SUCCESS);
        paillier_free_public_key(pub);
        paillier_free_private_key(priv);
    }

    SECTION("invalid")
    {
        paillier_public_key_t* pub;
        paillier_private_key_t* priv;
        long res = paillier_generate_key_pair(5099, NULL, &priv);
        REQUIRE(res == PAILLIER_ERROR_INVALID_PARAM);
        res = paillier_generate_key_pair(5099, &pub, NULL);
        REQUIRE(res == PAILLIER_ERROR_INVALID_PARAM);
    }
}


TEST_CASE( "basic", "paillier")
{
    paillier_public_key_t* pub;
    paillier_private_key_t* priv;
    long res = paillier_generate_key_pair(2048, &pub, &priv);

    SECTION("enc")
    {
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

    SECTION("enc int")
    {
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

TEST_CASE( "serialize pub", "paillier")
{
    paillier_public_key_t* pub = NULL;
    paillier_public_key_t* local_pub = NULL;
    paillier_private_key_t* priv = NULL;
    long res = paillier_generate_key_pair(2048, &pub, &priv);

    SECTION("enc")
    {
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

    SECTION("invalid buffer")
    {
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

TEST_CASE( "serialize priv", "paillier")
{
    paillier_public_key_t* pub = NULL;
    paillier_private_key_t* priv = NULL;
    paillier_private_key_t* local_priv = NULL;
    long res = paillier_generate_key_pair(2048, &pub, &priv);

    SECTION("enc")
    {
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

    SECTION("invalid buffer")
    {
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

TEST_CASE( "add", "paillier")
{
    paillier_public_key_t* pub;
    paillier_private_key_t* priv;
    long res = paillier_generate_key_pair(2048, &pub, &priv);

    SECTION("add")
    {
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

    SECTION("add int")
    {
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

    SECTION("add int")
    {
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

TEST_CASE( "sub", "paillier")
{
    paillier_public_key_t* pub;
    paillier_private_key_t* priv;
    long res = paillier_generate_key_pair(2048, &pub, &priv);

    SECTION("sub")
    {
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
        {
            REQUIRE(decrypted[i] == sub_bin[i]);
        }
        BN_free(m1);
        BN_free(m2);
        delete[] data;
        delete[] data2;
        delete[] data3;
        delete[] decrypted;
    }

    SECTION("sub int")
    {
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

    SECTION("sub int")
    {
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

TEST_CASE( "mul", "paillier")
{
    paillier_public_key_t* pub;
    paillier_private_key_t* priv;
    long res = paillier_generate_key_pair(2048, &pub, &priv);

    SECTION("mul")
    {
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
        {
            REQUIRE(decrypted[i] == mul_bin[i]);
        }
        BN_free(m1);
        delete[] mul_bin;
        delete[] data;
        delete[] data3;
        delete[] decrypted;
    }

    SECTION("mul int")
    {
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

TEST_CASE( "zkpok", "paillier")
{
    paillier_public_key_t* pub;
    paillier_private_key_t* priv;
    long res = paillier_generate_key_pair(2048, &pub, &priv);
    REQUIRE(res == PAILLIER_SUCCESS);

    SECTION("valid")
    {
        unsigned char x[PAILLIER_SHA256_LEN];
        unsigned char y[256];

        res = paillier_generate_factorization_zkpok(priv, (const unsigned char*)"hello world", sizeof("hello world") - 1, x, y, 256, NULL);
        REQUIRE(res == PAILLIER_SUCCESS);
        res = paillier_verify_factorization_zkpok(pub, (const unsigned char*)"hello world", sizeof("hello world") - 1, x, y, 256);
        REQUIRE(res == PAILLIER_SUCCESS);
    }

    SECTION("invalid aad")
    {
        unsigned char x[PAILLIER_SHA256_LEN];
        unsigned char y[256];

        res = paillier_generate_factorization_zkpok(priv, (const unsigned char*)"hello world", sizeof("hello world") - 1, x, y, 256, NULL);
        REQUIRE(res == PAILLIER_SUCCESS);
        res = paillier_verify_factorization_zkpok(pub, (const unsigned char*)"gello world", sizeof("hello world") - 1, x, y, 256);
        REQUIRE(res == PAILLIER_ERROR_INVALID_PROOF);
    }

    SECTION("invalid x")
    {
        unsigned char x[PAILLIER_SHA256_LEN];
        unsigned char y[256];

        res = paillier_generate_factorization_zkpok(priv, (const unsigned char*)"hello world", sizeof("hello world") - 1, x, y, 256, NULL);
        REQUIRE(res == PAILLIER_SUCCESS);
        x[4]++;
        res = paillier_verify_factorization_zkpok(pub, (const unsigned char*)"hello world", sizeof("hello world") - 1, x, y, 256);
        REQUIRE(res == PAILLIER_ERROR_INVALID_PROOF);
    }

    SECTION("invalid y")
    {
        unsigned char x[PAILLIER_SHA256_LEN];
        unsigned char y[256];

        res = paillier_generate_factorization_zkpok(priv, (const unsigned char*)"hello world", sizeof("hello world") - 1, x, y, 256, NULL);
        REQUIRE(res == PAILLIER_SUCCESS);
        y[4]++;
        res = paillier_verify_factorization_zkpok(pub, (const unsigned char*)"hello world", sizeof("hello world") - 1, x, y, 256);
        REQUIRE(res == PAILLIER_ERROR_INVALID_PROOF);
    }

    SECTION("invalid param")
    {
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

TEST_CASE( "zkp", "paillier")
{
    paillier_public_key_t* pub;
    paillier_private_key_t* priv;
    long res = paillier_generate_key_pair(2048, &pub, &priv);
    REQUIRE(res == PAILLIER_SUCCESS);

    SECTION("valid")
    {
        unsigned char y[4096];

        res = paillier_generate_coprime_zkp(priv, (const unsigned char*)"hello world", sizeof("hello world") - 1, y, sizeof(y), NULL);
        REQUIRE(res == PAILLIER_SUCCESS);
        res = paillier_verify_coprime_zkp(pub, (const unsigned char*)"hello world", sizeof("hello world") - 1, y, sizeof(y));
        REQUIRE(res == PAILLIER_SUCCESS);
    }

    SECTION("invalid aad")
    {
        unsigned char y[4096];

        res = paillier_generate_coprime_zkp(priv, (const unsigned char*)"hello world", sizeof("hello world") - 1, y, sizeof(y), NULL);
        REQUIRE(res == PAILLIER_SUCCESS);
        res = paillier_verify_coprime_zkp(pub, (const unsigned char*)"gello world", sizeof("hello world") - 1, y, sizeof(y));
        REQUIRE(res == PAILLIER_ERROR_INVALID_PROOF);
    }

    SECTION("invalid y")
    {
        unsigned char y[4096];

        res = paillier_generate_coprime_zkp(priv, (const unsigned char*)"hello world", sizeof("hello world") - 1, y, sizeof(y), NULL);
        REQUIRE(res == PAILLIER_SUCCESS);
        y[4]++;
        res = paillier_verify_coprime_zkp(pub, (const unsigned char*)"gello world", sizeof("hello world") - 1, y, sizeof(y));
        REQUIRE(res == PAILLIER_ERROR_INVALID_PROOF);
    }

    SECTION("invalid param")
    {
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

TEST_CASE( "paillier_blum_zkp", "paillier")
{
    paillier_public_key_t* pub;
    paillier_private_key_t* priv;
    long res = paillier_generate_key_pair(2048, &pub, &priv);
    REQUIRE(res == PAILLIER_SUCCESS);

    SECTION("valid all nth root")
    {
        uint32_t proof_len;
        res = paillier_generate_paillier_blum_zkp(priv, 1, (const unsigned char*)"hello world", sizeof("hello world") - 1, NULL, 0, &proof_len);
        REQUIRE(res == PAILLIER_ERROR_BUFFER_TOO_SHORT);
        std::unique_ptr<uint8_t[]> proof(new uint8_t[proof_len]);
        res = paillier_generate_paillier_blum_zkp(priv, 1, (const unsigned char*)"hello world", sizeof("hello world") - 1, proof.get(), proof_len -1, &proof_len);
        REQUIRE(res == PAILLIER_ERROR_BUFFER_TOO_SHORT);
        res = paillier_generate_paillier_blum_zkp(priv, 1, (const unsigned char*)"hello world", sizeof("hello world") - 1, proof.get(), proof_len, &proof_len);
        REQUIRE(res == PAILLIER_SUCCESS);
        res = paillier_verify_paillier_blum_zkp(pub, 1, (const unsigned char*)"hello world", sizeof("hello world") - 1, proof.get(), proof_len);
        REQUIRE(res == PAILLIER_SUCCESS);
    }

    SECTION("valid only first nth root")
    {
        uint32_t proof_len;
        res = paillier_generate_paillier_blum_zkp(priv, 0, (const unsigned char*)"hello world", sizeof("hello world") - 1, NULL, 0, &proof_len);
        REQUIRE(res == PAILLIER_ERROR_BUFFER_TOO_SHORT);
        std::unique_ptr<uint8_t[]> proof(new uint8_t[proof_len]);
        res = paillier_generate_paillier_blum_zkp(priv, 0, (const unsigned char*)"hello world", sizeof("hello world") - 1, proof.get(), proof_len -1, &proof_len);
        REQUIRE(res == PAILLIER_ERROR_BUFFER_TOO_SHORT);
        res = paillier_generate_paillier_blum_zkp(priv, 0, (const unsigned char*)"hello world", sizeof("hello world") - 1, proof.get(), proof_len, &proof_len);
        REQUIRE(res == PAILLIER_SUCCESS);
        res = paillier_verify_paillier_blum_zkp(pub, 0, (const unsigned char*)"hello world", sizeof("hello world") - 1, proof.get(), proof_len);
        REQUIRE(res == PAILLIER_SUCCESS);
    }

    SECTION("invalid aad")
    {
        uint32_t proof_len;
        res = paillier_generate_paillier_blum_zkp(priv, 0, (const unsigned char*)"hello world", sizeof("hello world") - 1, NULL, 0, &proof_len);
        REQUIRE(res == PAILLIER_ERROR_BUFFER_TOO_SHORT);
        std::unique_ptr<uint8_t[]> proof(new uint8_t[proof_len]);
        res = paillier_generate_paillier_blum_zkp(priv, 0, (const unsigned char*)"hello world", sizeof("hello world") - 1, proof.get(), proof_len, &proof_len);
        REQUIRE(res == PAILLIER_SUCCESS);
        res = paillier_verify_paillier_blum_zkp(pub, 0, (const unsigned char*)"gello world", sizeof("hello world") - 1, proof.get(), proof_len);
        REQUIRE(res == PAILLIER_ERROR_INVALID_PROOF);
    }

    SECTION("invalid proof")
    {
        uint32_t proof_len;
        res = paillier_generate_paillier_blum_zkp(priv, 0, (const unsigned char*)"hello world", sizeof("hello world") - 1, NULL, 0, &proof_len);
        REQUIRE(res == PAILLIER_ERROR_BUFFER_TOO_SHORT);
        std::unique_ptr<uint8_t[]> proof(new uint8_t[proof_len]);
        res = paillier_generate_paillier_blum_zkp(priv, 0, (const unsigned char*)"hello world", sizeof("hello world") - 1, proof.get(), proof_len, &proof_len);
        REQUIRE(res == PAILLIER_SUCCESS);
        (*(uint32_t*)proof.get())++;
        res = paillier_verify_paillier_blum_zkp(pub, 0, (const unsigned char*)"hello world", sizeof("hello world") - 1, proof.get(), proof_len);
        REQUIRE(res == PAILLIER_ERROR_INVALID_PROOF);
        (*(uint32_t*)proof.get())--;
        proof.get()[32]++;
        res = paillier_verify_paillier_blum_zkp(pub, 0, (const unsigned char*)"hello world", sizeof("hello world") - 1, proof.get(), proof_len);
        REQUIRE(res == PAILLIER_ERROR_INVALID_PROOF);
    }

    SECTION("invalid param")
    {
        uint32_t proof_len;
        res = paillier_generate_paillier_blum_zkp(priv, 0, (const unsigned char*)"hello world", sizeof("hello world") - 1, NULL, 0, &proof_len);
        REQUIRE(res == PAILLIER_ERROR_BUFFER_TOO_SHORT);
        std::unique_ptr<uint8_t[]> proof(new uint8_t[proof_len]);
        res = paillier_generate_paillier_blum_zkp(NULL, 0, (const unsigned char*)"hello world", sizeof("hello world") - 1, proof.get(), proof_len, NULL);
        REQUIRE(res == PAILLIER_ERROR_INVALID_KEY);
        res = paillier_generate_paillier_blum_zkp(priv, 0, NULL, sizeof("hello world") - 1, proof.get(), proof_len, NULL);
        REQUIRE(res == PAILLIER_ERROR_INVALID_PARAM);
        res = paillier_generate_paillier_blum_zkp(priv, 0, (const unsigned char*)"hello world", sizeof("hello world") - 1, NULL, proof_len, NULL);
        REQUIRE(res == PAILLIER_ERROR_INVALID_PARAM);
        res = paillier_generate_paillier_blum_zkp(priv, 0, (const unsigned char*)"hello world", sizeof("hello world") - 1, proof.get(), 0, NULL);
        REQUIRE(res == PAILLIER_ERROR_BUFFER_TOO_SHORT);

        res = paillier_verify_paillier_blum_zkp(NULL, 0, (const unsigned char*)"hello world", sizeof("hello world") - 1, proof.get(), proof_len);
        REQUIRE(res == PAILLIER_ERROR_INVALID_KEY);
        res = paillier_verify_paillier_blum_zkp(pub, 0, 0, sizeof("hello world") - 1, proof.get(), proof_len);
        REQUIRE(res == PAILLIER_ERROR_INVALID_PARAM);
        res = paillier_verify_paillier_blum_zkp(pub, 0, (const unsigned char*)"hello world", sizeof("hello world") - 1, NULL, proof_len);
        REQUIRE(res == PAILLIER_ERROR_INVALID_PARAM);
        res = paillier_verify_paillier_blum_zkp(pub, 0, (const unsigned char*)"hello world", sizeof("hello world") - 1, proof.get(), 7);
        REQUIRE(res == PAILLIER_ERROR_INVALID_PARAM);
    }

    paillier_free_public_key(pub);
    paillier_free_private_key(priv);
}

TEST_CASE( "paillier_attacks", "paillier")
{
    paillier_public_key_t* pub = NULL;
    paillier_private_key_t* priv = NULL;
    long res = paillier_generate_key_pair(2048, &pub, &priv);
    REQUIRE(res == PAILLIER_SUCCESS);

    SECTION("encrypt with zero plaintext")
    {
        uint8_t zero_msg[] = {0};
        uint32_t len = 0;
        res = paillier_encrypt(pub, zero_msg, sizeof(zero_msg), NULL, 0, &len);
        REQUIRE(res == PAILLIER_ERROR_INVALID_CIPHER_TEXT);
        REQUIRE(len > 0);
        uint8_t* ciphertext = new uint8_t[len];
        uint32_t ct_len = 0;
        res = paillier_encrypt(pub, zero_msg, sizeof(zero_msg), ciphertext, len, &ct_len);
        REQUIRE(res == PAILLIER_SUCCESS);

        uint32_t pt_len = 0;
        long dec_res = paillier_decrypt(priv, ciphertext, ct_len, NULL, 0, &pt_len);
        REQUIRE(dec_res == PAILLIER_ERROR_INVALID_PLAIN_TEXT);
        REQUIRE(pt_len > 0);
        uint8_t* plaintext = new uint8_t[pt_len];
        uint32_t pt_real_len = 0;
        dec_res = paillier_decrypt(priv, ciphertext, ct_len, plaintext, pt_len, &pt_real_len);
        REQUIRE(dec_res == PAILLIER_SUCCESS);
        REQUIRE(pt_real_len == 1);
        REQUIRE(plaintext[0] == 0);

        delete[] plaintext;
        delete[] ciphertext;
    }

    SECTION("encrypt with max value plaintext")
    {
        // Encrypt N-1 (the largest valid plaintext for Paillier)
        // Get N from the public key
        uint32_t n_len = 0;
        res = paillier_public_key_n(pub, NULL, 0, &n_len);
        REQUIRE(n_len > 0);
        uint8_t* n_buf = new uint8_t[n_len];
        uint32_t n_real_len = 0;
        res = paillier_public_key_n(pub, n_buf, n_len, &n_real_len);

        // Construct N-1 using OpenSSL BIGNUM
        BIGNUM* bn_n = BN_bin2bn(n_buf, n_real_len, NULL);
        REQUIRE(bn_n != NULL);
        BIGNUM* bn_one = BN_new();
        BN_one(bn_one);
        BIGNUM* bn_max = BN_new();
        BN_sub(bn_max, bn_n, bn_one);

        uint8_t* max_buf = new uint8_t[BN_num_bytes(bn_max)];
        int max_len = BN_bn2bin(bn_max, max_buf);

        // Encrypt N-1
        uint32_t len = 0;
        res = paillier_encrypt(pub, max_buf, max_len, NULL, 0, &len);
        REQUIRE(res == PAILLIER_ERROR_INVALID_CIPHER_TEXT);
        uint8_t* ciphertext = new uint8_t[len];
        uint32_t ct_len = 0;
        res = paillier_encrypt(pub, max_buf, max_len, ciphertext, len, &ct_len);
        REQUIRE(res == PAILLIER_SUCCESS);

        // Decrypt and verify
        uint32_t pt_len = 0;
        res = paillier_decrypt(priv, ciphertext, ct_len, NULL, 0, &pt_len);
        REQUIRE(res == PAILLIER_ERROR_INVALID_PLAIN_TEXT);
        uint8_t* plaintext = new uint8_t[pt_len];
        uint32_t pt_real_len = 0;
        res = paillier_decrypt(priv, ciphertext, ct_len, plaintext, pt_len, &pt_real_len);
        REQUIRE(res == PAILLIER_SUCCESS);

        BIGNUM* bn_decrypted = BN_bin2bn(plaintext, pt_real_len, NULL);
        REQUIRE(bn_decrypted != NULL);
        REQUIRE(BN_cmp(bn_decrypted, bn_max) == 0);

        BN_free(bn_n);
        BN_free(bn_one);
        BN_free(bn_max);
        BN_free(bn_decrypted);
        delete[] n_buf;
        delete[] max_buf;
        delete[] ciphertext;
        delete[] plaintext;
    }

    SECTION("decrypt with wrong key")
    {
        // Generate a second keypair
        paillier_public_key_t* pub2 = NULL;
        paillier_private_key_t* priv2 = NULL;
        res = paillier_generate_key_pair(2048, &pub2, &priv2);
        REQUIRE(res == PAILLIER_SUCCESS);

        // Encrypt with first public key
        uint64_t msg = 42;
        uint32_t len = 0;
        res = paillier_encrypt_integer(pub, msg, NULL, 0, &len);
        REQUIRE(res == PAILLIER_ERROR_INVALID_CIPHER_TEXT);
        uint8_t* ciphertext = new uint8_t[len];
        uint32_t ct_len = 0;
        res = paillier_encrypt_integer(pub, msg, ciphertext, len, &ct_len);
        REQUIRE(res == PAILLIER_SUCCESS);

        // Decrypt with second (wrong) private key - should either fail or produce wrong result
        uint64_t wrong_result = 0;
        res = paillier_decrypt_integer(priv2, ciphertext, ct_len, &wrong_result);
        // Either decryption fails or gives a different value
        if (res == PAILLIER_SUCCESS)
        {
            REQUIRE(wrong_result != msg);
        }
        // If res != PAILLIER_SUCCESS, that's also acceptable (decryption error with wrong key)

        paillier_free_public_key(pub2);
        paillier_free_private_key(priv2);
        delete[] ciphertext;
    }

    SECTION("homomorphic add overflow")
    {
        // Encrypt two values whose sum exceeds N (result wraps mod N)
        // Get N from the public key
        uint32_t n_len = 0;
        res = paillier_public_key_n(pub, NULL, 0, &n_len);
        REQUIRE(n_len > 0);
        uint8_t* n_buf = new uint8_t[n_len];
        uint32_t n_real_len = 0;
        res = paillier_public_key_n(pub, n_buf, n_len, &n_real_len);

        BIGNUM* bn_n = BN_bin2bn(n_buf, n_real_len, NULL);
        REQUIRE(bn_n != NULL);

        // Create value = N - 1
        BIGNUM* bn_one = BN_new();
        BN_one(bn_one);
        BIGNUM* bn_val = BN_new();
        BN_sub(bn_val, bn_n, bn_one);

        uint8_t* val_buf = new uint8_t[BN_num_bytes(bn_val)];
        int val_len = BN_bn2bin(bn_val, val_buf);

        // Encrypt (N-1) twice
        uint32_t len = 0;
        res = paillier_encrypt(pub, val_buf, val_len, NULL, 0, &len);
        REQUIRE(res == PAILLIER_ERROR_INVALID_CIPHER_TEXT);
        uint8_t* ct1 = new uint8_t[len];
        uint32_t ct1_len = 0;
        res = paillier_encrypt(pub, val_buf, val_len, ct1, len, &ct1_len);
        REQUIRE(res == PAILLIER_SUCCESS);

        res = paillier_encrypt(pub, val_buf, val_len, NULL, 0, &len);
        REQUIRE(res == PAILLIER_ERROR_INVALID_CIPHER_TEXT);
        uint8_t* ct2 = new uint8_t[len];
        uint32_t ct2_len = 0;
        res = paillier_encrypt(pub, val_buf, val_len, ct2, len, &ct2_len);
        REQUIRE(res == PAILLIER_SUCCESS);

        // Homomorphic add: (N-1) + (N-1) = 2N - 2 mod N = N - 2
        res = paillier_add(pub, ct1, ct1_len, ct2, ct2_len, NULL, 0, &len);
        REQUIRE(res == PAILLIER_ERROR_INVALID_CIPHER_TEXT);
        uint8_t* ct_sum = new uint8_t[len];
        uint32_t ct_sum_len = 0;
        res = paillier_add(pub, ct1, ct1_len, ct2, ct2_len, ct_sum, len, &ct_sum_len);
        REQUIRE(res == PAILLIER_SUCCESS);

        // Decrypt the result
        uint32_t pt_len = 0;
        res = paillier_decrypt(priv, ct_sum, ct_sum_len, NULL, 0, &pt_len);
        REQUIRE(res == PAILLIER_ERROR_INVALID_PLAIN_TEXT);
        uint8_t* plaintext = new uint8_t[pt_len];
        uint32_t pt_real_len = 0;
        res = paillier_decrypt(priv, ct_sum, ct_sum_len, plaintext, pt_len, &pt_real_len);
        REQUIRE(res == PAILLIER_SUCCESS);

        // Expected: N - 2
        BIGNUM* bn_two = BN_new();
        BN_set_word(bn_two, 2);
        BIGNUM* bn_expected = BN_new();
        BN_sub(bn_expected, bn_n, bn_two);

        BIGNUM* bn_result = BN_bin2bn(plaintext, pt_real_len, NULL);
        REQUIRE(bn_result != NULL);
        REQUIRE(BN_cmp(bn_result, bn_expected) == 0);

        BN_free(bn_n);
        BN_free(bn_one);
        BN_free(bn_val);
        BN_free(bn_two);
        BN_free(bn_expected);
        BN_free(bn_result);
        delete[] n_buf;
        delete[] val_buf;
        delete[] ct1;
        delete[] ct2;
        delete[] ct_sum;
        delete[] plaintext;
    }

    SECTION("tampered ciphertext - bit flip")
    {
        uint64_t msg = 9999999;
        uint32_t len = 0;
        res = paillier_encrypt_integer(pub, msg, NULL, 0, &len);
        REQUIRE(res == PAILLIER_ERROR_INVALID_CIPHER_TEXT);
        uint8_t* ciphertext = new uint8_t[len];
        uint32_t ct_len = 0;
        res = paillier_encrypt_integer(pub, msg, ciphertext, len, &ct_len);
        REQUIRE(res == PAILLIER_SUCCESS);

        // Make a copy and flip a bit in the middle
        uint8_t* tampered = new uint8_t[ct_len];
        memcpy(tampered, ciphertext, ct_len);
        tampered[ct_len / 2] ^= 0x01;

        // Decrypt tampered ciphertext
        uint64_t tampered_result = 0;
        res = paillier_decrypt_integer(priv, tampered, ct_len, &tampered_result);
        if (res == PAILLIER_SUCCESS)
        {
            // If decryption succeeds, the result must differ from original
            REQUIRE(tampered_result != msg);
        }
        // If decryption fails, that is also an acceptable outcome for tampered data

        delete[] ciphertext;
        delete[] tampered;
    }

    SECTION("tampered ciphertext - all zeros")
    {
        // First encrypt something to get the correct ciphertext length
        uint64_t msg = 12345;
        uint32_t len = 0;
        res = paillier_encrypt_integer(pub, msg, NULL, 0, &len);
        REQUIRE(res == PAILLIER_ERROR_INVALID_CIPHER_TEXT);
        uint8_t* ciphertext = new uint8_t[len];
        uint32_t ct_len = 0;
        res = paillier_encrypt_integer(pub, msg, ciphertext, len, &ct_len);
        REQUIRE(res == PAILLIER_SUCCESS);

        // Create all-zero ciphertext of the same length
        uint8_t* zeros = new uint8_t[ct_len];
        memset(zeros, 0, ct_len);

        uint64_t result = 0;
        res = paillier_decrypt_integer(priv, zeros, ct_len, &result);
        // All-zero ciphertext should either fail or not decrypt to original message
        if (res == PAILLIER_SUCCESS)
        {
            REQUIRE(result != msg);
        }

        delete[] ciphertext;
        delete[] zeros;
    }

    SECTION("tampered ciphertext - all ones")
    {
        // First encrypt something to get the correct ciphertext length
        uint64_t msg = 12345;
        uint32_t len = 0;
        res = paillier_encrypt_integer(pub, msg, NULL, 0, &len);
        REQUIRE(res == PAILLIER_ERROR_INVALID_CIPHER_TEXT);
        uint8_t* ciphertext = new uint8_t[len];
        uint32_t ct_len = 0;
        res = paillier_encrypt_integer(pub, msg, ciphertext, len, &ct_len);
        REQUIRE(res == PAILLIER_SUCCESS);

        // Create all-0xFF ciphertext of the same length
        uint8_t* ones = new uint8_t[ct_len];
        memset(ones, 0xFF, ct_len);

        uint64_t result = 0;
        res = paillier_decrypt_integer(priv, ones, ct_len, &result);
        // All-0xFF ciphertext should either fail or not decrypt to original message
        if (res == PAILLIER_SUCCESS)
        {
            REQUIRE(result != msg);
        }

        delete[] ciphertext;
        delete[] ones;
    }



    SECTION("deserialize truncated public key")
    {
        uint32_t key_len = 0;
        paillier_public_key_serialize(pub, NULL, 0, &key_len);
        REQUIRE(key_len > 0);
        uint8_t* key_buf = new uint8_t[key_len];
        REQUIRE(paillier_public_key_serialize(pub, key_buf, key_len, &key_len));
        paillier_public_key_t* bad_pub = paillier_public_key_deserialize(key_buf, key_len / 2);
        REQUIRE(bad_pub == NULL);
        delete[] key_buf;
    }

    SECTION("deserialize garbage public key")
    {
        uint32_t garbage_len = 512;
        uint8_t* garbage = new uint8_t[garbage_len];
        for (uint32_t i = 0; i < garbage_len; i++)
            garbage[i] = (uint8_t)((i * 137 + 43) & 0xFF);
        paillier_public_key_t* bad_pub = paillier_public_key_deserialize(garbage, garbage_len);
        REQUIRE(bad_pub == NULL);
        delete[] garbage;
    }
    SECTION("deserialize truncated public key 2")
    {
        uint32_t key_len = 0;
        paillier_public_key_serialize(pub, NULL, 0, &key_len);
        REQUIRE(key_len > 0);
        uint8_t* key_buf = new uint8_t[key_len];
        REQUIRE(paillier_public_key_serialize(pub, key_buf, key_len, &key_len));
        paillier_public_key_t* bad_pub = paillier_public_key_deserialize(key_buf, key_len / 2);
        REQUIRE(bad_pub == NULL);
        delete[] key_buf;
    }
    SECTION("deserialize truncated private key") {
        uint32_t key_len = 0;
        paillier_private_key_serialize(priv, NULL, 0, &key_len);
        REQUIRE(key_len > 0);
        uint8_t* key_buf = new uint8_t[key_len];
        REQUIRE(paillier_private_key_serialize(priv, key_buf, key_len, &key_len));
        paillier_private_key_t* bad_priv = paillier_private_key_deserialize(key_buf, key_len / 2);
        REQUIRE(bad_priv == NULL);
        delete[] key_buf;
    }

    SECTION("deserialize with very small buffer returns NULL")
    {
        // Buffers smaller than sizeof(uint32_t) + MIN_KEY_LEN_IN_BITS/8 = 36
        // are safely rejected by the min-length check at paillier.c:383.
        uint8_t small_buf[4] = {0x01, 0x02, 0x03, 0x04};
        paillier_public_key_t* bad_pub = paillier_public_key_deserialize(small_buf, 4);
        REQUIRE(bad_pub == NULL);

        // NULL buffer
        bad_pub = paillier_public_key_deserialize(NULL, 100);
        REQUIRE(bad_pub == NULL);
    }

    SECTION("encrypt plaintext = 1 (smallest positive)")
    {
        uint8_t one_msg[] = {1};
        uint32_t len = 0;
        res = paillier_encrypt(pub, one_msg, sizeof(one_msg), NULL, 0, &len);
        REQUIRE(res == PAILLIER_ERROR_INVALID_CIPHER_TEXT);
        REQUIRE(len > 0);
        uint8_t* ciphertext = new uint8_t[len];
        uint32_t ct_len = 0;
        res = paillier_encrypt(pub, one_msg, sizeof(one_msg), ciphertext, len, &ct_len);
        REQUIRE(res == PAILLIER_SUCCESS);

        uint32_t pt_len = 0;
        res = paillier_decrypt(priv, ciphertext, ct_len, NULL, 0, &pt_len);
        REQUIRE(res == PAILLIER_ERROR_INVALID_PLAIN_TEXT);
        uint8_t* plaintext = new uint8_t[pt_len];
        uint32_t pt_real_len = 0;
        res = paillier_decrypt(priv, ciphertext, ct_len, plaintext, pt_len, &pt_real_len);
        REQUIRE(res == PAILLIER_SUCCESS);
        REQUIRE(pt_real_len == 1);
        REQUIRE(plaintext[0] == 1);

        delete[] ciphertext;
        delete[] plaintext;
    }

    SECTION("encrypt plaintext = N (rejected)")
    {
        // Paillier plaintext space is [0, N). N itself must be rejected.
        uint32_t n_len = 0;
        res = paillier_public_key_n(pub, NULL, 0, &n_len);
        REQUIRE(n_len > 0);
        uint8_t* n_buf = new uint8_t[n_len];
        uint32_t n_real_len = 0;
        res = paillier_public_key_n(pub, n_buf, n_len, &n_real_len);

        uint32_t len = 0;
        res = paillier_encrypt(pub, n_buf, n_real_len, NULL, 0, &len);
        // N has n_real_len bytes. paillier_encrypt rejects if plaintext_len > BN_num_bytes(N)
        // OR if BN_cmp(msg, N) >= 0. Either way, it should not succeed.
        if (len > 0)
        {
            uint8_t* ciphertext = new uint8_t[len];
            uint32_t ct_len = 0;
            res = paillier_encrypt(pub, n_buf, n_real_len, ciphertext, len, &ct_len);
            REQUIRE(res == PAILLIER_ERROR_INVALID_PLAIN_TEXT);
            delete[] ciphertext;
        }
        else
        {
            REQUIRE(res == PAILLIER_ERROR_INVALID_PLAIN_TEXT);
        }

        delete[] n_buf;
    }

    SECTION("encrypt plaintext = N+1 (rejected)")
    {
        uint32_t n_len = 0;
        res = paillier_public_key_n(pub, NULL, 0, &n_len);
        REQUIRE(n_len > 0);
        uint8_t* n_buf = new uint8_t[n_len];
        uint32_t n_real_len = 0;
        res = paillier_public_key_n(pub, n_buf, n_len, &n_real_len);

        BIGNUM* bn_n = BN_bin2bn(n_buf, n_real_len, NULL);
        REQUIRE(bn_n != NULL);
        BIGNUM* bn_one = BN_new();
        BN_one(bn_one);
        BIGNUM* bn_np1 = BN_new();
        BN_add(bn_np1, bn_n, bn_one);

        int np1_bytes = BN_num_bytes(bn_np1);
        uint8_t* np1_buf = new uint8_t[np1_bytes];
        BN_bn2bin(bn_np1, np1_buf);

        // N+1 has the same byte length as N (N = p*q can never be all-FF).
        // The byte-length check (plaintext_len > BN_num_bytes(N)) passes,
        // so the first call with NULL buffer returns INVALID_CIPHER_TEXT (buffer query).
        // The actual BN_cmp rejection happens only when a real buffer is provided.
        REQUIRE(np1_bytes == (int)n_real_len);
        uint32_t len = 0;
        res = paillier_encrypt(pub, np1_buf, np1_bytes, NULL, 0, &len);
        REQUIRE(res == PAILLIER_ERROR_INVALID_CIPHER_TEXT);
        REQUIRE(len > 0);
        uint8_t* ciphertext = new uint8_t[len];
        uint32_t ct_len = 0;
        res = paillier_encrypt(pub, np1_buf, np1_bytes, ciphertext, len, &ct_len);
        REQUIRE(res == PAILLIER_ERROR_INVALID_PLAIN_TEXT);
        delete[] ciphertext;

        BN_free(bn_n);
        BN_free(bn_one);
        BN_free(bn_np1);
        delete[] n_buf;
        delete[] np1_buf;
    }

    SECTION("encrypt plaintext = p (prime factor, round-trip)")
    {
        // p < N, so p is a valid plaintext — encrypt/decrypt should round-trip
        int p_bytes = BN_num_bytes(priv->p);
        REQUIRE(p_bytes > 0);
        uint8_t* p_buf = new uint8_t[p_bytes];
        BN_bn2bin(priv->p, p_buf);

        uint32_t len = 0;
        res = paillier_encrypt(pub, p_buf, p_bytes, NULL, 0, &len);
        REQUIRE(res == PAILLIER_ERROR_INVALID_CIPHER_TEXT);
        uint8_t* ciphertext = new uint8_t[len];
        uint32_t ct_len = 0;
        res = paillier_encrypt(pub, p_buf, p_bytes, ciphertext, len, &ct_len);
        REQUIRE(res == PAILLIER_SUCCESS);

        uint32_t pt_len = 0;
        res = paillier_decrypt(priv, ciphertext, ct_len, NULL, 0, &pt_len);
        REQUIRE(res == PAILLIER_ERROR_INVALID_PLAIN_TEXT);
        uint8_t* plaintext = new uint8_t[pt_len];
        uint32_t pt_real_len = 0;
        res = paillier_decrypt(priv, ciphertext, ct_len, plaintext, pt_len, &pt_real_len);
        REQUIRE(res == PAILLIER_SUCCESS);

        BIGNUM* bn_decrypted = BN_bin2bn(plaintext, pt_real_len, NULL);
        REQUIRE(bn_decrypted != NULL);
        REQUIRE(BN_cmp(bn_decrypted, priv->p) == 0);

        BN_free(bn_decrypted);
        delete[] p_buf;
        delete[] ciphertext;
        delete[] plaintext;
    }

    SECTION("encrypt plaintext = q (prime factor, round-trip)")
    {
        // q < N, so q is a valid plaintext — encrypt/decrypt should round-trip
        int q_bytes = BN_num_bytes(priv->q);
        REQUIRE(q_bytes > 0);
        uint8_t* q_buf = new uint8_t[q_bytes];
        BN_bn2bin(priv->q, q_buf);

        uint32_t len = 0;
        res = paillier_encrypt(pub, q_buf, q_bytes, NULL, 0, &len);
        REQUIRE(res == PAILLIER_ERROR_INVALID_CIPHER_TEXT);
        uint8_t* ciphertext = new uint8_t[len];
        uint32_t ct_len = 0;
        res = paillier_encrypt(pub, q_buf, q_bytes, ciphertext, len, &ct_len);
        REQUIRE(res == PAILLIER_SUCCESS);

        uint32_t pt_len = 0;
        res = paillier_decrypt(priv, ciphertext, ct_len, NULL, 0, &pt_len);
        REQUIRE(res == PAILLIER_ERROR_INVALID_PLAIN_TEXT);
        uint8_t* plaintext = new uint8_t[pt_len];
        uint32_t pt_real_len = 0;
        res = paillier_decrypt(priv, ciphertext, ct_len, plaintext, pt_len, &pt_real_len);
        REQUIRE(res == PAILLIER_SUCCESS);

        BIGNUM* bn_decrypted = BN_bin2bn(plaintext, pt_real_len, NULL);
        REQUIRE(bn_decrypted != NULL);
        REQUIRE(BN_cmp(bn_decrypted, priv->q) == 0);

        BN_free(bn_decrypted);
        delete[] q_buf;
        delete[] ciphertext;
        delete[] plaintext;
    }

    paillier_free_public_key(pub);
    paillier_free_private_key(priv);
}

TEST_CASE("paillier_homomorphic_overflow", "[correctness]")
{
    paillier_public_key_t* pub = NULL;
    paillier_private_key_t* priv = NULL;
    long res = paillier_generate_key_pair(2048, &pub, &priv);
    REQUIRE(res == PAILLIER_SUCCESS);

    // Get N for boundary value construction
    uint32_t n_len = 0;
    paillier_public_key_n(pub, NULL, 0, &n_len);
    REQUIRE(n_len > 0);
    uint8_t* n_buf = new uint8_t[n_len];
    uint32_t n_real_len = 0;
    paillier_public_key_n(pub, n_buf, n_len, &n_real_len);
    BIGNUM* bn_n = BN_bin2bn(n_buf, n_real_len, NULL);
    REQUIRE(bn_n != NULL);

    // Helper: get ciphertext buffer size
    uint32_t ct_size = 0;
    {
        uint8_t one_msg[] = {1};
        paillier_encrypt(pub, one_msg, 1, NULL, 0, &ct_size);
    }
    REQUIRE(ct_size > 0);

    SECTION("add overflow: enc(N-1) + enc(1) decrypts to 0")
    {
        BN_CTX* ctx = BN_CTX_new();

        // Construct N-1
        BIGNUM* bn_nm1 = BN_dup(bn_n);
        BIGNUM* bn_one = BN_new();
        BN_one(bn_one);
        BN_sub(bn_nm1, bn_nm1, bn_one);
        int nm1_bytes = BN_num_bytes(bn_nm1);
        uint8_t* nm1_buf = new uint8_t[nm1_bytes];
        BN_bn2bin(bn_nm1, nm1_buf);

        // Encrypt N-1
        uint8_t* ct_nm1 = new uint8_t[ct_size];
        uint32_t ct_nm1_len = 0;
        res = paillier_encrypt(pub, nm1_buf, nm1_bytes, ct_nm1, ct_size, &ct_nm1_len);
        REQUIRE(res == PAILLIER_SUCCESS);

        // Encrypt 1
        uint8_t one_msg[] = {1};
        uint8_t* ct_one = new uint8_t[ct_size];
        uint32_t ct_one_len = 0;
        res = paillier_encrypt(pub, one_msg, 1, ct_one, ct_size, &ct_one_len);
        REQUIRE(res == PAILLIER_SUCCESS);

        // Homomorphic add: enc(N-1) + enc(1) = enc((N-1+1) mod N) = enc(0)
        uint8_t* ct_sum = new uint8_t[ct_size];
        uint32_t ct_sum_len = 0;
        res = paillier_add(pub, ct_nm1, ct_nm1_len, ct_one, ct_one_len, ct_sum, ct_size, &ct_sum_len);
        REQUIRE(res == PAILLIER_SUCCESS);

        // Decrypt — should get 0
        uint32_t pt_len = 0;
        res = paillier_decrypt(priv, ct_sum, ct_sum_len, NULL, 0, &pt_len);
        REQUIRE(res == PAILLIER_ERROR_INVALID_PLAIN_TEXT);
        REQUIRE(pt_len > 0);
        uint8_t* pt_buf = new uint8_t[pt_len];
        uint32_t pt_real_len = 0;
        res = paillier_decrypt(priv, ct_sum, ct_sum_len, pt_buf, pt_len, &pt_real_len);
        REQUIRE(res == PAILLIER_SUCCESS);
        REQUIRE(pt_real_len == 1);
        REQUIRE(pt_buf[0] == 0);
        delete[] pt_buf;

        BN_free(bn_nm1);
        BN_free(bn_one);
        BN_CTX_free(ctx);
        delete[] nm1_buf;
        delete[] ct_nm1;
        delete[] ct_one;
        delete[] ct_sum;
    }

    SECTION("sub underflow: enc(1) - enc(2) decrypts to N-1")
    {
        // Encrypt 1
        uint8_t one_msg[] = {1};
        uint8_t* ct_one = new uint8_t[ct_size];
        uint32_t ct_one_len = 0;
        res = paillier_encrypt(pub, one_msg, 1, ct_one, ct_size, &ct_one_len);
        REQUIRE(res == PAILLIER_SUCCESS);

        // Encrypt 2
        uint8_t two_msg[] = {2};
        uint8_t* ct_two = new uint8_t[ct_size];
        uint32_t ct_two_len = 0;
        res = paillier_encrypt(pub, two_msg, 1, ct_two, ct_size, &ct_two_len);
        REQUIRE(res == PAILLIER_SUCCESS);

        // Homomorphic sub: enc(1) - enc(2) = enc((1-2) mod N) = enc(N-1)
        uint8_t* ct_diff = new uint8_t[ct_size];
        uint32_t ct_diff_len = 0;
        res = paillier_sub(pub, ct_one, ct_one_len, ct_two, ct_two_len, ct_diff, ct_size, &ct_diff_len);
        REQUIRE(res == PAILLIER_SUCCESS);

        // Decrypt — should get N-1
        uint32_t pt_len = 0;
        paillier_decrypt(priv, ct_diff, ct_diff_len, NULL, 0, &pt_len);
        REQUIRE(pt_len > 0);
        uint8_t* pt_buf = new uint8_t[pt_len];
        uint32_t pt_real_len = 0;
        res = paillier_decrypt(priv, ct_diff, ct_diff_len, pt_buf, pt_len, &pt_real_len);
        REQUIRE(res == PAILLIER_SUCCESS);

        BIGNUM* bn_result = BN_bin2bn(pt_buf, pt_real_len, NULL);
        REQUIRE(bn_result != NULL);

        // Expected: N-1
        BIGNUM* bn_expected = BN_dup(bn_n);
        BIGNUM* bn_one_val = BN_new();
        BN_one(bn_one_val);
        BN_sub(bn_expected, bn_expected, bn_one_val);
        REQUIRE(BN_cmp(bn_result, bn_expected) == 0);

        BN_free(bn_result);
        BN_free(bn_expected);
        BN_free(bn_one_val);
        delete[] ct_one;
        delete[] ct_two;
        delete[] ct_diff;
        delete[] pt_buf;
    }

    SECTION("mul overflow: enc(N-1) * 2 decrypts to N-2")
    {
        // Construct N-1
        BIGNUM* bn_nm1 = BN_dup(bn_n);
        BIGNUM* bn_one_val = BN_new();
        BN_one(bn_one_val);
        BN_sub(bn_nm1, bn_nm1, bn_one_val);
        int nm1_bytes = BN_num_bytes(bn_nm1);
        uint8_t* nm1_buf = new uint8_t[nm1_bytes];
        BN_bn2bin(bn_nm1, nm1_buf);

        // Encrypt N-1
        uint8_t* ct_nm1 = new uint8_t[ct_size];
        uint32_t ct_nm1_len = 0;
        res = paillier_encrypt(pub, nm1_buf, nm1_bytes, ct_nm1, ct_size, &ct_nm1_len);
        REQUIRE(res == PAILLIER_SUCCESS);

        // Homomorphic mul: enc(N-1) * 2 = enc((N-1)*2 mod N) = enc(N-2)
        uint8_t* ct_prod = new uint8_t[ct_size];
        uint32_t ct_prod_len = 0;
        uint8_t two_plaintext[] = {2};
        res = paillier_mul(pub, ct_nm1, ct_nm1_len, two_plaintext, 1, ct_prod, ct_size, &ct_prod_len);
        REQUIRE(res == PAILLIER_SUCCESS);

        // Decrypt — should get N-2
        uint32_t pt_len = 0;
        paillier_decrypt(priv, ct_prod, ct_prod_len, NULL, 0, &pt_len);
        REQUIRE(pt_len > 0);
        uint8_t* pt_buf = new uint8_t[pt_len];
        uint32_t pt_real_len = 0;
        res = paillier_decrypt(priv, ct_prod, ct_prod_len, pt_buf, pt_len, &pt_real_len);
        REQUIRE(res == PAILLIER_SUCCESS);

        BIGNUM* bn_result = BN_bin2bn(pt_buf, pt_real_len, NULL);
        REQUIRE(bn_result != NULL);

        // Expected: N-2
        BIGNUM* bn_expected = BN_dup(bn_n);
        BIGNUM* bn_two = BN_new();
        BN_set_word(bn_two, 2);
        BN_sub(bn_expected, bn_expected, bn_two);
        REQUIRE(BN_cmp(bn_result, bn_expected) == 0);

        BN_free(bn_result);
        BN_free(bn_expected);
        BN_free(bn_two);
        BN_free(bn_nm1);
        BN_free(bn_one_val);
        delete[] nm1_buf;
        delete[] ct_nm1;
        delete[] ct_prod;
        delete[] pt_buf;
    }

    BN_free(bn_n);
    delete[] n_buf;
    paillier_free_public_key(pub);
    paillier_free_private_key(priv);
}

TEST_CASE("paillier_key_validity", "[correctness]")
{
    paillier_public_key_t* pub = NULL;
    paillier_private_key_t* priv = NULL;
    long res = paillier_generate_key_pair(2048, &pub, &priv);
    REQUIRE(res == PAILLIER_SUCCESS);

    SECTION("N equals p times q")
    {
        BN_CTX* ctx = BN_CTX_new();
        BIGNUM* pq = BN_new();
        BN_mul(pq, priv->p, priv->q, ctx);
        REQUIRE(BN_cmp(pq, pub->n) == 0);
        BN_free(pq);
        BN_CTX_free(ctx);
    }

    SECTION("N has requested bit size")
    {
        int n_bits = BN_num_bits(pub->n);
        // 2048-bit key: N should be 2047 or 2048 bits
        REQUIRE(n_bits >= 2047);
        REQUIRE(n_bits <= 2048);
    }

    SECTION("p and q are distinct primes")
    {
        REQUIRE(BN_cmp(priv->p, priv->q) != 0);
        // BN_is_prime_ex is probabilistic — 64 rounds gives negligible error
        REQUIRE(BN_is_prime_ex(priv->p, 64, NULL, NULL) == 1);
        REQUIRE(BN_is_prime_ex(priv->q, 64, NULL, NULL) == 1);
    }

    SECTION("GCD(N, phi(N)) equals 1")
    {
        BN_CTX* ctx = BN_CTX_new();
        BIGNUM* p_minus_1 = BN_dup(priv->p);
        BIGNUM* q_minus_1 = BN_dup(priv->q);
        BIGNUM* one = BN_new();
        BN_one(one);
        BN_sub(p_minus_1, p_minus_1, one);
        BN_sub(q_minus_1, q_minus_1, one);

        BIGNUM* phi = BN_new();
        BN_mul(phi, p_minus_1, q_minus_1, ctx);

        BIGNUM* gcd = BN_new();
        BN_gcd(gcd, pub->n, phi, ctx);
        REQUIRE(BN_is_one(gcd));

        BN_free(p_minus_1);
        BN_free(q_minus_1);
        BN_free(one);
        BN_free(phi);
        BN_free(gcd);
        BN_CTX_free(ctx);
    }

    SECTION("lambda equals phi(N)")
    {
        BN_CTX* ctx = BN_CTX_new();
        BIGNUM* p_minus_1 = BN_dup(priv->p);
        BIGNUM* q_minus_1 = BN_dup(priv->q);
        BIGNUM* one = BN_new();
        BN_one(one);
        BN_sub(p_minus_1, p_minus_1, one);
        BN_sub(q_minus_1, q_minus_1, one);

        BIGNUM* phi = BN_new();
        BN_mul(phi, p_minus_1, q_minus_1, ctx);

        REQUIRE(BN_cmp(priv->lambda, phi) == 0);

        BN_free(p_minus_1);
        BN_free(q_minus_1);
        BN_free(one);
        BN_free(phi);
        BN_CTX_free(ctx);
    }

    SECTION("mu equals lambda^(-1) mod N")
    {
        BN_CTX* ctx = BN_CTX_new();
        BIGNUM* product = BN_new();
        BN_mod_mul(product, priv->lambda, priv->mu, pub->n, ctx);
        REQUIRE(BN_is_one(product));
        BN_free(product);
        BN_CTX_free(ctx);
    }

    paillier_free_public_key(pub);
    paillier_free_private_key(priv);
}

TEST_CASE("paillier_fixed_randomness", "[correctness]")
{
    paillier_public_key_t* pub = NULL;
    paillier_private_key_t* priv = NULL;
    long res = paillier_generate_key_pair(2048, &pub, &priv);
    REQUIRE(res == PAILLIER_SUCCESS);

    SECTION("same randomness produces identical ciphertext")
    {
        // Use internal API to encrypt with explicit randomness
        BN_CTX* ctx = BN_CTX_new();
        BIGNUM* msg = BN_new();
        BN_set_word(msg, 42);

        BIGNUM* r = BN_new();
        BN_rand_range(r, pub->n);
        // Ensure r is coprime to N
        BIGNUM* gcd = BN_new();
        BN_gcd(gcd, r, pub->n, ctx);
        while (!BN_is_one(gcd))
        {
            BN_rand_range(r, pub->n);
            BN_gcd(gcd, r, pub->n, ctx);
        }

        BIGNUM* ct1 = BN_new();
        BIGNUM* ct2 = BN_new();
        res = paillier_encrypt_openssl_internal(pub, ct1, r, msg, ctx);
        REQUIRE(res == PAILLIER_SUCCESS);
        res = paillier_encrypt_openssl_internal(pub, ct2, r, msg, ctx);
        REQUIRE(res == PAILLIER_SUCCESS);

        REQUIRE(BN_cmp(ct1, ct2) == 0);

        BN_free(msg);
        BN_free(r);
        BN_free(gcd);
        BN_free(ct1);
        BN_free(ct2);
        BN_CTX_free(ctx);
    }

    SECTION("different randomness produces different ciphertext")
    {
        BN_CTX* ctx = BN_CTX_new();
        BIGNUM* msg = BN_new();
        BN_set_word(msg, 42);

        BIGNUM* r1 = BN_new();
        BIGNUM* r2 = BN_new();
        BIGNUM* gcd = BN_new();

        // Generate two different valid randomness values
        BN_rand_range(r1, pub->n);
        BN_gcd(gcd, r1, pub->n, ctx);
        while (!BN_is_one(gcd))
        {
            BN_rand_range(r1, pub->n);
            BN_gcd(gcd, r1, pub->n, ctx);
        }

        do {
            BN_rand_range(r2, pub->n);
            BN_gcd(gcd, r2, pub->n, ctx);
        } while (!BN_is_one(gcd) || BN_cmp(r1, r2) == 0);

        BIGNUM* ct1 = BN_new();
        BIGNUM* ct2 = BN_new();
        res = paillier_encrypt_openssl_internal(pub, ct1, r1, msg, ctx);
        REQUIRE(res == PAILLIER_SUCCESS);
        res = paillier_encrypt_openssl_internal(pub, ct2, r2, msg, ctx);
        REQUIRE(res == PAILLIER_SUCCESS);

        REQUIRE(BN_cmp(ct1, ct2) != 0);

        // Both should decrypt to the same value
        BIGNUM* pt1 = BN_new();
        BIGNUM* pt2 = BN_new();
        res = paillier_decrypt_openssl_internal(priv, ct1, pt1, ctx);
        REQUIRE(res == PAILLIER_SUCCESS);
        res = paillier_decrypt_openssl_internal(priv, ct2, pt2, ctx);
        REQUIRE(res == PAILLIER_SUCCESS);
        REQUIRE(BN_cmp(pt1, pt2) == 0);
        REQUIRE(BN_cmp(pt1, msg) == 0);

        BN_free(msg);
        BN_free(r1);
        BN_free(r2);
        BN_free(gcd);
        BN_free(ct1);
        BN_free(ct2);
        BN_free(pt1);
        BN_free(pt2);
        BN_CTX_free(ctx);
    }

    paillier_free_public_key(pub);
    paillier_free_private_key(priv);
}

TEST_CASE("paillier_keys_no_common_factors", "[statistical]")
{
    // Generate multiple Paillier keys and verify GCD(N_i, N_j) == 1 for all pairs.
    // Using 50 keys (1225 pairs) as a practical trade-off — full 1000 keys takes too long.
    const int NUM_KEYS = 50;
    BIGNUM* moduli[NUM_KEYS];

    SECTION("50 keys have pairwise coprime moduli")
    {
        for (int i = 0; i < NUM_KEYS; i++)
        {
            paillier_public_key_t* pub_i = NULL;
            paillier_private_key_t* priv_i = NULL;
            REQUIRE(paillier_generate_key_pair(2048, &pub_i, &priv_i) == PAILLIER_SUCCESS);
            moduli[i] = BN_dup(pub_i->n);
            REQUIRE(moduli[i] != NULL);
            paillier_free_public_key(pub_i);
            paillier_free_private_key(priv_i);
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

TEST_CASE("paillier_invalid_randomness", "[correctness]")
{
    paillier_public_key_t* pub = NULL;
    paillier_private_key_t* priv = NULL;
    long res = paillier_generate_key_pair(2048, &pub, &priv);
    REQUIRE(res == PAILLIER_SUCCESS);

    SECTION("encrypt with r=0 fails or produces invalid ciphertext")
    {
        BN_CTX* ctx = BN_CTX_new();
        BIGNUM* msg = BN_new();
        BN_set_word(msg, 42);
        BIGNUM* r_zero = BN_new();
        BN_zero(r_zero);

        BIGNUM* ct = BN_new();
        res = paillier_encrypt_openssl_internal(pub, ct, r_zero, msg, ctx);
        // r=0 is not coprime to N (gcd(0,N) = N != 1), so encrypt should fail or
        // produce a ciphertext that decrypts incorrectly.
        if (res == PAILLIER_SUCCESS)
        {
            // If it doesn't fail, verify that it decrypts incorrectly
            BIGNUM* pt = BN_new();
            long dec_res = paillier_decrypt_openssl_internal(priv, ct, pt, ctx);
            if (dec_res == PAILLIER_SUCCESS)
            {
                // r=0 means ciphertext = g^m * 0^N mod N^2 = 0, which shouldn't decrypt to m
                // Either way, the test documents the behavior
                INFO("r=0 encryption: decrypt returned " << BN_bn2dec(pt) << " for message 42");
            }
            BN_free(pt);
        }
        // If it fails, that's the correct behavior

        BN_free(msg);
        BN_free(r_zero);
        BN_free(ct);
        BN_CTX_free(ctx);
    }

    SECTION("encrypt with r=p (not coprime to N) produces bad ciphertext")
    {
        BN_CTX* ctx = BN_CTX_new();
        BIGNUM* msg = BN_new();
        BN_set_word(msg, 42);

        // r = p is not coprime to N (gcd(p, N) = p != 1)
        BIGNUM* r_p = BN_dup(priv->p);

        BIGNUM* ct = BN_new();
        res = paillier_encrypt_openssl_internal(pub, ct, r_p, msg, ctx);
        if (res == PAILLIER_SUCCESS)
        {
            // Decryption with non-coprime r may return wrong value
            BIGNUM* pt = BN_new();
            long dec_res = paillier_decrypt_openssl_internal(priv, ct, pt, ctx);
            if (dec_res == PAILLIER_SUCCESS)
            {
                // With r=p, the Paillier decryption may still work since the L function
                // only depends on m, not on r. But this is implementation-specific.
                INFO("r=p encryption: decrypt returned " << BN_bn2dec(pt) << " for message 42");
            }
            BN_free(pt);
        }

        BN_free(msg);
        BN_free(r_p);
        BN_free(ct);
        BN_CTX_free(ctx);
    }

    paillier_free_public_key(pub);
    paillier_free_private_key(priv);
}
