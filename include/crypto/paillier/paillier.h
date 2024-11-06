#ifndef __PAILLIER_H__
#define __PAILLIER_H__

#include "cosigner_export.h"

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif //__cplusplus

typedef struct paillier_public_key paillier_public_key_t;
typedef struct paillier_private_key paillier_private_key_t;
typedef struct paillier_ciphertext paillier_ciphertext_t;

#define PAILLIER_SUCCESS 0
#define PAILLIER_ERROR_UNKNOWN 1
#define PAILLIER_ERROR_KEYLEN_TOO_SHORT 2
#define PAILLIER_ERROR_INVALID_PLAIN_TEXT 3
#define PAILLIER_ERROR_INVALID_CIPHER_TEXT 4
#define PAILLIER_ERROR_INVALID_RANDOMNESS 5
#define PAILLIER_ERROR_INVALID_KEY 6
#define PAILLIER_ERROR_INVALID_PARAM 7
#define PAILLIER_ERROR_INVALID_PROOF 8
#define PAILLIER_ERROR_BUFFER_TOO_SHORT 9
#define PAILLIER_ERROR_OUT_OF_MEMORY 10

#define PAILLIER_SHA512_LEN 64
#define PAILLIER_SHA256_LEN 32
#define PAILLIER_IS_OPENSSL_ERROR(err) ((long)(err) < 0)
#define PAILLIER_TO_OPENSSL_ERROR(err) ((long)(err) * -1)

COSIGNER_EXPORT long paillier_generate_key_pair(uint32_t key_len, paillier_public_key_t **pub, paillier_private_key_t **priv);

COSIGNER_EXPORT long paillier_generate_factorization_zkpok(const paillier_private_key_t *priv, const uint8_t *aad, uint32_t aad_len, uint8_t x[PAILLIER_SHA256_LEN], uint8_t *y, uint32_t y_len, uint32_t *y_real_len);
COSIGNER_EXPORT long paillier_verify_factorization_zkpok(const paillier_public_key_t *pub, const uint8_t *aad, uint32_t aad_len, const uint8_t x[PAILLIER_SHA256_LEN], const uint8_t *y, uint32_t y_len);

COSIGNER_EXPORT long paillier_generate_coprime_zkp(const paillier_private_key_t *priv, const uint8_t *aad, uint32_t aad_len, uint8_t *y, uint32_t y_len, uint32_t *y_real_len);
COSIGNER_EXPORT long paillier_verify_coprime_zkp(const paillier_public_key_t *pub, const uint8_t *aad, uint32_t aad_len, const uint8_t *y, uint32_t y_len);

COSIGNER_EXPORT long paillier_generate_paillier_blum_zkp(const paillier_private_key_t *priv, const uint8_t *aad, uint32_t aad_len, uint8_t *serialized_proof, uint32_t proof_len, uint32_t *proof_real_len);
COSIGNER_EXPORT long paillier_verify_paillier_blum_zkp(const paillier_public_key_t *pub, const uint8_t *aad, uint32_t aad_len, const uint8_t *serialized_proof, uint32_t proof_len);

COSIGNER_EXPORT long paillier_public_key_n(const paillier_public_key_t *pub, uint8_t *n, uint32_t n_len, uint32_t *n_real_len);
COSIGNER_EXPORT uint32_t paillier_public_key_size(const paillier_public_key_t *pub);
COSIGNER_EXPORT uint8_t *paillier_public_key_serialize(const paillier_public_key_t *pub, uint8_t *buffer, uint32_t buffer_len, uint32_t *real_buffer_len);
COSIGNER_EXPORT paillier_public_key_t *paillier_public_key_deserialize(const uint8_t *buffer, uint32_t buffer_len);
COSIGNER_EXPORT void paillier_free_public_key(paillier_public_key_t *pub);

COSIGNER_EXPORT long paillier_private_key_n(const paillier_private_key_t *priv, uint8_t *n, uint32_t n_len, uint32_t *n_real_len);
COSIGNER_EXPORT const paillier_public_key_t* paillier_private_key_get_public(const paillier_private_key_t *priv); // the returned public pey must not be freed!
COSIGNER_EXPORT uint8_t *paillier_private_key_serialize(const paillier_private_key_t *priv, uint8_t *buffer, uint32_t buffer_len, uint32_t *real_buffer_len);
COSIGNER_EXPORT paillier_private_key_t *paillier_private_key_deserialize(const uint8_t *buffer, uint32_t buffer_len);
COSIGNER_EXPORT void paillier_free_private_key(paillier_private_key_t *priv);

COSIGNER_EXPORT long paillier_encrypt(const paillier_public_key_t *key, const uint8_t *plaintext, uint32_t plaintext_len, uint8_t *ciphertext, uint32_t ciphertext_len, uint32_t *ciphertext_real_len);
COSIGNER_EXPORT long paillier_encrypt_to_ciphertext(const paillier_public_key_t *key, const uint8_t *plaintext, uint32_t plaintext_len, paillier_ciphertext_t **ciphertext);
COSIGNER_EXPORT long paillier_encrypt_integer(const paillier_public_key_t *key, uint64_t plaintext, uint8_t *ciphertext, uint32_t ciphertext_len, uint32_t *ciphertext_real_len);
COSIGNER_EXPORT long paillier_decrypt(const paillier_private_key_t *key, const uint8_t *ciphertext, uint32_t ciphertext_len, uint8_t *plaintext, uint32_t plaintext_len, uint32_t *plaintext_real_len);
COSIGNER_EXPORT long paillier_decrypt_integer(const paillier_private_key_t *key, const uint8_t *ciphertext, uint32_t ciphertext_len, uint64_t *plaintext);

// result = a + b
COSIGNER_EXPORT long paillier_add(const paillier_public_key_t *key, const uint8_t *a_ciphertext, uint32_t a_ciphertext_len, const uint8_t *b_ciphertext, uint32_t b_ciphertext_len, 
    uint8_t *result, uint32_t result_len, uint32_t *result_real_len);
COSIGNER_EXPORT long paillier_add_integer(const paillier_public_key_t *key, const uint8_t *a_ciphertext, uint32_t a_ciphertext_len, uint64_t b, uint8_t *result, uint32_t result_len, uint32_t *result_real_len);

// result = a - b
COSIGNER_EXPORT long paillier_sub(const paillier_public_key_t *key, const uint8_t *a_ciphertext, uint32_t a_ciphertext_len, const uint8_t *b_ciphertext, uint32_t b_ciphertext_len, 
    uint8_t *result, uint32_t result_len, uint32_t *result_real_len);
COSIGNER_EXPORT long paillier_sub_integer(const paillier_public_key_t *key, const uint8_t *a_ciphertext, uint32_t a_ciphertext_len, uint64_t b, uint8_t *result, uint32_t result_len, uint32_t *result_real_len);

// result = a * b
COSIGNER_EXPORT long paillier_mul(const paillier_public_key_t *key, const uint8_t *a_ciphertext, uint32_t a_ciphertext_len, const uint8_t *b_plaintext, uint32_t b_plaintext_len, 
    uint8_t *result, uint32_t result_len, uint32_t *result_real_len);
COSIGNER_EXPORT long paillier_mul_integer(const paillier_public_key_t *key, const uint8_t *a_ciphertext, uint32_t a_ciphertext_len, uint64_t b, uint8_t *result, uint32_t result_len, uint32_t *result_real_len);

COSIGNER_EXPORT long paillier_get_ciphertext(const paillier_ciphertext_t *ciphertext_object, uint8_t *ciphertext, uint32_t ciphertext_len, uint32_t *ciphertext_real_len);
COSIGNER_EXPORT void paillier_free_ciphertext(paillier_ciphertext_t *ciphertext_object);
#ifdef __cplusplus
}
#endif //__cplusplus

#endif //__PAILLIER_H__