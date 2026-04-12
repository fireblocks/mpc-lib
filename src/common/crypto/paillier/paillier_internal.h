#ifndef __PAILLIER_INTERNAL_H__
#define __PAILLIER_INTERNAL_H__

#include "crypto/paillier/paillier.h"
#include <openssl/sha.h>
#include <openssl/bn.h>

#ifdef __cplusplus
extern "C" {
#endif //__cplusplus

typedef uint8_t sha512_md_t[SHA512_DIGEST_LENGTH];
typedef uint8_t sha256_md_t[SHA256_DIGEST_LENGTH];

struct paillier_public_key 
{
    BIGNUM *n;
    BIGNUM *n2;
};

struct paillier_private_key 
{
    paillier_public_key_t pub;
    BIGNUM *p;
    BIGNUM *q;
    BIGNUM *lambda;  // phi(n)
    BIGNUM *mu;     // phi(n) ^ (-1) in mod(n)
};

struct paillier_ciphertext
{
    BIGNUM *ciphertext;
    BIGNUM *r;
    uint32_t cipher_size; //size in bytes of the ciphertext if serialized
};

long paillier_encrypt_openssl_internal(const paillier_public_key_t *key, BIGNUM *ciphertext, const BIGNUM *r, const BIGNUM *plaintext, BN_CTX *ctx);
long paillier_decrypt_openssl_internal(const paillier_private_key_t *key, const BIGNUM *ciphertext, BIGNUM *plaintext, BN_CTX *ctx);
uint64_t paillier_L(BIGNUM *res, const BIGNUM *x, const BIGNUM *n, BN_CTX *ctx);
long paillier_error_from_openssl();

#ifdef __cplusplus
}
#endif //__cplusplus

#endif //__PAILLIER_INTERNAL_H__