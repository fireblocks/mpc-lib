#ifndef __PAILLIER_INTERNAL_H__
#define __PAILLIER_INTERNAL_H__

#include "crypto/paillier/paillier.h"
#include "crypto/commitments/ring_pedersen.h"
#include <openssl/sha.h>
#include <openssl/bn.h>

#ifdef __cplusplus
extern "C" {
#endif //__cplusplus

#define MIN_KEY_LEN_IN_BITS 256

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
    BIGNUM *lamda;
    BIGNUM *mu;
};

struct paillier_ciphertext
{
    BIGNUM *ciphertext;
    BIGNUM *r;
};

int is_coprime_fast(const BIGNUM *in_a, const BIGNUM *in_b, BN_CTX *ctx);
long paillier_encrypt_openssl_internal(const paillier_public_key_t *key, BIGNUM *ciphertext, const BIGNUM *r, const BIGNUM *plaintext, BN_CTX *ctx);
long paillier_decrypt_openssl_internal(const paillier_private_key_t *key, const BIGNUM *ciphertext, BIGNUM *plaintext, BN_CTX *ctx);

// ring pedersen internal structs
struct ring_pedersen_public 
{
    BIGNUM *n;
    BIGNUM *s;
    BIGNUM *t;
    BN_MONT_CTX *mont;
};

struct ring_pedersen_private 
{
    ring_pedersen_public_t pub;
    BIGNUM *lamda;
    BIGNUM *phi_n;
};
ring_pedersen_status ring_pedersen_init_montgomery(const ring_pedersen_public_t *pub, BN_CTX *ctx);
ring_pedersen_status ring_pedersen_create_commitment_internal(const ring_pedersen_public_t *pub, const BIGNUM *x, const BIGNUM *r, BIGNUM *commitment, BN_CTX *ctx);
ring_pedersen_status ring_pedersen_verify_batch_commitments_internal(const ring_pedersen_private_t *priv, uint32_t batch_size, const BIGNUM **x, const BIGNUM **r, const BIGNUM **commitments, BN_CTX *ctx);

#ifdef __cplusplus
}
#endif //__cplusplus

#endif //__PAILLIER_INTERNAL_H__