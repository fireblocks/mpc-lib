#ifndef __PAILLIER_COMMITMENT_INTERNAL_H__
#define __PAILLIER_COMMITMENT_INTERNAL_H__
#include <openssl/bn.h>

#ifdef __cplusplus
extern "C" {
#endif //__cplusplus

struct paillier_commitment_public_key
{
    BIGNUM* n;          // public key n = p * q
    BIGNUM* t;          // damgard fujisaki generator, also used as rho0 in paillier
    BIGNUM* s;          // damgard fujisaki t^lambda in mod n^2 public. Also used in paillier encryption
    BIGNUM* n2;         // calculated n^2
    BIGNUM* rho;        // t^n mod n^2 - either restored or calculated. used as rho in paillier
    BIGNUM* sigma_0;    // (1 + n) * s^n mod n^2 - either restored or calculated
    BN_MONT_CTX* mont_n2;  // montgomery context used for in mod n^2
};

struct paillier_commitment_private_key
{
    struct paillier_commitment_public_key pub;
    BIGNUM* p;          // secret tough prime
    BIGNUM* q;          // secret tough prime
    BIGNUM* lambda;     // secret of the damgard fujisaki 
    BIGNUM* p2;         // calculated - holds (p^2)
    BIGNUM* q2;         // calculated - holds (q^2)
    BIGNUM* q2_inv_p2;  // calculated - holds (q^2^-1) mod (p^2)
    BIGNUM* phi_n;      // calculated - phi(n) also known as lambda in paillier 
    BIGNUM* phi_n_inv;  // calculated - phi(n) ^ 1 in mod(n) also known as mu in paillier
    
};

struct paillier_commitment_with_randomizer_power
{
    uint8_t* commitment;
    uint32_t commitment_size;

    uint8_t* randomizer_exponent;
    uint32_t randomizer_exponent_size;
};

long paillier_commitment_encrypt_openssl_fixed_power_internal(const struct paillier_commitment_public_key *pub, 
                                                              BIGNUM *ciphertext, 
                                                              const BIGNUM *r_power, 
                                                              const BIGNUM *message, 
                                                              BN_CTX *ctx);

long paillier_commitment_encrypt_openssl_with_private_internal(const struct paillier_commitment_private_key *priv, 
                                                               const uint32_t r_power_bitsize,
                                                               const BIGNUM *message, 
                                                               BN_CTX *ctx,
                                                               BIGNUM *ciphertext, 
                                                               BIGNUM *r_power);

long paillier_commitment_decrypt_openssl_internal(const struct paillier_commitment_private_key *priv, 
                                                  const BIGNUM *ciphertext, 
                                                  BIGNUM *plaintext, 
                                                  BN_CTX *ctx);

long paillier_commitment_commit_with_private_internal(const struct paillier_commitment_private_key *priv,
                                                      const BIGNUM* commited_val,
                                                      const BIGNUM* randomizer_expo,
                                                      const BIGNUM* modifier,
                                                      const BIGNUM* modifier_expo,
                                                      BIGNUM* commitment,
                                                      BN_CTX *ctx);

long paillier_commitment_commit_internal(const struct paillier_commitment_public_key *pub,
                                         const BIGNUM* commited_val,
                                         const BIGNUM* randomizer_expo,
                                         const BIGNUM* modifier,
                                         const BIGNUM* modifier_expo,
                                         BIGNUM* commitment,
                                         BN_CTX *ctx);

#ifdef __cplusplus
}
#endif //__cplusplus


#endif //__PAILLIER_COMMITMENT_INTERNAL_H__