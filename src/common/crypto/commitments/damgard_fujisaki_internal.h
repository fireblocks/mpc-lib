#ifndef __DAMGARD_FUJISAKI_INTERNAL_H__
#define __DAMGARD_FUJISAKI_INTERNAL_H__

#include "crypto/commitments/ring_pedersen.h"
#include <openssl/bn.h>

// damgard_fujisaki combines multiple ring pedersen commitments into a single commitment
// which can be verified together
// Number of the commitments is the same as number of secrets "lambda" and same as number of public "s" values

#ifdef __cplusplus
extern "C" {
#endif //__cplusplus

struct damgard_fujisaki_public 
{
    uint32_t dimension; // number of secrets
    BIGNUM *n;          // public part of p * q
    BIGNUM **s;         // for each secret lambda holds its public t^lambda
    BIGNUM *t;          // single t used for all s
    BN_MONT_CTX *mont;  // montgomery context used for calculations
};

struct damgard_fujisaki_private 
{
    struct damgard_fujisaki_public pub;
    BIGNUM **lambda; // secrets, same count as pub->dimension
    BIGNUM *phi_n;  // (p-1) * (q-1)
    BIGNUM *p;
    BIGNUM *q;
    BIGNUM *qinvp; // 1/q in modulo p
};
ring_pedersen_status damgard_fujisaki_init_montgomery(struct damgard_fujisaki_public *pub, BN_CTX* ctx);

// generate a single commitment for mulitple "x" values using a single random value r for hiding
ring_pedersen_status damgard_fujisaki_create_commitment_internal(const struct damgard_fujisaki_public *pub, const BIGNUM **x, const uint32_t x_size, const BIGNUM *r, BIGNUM *commitment, BN_CTX *ctx);

// used for commitment verification. Calls damgard_fujisaki_create_commitment_with_private_internal()
// and compares the result
ring_pedersen_status damgard_fujisaki_verify_commitment_internal(const struct damgard_fujisaki_private *priv, const BIGNUM **x, const uint32_t x_size, const BIGNUM *r, const BIGNUM *commitment, BN_CTX *ctx);

#ifdef __cplusplus
}
#endif //__cplusplus

#endif //__DAMGARD_FUJISAKI_INTERNAL_H__