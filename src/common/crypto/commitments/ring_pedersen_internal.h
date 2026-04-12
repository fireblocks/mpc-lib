#ifndef __RING_PEDERSEN_INTERNAL_H__
#define __RING_PEDERSEN_INTERNAL_H__


#include "crypto/commitments/ring_pedersen.h"
#include <openssl/bn.h>


#ifdef __cplusplus
extern "C" {
#endif //__cplusplus

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
    struct ring_pedersen_public pub;
    BIGNUM *lambda;
    BIGNUM *phi_n;
};
ring_pedersen_status ring_pedersen_init_montgomery(struct ring_pedersen_public *pub, BN_CTX *ctx);
ring_pedersen_status ring_pedersen_create_commitment_internal(const struct ring_pedersen_public *pub, const BIGNUM *x, const BIGNUM *r, BIGNUM *commitment, BN_CTX *ctx);
ring_pedersen_status ring_pedersen_verify_batch_commitments_internal(const struct ring_pedersen_private *priv, uint32_t batch_size, const BIGNUM **x, const BIGNUM **r, const BIGNUM **commitments, BN_CTX *ctx);

#ifdef __cplusplus
}
#endif //__cplusplus

#endif // __RING_PEDERSEN_INTERNAL_H__