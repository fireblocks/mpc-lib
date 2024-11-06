#ifndef __DIFFIE_HELLMAN_H__
#define __DIFFIE_HELLMAN_H__

#include "cosigner_export.h"

#include "crypto/zero_knowledge_proof/zero_knowledge_proof_status.h"
#include "crypto/elliptic_curve_algebra/elliptic_curve256_algebra.h"


#ifdef __cplusplus
extern "C" {
#endif //__cplusplus

typedef struct diffie_hellman_log_zkp
{
    elliptic_curve256_point_t  D;
    elliptic_curve256_point_t  Y;
    elliptic_curve256_point_t  V;
    elliptic_curve256_scalar_t w;
    elliptic_curve256_scalar_t z;
} diffie_hellman_log_zkp_t;

typedef struct diffie_hellman_log_public_data
{
    elliptic_curve256_point_t  A;
    elliptic_curve256_point_t  B;
    elliptic_curve256_point_t  C;
    elliptic_curve256_point_t  X;
} diffie_hellman_log_public_data_t;

/* Creates diffie hellman discrete log zero knowledge proof for secret having public point (base_point^secret) public_data, A = g^a, B = g^b and C = g^(ab + secret) */
COSIGNER_EXPORT zero_knowledge_proof_status diffie_hellman_log_zkp_generate(const elliptic_curve256_algebra_ctx_t *algebra, const uint8_t *aad, uint32_t aad_len, const elliptic_curve256_point_t *base_point, const elliptic_curve256_scalar_t *secret, 
    const elliptic_curve256_scalar_t *a, const elliptic_curve256_scalar_t *b, const diffie_hellman_log_public_data_t *public_data, diffie_hellman_log_zkp_t *proof);
/* Verifies that the public data was created from the secret */
COSIGNER_EXPORT zero_knowledge_proof_status diffie_hellman_log_zkp_verify(const elliptic_curve256_algebra_ctx_t *algebra, const uint8_t *aad, uint32_t aad_len, const elliptic_curve256_point_t *base_point, 
    const diffie_hellman_log_public_data_t *public_data, const diffie_hellman_log_zkp_t *proof);

#ifdef __cplusplus
}
#endif //__cplusplus

#endif // __DIFFIE_HELLMAN_H__