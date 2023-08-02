#ifndef __SCHNORR_H__
#define __SCHNORR_H__

#include "crypto/zero_knowledge_proof/zero_knowledge_proof_status.h"
#include "crypto/elliptic_curve_algebra/elliptic_curve256_algebra.h"


#ifdef __cplusplus
extern "C" {
#endif //__cplusplus

typedef struct schnorr_zkp
{
    elliptic_curve256_point_t  R;
    elliptic_curve256_scalar_t s;
} schnorr_zkp_t;

/* Creates schnorr zero knowledge proof for secret having public point public_data */
zero_knowledge_proof_status schnorr_zkp_generate(const elliptic_curve256_algebra_ctx_t *algebra, const uint8_t *prover_id, uint32_t id_len, const elliptic_curve256_scalar_t *secret, const elliptic_curve256_point_t *public_data, schnorr_zkp_t *proof);
/* Creates schnorr zero knowledge proof for raw secret and addtionaly returns the public point */
zero_knowledge_proof_status schnorr_zkp_generate_for_data(const elliptic_curve256_algebra_ctx_t *algebra, const uint8_t *prover_id, uint32_t id_len, const uint8_t *secret, uint32_t secret_size, elliptic_curve256_point_t *public_data, schnorr_zkp_t *proof);
/* Creates schnorr zero knowledge proof for secret having public point public_data using randomness such that R = g^randomness, a.k.a makriyannis schnorr zkp */
zero_knowledge_proof_status schnorr_zkp_generate_with_custom_randomness(const elliptic_curve256_algebra_ctx_t *algebra, const uint8_t *prover_id, uint32_t id_len, const elliptic_curve256_scalar_t *secret, const elliptic_curve256_point_t *public_data, 
    const elliptic_curve256_scalar_t *randomness, schnorr_zkp_t *proof);
/* Verifies that the public data was created from the secret */
zero_knowledge_proof_status schnorr_zkp_verify(const elliptic_curve256_algebra_ctx_t *algebra, const uint8_t *prover_id, uint32_t id_len, const elliptic_curve256_point_t *public_data, const schnorr_zkp_t *proof);

#ifdef __cplusplus
}
#endif //__cplusplus

#endif // __SCHNORR_H__