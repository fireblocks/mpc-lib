#ifndef __RANGE_PROOFS_H__
#define __RANGE_PROOFS_H__

#include <stdint.h>
#include "crypto/zero_knowledge_proof/zero_knowledge_proof_status.h"
#include "crypto/elliptic_curve_algebra/elliptic_curve256_algebra.h"
#include "crypto/paillier/paillier.h"
#include "crypto/commitments/ring_pedersen.h"

#ifdef __cplusplus
extern "C" {
#endif //__cplusplus

typedef struct
{
    uint8_t *ciphertext;
    uint32_t ciphertext_len;
    uint8_t *serialized_proof;
    uint32_t proof_len;
} paillier_with_range_proof_t;

// Knowledge of Exponent vs Paillier Encryption range proof
zero_knowledge_proof_status range_proof_paillier_exponent_zkpok_generate(const ring_pedersen_public_t *ring_pedersen, const paillier_public_key_t *paillier, const elliptic_curve256_algebra_ctx_t *algebra, 
    const uint8_t *aad, uint32_t aad_len, const elliptic_curve256_scalar_t *secret, const paillier_ciphertext_t *ciphertext, uint8_t *serialized_proof, uint32_t proof_len, uint32_t *real_proof_len);
zero_knowledge_proof_status range_proof_paillier_encrypt_with_exponent_zkpok_generate(const ring_pedersen_public_t *ring_pedersen, const paillier_public_key_t *paillier, const elliptic_curve256_algebra_ctx_t *algebra, 
    const uint8_t *aad, uint32_t aad_len, const elliptic_curve256_scalar_t *secret, paillier_with_range_proof_t **proof);
zero_knowledge_proof_status range_proof_exponent_zkpok_verify(const ring_pedersen_private_t *ring_pedersen, const paillier_public_key_t *paillier, const elliptic_curve256_algebra_ctx_t *algebra, 
    const uint8_t *aad, uint32_t aad_len, const elliptic_curve256_point_t *public_point, const paillier_with_range_proof_t *proof);
zero_knowledge_proof_status range_proof_exponent_zkpok_batch_verify(const ring_pedersen_private_t *ring_pedersen, const paillier_public_key_t *paillier, const elliptic_curve256_algebra_ctx_t *algebra, 
    const uint8_t *aad, uint32_t aad_len, uint32_t batch_size, const elliptic_curve256_point_t *public_points, const paillier_with_range_proof_t *proofs);

// Knowledge of (a, b, x) such that public_point = g^(a*b+x) vs Paillier Encryption of x range proof
zero_knowledge_proof_status range_proof_diffie_hellman_zkpok_generate(const ring_pedersen_public_t *ring_pedersen, const paillier_public_key_t *paillier, const elliptic_curve256_algebra_ctx_t *algebra, 
    const uint8_t *aad, uint32_t aad_len, const elliptic_curve256_scalar_t *secret, const elliptic_curve256_scalar_t *a, const elliptic_curve256_scalar_t *b, const paillier_ciphertext_t *ciphertext, 
    uint8_t *serialized_proof, uint32_t proof_len, uint32_t *real_proof_len);
zero_knowledge_proof_status range_proof_paillier_encrypt_with_diffie_hellman_zkpok_generate(const ring_pedersen_public_t *ring_pedersen, const paillier_public_key_t *paillier, const elliptic_curve256_algebra_ctx_t *algebra, 
    const uint8_t *aad, uint32_t aad_len, const elliptic_curve256_scalar_t *secret, const elliptic_curve256_scalar_t *a, const elliptic_curve256_scalar_t *b, paillier_with_range_proof_t **proof);
zero_knowledge_proof_status range_proof_diffie_hellman_zkpok_verify(const ring_pedersen_private_t *ring_pedersen, const paillier_public_key_t *paillier, const elliptic_curve256_algebra_ctx_t *algebra, 
    const uint8_t *aad, uint32_t aad_len, const elliptic_curve256_point_t *public_point, const elliptic_curve256_point_t *A, const elliptic_curve256_point_t *B, const paillier_with_range_proof_t *proof);

void range_proof_free_paillier_with_range_proof(paillier_with_range_proof_t *proof);

zero_knowledge_proof_status range_proof_paillier_large_factors_zkp_generate(const paillier_private_key_t *priv, const ring_pedersen_public_t *ring_pedersen, const uint8_t *aad, uint32_t aad_len, uint8_t *serialized_proof, uint32_t proof_len, uint32_t *real_proof_len);
zero_knowledge_proof_status range_proof_paillier_large_factors_zkp_verify(const paillier_public_key_t *pub, const ring_pedersen_private_t *ring_pedersen, const uint8_t *aad, uint32_t aad_len, const uint8_t *serialized_proof, uint32_t proof_len);

#ifdef __cplusplus
}
#endif //__cplusplus

#endif // __RANGE_PROOFS_H__
