#ifndef __RANGE_PROOFS_H__
#define __RANGE_PROOFS_H__

#include "cosigner_export.h"

#include <stdint.h>
#include "crypto/zero_knowledge_proof/zero_knowledge_proof_status.h"
#include "crypto/elliptic_curve_algebra/elliptic_curve256_algebra.h"
#include "crypto/paillier/paillier.h"
#include "crypto/commitments/ring_pedersen.h"
#include "crypto/commitments/damgard_fujisaki.h"
#include "crypto/paillier_commitment/paillier_commitment.h"

#ifdef __cplusplus
extern "C" {
#endif //__cplusplus

// Structure for Paillier ciphertext and associated range proof
/**
 * @brief Structure representing a Paillier ciphertext and associated range proof.
 *
 * This structure holds the ciphertext data and the serialized proof for range proofs.
 */
typedef struct
{
    uint8_t *ciphertext;           // Pointer to ciphertext data
    uint32_t ciphertext_len;       // Length of the ciphertext
    uint8_t *serialized_proof;     // Pointer to serialized proof data
    uint32_t proof_len;            // Length of the serialized proof
} paillier_with_range_proof_t;

// Const version of the Paillier ciphertext and proof structure
/**
 * @brief Const structure representing a Paillier ciphertext and associated range proof.
 *
 * This structure holds constant pointers to the ciphertext data and the serialized proof for range proofs.
 */
typedef struct
{
    const uint8_t* const ciphertext;        // Pointer to ciphertext data
    const uint32_t ciphertext_len;          // Length of the ciphertext
    const uint8_t* const serialized_proof;  // Pointer to serialized proof data
    const uint32_t proof_len;               // Length of the serialized proof
} const_paillier_with_range_proof_t;

// Function declarations for generating and verifying range proofs

/**
 * @brief Generates a range proof for Paillier encryption with a known exponent.
 *
 * This function generates a range proof for the provided Paillier ciphertext using the given secret exponent.
 *
 * @param[in] ring_pedersen Pointer to the Ring Pedersen public parameters.
 * @param[in] paillier Pointer to the Paillier public key.
 * @param[in] algebra Pointer to the elliptic curve algebra context.
 * @param[in] aad Pointer to additional authenticated data.
 * @param[in] aad_len Length of the additional authenticated data.
 * @param[in] secret Pointer to the secret exponent.
 * @param[in] ciphertext Pointer to the Paillier ciphertext.
 * @param[out] serialized_proof Pointer to the buffer to store the serialized proof.
 * @param[in] proof_len Length of the proof buffer.
 * @param[out] real_proof_len Pointer to store the actual length of the generated proof.
 *
 * @return Status of the zero-knowledge proof generation.
 */
COSIGNER_EXPORT zero_knowledge_proof_status range_proof_paillier_exponent_zkpok_generate(const ring_pedersen_public_t *ring_pedersen, const paillier_public_key_t *paillier, const elliptic_curve256_algebra_ctx_t *algebra, 
    const uint8_t *aad, uint32_t aad_len, const elliptic_curve256_scalar_t *secret, const paillier_ciphertext_t *ciphertext, const uint8_t use_extended_seed, uint8_t *serialized_proof, uint32_t proof_len, uint32_t *real_proof_len);

/**
 * @brief Generates a Paillier encryption along with a range proof for the given exponent.
 *
 * This function generates a Paillier ciphertext and an associated range proof for the provided secret exponent.
 *
 * @param[in] ring_pedersen Pointer to the Ring Pedersen public parameters.
 * @param[in] paillier Pointer to the Paillier public key.
 * @param[in] algebra Pointer to the elliptic curve algebra context.
 * @param[in] aad Pointer to additional authenticated data.
 * @param[in] aad_len Length of the additional authenticated data.
 * @param[in] secret Pointer to the secret exponent.
 * @param[out] proof Pointer to store the generated Paillier ciphertext and range proof.
 *
 * @return Status of the zero-knowledge proof generation.
 */
COSIGNER_EXPORT zero_knowledge_proof_status range_proof_paillier_encrypt_with_exponent_zkpok_generate(const ring_pedersen_public_t *ring_pedersen, const paillier_public_key_t *paillier, const elliptic_curve256_algebra_ctx_t *algebra, 
    const uint8_t *aad, uint32_t aad_len, const elliptic_curve256_scalar_t *secret, const uint8_t use_extended_seed, paillier_with_range_proof_t **proof);

/**
 * @brief Verifies a range proof for Paillier encryption with a known exponent.
 *
 * This function verifies the provided range proof for a Paillier ciphertext with a known public point.
 *
 * @param[in] ring_pedersen Pointer to the Ring Pedersen private parameters.
 * @param[in] paillier Pointer to the Paillier public key.
 * @param[in] algebra Pointer to the elliptic curve algebra context.
 * @param[in] aad Pointer to additional authenticated data.
 * @param[in] aad_len Length of the additional authenticated data.
 * @param[in] public_point Pointer to the elliptic curve public point.
 * @param[in] proof Pointer to the Paillier ciphertext and range proof.
 * @param[in] strict_ciphertext_length Verify that the ciphertext length is exactly same as n2 of the paillier
 *
 * @return Status of the zero-knowledge proof verification.
 */
COSIGNER_EXPORT zero_knowledge_proof_status range_proof_exponent_zkpok_verify(const ring_pedersen_private_t *ring_pedersen, 
                                                                              const paillier_public_key_t *paillier, 
                                                                              const elliptic_curve256_algebra_ctx_t *algebra, 
                                                                              const uint8_t *aad, 
                                                                              uint32_t aad_len, 
                                                                              const elliptic_curve256_point_t *public_point, 
                                                                              const paillier_with_range_proof_t *proof,
                                                                              const uint8_t strict_ciphertext_length,
                                                                              const uint8_t use_extended_seed);

/**
 * @brief Generates a Diffie-Hellman range proof for a relationship involving Paillier encryption.
 *
 * This function generates a range proof for a Diffie-Hellman relationship involving Paillier ciphertexts and elliptic curve scalars.
 *
 * @param[in] ring_pedersen Pointer to the Ring Pedersen public parameters.
 * @param[in] paillier Pointer to the Paillier public key.
 * @param[in] algebra Pointer to the elliptic curve algebra context.
 * @param[in] aad Pointer to additional authenticated data.
 * @param[in] aad_len Length of the additional authenticated data.
 * @param[in] secret Pointer to the secret scalar value.
 * @param[in] a Pointer to the first scalar value.
 * @param[in] b Pointer to the second scalar value.
 * @param[in] ciphertext Pointer to the Paillier ciphertext.
 * @param[out] serialized_proof Pointer to the buffer to store the serialized proof.
 * @param[in] proof_len Length of the proof buffer.
 * @param[out] real_proof_len Pointer to store the actual length of the generated proof.
 *
 * @return Status of the zero-knowledge proof generation.
 */
COSIGNER_EXPORT zero_knowledge_proof_status range_proof_diffie_hellman_zkpok_generate(const ring_pedersen_public_t *ring_pedersen, const paillier_public_key_t *paillier, const elliptic_curve256_algebra_ctx_t *algebra, 
    const uint8_t *aad, uint32_t aad_len, const elliptic_curve256_scalar_t *secret, const elliptic_curve256_scalar_t *a, const elliptic_curve256_scalar_t *b, const paillier_ciphertext_t *ciphertext, 
    const uint8_t use_extended_seed, uint8_t *serialized_proof, uint32_t proof_len, uint32_t *real_proof_len);

/**
 * @brief Generates a Paillier encryption along with a Diffie-Hellman range proof.
 *
 * This function generates a Paillier ciphertext and an associated Diffie-Hellman range proof.
 *
 * @param[in] ring_pedersen Pointer to the Ring Pedersen public parameters.
 * @param[in] paillier Pointer to the Paillier public key.
 * @param[in] algebra Pointer to the elliptic curve algebra context.
 * @param[in] aad Pointer to additional authenticated data.
 * @param[in] aad_len Length of the additional authenticated data.
 * @param[in] secret Pointer to the secret scalar value.
 * @param[in] a Pointer to the first scalar value.
 * @param[in] b Pointer to the second scalar value.
 * @param[out] proof Pointer to store the generated Paillier ciphertext and range proof.
 *
 * @return Status of the zero-knowledge proof generation.
 */
COSIGNER_EXPORT zero_knowledge_proof_status range_proof_paillier_encrypt_with_diffie_hellman_zkpok_generate(const ring_pedersen_public_t *ring_pedersen, const paillier_public_key_t *paillier, const elliptic_curve256_algebra_ctx_t *algebra, 
    const uint8_t *aad, uint32_t aad_len, const elliptic_curve256_scalar_t *secret, const elliptic_curve256_scalar_t *a, const elliptic_curve256_scalar_t *b, const uint8_t use_extended_seed, paillier_with_range_proof_t **proof);

/**
 * @brief Verifies a Diffie-Hellman range proof for a relationship involving Paillier encryption.
 *
 * This function verifies the provided Diffie-Hellman range proof for a relationship involving elliptic curve points and Paillier ciphertexts.
 *
 * @param[in] ring_pedersen Pointer to the Ring Pedersen private parameters.
 * @param[in] paillier Pointer to the Paillier public key.
 * @param[in] algebra Pointer to the elliptic curve algebra context.
 * @param[in] aad Pointer to additional authenticated data.
 * @param[in] aad_len Length of the additional authenticated data.
 * @param[in] public_point Pointer to the elliptic curve public point.
 * @param[in] A Pointer to the first elliptic curve point.
 * @param[in] B Pointer to the second elliptic curve point.
 * @param[in] proof Pointer to the Paillier ciphertext and range proof.
 * @param[in] strict_ciphertext_length Verify that the ciphertext length is exactly same as n2 of the paillier
 *
 * @return Status of the zero-knowledge proof verification.
 */
COSIGNER_EXPORT zero_knowledge_proof_status range_proof_diffie_hellman_zkpok_verify(const ring_pedersen_private_t *ring_pedersen, 
                                                                                    const paillier_public_key_t *paillier, 
                                                                                    const elliptic_curve256_algebra_ctx_t *algebra, 
                                                                                    const uint8_t *aad, 
                                                                                    uint32_t aad_len, 
                                                                                    const elliptic_curve256_point_t *public_point, 
                                                                                    const elliptic_curve256_point_t *A,
                                                                                    const elliptic_curve256_point_t *B, 
                                                                                    const paillier_with_range_proof_t *proof,
                                                                                    const uint8_t strict_ciphertext_length,
                                                                                    const uint8_t use_extended_seed);

/**
 * @brief Frees the memory associated with a Paillier ciphertext and range proof.
 *
 * This function releases the memory allocated for a Paillier ciphertext and its associated range proof.
 *
 * @param[in] proof Pointer to the Paillier ciphertext and range proof structure to free.
 */
COSIGNER_EXPORT void range_proof_free_paillier_with_range_proof(paillier_with_range_proof_t *proof);

/**
 * @brief Generates a range proof for Paillier encryption with large factors.
 *
 * This function generates a range proof for Paillier encryption with large factors, using the provided private key and Ring Pedersen parameters.
 *
 * @param[in] priv Pointer to the Paillier private key.
 * @param[in] ring_pedersen Pointer to the Ring Pedersen public parameters.
 * @param[in] aad Pointer to additional authenticated data.
 * @param[in] aad_len Length of the additional authenticated data.
 * @param[in] use_extended_seed Use extended
 * @param[out] serialized_proof Pointer to the buffer to store the serialized proof.
 * @param[in] proof_len Length of the proof buffer.
 * @param[out] real_proof_len Pointer to store the actual length of the generated proof.
 *
 * @return Status of the zero-knowledge proof generation.
 */
COSIGNER_EXPORT zero_knowledge_proof_status range_proof_paillier_large_factors_zkp_generate(const paillier_private_key_t *priv, 
                                                                                            const ring_pedersen_public_t *ring_pedersen, 
                                                                                            const uint8_t *aad, 
                                                                                            uint32_t aad_len, 
                                                                                            const uint8_t use_extended_seed,
                                                                                            uint8_t *serialized_proof, 
                                                                                            uint32_t proof_len, 
                                                                                            uint32_t *real_proof_len);

/**
 * @brief Verifies a range proof for Paillier encryption with large factors.
 *
 * This function verifies the provided range proof for Paillier encryption with large factors.
 *
 * @param[in] pub Pointer to the Paillier public key.
 * @param[in] ring_pedersen Pointer to the Ring Pedersen private parameters.
 * @param[in] aad Pointer to additional authenticated data.
 * @param[in] aad_len Length of the additional authenticated data.
 * @param[in] use_extended_seed Use extended version of the seed
 * @param[in] serialized_proof Pointer to the serialized proof data.
 * @param[in] proof_len Length of the serialized proof.
 *
 * @return Status of the zero-knowledge proof verification.
 */
COSIGNER_EXPORT zero_knowledge_proof_status range_proof_paillier_large_factors_zkp_verify(const paillier_public_key_t *pub, 
                                                                                          const ring_pedersen_private_t *ring_pedersen, 
                                                                                          const uint8_t *aad, 
                                                                                          uint32_t aad_len, 
                                                                                          const uint8_t use_extended_seed,
                                                                                          const uint8_t *serialized_proof, 
                                                                                          uint32_t proof_len);

/**
 * @brief return minimal size of "d" prime required for range_proof_paillier_large_factors_quadratic_zkp_generate()
 *
 * This function requires initialized public key and returns the minimal size in bits required for the "d" safe prime 
 *
 * @param[in] pub Pointer to the Paillier public key.
 *
 * @return Returns number of bits required. 0 in case of an error.
 */
COSIGNER_EXPORT uint32_t range_proof_paillier_large_factors_quadratic_zkp_compute_d_bitsize(const paillier_public_key_t* pub);

/**
 * @brief Generates a range proof for Paillier encryption with quadratic large factors.
 *
 * This function generates a range proof for Paillier encryption with quadratic large factors, using the provided private key.
 *
 * @param[in] priv Pointer to the Paillier private key.
 * @param[in] aad Pointer to additional authenticated data.
 * @param[in] aad_len Length of the additional authenticated data.
 * @param[in] d_prime Optional large safe prime. If NULL is given will be generated inside
 * @param[in] d_prime_len Length of d_prime
 * @param[out] serialized_proof Pointer to the buffer to store the serialized proof.
 * @param[in] proof_len Length of the proof buffer.
 * @param[out] real_proof_len Pointer to store the actual length of the generated proof.
 *
 * @return Status of the zero-knowledge proof generation.
 */
COSIGNER_EXPORT zero_knowledge_proof_status range_proof_paillier_large_factors_quadratic_zkp_generate(
    const paillier_private_key_t *priv, 
    const uint8_t *aad, 
    const uint32_t aad_len, 
    const uint8_t *d_prime,
    const uint32_t d_prime_len,
    uint8_t *serialized_proof, 
    uint32_t proof_len, 
    uint32_t *real_proof_len);

/**
 * @brief Verifies a range proof for Paillier encryption with quadratic large factors.
 *
 * This function verifies the provided range proof for Paillier encryption with quadratic large factors.
 *
 * @param[in] pub Pointer to the Paillier public key.
 * @param[in] aad Pointer to additional authenticated data.
 * @param[in] aad_len Length of the additional authenticated data.
 * @param[in] serialized_proof Pointer to the serialized proof data.
 * @param[in] proof_len Length of the serialized proof.
 *
 * @return Status of the zero-knowledge proof verification.
 */
COSIGNER_EXPORT zero_knowledge_proof_status range_proof_paillier_large_factors_quadratic_zkp_verify(const paillier_public_key_t *pub, 
                                                                                                    const uint8_t *aad, 
                                                                                                    uint32_t aad_len, 
                                                                                                    const uint8_t *serialized_proof, 
                                                                                                    uint32_t proof_len);

/**
 * @brief Generates a range proof for a small group Paillier encryption with an exponent.
 *
 * This function generates a Paillier ciphertext and an associated range proof for a small group exponent.
 *
 * @param[in] damgard_fujisaki Pointer to the Damgård-Fujisaki public parameters.
 * @param[in] paillier Pointer to the Paillier commitment private key.
 * @param[in] algebra Pointer to the elliptic curve algebra context.
 * @param[in] aad Pointer to additional authenticated data.
 * @param[in] aad_len Length of the additional authenticated data.
 * @param[in] secret Pointer to the secret value.
 * @param[in] secret_len Length of the secret value.
 * @param[out] proof Pointer to store the generated Paillier ciphertext and range proof.
 *
 * @return Status of the zero-knowledge proof generation.
 */
COSIGNER_EXPORT zero_knowledge_proof_status paillier_commitment_encrypt_with_exponent_zkpok_generate(const damgard_fujisaki_public_t *damgard_fujisaki, 
                                                                                                     const paillier_commitment_private_key_t *paillier, 
                                                                                                     const elliptic_curve256_algebra_ctx_t *algebra,
                                                                                                     const uint8_t *aad, 
                                                                                                     const uint32_t aad_len, 
                                                                                                     const uint8_t* secret, 
                                                                                                     const uint32_t secret_len, 
                                                                                                     const uint8_t use_extended_seed,
                                                                                                     paillier_with_range_proof_t **proof);



/**
 * @brief Verifies a range proof for small group Paillier encryption with an exponent.
 *
 * This function verifies the provided range proof for a small group Paillier ciphertext with a known public point.
 *
 * @param[in] damgard_fujisaki Pointer to the Damgård-Fujisaki private parameters.
 * @param[in] paillier Pointer to the Paillier commitment public key.
 * @param[in] algebra Pointer to the elliptic curve algebra context.
 * @param[in] aad Pointer to additional authenticated data.
 * @param[in] aad_len Length of the additional authenticated data.
 * @param[in] public_point Pointer to the elliptic curve public point.
 * @param[in] proof Pointer to the Paillier ciphertext and range proof.
 *
 * @return Status of the zero-knowledge proof verification.
 */
COSIGNER_EXPORT zero_knowledge_proof_status paillier_commitment_exponent_zkpok_verify(const damgard_fujisaki_private_t* damgard_fujisaki, 
                                                                                      const paillier_commitment_public_key_t* paillier, 
                                                                                      const elliptic_curve256_algebra_ctx_t* algebra,
                                                                                      const uint8_t* aad, 
                                                                                      const uint32_t aad_len, 
                                                                                      const elliptic_curve256_point_t* public_point, 
                                                                                      const const_paillier_with_range_proof_t* proof,
                                                                                      const uint8_t use_extended_seed);

#ifdef __cplusplus
}
#endif //__cplusplus

#endif // __RANGE_PROOFS_H__
