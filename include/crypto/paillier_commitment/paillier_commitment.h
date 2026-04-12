#ifndef __PAILLIER_COMMITMENT_H__
#define __PAILLIER_COMMITMENT_H__

#include <stdint.h>
#include "crypto/paillier/paillier.h"
#include "crypto/zero_knowledge_proof/zero_knowledge_proof_status.h"
#include "cosigner_export.h"

#ifdef __cplusplus
extern "C" {
#endif //__cplusplus

/**
 * Structures representing Paillier Commitment keys and commitments.
 */
typedef struct paillier_commitment_public_key paillier_commitment_public_key_t;
typedef struct paillier_commitment_private_key paillier_commitment_private_key_t;
typedef struct paillier_commitment_with_randomizer_power paillier_commitment_with_randomizer_power_t;

/**
 * Generates a private key for the Paillier Commitment scheme.
 * 
 * @param key_len Length of the key in bits (must be a multiple of 256).
 * @param priv Pointer to a pointer to hold the generated private key.
 * @return 0 on success, or an error code on failure.
 */
COSIGNER_EXPORT long paillier_commitment_generate_private_key(const uint32_t key_len, paillier_commitment_private_key_t **priv);

/**
 * Returns the public key associated with a given private key.
 * 
 * @param priv Pointer to the private key.
 * @return Pointer to the public key. Do not free this pointer directly.
 */
COSIGNER_EXPORT const paillier_commitment_public_key_t* paillier_commitment_private_cast_to_public(const paillier_commitment_private_key_t *priv);

/**
 * Frees the memory allocated for a public key.
 * 
 * @param pub Pointer to the public key to free.
 */
COSIGNER_EXPORT void paillier_commitment_free_public_key(paillier_commitment_public_key_t *pub);

/**
 * Frees the memory allocated for a private key.
 * 
 * @param priv Pointer to the private key to free.
 */
COSIGNER_EXPORT void paillier_commitment_free_private_key(paillier_commitment_private_key_t *priv);

/**
 * Returns the bit size of the modulus (n) in the public key.
 * 
 * @param pub Pointer to the public key.
 * @return Size of n in bits, or 0 if the public key is invalid.
 */
COSIGNER_EXPORT uint32_t paillier_commitment_public_bitsize(const paillier_commitment_public_key_t *pub);

/**
 * Serializes a public key to a buffer.
 * 
 * @param pub Pointer to the public key to serialize.
 * @param is_reduced Flag indicating if a reduced serialization should be used.
 * @param buffer Buffer to store the serialized key.
 * @param buffer_len Length of the buffer.
 * @param real_buffer_len Actual length of the serialized key.
 * @return 0 on success, or an error code on failure.
 */
COSIGNER_EXPORT long paillier_commitment_public_key_serialize(const paillier_commitment_public_key_t *pub,
                                                              const int is_reduced,
                                                              uint8_t *buffer,
                                                              const uint32_t buffer_len,
                                                              uint32_t *real_buffer_len);

/**
 * Deserializes a public key from a buffer.
 * 
 * @param is_reduced Flag indicating if the serialization is reduced.
 * @param buffer Buffer containing the serialized key.
 * @param buffer_len Length of the buffer.
 * @return Pointer to the deserialized public key, or NULL on failure.
 */
COSIGNER_EXPORT paillier_commitment_public_key_t* paillier_commitment_public_key_deserialize(const int is_reduced, const uint8_t *buffer, uint32_t buffer_len);

/**
 * Serializes a private key to a buffer.
 * 
 * @param priv Pointer to the private key to serialize.
 * @param buffer Buffer to store the serialized key.
 * @param buffer_len Length of the buffer.
 * @param real_buffer_len Actual length of the serialized key.
 * @return 0 on success, or an error code on failure.
 */
COSIGNER_EXPORT long paillier_commitment_private_key_serialize(const paillier_commitment_private_key_t *priv,
                                                               uint8_t *buffer,
                                                               const uint32_t buffer_len,
                                                               uint32_t *real_buffer_len);

/**
 * Deserializes a private key from a buffer.
 * 
 * @param buffer Buffer containing the serialized key.
 * @param buffer_len Length of the buffer.
 * @return Pointer to the deserialized private key, or NULL on failure.
 */
COSIGNER_EXPORT paillier_commitment_private_key_t* paillier_commitment_private_key_deserialize(const uint8_t *buffer, uint32_t buffer_len);

/**
 * Encrypts a plaintext using a Paillier Commitment public key.
 * 
 * @param key Pointer to the public key.
 * @param plaintext Pointer to the plaintext data.
 * @param plaintext_len Length of the plaintext in bytes.
 * @param ciphertext Buffer to store the ciphertext.
 * @param ciphertext_len Length of the ciphertext buffer.
 * @param ciphertext_real_len Actual length of the ciphertext.
 * @return 0 on success, or an error code on failure.
 */
COSIGNER_EXPORT long paillier_commitment_encrypt(const paillier_commitment_public_key_t *key,
                                                 const uint8_t *plaintext,
                                                 const uint32_t plaintext_len,
                                                 uint8_t *ciphertext,
                                                 const uint32_t ciphertext_len,
                                                 uint32_t *ciphertext_real_len);

/**
 * Decrypts a ciphertext using a Paillier Commitment private key.
 * 
 * @param priv Pointer to the private key.
 * @param ciphertext Pointer to the ciphertext data.
 * @param ciphertext_len Length of the ciphertext in bytes.
 * @param plaintext Buffer to store the decrypted plaintext.
 * @param plaintext_len Length of the plaintext buffer.
 * @param plaintext_real_len Actual length of the plaintext.
 * @return 0 on success, or an error code on failure.
 */
COSIGNER_EXPORT long paillier_commitment_decrypt(const paillier_commitment_private_key_t *priv,
                                                 const uint8_t *ciphertext,
                                                 const uint32_t ciphertext_len,
                                                 uint8_t *plaintext,
                                                 const uint32_t plaintext_len,
                                                 uint32_t *plaintext_real_len);

/**
 * Generates a commitment with a given randomizer and modifier.
 * 
 * @param pub Pointer to the public key.
 * @param commited_value Pointer to the value to commit to.
 * @param commited_value_len Length of the committed value in bytes.
 * @param randomizer_bitlength Bit length of the randomizer.
 * @param modifier Pointer to the optional modifier.
 * @param modifier_size Length of the modifier in bytes.
 * @param modifier_exp Pointer to the optional modifier exponent.
 * @param modifier_exp_size Length of the modifier exponent in bytes.
 * @param commitment Pointer to store the generated commitment.
 * @return 0 on success, or an error code on failure.
 */
COSIGNER_EXPORT long paillier_commitment_commit(const paillier_commitment_public_key_t *pub,
                                                const uint8_t *commited_value,
                                                const uint32_t commited_value_len,
                                                const uint32_t randomizer_bitlength,
                                                const uint8_t *modifier,
                                                const uint32_t modifier_size,
                                                const uint8_t *modifier_exp,
                                                const uint32_t modifier_exp_size,
                                                paillier_commitment_with_randomizer_power_t** commitment);

/**
 * Verifies a commitment against the original value, modifier, and randomizer.
 * 
 * @param pub Pointer to the public key.
 * @param commited_value Pointer to the committed value.
 * @param commited_value_len Length of the committed value in bytes.
 * @param modifier Pointer to the modifier used during commitment.
 * @param modifier_size Length of the modifier in bytes.
 * @param modifier_exp Pointer to the modifier exponent.
 * @param modifier_exp_size Length of the modifier exponent in bytes.
 * @param commitment Pointer to the commitment to verify.
 * @return 0 if valid, or an error code if invalid.
 */
COSIGNER_EXPORT long paillier_commitment_verify(const paillier_commitment_public_key_t *pub,
                                                const uint8_t *commited_value,
                                                const uint32_t commited_value_len,
                                                const uint8_t *modifier,
                                                const uint32_t modifier_size,
                                                const uint8_t *modifier_exp,
                                                const uint32_t modifier_exp_size,
                                                const paillier_commitment_with_randomizer_power_t* commitment);

/**
 * Frees the memory allocated for a commitment.
 * 
 * @param commitment Pointer to the commitment to free.
 */
COSIGNER_EXPORT void paillier_commitment_commitment_free(paillier_commitment_with_randomizer_power_t* commitment);

/**
 * Serializes a commitment to a buffer.
 * 
 * @param commitment Pointer to the commitment to serialize.
 * @param serialized_proof Buffer to store the serialized proof.
 * @param proof_len Length of the serialized proof buffer.
 * @param real_proof_len Actual length of the serialized proof.
 * @return 0 on success, or an error code on failure.
 */
COSIGNER_EXPORT long paillier_commitment_commitment_serialize(const paillier_commitment_with_randomizer_power_t* commitment, 
                                                              uint8_t *serialized_proof, 
                                                              uint32_t proof_len, 
                                                              uint32_t *real_proof_len);

/**
 * Deserializes a commitment from a buffer.
 * 
 * @param serialized_proof Buffer containing the serialized proof.
 * @param proof_len Length of the buffer.
 * @return Pointer to the deserialized commitment, or NULL on failure.
 */
COSIGNER_EXPORT paillier_commitment_with_randomizer_power_t* paillier_commitment_commitment_deserialize(const uint8_t *serialized_proof, const uint32_t proof_len);

/**
 * Generates a zero-knowledge proof (ZKP) for a Paillier Commitment using Blum's protocol.
 * 
 * @param priv Pointer to the private key.
 * @param aad Additional authenticated data for the ZKP.
 * @param aad_len Length of the additional authenticated data.
 * @param serialized_proof Buffer to store the serialized ZKP.
 * @param proof_len Length of the buffer.
 * @param proof_real_len Actual length of the ZKP.
 * @return 0 on success, or an error code on failure.
 */
COSIGNER_EXPORT long paillier_commitment_paillier_blum_zkp_generate(const paillier_commitment_private_key_t *priv, 
                                                                    const uint8_t *aad, 
                                                                    uint32_t aad_len, 
                                                                    uint8_t *serialized_proof, 
                                                                    uint32_t proof_len, 
                                                                    uint32_t *proof_real_len);

/**
 * Verifies a zero-knowledge proof (ZKP) for a Paillier Commitment using Blum's protocol.
 * 
 * @param pub Pointer to the public key.
 * @param aad Additional authenticated data for the ZKP.
 * @param aad_len Length of the additional authenticated data.
 * @param serialized_proof Buffer containing the serialized ZKP.
 * @param proof_len Length of the buffer.
 * @return 0 if valid, or an error code if invalid.
 */
COSIGNER_EXPORT long paillier_commitment_paillier_blum_zkp_verify(const paillier_commitment_public_key_t *pub, 
                                                                  const uint8_t *aad, 
                                                                  uint32_t aad_len, 
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
COSIGNER_EXPORT uint32_t range_proof_paillier_commitment_large_factors_zkp_compute_d_bitsize(const paillier_commitment_public_key_t* pub);

/**
 * Generates a range proof for a Paillier Commitment with large factors.
 * 
 * @param priv Pointer to the private key.
 * @param aad Additional authenticated data for the proof.
 * @param aad_len Length of the additional authenticated data.
 * @param d_prime Large prime to be used to generate the proof
 * @param d_prime_len d_prime size
 * @param serialized_proof Buffer to store the serialized proof.
 * @param proof_len Length of the buffer.
 * @param real_proof_len Actual length of the proof.
 * @return Status of the proof generation (success or error).
 */
COSIGNER_EXPORT zero_knowledge_proof_status range_proof_paillier_commitment_large_factors_zkp_generate(
    const paillier_commitment_private_key_t *priv, 
    const uint8_t *aad, 
    const uint32_t aad_len, 
    const uint8_t *d_prime,
    const uint32_t d_prime_len,
    uint8_t *serialized_proof, 
    uint32_t proof_len, 
    uint32_t *real_proof_len);

/**
 * Verifies a range proof for a Paillier Commitment with large factors.
 * 
 * @param pub Pointer to the public key.
 * @param aad Additional authenticated data for the proof.
 * @param aad_len Length of the additional authenticated data.
 * @param serialized_proof Buffer containing the serialized proof.
 * @param proof_len Length of the buffer.
 * @return Status of the proof verification (success or error).
 */
COSIGNER_EXPORT zero_knowledge_proof_status range_proof_paillier_commitment_large_factors_zkp_verify(
    const paillier_commitment_public_key_t *pub, 
    const uint8_t *aad, 
    const uint32_t aad_len, 
    const uint8_t *serialized_proof, 
    const uint32_t proof_len);

/**
 * Generates a zero-knowledge proof (ZKP) for the Damgård-Fujisaki parameters in a Paillier Commitment.
 * 
 * @param priv Pointer to the private key.
 * @param aad Additional authenticated data for the ZKP.
 * @param aad_len Length of the additional authenticated data.
 * @param challenge_bitlength Length of the ZKP challenge in bits.
 * @param serialized_proof Buffer to store the serialized ZKP.
 * @param proof_len Length of the buffer.
 * @param proof_real_len Actual length of the ZKP.
 * @return Status of the ZKP generation (success or error).
 */
COSIGNER_EXPORT zero_knowledge_proof_status paillier_commitment_damgard_fujisaki_parameters_zkp_generate(
    const paillier_commitment_private_key_t *priv, 
    const uint8_t* aad, 
    const uint32_t aad_len, 
     uint8_t* serialized_proof, 
    const uint32_t proof_len, 
    uint32_t* proof_real_len);

/**
 * Verifies a zero-knowledge proof (ZKP) for the Damgård-Fujisaki parameters in a Paillier Commitment.
 * 
 * @param pub Pointer to the public key.
 * @param aad Additional authenticated data for the ZKP.
 * @param aad_len Length of the additional authenticated data.
  * @param serialized_proof Buffer containing the serialized ZKP.
 * @param proof_len Length of the buffer.
 * @return Status of the ZKP verification (success or error).
 */
COSIGNER_EXPORT zero_knowledge_proof_status paillier_commitment_damgard_fujisaki_parameters_zkp_verify(
    const paillier_commitment_public_key_t *pub, 
    const uint8_t* aad, 
    const uint32_t aad_len, 
    const uint8_t* serialized_proof, 
    const uint32_t proof_len);

#ifdef __cplusplus
}
#endif //__cplusplus

#endif
