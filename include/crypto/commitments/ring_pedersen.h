#ifndef __RING_PEDERSEN_PARAMETERS_H__
#define __RING_PEDERSEN_PARAMETERS_H__

#include <stdint.h>
#include "crypto/zero_knowledge_proof/zero_knowledge_proof_status.h"

#ifdef __cplusplus
extern "C" {
#endif //__cplusplus

typedef struct ring_pedersen_private ring_pedersen_private_t;
typedef struct ring_pedersen_public ring_pedersen_public_t;

typedef enum
{
    RING_PEDERSEN_SUCCESS               =  0,
    RING_PEDERSEN_UNKNOWN_ERROR         = -1,
    RING_PEDERSEN_KEYLEN_TOO_SHORT      = -2,
    RING_PEDERSEN_INVALID_PARAMETER     = -3,
    RING_PEDERSEN_BUFFER_TOO_SHORT      = -4,
    RING_PEDERSEN_INVALID_COMMITMENT    = -5,
    RING_PEDERSEN_OUT_OF_MEMORY         = -6,
} ring_pedersen_status;

typedef struct
{
    uint32_t size;
    uint8_t *data;
} ring_pedersen_batch_data_t;


ring_pedersen_status ring_pedersen_generate_key_pair(uint32_t key_len, ring_pedersen_public_t **pub, ring_pedersen_private_t **priv);

uint32_t ring_pedersen_public_size(const ring_pedersen_public_t *pub);
uint8_t *ring_pedersen_public_serialize(const ring_pedersen_public_t *pub, uint8_t *buffer, uint32_t buffer_len, uint32_t *real_buffer_len);
ring_pedersen_public_t *ring_pedersen_public_deserialize(const uint8_t *buffer, uint32_t buffer_len);
void ring_pedersen_free_public(ring_pedersen_public_t *pub);

const ring_pedersen_public_t* ring_pedersen_private_key_get_public(const ring_pedersen_private_t *priv); // the returned public pey must not be freed!
uint8_t *ring_pedersen_private_serialize(const ring_pedersen_private_t *priv, uint8_t *buffer, uint32_t buffer_len, uint32_t *real_buffer_len);
ring_pedersen_private_t *ring_pedersen_private_deserialize(const uint8_t *buffer, uint32_t buffer_len);
void ring_pedersen_free_private(ring_pedersen_private_t *priv);

zero_knowledge_proof_status ring_pedersen_parameters_zkp_generate(const ring_pedersen_private_t *priv, const uint8_t *aad, uint32_t aad_len, uint8_t *serialized_proof, uint32_t proof_len, uint32_t *proof_real_len);
zero_knowledge_proof_status ring_pedersen_parameters_zkp_verify(const ring_pedersen_public_t *pub, const uint8_t *aad, uint32_t aad_len, const uint8_t *serialized_proof, uint32_t proof_len);

ring_pedersen_status ring_pedersen_create_commitment(const ring_pedersen_public_t *pub, const uint8_t *x, uint32_t x_len, const uint8_t *r, uint32_t r_len, uint8_t *commitment, uint32_t commitment_len, uint32_t *commitment_real_len);
ring_pedersen_status ring_pedersen_verify_commitment(const ring_pedersen_private_t *priv, const uint8_t *x, uint32_t x_len, const uint8_t *r, uint32_t r_len, const uint8_t *commitment, uint32_t commitment_len);
ring_pedersen_status ring_pedersen_verify_batch_commitments(const ring_pedersen_private_t *priv, uint32_t batch_size, const ring_pedersen_batch_data_t *x, const ring_pedersen_batch_data_t *r, const ring_pedersen_batch_data_t *commitments);

#ifdef __cplusplus
}
#endif //__cplusplus

#endif // __RING_PEDERSEN_PARAMETERS_H__
