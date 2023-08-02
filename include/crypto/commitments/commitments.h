#ifndef __COMMITMENTS_H__
#define __COMMITMENTS_H__

#ifdef __cplusplus
extern "C" {
#endif //__cplusplus

#include <stdint.h>

typedef struct commitments_ctx commitments_ctx_t;

typedef uint8_t commitments_sha256_t[32];

typedef struct commitments_commitment
{
    commitments_sha256_t salt;
    commitments_sha256_t commitment;
} commitments_commitment_t;

typedef enum
{
    COMMITMENTS_SUCCESS               =  0,
    COMMITMENTS_INTERNAL_ERROR        = -1,
    COMMITMENTS_INVALID_PARAMETER     = -2,
    COMMITMENTS_OUT_OF_MEMORY         = -3,
    COMMITMENTS_INVALID_CONTEXT       = -4,
    COMMITMENTS_INVALID_COMMITMENT    = -5,
} commitments_status;

/* Creates commitment (SHA256) the data */
commitments_status commitments_create_commitment_for_data(const uint8_t *data, uint32_t data_len, commitments_commitment_t *commitment);
/* Verfies the data commitment (SHA256) */
commitments_status commitments_verify_commitment(const uint8_t *data, uint32_t data_len, const commitments_commitment_t *commitment);

/* Commitment context functions are usfull to create/verify commitment on scattered data */

/* Creates commitment context */
commitments_status commitments_ctx_commitment_new(commitments_ctx_t **ctx);
/* Updates commitment context with data */
commitments_status commitments_ctx_commitment_update(commitments_ctx_t *ctx, const void *data, uint32_t data_len);
/* Creates final commitment, and frees the commitment context */
commitments_status commitments_ctx_commitment_final(commitments_ctx_t *ctx, commitments_commitment_t *commitment);

/* Creates commitment verification context */
commitments_status commitments_ctx_verify_new(commitments_ctx_t **ctx, const commitments_commitment_t *commitment);
/* Updates commitment verification context with data */
commitments_status commitments_ctx_verify_update(commitments_ctx_t *ctx, const void *data, uint32_t data_len);
/* Verfies the commitment, and frees the commitment context */
commitments_status commitments_ctx_verify_final(commitments_ctx_t *ctx);

// frees the commitment context, usefull for breaking in the middle of commit/verify operation
void commitments_ctx_free(commitments_ctx_t *ctx);

#ifdef __cplusplus
}
#endif //__cplusplus

#endif // __COMMITMENTS_H__