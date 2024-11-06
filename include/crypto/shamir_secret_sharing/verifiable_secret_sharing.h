#ifndef __VERIFIABLE_SECRET_SHARING_H__
#define __VERIFIABLE_SECRET_SHARING_H__

#include "cosigner_export.h"

#ifdef __cplusplus
extern "C" {
#endif //__cplusplus

#include <stdint.h>

#include "crypto/elliptic_curve_algebra/elliptic_curve256_algebra.h"
#include "crypto/commitments/commitments.h"

/*
*  This module implements shamir secret sharing over 2^256 field (same field used by secp256k1) e.g. module 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f
*/

typedef struct verifiable_secret_sharing verifiable_secret_sharing_t;

/* uint256_t represented in big endian */
typedef elliptic_curve256_scalar_t shamir_secret_sharing_scalar_t;

typedef struct shamir_secret_share
{
    shamir_secret_sharing_scalar_t data;
    uint64_t id;
} shamir_secret_share_t;

typedef enum
{
    VERIFIABLE_SECRET_SHARING_SUCCESS               =  0,
    VERIFIABLE_SECRET_SHARING_UNKNOWN_ERROR         = -1,
    VERIFIABLE_SECRET_SHARING_INVALID_PARAMETER     = -2,
    VERIFIABLE_SECRET_SHARING_INVALID_INDEX         = -3,
    VERIFIABLE_SECRET_SHARING_INVALID_SECRET        = -4,
    VERIFIABLE_SECRET_SHARING_INVALID_SHARE         = -5,
    VERIFIABLE_SECRET_SHARING_INVALID_SHARE_ID      = -6,
    VERIFIABLE_SECRET_SHARING_INSUFFICIENT_BUFFER   = -7,
    VERIFIABLE_SECRET_SHARING_OUT_OF_MEMORY         = -8,
} verifiable_secret_sharing_status;

/* Splits the secret to n shares, so any subset t of them can reconstruct the secret */
COSIGNER_EXPORT verifiable_secret_sharing_status verifiable_secret_sharing_split(const elliptic_curve256_algebra_ctx_t *algebra, const uint8_t *secret, uint32_t secret_len, uint8_t t, uint8_t n, verifiable_secret_sharing_t **shares);
/* Splits the secret to n shares, so any subset t of them can reconstruct the secret using user provided ids for the users (instead of running index) 
 * ids must be an arry of size n */
COSIGNER_EXPORT verifiable_secret_sharing_status verifiable_secret_sharing_split_with_custom_ids(const elliptic_curve256_algebra_ctx_t *algebra, const uint8_t *secret, uint32_t secret_len, uint8_t t, uint8_t n, uint64_t *ids, 
    verifiable_secret_sharing_t **shares);

/* Gets a spesific share (zero indexed) from initialized shares */
COSIGNER_EXPORT verifiable_secret_sharing_status verifiable_secret_sharing_get_share(const verifiable_secret_sharing_t *shares, uint8_t index, shamir_secret_share_t *share);
/* Gets a spesific share and it's zero knowledge proof (zero indexed) from initialized shares */
COSIGNER_EXPORT verifiable_secret_sharing_status verifiable_secret_sharing_get_share_and_proof(const verifiable_secret_sharing_t *shares, uint8_t index, shamir_secret_share_t *share, elliptic_curve256_point_t *proof);
/* Gets a commitment for all shares */
COSIGNER_EXPORT verifiable_secret_sharing_status verifiable_secret_sharing_get_shares_commitment(const verifiable_secret_sharing_t *shares, commitments_commitment_t *commitment);

/* Gets the number of players e.g. n, -1 is returned if shares are invalid */
COSIGNER_EXPORT int verifiable_secret_sharing_get_number_of_players(const verifiable_secret_sharing_t *shares);
/* Gets the threshold of the of the schema e.g. t, -1 is returned if shares are invalid */
COSIGNER_EXPORT int verifiable_secret_sharing_get_threshold(const verifiable_secret_sharing_t *shares);
/* Gets proofs for the polynom coefficients e.g. G^coef, proofs_count must be >= threshold */
COSIGNER_EXPORT verifiable_secret_sharing_status verifiable_secret_sharing_get_polynom_proofs(const verifiable_secret_sharing_t *shares, elliptic_curve256_point_t *proofs, uint8_t proofs_count);
/* Gets commitments for polynom coefficients e.g. SHA(G^coef) */
COSIGNER_EXPORT verifiable_secret_sharing_status verifiable_secret_sharing_get_polynom_commitment(const verifiable_secret_sharing_t *shares, commitments_commitment_t *commitment);

/* Reconstruct the secret using shares_count shares, the actual size of the share is optionally returned via out_secret_len 
 * if shares_count is less then the needed t shares wrong secret will be generated */
COSIGNER_EXPORT verifiable_secret_sharing_status verifiable_secret_sharing_reconstruct(const elliptic_curve256_algebra_ctx_t *algebra, const shamir_secret_share_t *shares, uint8_t shares_count, uint8_t *secret, uint32_t secret_len, uint32_t *out_secret_len);

/* Verifies that share proof for share id id, is a vaild share for polynom represented by coefficient_proofs
 * The share proof it self should be authenticated using secp256k1_algebra_verify function 
 * each share proof and coefficient proof should be verified using the pre given commitments and the verifiable_secret_sharing_verify_commitment func */
COSIGNER_EXPORT verifiable_secret_sharing_status verifiable_secret_sharing_verify_share(const elliptic_curve256_algebra_ctx_t *algebra, uint64_t id, const elliptic_curve256_point_t *share_proof, uint8_t threshold, const elliptic_curve256_point_t *coefficient_proofs);
/* Verfies the proofs commitment (SHA256) */
COSIGNER_EXPORT verifiable_secret_sharing_status verifiable_secret_sharing_verify_commitment(const elliptic_curve256_point_t *proofs, uint8_t proofs_count, const commitments_commitment_t *commitment);

COSIGNER_EXPORT void verifiable_secret_sharing_free_shares(verifiable_secret_sharing_t *shares);

#ifdef __cplusplus
}
#endif //__cplusplus

#endif // __VERIFIABLE_SECRET_SHARING_H__