#include "crypto/algebra_utils/status_convert.h"

ring_pedersen_status algebra_to_ring_pedersen_status(const elliptic_curve_algebra_status status)
{
    switch(status)
    {
    case ELLIPTIC_CURVE_ALGEBRA_SUCCESS:            return RING_PEDERSEN_SUCCESS;
    case ELLIPTIC_CURVE_ALGEBRA_UNKNOWN_ERROR:      return RING_PEDERSEN_UNKNOWN_ERROR;
    case ELLIPTIC_CURVE_ALGEBRA_INVALID_PARAMETER:  return RING_PEDERSEN_INVALID_PARAMETER;
    case ELLIPTIC_CURVE_ALGEBRA_OUT_OF_MEMORY:      return RING_PEDERSEN_OUT_OF_MEMORY;
    case ELLIPTIC_CURVE_ALGEBRA_INSUFFICIENT_BUFFER:return RING_PEDERSEN_BUFFER_TOO_SHORT;
    case ELLIPTIC_CURVE_ALGEBRA_INVALID_SCALAR:     return RING_PEDERSEN_INVALID_PARAMETER;
    case ELLIPTIC_CURVE_ALGEBRA_INVALID_POINT:      return RING_PEDERSEN_INVALID_PARAMETER;
    case ELLIPTIC_CURVE_ALGEBRA_INVALID_SIGNATURE:  return RING_PEDERSEN_INVALID_COMMITMENT;
    default:                                        return RING_PEDERSEN_UNKNOWN_ERROR;
    }
}

zero_knowledge_proof_status convert_drng_to_zkp_status(const drng_status status)
{
    switch (status)
    {
    case DRNG_SUCCESS:              return ZKP_SUCCESS;
    case DRNG_INVALID_PARAMETER:    return ZKP_INVALID_PARAMETER;
    case DRNG_OUT_OF_MEMORY:        return ZKP_OUT_OF_MEMORY;
    case DRNG_INTERNAL_ERROR:       // fallthrough
    default:                        return ZKP_UNKNOWN_ERROR;
    }
}

zero_knowledge_proof_status convert_paillier_to_zkp_status(const long status)
{
    switch (status)
    {
    case PAILLIER_SUCCESS:                      return ZKP_SUCCESS;
    case PAILLIER_ERROR_UNKNOWN:                return ZKP_UNKNOWN_ERROR;
    case PAILLIER_ERROR_OUT_OF_MEMORY:          return ZKP_OUT_OF_MEMORY;
    case PAILLIER_ERROR_INVALID_PARAM:          return ZKP_INVALID_PARAMETER;
    case PAILLIER_ERROR_KEYLEN_TOO_SHORT:       return ZKP_INVALID_PARAMETER;
    case PAILLIER_ERROR_INVALID_PLAIN_TEXT:     return ZKP_INVALID_PARAMETER;
    case PAILLIER_ERROR_INVALID_CIPHER_TEXT:    return ZKP_INVALID_PARAMETER;
    case PAILLIER_ERROR_INVALID_RANDOMNESS:     return ZKP_INVALID_PARAMETER;
    case PAILLIER_ERROR_INVALID_KEY:            return ZKP_INVALID_PARAMETER;
    case PAILLIER_ERROR_INVALID_PROOF:          return ZKP_VERIFICATION_FAILED;
    case PAILLIER_ERROR_BUFFER_TOO_SHORT:       return ZKP_INSUFFICIENT_BUFFER;
    default:                                    return ZKP_UNKNOWN_ERROR;

    }
}

zero_knowledge_proof_status convert_ring_pedersen_to_zkp_status(const ring_pedersen_status status)
{
    switch (status)
    {
    case RING_PEDERSEN_SUCCESS:             return ZKP_SUCCESS;
    case RING_PEDERSEN_INVALID_PARAMETER:   return ZKP_INVALID_PARAMETER;
    case RING_PEDERSEN_OUT_OF_MEMORY:       return ZKP_OUT_OF_MEMORY;
    case RING_PEDERSEN_UNKNOWN_ERROR:       return ZKP_UNKNOWN_ERROR;
    case RING_PEDERSEN_BUFFER_TOO_SHORT:    return ZKP_INSUFFICIENT_BUFFER;
    case RING_PEDERSEN_KEYLEN_TOO_SHORT:    return ZKP_INVALID_PARAMETER;
    case RING_PEDERSEN_INVALID_COMMITMENT:  return ZKP_UNKNOWN_ERROR;
    default:                                return ZKP_VERIFICATION_FAILED;
    }
}

zero_knowledge_proof_status convert_algebra_to_zkp_status(const elliptic_curve_algebra_status status)
{
    
    switch(status)
    {
    case ELLIPTIC_CURVE_ALGEBRA_SUCCESS:            return ZKP_SUCCESS;
    case ELLIPTIC_CURVE_ALGEBRA_UNKNOWN_ERROR:      return ZKP_UNKNOWN_ERROR;
    case ELLIPTIC_CURVE_ALGEBRA_INVALID_PARAMETER:  return ZKP_INVALID_PARAMETER;
    case ELLIPTIC_CURVE_ALGEBRA_OUT_OF_MEMORY:      return ZKP_OUT_OF_MEMORY;
    case ELLIPTIC_CURVE_ALGEBRA_INSUFFICIENT_BUFFER:return ZKP_INSUFFICIENT_BUFFER;
    case ELLIPTIC_CURVE_ALGEBRA_INVALID_SCALAR:     return ZKP_INVALID_PARAMETER;
    case ELLIPTIC_CURVE_ALGEBRA_INVALID_POINT:      return ZKP_INVALID_PARAMETER;
    case ELLIPTIC_CURVE_ALGEBRA_INVALID_SIGNATURE:  return ZKP_VERIFICATION_FAILED;
    default:                                        return ZKP_UNKNOWN_ERROR;
    }
}
