#include "cosigner/cosigner_exception.h"
#include "crypto/paillier/paillier.h"
#include "logging/logging_t.h"

namespace fireblocks
{
namespace common
{
namespace cosigner
{

void throw_cosigner_exception(verifiable_secret_sharing_status status)
{
    switch (status)
    {
        case VERIFIABLE_SECRET_SHARING_SUCCESS: return; 
        case VERIFIABLE_SECRET_SHARING_INVALID_PARAMETER: throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
        case VERIFIABLE_SECRET_SHARING_INVALID_SHARE: throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
        case VERIFIABLE_SECRET_SHARING_OUT_OF_MEMORY: throw cosigner_exception(cosigner_exception::NO_MEM);
        case VERIFIABLE_SECRET_SHARING_UNKNOWN_ERROR:
        case VERIFIABLE_SECRET_SHARING_INVALID_INDEX:
        case VERIFIABLE_SECRET_SHARING_INVALID_SECRET:
        case VERIFIABLE_SECRET_SHARING_INVALID_SHARE_ID:
        case VERIFIABLE_SECRET_SHARING_INSUFFICIENT_BUFFER:
        default: throw cosigner_exception(cosigner_exception::INTERNAL_ERROR);
    }
}

void throw_cosigner_exception(elliptic_curve_algebra_status status)
{
    switch (status)
    {
        case ELLIPTIC_CURVE_ALGEBRA_SUCCESS: return; 
        case ELLIPTIC_CURVE_ALGEBRA_INVALID_PARAMETER: throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
        case ELLIPTIC_CURVE_ALGEBRA_INVALID_POINT: throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
        case ELLIPTIC_CURVE_ALGEBRA_INVALID_SCALAR: throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
        case ELLIPTIC_CURVE_ALGEBRA_OUT_OF_MEMORY: throw cosigner_exception(cosigner_exception::NO_MEM);
        case ELLIPTIC_CURVE_ALGEBRA_INSUFFICIENT_BUFFER:
        case ELLIPTIC_CURVE_ALGEBRA_UNKNOWN_ERROR:
        case ELLIPTIC_CURVE_ALGEBRA_INVALID_SIGNATURE:
        default: throw cosigner_exception(cosigner_exception::INTERNAL_ERROR);
    }
}

void throw_cosigner_exception(commitments_status status)
{
    switch (status)
    {
        case COMMITMENTS_SUCCESS: return; 
        case COMMITMENTS_INVALID_PARAMETER: throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
        case COMMITMENTS_INVALID_CONTEXT: throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
        case COMMITMENTS_OUT_OF_MEMORY: throw cosigner_exception(cosigner_exception::NO_MEM);
        case COMMITMENTS_INVALID_COMMITMENT: throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
        case COMMITMENTS_INTERNAL_ERROR:
        default: throw cosigner_exception(cosigner_exception::INTERNAL_ERROR);
    }
}

void throw_cosigner_exception(zero_knowledge_proof_status status)
{
    switch (status)
    {
        case ZKP_SUCCESS: return;
        case ZKP_INVALID_PARAMETER: throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
        case ZKP_INSUFFICIENT_BUFFER: throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
        case ZKP_VERIFICATION_FAILED: throw cosigner_exception(cosigner_exception::INTERNAL_ERROR);
        case ZKP_OUT_OF_MEMORY: throw cosigner_exception(cosigner_exception::NO_MEM);
        case ZKP_UNKNOWN_ERROR:
        default: throw cosigner_exception(cosigner_exception::INTERNAL_ERROR);
    }
}

void throw_paillier_exception(long status)
{
    if (status == PAILLIER_SUCCESS)
        return;
    else if (status == PAILLIER_ERROR_OUT_OF_MEMORY)
        throw cosigner_exception(cosigner_exception::NO_MEM);
    if (PAILLIER_IS_OPENSSL_ERROR(status))
    {
        LOG_ERROR("openssl error %ld in paillier", PAILLIER_TO_OPENSSL_ERROR(status));
    }
    throw cosigner_exception(cosigner_exception::INTERNAL_ERROR);
}

void throw_cosigner_exception(ring_pedersen_status status)
{
    switch (status)
    {
        case RING_PEDERSEN_SUCCESS: return; 
        case RING_PEDERSEN_INVALID_PARAMETER: throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
        case RING_PEDERSEN_BUFFER_TOO_SHORT: throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
        case RING_PEDERSEN_KEYLEN_TOO_SHORT: throw cosigner_exception(cosigner_exception::INTERNAL_ERROR);
        case RING_PEDERSEN_OUT_OF_MEMORY: throw cosigner_exception(cosigner_exception::NO_MEM);
        case RING_PEDERSEN_UNKNOWN_ERROR:
        case RING_PEDERSEN_INVALID_COMMITMENT:
        default: throw cosigner_exception(cosigner_exception::INTERNAL_ERROR);
    }
}

}
}
}