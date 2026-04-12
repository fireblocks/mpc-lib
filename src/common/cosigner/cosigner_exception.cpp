#include "cosigner/cosigner_exception.h"
#include "crypto/paillier/paillier.h"
#include "logging/logging_t.h"

namespace fireblocks
{
namespace common
{
namespace cosigner
{

void do_throw_cosigner_exception(verifiable_secret_sharing_status status)
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

void do_throw_cosigner_exception(elliptic_curve_algebra_status status)
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

void do_throw_cosigner_exception(commitments_status status)
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

void do_throw_cosigner_exception(zero_knowledge_proof_status status)
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

void do_throw_cosigner_exception(paillier_dummy_error_code paillier_error_code)
{
    long status = (long)paillier_error_code;
    if (status == PAILLIER_SUCCESS)
    {
        return;
    }
    else if (status == PAILLIER_ERROR_OUT_OF_MEMORY)
    {
        throw cosigner_exception(cosigner_exception::NO_MEM);
    }
    
    if (PAILLIER_IS_OPENSSL_ERROR(status))
    {
        LOG_ERROR("openssl error %ld in paillier", PAILLIER_TO_OPENSSL_ERROR(status));
    }
    
    throw cosigner_exception(cosigner_exception::INTERNAL_ERROR);
}

void do_throw_cosigner_exception(ring_pedersen_status status)
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

void do_throw_cosigner_exception(drng_status status)
{
    switch (status)
    {
        case DRNG_SUCCESS: return;
        case DRNG_INVALID_PARAMETER: throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
        case DRNG_OUT_OF_MEMORY: throw cosigner_exception(cosigner_exception::NO_MEM);
        case DRNG_INTERNAL_ERROR:
        default: throw cosigner_exception(cosigner_exception::INTERNAL_ERROR);
    }
}


void do_throw_cosigner_exception(cosigner_status_t status)
{
    switch (status)
    {
        case COSIGNER_STATUS_SUCCESS: return; 
        case COSIGNER_STATUS_INVALID_PARAMETER: throw cosigner_exception(cosigner_exception::INTERNAL_ERROR);
        case COSIGNER_STATUS_BAD_PRIVATE_KEY: throw cosigner_exception(cosigner_exception::BAD_KEY);
        case COSIGNER_STATUS_BAD_KEY_LEN: throw cosigner_exception(cosigner_exception::BAD_KEY);
        case COSIGNER_STATUS_BAD_DATA_LEN: throw  cosigner_exception(cosigner_exception::NOT_ALIGNED_DATA);
        case COSIGNER_STATUS_PUBLIC_KEY_TOO_SMALL: throw cosigner_exception(cosigner_exception::INTERNAL_ERROR);
        case COSIGNER_STATUS_SIGNATURE_BLOCK_TOO_SMALL: throw cosigner_exception(cosigner_exception::INTERNAL_ERROR);
        case COSIGNER_STATUS_NOT_IMPLEMENTED: throw cosigner_exception(cosigner_exception::NOT_IMPLEMENTED);
        case COSIGNER_STATUS_UNKNOWN_ALGORITHM: throw cosigner_exception(cosigner_exception::UNKNOWN_ALGORITHM);
        case COSIGNER_STATUS_INTERNAL_ERROR:
        default: throw cosigner_exception(cosigner_exception::INTERNAL_ERROR);
    }
}

void log_exception(const std::string& name, const std::string& what, const char* file, const char* func, const int line)
{
    if (!what.empty())
    {
        cosigner_log_msg(COSIGNER_LOG_LEVEL_ERROR, file, line, func, "Throwing cosigner exception %s:%s", name.c_str(), what.c_str() );
    }
    else
    {
        cosigner_log_msg(COSIGNER_LOG_LEVEL_ERROR, file, line, func, "Throwing cosigner exception %s", name.c_str());
    }
}

void do_throw_cosigner_exception(cosigner_exception::exception_code code)
{
    throw cosigner_exception(code);
}

}
}
}
