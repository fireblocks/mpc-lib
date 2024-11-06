#pragma once

#include "cosigner_export.h"

#include "crypto/commitments/commitments.h"
#include "crypto/commitments/ring_pedersen.h"
#include "crypto/elliptic_curve_algebra/elliptic_curve_algebra_status.h"
#include "crypto/shamir_secret_sharing/verifiable_secret_sharing.h"
#include "crypto/zero_knowledge_proof/zero_knowledge_proof_status.h"

#include <exception>
#include <string>

namespace fireblocks
{
namespace common
{
namespace cosigner
{

class COSIGNER_EXPORT cosigner_exception : public std::exception
{
public:
    enum exception_code
    {
        GENERIC_ERROR,
        INTERNAL_ERROR,
        INVALID_PARAMETERS,
        BAD_KEY,
        INVALID_TRANSACTION,
        NOT_ALIGNED_DATA,
        NOT_IMPLEMENTED,
        UNKNOWN_ALGORITHM,
        NO_MEM,
        UNAUTHORIZED,
        REJECTED,
        BUSY,
        BACKUP_FAILED,
        AUTHORIZATION_FAILED,
        DISABLED_DEVICE,
        INVALID_PRESIGNING_INDEX,
        BAD_IMPORTED_PUBLIC_KEY,
        BAD_IMPORTED_PRIVATE_KEY,
        BAD_IMPORTED_KEY_ALREADY_EXISTS,
        NO_SIGNING_INFO_GIVEN,
        PARTIAL_SIGNING_INFO_GIVEN
    };

    cosigner_exception(exception_code err) : _err(err) {}
    ~cosigner_exception();

    const char* what() const noexcept override
    {
        switch (_err)
        {
            case INTERNAL_ERROR: return "Internal error has occurred";
            case INVALID_PARAMETERS: return "Invalid parameter";
            case BAD_KEY: return "Wrong keyid was specified";
            case NOT_ALIGNED_DATA: return "Data to signed size must be a alligned to key size";
            case NOT_IMPLEMENTED: return "Operation not yet implemented";
            case UNKNOWN_ALGORITHM: return "Unknown signing algorithm was specified";
            case INVALID_TRANSACTION: return "Invalid transaction id";
            case NO_MEM: return "Out of memory";
            case UNAUTHORIZED: return "Unauthorized request";
            case REJECTED: return "Request rejected by user";
            case BUSY: return "Cosigner is busy, try later";
            case BACKUP_FAILED: return "Failed to backup db";
            case AUTHORIZATION_FAILED: return "Failed to authorize transaction";
            case DISABLED_DEVICE: return "The device was disabled";
            case INVALID_PRESIGNING_INDEX: return "The presigning info index is invalid";
            case BAD_IMPORTED_PUBLIC_KEY: return "The imported public key is invalid";
            case BAD_IMPORTED_PRIVATE_KEY: return "The imported private key is invalid or incorrectly encrypted";
            case BAD_IMPORTED_KEY_ALREADY_EXISTS: return "The specified key id already is already registered";
            case NO_SIGNING_INFO_GIVEN: return "No signing info was given";
            case PARTIAL_SIGNING_INFO_GIVEN: return "Partial signing info was given";
            case GENERIC_ERROR:
            default: return "Unexpected error";
        }
    }
    exception_code error_code() const {return _err;}

private:
    const exception_code _err;
};

class COSIGNER_EXPORT unknown_txid_exception : public std::exception
{
public:
    unknown_txid_exception(const std::string& txid) : _txid(txid) {}
    const std::string& get_txid() const {return _txid;}
private:
    const std::string _txid;
};

COSIGNER_EXPORT void throw_cosigner_exception(verifiable_secret_sharing_status status);
COSIGNER_EXPORT void throw_cosigner_exception(elliptic_curve_algebra_status status);
COSIGNER_EXPORT void throw_cosigner_exception(commitments_status status);
COSIGNER_EXPORT void throw_cosigner_exception(zero_knowledge_proof_status status);
COSIGNER_EXPORT void throw_paillier_exception(long status);
COSIGNER_EXPORT void throw_cosigner_exception(ring_pedersen_status status);

}
}
}
