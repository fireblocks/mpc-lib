#pragma once

#include <exception>
#include <string>

#include "cosigner_export.h"
#include "crypto/commitments/commitments.h"
#include "crypto/commitments/ring_pedersen.h"
#include "crypto/elliptic_curve_algebra/elliptic_curve_algebra_status.h"
#include "crypto/shamir_secret_sharing/verifiable_secret_sharing.h"
#include "crypto/zero_knowledge_proof/zero_knowledge_proof_status.h"
#include "crypto/drng/drng.h"
#include "cosigner_status.h"

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
    const char* what() const noexcept override
    {
        switch (_err)
        {
            case INTERNAL_ERROR: return "Internal error has occurred";
            case INVALID_PARAMETERS: return "Invalid parameter";
            case BAD_KEY: return "Wrong keyid was specified";
            case NOT_ALIGNED_DATA: return "Data to signed size must be a aligned to key size";
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
            case BAD_IMPORTED_KEY_ALREADY_EXISTS: return "The specified key id is already registered";
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

class unknown_txid_exception : public std::exception
{
public:
    unknown_txid_exception(const std::string& txid) : _txid(txid) {}
    const std::string& get_txid() const {return _txid;}
private:
    const std::string _txid;
};

template <class T>
struct cosigner_exception_type_name
{
    static constexpr const bool implemented = false;
};

#define DECLARE_COSIGNER_EXCEPTION_TYPE_EX(TYPE, ANNOTATION) \
    ANNOTATION COSIGNER_EXPORT void do_throw_cosigner_exception(TYPE status); \
    template <> \
    struct cosigner_exception_type_name<TYPE> \
    { \
        static constexpr const bool implemented = true;\
        static constexpr const char* name = #TYPE;\
    }

#define DECLARE_COSIGNER_EXCEPTION_TYPE(TYPE)     DECLARE_COSIGNER_EXCEPTION_TYPE_EX(TYPE, )

enum paillier_dummy_error_code
{

};

DECLARE_COSIGNER_EXCEPTION_TYPE_EX(cosigner_exception::exception_code, [[noreturn]]);
DECLARE_COSIGNER_EXCEPTION_TYPE(verifiable_secret_sharing_status);
DECLARE_COSIGNER_EXCEPTION_TYPE(elliptic_curve_algebra_status);
DECLARE_COSIGNER_EXCEPTION_TYPE(commitments_status);
DECLARE_COSIGNER_EXCEPTION_TYPE(zero_knowledge_proof_status);
DECLARE_COSIGNER_EXCEPTION_TYPE(paillier_dummy_error_code);
DECLARE_COSIGNER_EXCEPTION_TYPE(ring_pedersen_status);
DECLARE_COSIGNER_EXCEPTION_TYPE(drng_status);
DECLARE_COSIGNER_EXCEPTION_TYPE(cosigner_status_t);

// use this function instead of including logging.h file directly. 
// Otherwise will force the cosigner tests to link with the full logging stack.
COSIGNER_EXPORT void log_exception(const std::string& name, const std::string& what, const char* file, const char* func, const int line);

#define throw_cosigner_exception(X) do \
    { \
        typedef std::remove_const<std::remove_reference<decltype((X))>::type>::type basa_type; \
        static_assert(::fireblocks::common::cosigner::cosigner_exception_type_name<basa_type>::implemented, "Must be implemented"); \
        basa_type ret(static_cast<basa_type>(-1)); \
        try \
        { \
            ret = (X); \
            ::fireblocks::common::cosigner::do_throw_cosigner_exception(ret);\
        } \
        catch(const std::exception& ex##__LINE__) \
        { \
            ::fireblocks::common::cosigner::log_exception(::fireblocks::common::cosigner::cosigner_exception_type_name<basa_type>::name, \
                          (ex##__LINE__).what(), \
                          __FILE__, \
                          __PRETTY_FUNCTION__, \
                          __LINE__); \
            throw; \
        } \
        catch(...) \
        { \
            ::fireblocks::common::cosigner::log_exception(::fireblocks::common::cosigner::cosigner_exception_type_name<basa_type>::name, \
                          "", \
                          __FILE__, \
                          __PRETTY_FUNCTION__, \
                          __LINE__); \
            throw; \
        } \
    } while(false)

#define throw_paillier_exception(X) throw_cosigner_exception((paillier_dummy_error_code)(X))

}
}
}