#pragma once

#include "cosigner/types.h"
#include "cosigner/cosigner_exception.h"

#include "crypto/paillier/paillier.h"

#include <map>
#include <memory>

namespace fireblocks
{
namespace common
{
namespace cosigner
{

namespace mta
{
    class response_verifier;
}

class cmp_key_persistency;
class platform_service;
class cmp_key_metadata;
struct auxiliary_keys;

struct cmp_mta_message
{
    byte_vector_t message;
    byte_vector_t commitment;
    byte_vector_t proof;
};

struct cmp_mta_request
{
    cmp_mta_message mta;
    std::map<uint64_t, byte_vector_t> mta_proofs;
    elliptic_curve_point A;
    elliptic_curve_point B;
    elliptic_curve_point Z;
};

struct cmp_mta_response
{
    std::map<uint64_t, cmp_mta_message> k_gamma_mta;
    std::map<uint64_t, cmp_mta_message> k_x_mta;
    elliptic_curve_point GAMMA;
    std::map<uint64_t, byte_vector_t> gamma_proofs;
};

struct cmp_mta_responses
{
    commitments_sha256_t ack;
    std::vector<cmp_mta_response> response;
};

struct cmp_mta_deltas
{
    elliptic_curve_scalar delta;
    elliptic_curve_point DELTA;
    byte_vector_t proof;
};

struct ecdsa_signing_public_data
{
    elliptic_curve_point A;
    elliptic_curve_point B;
    elliptic_curve_point Z;
    elliptic_curve_point GAMMA;
    byte_vector_t gamma_commitment;
};

struct ecdsa_signing_data
{
    elliptic_curve_scalar k;
    elliptic_curve_scalar gamma;
    elliptic_curve_scalar a;
    elliptic_curve_scalar b;
    elliptic_curve_scalar delta;
    elliptic_curve_scalar chi;
    elliptic_curve_point GAMMA;
    byte_vector_t mta_request;
    std::map<uint64_t, byte_vector_t> G_proofs;
    std::map<uint64_t, ecdsa_signing_public_data> public_data;
    ~ecdsa_signing_data() {memset_s(k.data, sizeof(ecdsa_signing_data), 0, sizeof(elliptic_curve256_scalar_t) * 6);}
};

// this class holds the common functionality for cmp_ecdsa_online_signing_service and cmp_ecdsa_offline_signing_service
class cmp_ecdsa_signing_service
{
protected:
    cmp_ecdsa_signing_service(platform_service& service, const cmp_key_persistency& key_persistency) : _service(service), _key_persistency(key_persistency) {}
    virtual ~cmp_ecdsa_signing_service() {}

    static cmp_mta_request create_mta_request(ecdsa_signing_data& data, const elliptic_curve256_algebra_ctx_t* algebra, uint64_t my_id, const std::vector<uint8_t>& aad, const cmp_key_metadata& metadata, const std::shared_ptr<paillier_public_key_t>& paillier);
    static void ack_mta_request(uint32_t count, const std::map<uint64_t, std::vector<cmp_mta_request>>& requests, const std::set<uint64_t>& player_ids, commitments_sha256_t& ack);
    static cmp_mta_response create_mta_response(ecdsa_signing_data& data, const elliptic_curve256_algebra_ctx_t* algebra, uint64_t my_id, const std::vector<uint8_t>& aad, const cmp_key_metadata& metadata,
        const std::map<uint64_t, std::vector<cmp_mta_request>>& requests, size_t index, const elliptic_curve_scalar& key, const auxiliary_keys& aux_keys);
    static cmp_mta_deltas mta_verify(ecdsa_signing_data& data, const elliptic_curve256_algebra_ctx_t* algebra, uint64_t my_id, const std::string& uuid, const std::vector<uint8_t>& aad, const cmp_key_metadata& metadata,
        const std::map<uint64_t, cmp_mta_responses>& mta_responses, size_t index, const auxiliary_keys& aux_keys, std::map<uint64_t, mta::response_verifier>& verifers);
    static void calc_R(ecdsa_signing_data& data, elliptic_curve_point& R, const elliptic_curve256_algebra_ctx_t* algebra, uint64_t my_id, const std::string& uuid, const cmp_key_metadata& metadata,
        const std::map<uint64_t, std::vector<cmp_mta_deltas>>& deltas, size_t index);

    static elliptic_curve_scalar derivation_key_delta(const elliptic_curve256_algebra_ctx_t* algebra, const elliptic_curve256_point_t& public_key, const HDChaincode& chaincode, const std::vector<uint32_t>& path);
    static void make_sig_s_positive(cosigner_sign_algorithm algorithm, elliptic_curve256_algebra_ctx_t* algebra, recoverable_signature& sig);
    static std::vector<uint8_t> build_aad(const std::string& sid, uint64_t id, const commitments_sha256_t srid);

    static inline elliptic_curve256_algebra_ctx_t* get_algebra(cosigner_sign_algorithm algorithm)  {return algorithm == ECDSA_SECP256K1 ? _secp256k1.get() : 
                                                                                                    algorithm == ECDSA_SECP256R1 ? _secp256r1.get() : 
                                                                                                    algorithm == ECDSA_STARK ? _stark.get() : 
                                                                                                    throw cosigner_exception(cosigner_exception::UNKNOWN_ALGORITHM);}

    static inline bool is_odd_point(const elliptic_curve256_point_t& p)
    {
        return (p[0] & 1) == 1;
    }

    static inline bool is_positive(cosigner_sign_algorithm algorithm, const elliptic_curve256_scalar_t& n)
    {
        if (algorithm == ECDSA_STARK)
            return n[0] < 4; // stark curve is 252bit
        return (n[0] & 0x80) == 0;
    }

    platform_service& _service;
    const cmp_key_persistency& _key_persistency;

    static const std::unique_ptr<elliptic_curve256_algebra_ctx_t, void(*)(elliptic_curve256_algebra_ctx_t*)> _secp256k1;
    static const std::unique_ptr<elliptic_curve256_algebra_ctx_t, void(*)(elliptic_curve256_algebra_ctx_t*)> _secp256r1;
    static const std::unique_ptr<elliptic_curve256_algebra_ctx_t, void(*)(elliptic_curve256_algebra_ctx_t*)> _stark;
};

}
}
}
