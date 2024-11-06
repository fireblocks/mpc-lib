#pragma once

#include "cosigner_export.h"

#include "cosigner/cmp_ecdsa_signing_service.h"
#include "cosigner/timing_map.h"

namespace fireblocks
{
namespace common
{
namespace cosigner
{

struct cmp_signature_data : public ecdsa_signing_data
{
    uint32_t flags;
    elliptic_curve256_scalar_t message;
    elliptic_curve_point R;
    std::vector<uint32_t> path;
};

struct cmp_signing_metadata
{
    std::string key_id;
    HDChaincode chaincode;
    commitments_sha256_t ack;
    uint32_t version;
    std::vector<cmp_signature_data> sig_data;
    std::set<uint64_t> signers_ids;
};

// this class implements MPC CMP for online signing based on https://eprint.iacr.org/2020/492 paper
class COSIGNER_EXPORT cmp_ecdsa_online_signing_service final : public cmp_ecdsa_signing_service
{
public:
    class signing_persistency
    {
    public:
        virtual ~signing_persistency();

        virtual void store_cmp_signing_data(const std::string& txid, const cmp_signing_metadata& data) = 0;
        virtual void load_cmp_signing_data(const std::string& txid, cmp_signing_metadata& data) const = 0;
        virtual void update_cmp_signing_data(const std::string& txid, const cmp_signing_metadata& data) = 0;
        virtual void delete_signing_data(const std::string& txid) = 0;
    };

    cmp_ecdsa_online_signing_service(platform_service& service, const cmp_key_persistency& key_persistency, signing_persistency& persistency);

    void start_signing(const std::string& key_id, const std::string& txid, cosigner_sign_algorithm algorithm, const signing_data& data, const std::string& metadata_json, const std::set<std::string>& players, const std::set<uint64_t>& players_ids, std::vector<cmp_mta_request>& mta_requests);
    uint64_t mta_response(const std::string& txid, const std::map<uint64_t, std::vector<cmp_mta_request>>& requests, uint32_t version, cmp_mta_responses& response);
    uint64_t mta_verify(const std::string& txid, const std::map<uint64_t, cmp_mta_responses>& mta_responses, std::vector<cmp_mta_deltas>& deltas);
    uint64_t get_si(const std::string& txid, const std::map<uint64_t, std::vector<cmp_mta_deltas>>& deltas, std::vector<elliptic_curve_scalar>& sis);
    uint64_t get_cmp_signature(const std::string& txid, const std::map<uint64_t, std::vector<elliptic_curve_scalar>>& s, std::vector<recoverable_signature>& full_sig);

    void cancel_signing(const std::string& txid);

private:
    signing_persistency& _signing_persistency;

    TimingMap _timing_map;
};

}
}
}
