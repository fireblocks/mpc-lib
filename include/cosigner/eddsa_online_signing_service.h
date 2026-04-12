#pragma once

#include "cosigner_export.h"

#include "cosigner/types.h"
#include "cosigner/timing_map.h"

#include <openssl/crypto.h>
#include <map>
#include <memory>
#include <mutex>

namespace fireblocks
{
namespace common
{
namespace cosigner
{

class cmp_key_persistency;
class platform_service;

struct eddsa_signature_data
{
    elliptic_curve_scalar k;
    elliptic_curve_point R;
    elliptic_curve_scalar s;
    std::vector<uint32_t> path;
    byte_vector_t message;
    uint32_t flags;
    ~eddsa_signature_data() {OPENSSL_cleanse(k.data, sizeof(k.data));}
};

struct eddsa_signing_metadata
{
    std::string key_id;
    HDChaincode chaincode;
    std::vector<eddsa_signature_data> sig_data;
    std::set<uint64_t> signers_ids;
    uint32_t version;
    int64_t timestamp;
    commitments_map commitments;
};

class COSIGNER_EXPORT eddsa_online_signing_service final
{
public:
    class signing_persistency
    {
    public:
        virtual ~signing_persistency() = default;
        virtual void store_eddsa_signing_data(const std::string& txid, const std::shared_ptr<eddsa_signing_metadata>& data) = 0;
        virtual std::shared_ptr<eddsa_signing_metadata> load_eddsa_signing_data(const std::string& txid) const = 0;
        virtual void update_eddsa_signing_data(const std::string& txid, const std::shared_ptr<eddsa_signing_metadata>& data) = 0;
        virtual void store_signing_commitments(const std::string& txid, const commitments_map& commitments) = 0;
        virtual void load_signing_commitments(const std::string& txid, commitments_map& commitments) = 0;
        virtual bool delete_eddsa_signing_data(const std::string& txid) = 0;
};

    eddsa_online_signing_service(platform_service& service, const cmp_key_persistency& key_persistency, signing_persistency& signing_persistency) : _service(service), _key_persistency(key_persistency), _signing_persistency(signing_persistency), _timing_map(service) {}
    void start_signing(const std::string& key_id, const std::string& txid, const signing_data& data, const std::string& metadata_json, const std::set<std::string>& players, const std::set<uint64_t>& players_ids, std::vector<commitment>& commitments);
    uint64_t store_commitments(const std::string& txid, const commitments_map& commitments, uint32_t version, std::vector<elliptic_curve_point>& R);
    uint64_t broadcast_si(const std::string& txid, const std::map<uint64_t, std::vector<elliptic_curve_point>>& Rs, std::vector<elliptic_curve_scalar>& si);
    uint64_t get_eddsa_signature(const std::string& txid, const std::map<uint64_t, std::vector<elliptic_curve_scalar>>& s, std::vector<eddsa_signature>& sig);

    void cancel_signing(const std::string& txid);

private:
    void calc_w(elliptic_curve_scalar& x, uint64_t my_id, const std::set<uint64_t>& ids);
    platform_service& _service;
    const cmp_key_persistency& _key_persistency;
    signing_persistency& _signing_persistency;

    TimingMap _timing_map;

    static const std::unique_ptr<elliptic_curve256_algebra_ctx_t, void(*)(elliptic_curve256_algebra_ctx_t*)> _ed25519;
};

}
}
}
