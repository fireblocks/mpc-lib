#pragma once

#include "cosigner_export.h"

#include "asymmetric_eddsa_cosigner.h"
#include "crypto/commitments/commitments.h"
#include "crypto/ed25519_algebra/ed25519_algebra.h"
#include "cosigner/timing_map.h"

#include <openssl/crypto.h>

#include <array>
#include <map>
#include <mutex>
#include <set>
#include <string>
#include <vector>

namespace fireblocks
{
namespace common
{
namespace cosigner
{

struct asymmetric_eddsa_signature_data
{
    elliptic_curve_scalar k;
    elliptic_curve_point R;
    std::vector<uint32_t> path;
    byte_vector_t message;
    uint32_t flags;
    ~asymmetric_eddsa_signature_data() {OPENSSL_cleanse(k.data, sizeof(asymmetric_eddsa_signature_data));}
};

struct asymmetric_eddsa_signing_metadata
{
    std::string key_id;
    HDChaincode chaincode;
    std::vector<asymmetric_eddsa_signature_data> sig_data;
    std::set<uint64_t> signers_ids;
    uint32_t version;
    uint32_t start_index;
};

typedef std::array<uint8_t, sizeof(commitments_sha256_t)> eddsa_commitment;

class COSIGNER_EXPORT asymmetric_eddsa_cosigner_server : public asymmetric_eddsa_cosigner
{
public:
    class signing_persistency
    {
    public:
        virtual ~signing_persistency();

        // This function should allocate preprocessed data array sized size
        virtual void create_preprocessed_data(const std::string& key_id, uint64_t size) = 0;
        // This function set the value R_commitment at index, in case index is larger then larger then array size the function should throw exception
        virtual void store_preprocessed_data(const std::string& key_id, uint64_t index, const eddsa_commitment& R_commitment) = 0;
        // This function load the at index and deletes it, in case index is larger then larger then array size or the value isn't set the function should throw exception
        virtual void load_preprocessed_data(const std::string& key_id, uint64_t index, eddsa_commitment& R_commitment) = 0;
        virtual void delete_preprocessed_data(const std::string& key_id) = 0;

        virtual void store_commitments(const std::string& txid, const std::map<uint64_t, std::vector<eddsa_commitment>>& commitments) = 0;
        virtual void load_commitments(const std::string& txid, std::map<uint64_t, std::vector<eddsa_commitment>>& commitments) = 0;
        virtual void delete_commitments(const std::string& txid) = 0;
        virtual void store_signing_data(const std::string& txid, const asymmetric_eddsa_signing_metadata& data, bool update) = 0;
        virtual void load_signing_data(const std::string& txid, asymmetric_eddsa_signing_metadata& data) = 0;
        virtual void delete_signing_data(const std::string& txid) = 0;
    };

    asymmetric_eddsa_cosigner_server(platform_service& cosigner_service, const cmp_key_persistency& key_persistency, signing_persistency& signing_persistency);
    virtual ~asymmetric_eddsa_cosigner_server() {}

    void store_presigning_data(const std::string& key_id, const std::string& request_id, uint32_t start_index, uint32_t count, uint32_t total_count, const std::set<uint64_t>& players_ids, 
        uint64_t sender, const std::vector<eddsa_commitment>& R_commitments);

    void eddsa_sign_offline(const std::string& key_id, const std::string& txid, const signing_data& data, const std::string& metadata_json, const std::set<std::string>& players, const std::set<uint64_t>& players_ids, uint64_t preprocessed_data_index,
        std::vector<eddsa_commitment>& R_commitments, Rs_and_commitments& Rs);
    uint64_t decommit_r(const std::string& txid, const std::map<uint64_t, std::vector<eddsa_commitment>>& commitments, std::vector<elliptic_curve_point>& Rs);
    uint64_t broadcast_r(const std::string& txid, const std::map<uint64_t, std::vector<elliptic_curve_point>>& players_R, Rs_and_commitments& Rs, uint64_t& send_to);
    uint64_t broadcast_si(const std::string& txid, uint64_t sender, uint32_t version, const std::vector<eddsa_signature>& partial_sigs, std::vector<eddsa_signature>& sigs, std::set<uint64_t>& send_to, bool& final_signature);
    uint64_t get_eddsa_signature(const std::string& txid, const std::map<uint64_t, std::vector<eddsa_signature>>& partial_sigs, std::vector<eddsa_signature>& sigs);

    void cancel_signing(const std::string& txid);

private:
    bool verify_client_s(const ed25519_point_t& R, const ed25519_scalar_t& s, const ed25519_le_scalar_t& hram, const elliptic_curve_point& public_share, const ed25519_scalar_t& delta);
    void commit_to_Rs(const std::string& txid, uint64_t id, const std::vector<elliptic_curve_point>& Rs, eddsa_commitment& commitment);
    signing_persistency& _signing_persistency;

    TimingMap _timing_map;
};

}
}
}
