#pragma once

#include "cosigner/asymmetric_eddsa_cosigner.h"

#include <array>
#include <map>
#include <set>
#include <string>
#include <vector>

namespace fireblocks
{
namespace common
{
namespace cosigner
{


class asymmetric_eddsa_cosigner_client : public asymmetric_eddsa_cosigner
{
public:
    class preprocessing_persistency
    {
    public:
        virtual ~preprocessing_persistency() {}
        // This function should allocate preprocessed data array sized size
        virtual void create_preprocessed_data(const std::string& key_id, uint64_t size) = 0;
        // This function set the value k at index, in case index is larger then larger then array size the function should throw exception
        virtual void store_preprocessed_data(const std::string& key_id, uint64_t index, const ed25519_scalar_t& k) = 0;
        // This function load the at index and deletes it, in case index is larger then larger then array size or the value isn't set the function should throw exception
        virtual void load_preprocessed_data(const std::string& key_id, uint64_t index, ed25519_scalar_t& k) = 0;
        virtual void delete_preprocessed_data(const std::string& key_id) = 0;
    };

    asymmetric_eddsa_cosigner_client(platform_service& cosigner_service, const cmp_key_persistency& key_persistency, preprocessing_persistency& preprocessing_persistency);
    ~asymmetric_eddsa_cosigner_client();

    virtual void start_signature_preprocessing(const std::string& tenant_id, const std::string& key_id, const std::string& request_id, uint32_t start_index, uint32_t count, uint32_t total_count, const std::set<uint64_t>& players_ids, 
        std::vector<std::array<uint8_t, sizeof(commitments_sha256_t)>>& R_commitments);
    virtual uint64_t eddsa_sign_offline(const std::string& key_id, const std::string& txid, const signing_data& data, const std::string& metadata_json, const std::set<std::string>& players, const std::set<uint64_t>& players_ids, uint64_t preprocessed_data_index,
        const std::map<uint64_t, Rs_and_commitments>& Rs, std::vector<eddsa_signature>& partial_sigs);

private:
    preprocessing_persistency& _preprocessing_persistency;
};

}
}
}
