#pragma once

#include "cosigner_export.h"

#include "cosigner/cmp_ecdsa_signing_service.h"

namespace fireblocks
{
namespace common
{
namespace cosigner
{

struct cmp_signature_preprocessed_data;

// this class implements MPC CMP for offline signing based on https://eprint.iacr.org/2020/492 paper
class COSIGNER_EXPORT cmp_ecdsa_offline_signing_service final : public cmp_ecdsa_signing_service
{
public:
    class preprocessing_persistency
    {
    public:
        virtual ~preprocessing_persistency();

        virtual void store_preprocessing_metadata(const std::string& request_id, const preprocessing_metadata& data, bool override = false) = 0;
        virtual void load_preprocessing_metadata(const std::string& request_id, preprocessing_metadata& data) const = 0;
        virtual void store_preprocessing_data(const std::string& request_id, uint64_t index, const ecdsa_signing_data& data) = 0;
        virtual void load_preprocessing_data(const std::string& request_id, uint64_t index, ecdsa_signing_data& data) const = 0;
        virtual void delete_preprocessing_data(const std::string& request_id) = 0;
        
        // This function should allocate preprocessed data array sized size
        virtual void create_preprocessed_data(const std::string& key_id, uint64_t size) = 0;
        // This function set the data at index, in case index is larger then larger then array size the function should throw exception
        virtual void store_preprocessed_data(const std::string& key_id, uint64_t index, const cmp_signature_preprocessed_data& data) = 0;
        // This function load the at index and deletes it, in case index is larger then larger then array size or the value isn't set the function should throw exception
        // Note that the function MUST delete the preprocessed data, as using the same preprocessed data twice may lead to share exposure
        virtual void load_preprocessed_data(const std::string& key_id, uint64_t index, cmp_signature_preprocessed_data& data) = 0;
        virtual void delete_preprocessed_data(const std::string& key_id) = 0;
    };

    cmp_ecdsa_offline_signing_service(platform_service& service, const cmp_key_persistency& key_persistency, preprocessing_persistency& persistency) : cmp_ecdsa_signing_service(service, key_persistency), _preprocessing_persistency(persistency) {}
    
    void start_ecdsa_signature_preprocessing(const std::string& tenant_id, const std::string& key_id, const std::string& request_id, uint32_t start_index, uint32_t count, uint32_t total_count, const std::set<uint64_t>& players_ids, std::vector<cmp_mta_request>& mta_requests);
    uint64_t offline_mta_response(const std::string& request_id, const std::map<uint64_t, std::vector<cmp_mta_request>>& requests, cmp_mta_responses& response);
    uint64_t offline_mta_verify(const std::string& request_id, const std::map<uint64_t, cmp_mta_responses>& mta_responses, std::vector<cmp_mta_deltas>& deltas);
    uint64_t store_presigning_data(const std::string& request_id, const std::map<uint64_t, std::vector<cmp_mta_deltas>>& deltas, std::string& key_id);
    void ecdsa_sign(const std::string& key_id, const std::string& txid, const signing_data& data, const std::string& metadata_json, const std::set<std::string>& players, const std::set<uint64_t>& players_ids, uint64_t preprocessed_data_index,
                            std::vector<recoverable_signature>& partial_sigs);
    uint64_t ecdsa_offline_signature(const std::string& key_id, const std::string& txid, cosigner_sign_algorithm algorithm, const std::map<uint64_t, std::vector<recoverable_signature>>& partial_sigs, 
        std::vector<recoverable_signature>& sigs);

    void cancel_preprocessing(const std::string& request_id);

private:
    preprocessing_persistency& _preprocessing_persistency;
};

}
}
}
