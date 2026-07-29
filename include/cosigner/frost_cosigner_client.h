#pragma once

#include "cosigner/frost_cosigner.h"
#include <vector>

namespace fireblocks::common::cosigner
{

class frost_key_persistency_client;

class COSIGNER_EXPORT frost_cosigner_client : public frost_cosigner
{
public:
    frost_cosigner_client(platform_service& platform_service, frost_key_persistency_client& key_persistency);
    virtual ~frost_cosigner_client() = default;

    void start_new_key_generation(const std::string& key_id,
                                  const std::string& tenant_id,
                                  const uint64_t client_id,
                                  const uint64_t server_id,
                                  cosigner_sign_algorithm algo);

    void start_add_user(const std::string& key_id,
                        const std::string& tenant_id,
                        const uint64_t client_id,
                        const uint64_t server_id,
                        const cosigner_sign_algorithm algo,
                        const std::map<uint64_t, add_user_data>& data);

    void store_commitment_and_generate_proofs(const std::string& key_id, const commitments_sha256_t& B, const uint64_t server_id, frost_cosigner::key_share_public_data& message);
    void verify_key_decommitment_and_proofs(const std::string& key_id, const uint64_t server_id, const frost_cosigner::key_share_public_data& server_message, frost_cosigner::generated_public_key& pub_key_data);

    void compute_partial_signature(const std::string& key_id,
                                   const std::string& tx_id,
                                   const uint32_t version,
                                   const uint64_t server_id,
                                   const uint64_t client_id,
                                   const signing_data& data,
                                   const std::string& metadata_json,
                                   const std::set<std::string>& players_set,
                                   const std::vector<frost_cosigner::server_signature_shared_data>& server_shares,
                                   std::vector<frost_cosigner::client_partial_signature_data>& partial_signatures);
private:
    void start_key_generation(const std::string& key_id,
        const std::string& tenant_id,
        const uint64_t client_id,
        const uint64_t server_id,
        const cosigner_sign_algorithm algo,
        const elliptic_curve_scalar& secret,
        const elliptic_curve256_point_t& expected_public_key);

    frost_key_persistency_client& _key_persistency;

};

}
