#pragma once

#include "cosigner/frost_cosigner.h"
#include <set>
#include <string>

namespace fireblocks::common::cosigner
{

class frost_key_persistency_server;
class frost_tx_persistency;

class COSIGNER_EXPORT frost_cosigner_server : public frost_cosigner
{
public:
    frost_cosigner_server(platform_service& platform_service, frost_key_persistency_server& key_persistency, frost_tx_persistency& tx_persistency);
    virtual ~frost_cosigner_server() = default;

    void shutdown();

    void generate_share_and_commit(const std::string& key_id, const std::string& tenant_id, cosigner_sign_algorithm algo, uint64_t server_id, uint64_t client_id, commitments_sha256_t& commitment);
    void add_user_and_commit(const std::string& key_id, const std::string& tenant_id, cosigner_sign_algorithm algo, uint64_t server_id, uint64_t client_id, const std::map<uint64_t, add_user_data>& data, commitments_sha256_t& commitment);
    void verify_client_proofs_and_decommit_share_with_proof(const std::string& key_id, uint64_t server_id, uint64_t client_id, const key_share_public_data& client_key_share_message, key_share_public_data& server_key_share_message);

    // Batch signing entry point — following BAM's generate_signature_share naming and pattern
    void generate_signature_share(const std::string& key_id, const std::string& tx_id,
                                  uint32_t version, uint64_t server_id, uint64_t client_id,
                                  const signing_data& data, const std::string& metadata_json,
                                  const std::set<std::string>& players_set,
                                  cosigner_sign_algorithm requested_algorithm,
                                  std::vector<server_signature_shared_data>& commitments);

    void verify_partial_signature_and_output_signature(const std::string& key_id,
                                                       const std::string& tx_id,
                                                       uint64_t client_id,
                                                       const std::vector<client_partial_signature_data>& partial_signatures,
                                                       std::vector<eddsa_signature>& full_signatures,
                                                       cosigner_sign_algorithm& algorithm);

    void get_public_key(const std::string& key_id, generated_public_key& pub_key_data) const;
    int validate_schnorr_signature(const elliptic_curve256_algebra_ctx_t *ctx, const eddsa_signature& cur_sig, const uint8_t* message,
                                   size_t message_len, const elliptic_curve256_point_t *derived_public_key, bool use_keccak,
                                   const byte_vector_t& prefix = byte_vector_t(), const byte_vector_t& suffix = byte_vector_t());
private:
    void commit_to_share(const cosigner_sign_algorithm algo, const std::string& key_id, uint64_t server_id, uint64_t client_id,
                         const elliptic_curve256_point_t& public_key, const elliptic_curve_scalar& secret_key, commitments_sha256_t& commitment);

    frost_key_persistency_server& _key_persistency;
    frost_tx_persistency& _tx_persistency;
};

}
