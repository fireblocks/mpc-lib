#pragma once
#include "cosigner_export.h"
#include "bam_ecdsa_cosigner.h"
#include "bam_key_persistency_structures_server.h"

struct elliptic_curve256_algebra_ctx;

namespace fireblocks::common::cosigner
{

class bam_key_persistency_server;
class bam_tx_persistency_server;

class COSIGNER_EXPORT bam_ecdsa_cosigner_server : public bam_ecdsa_cosigner
{
public:
    bam_ecdsa_cosigner_server(platform_service& cosigner_service, bam_key_persistency_server& key_persistecy, bam_tx_persistency_server& tx_persistecy);

    void shutdown();

    // generate setup proof. Can be reused for multiple clients
    void generate_setup_with_proof(const std::string& setup_id,
                                   const std::string& tenant_id,
                                   const cosigner_sign_algorithm algorithm,
                                   server_setup_shared_data& serialized_setup_data);



    void generate_share_and_commit(const std::string& setup_id,
                                   const std::string& key_id,
                                   const uint64_t server_id,
                                   const uint64_t client_id,
                                   const cosigner_sign_algorithm algorithm,
                                   commitments_sha256_t& B);

    void add_user_and_commit(const std::string& setup_id,
                             const std::string& key_id,
                             const uint64_t server_id,
                             const uint64_t client_id,
                             const cosigner_sign_algorithm algorithm,
                             const std::map<uint64_t, add_user_data>& data,
                             commitments_sha256_t& B);


    // 2nd stage of key generation - verify client proofs and generate server decommitment
    void verify_client_proofs_and_decommit_share_with_proof(const std::string& key_id,
                                                            const uint64_t client_id,
                                                            const client_key_shared_data& client_message,
                                                            server_key_shared_data& server_message);

    // Initiate signature process
    void generate_signature_share(const std::string& key_id,
                                  const std::string& tx_id,
                                  const uint32_t version,
                                  const uint64_t server_id,
                                  const uint64_t client_id,
                                  const cosigner_sign_algorithm requested_algorithm,
                                  const common::cosigner::signing_data& data,
                                  const std::string& metadata_json,
                                  const std::set<std::string>& players_set,
                                  std::vector<server_signature_shared_data>& server_commitments);

    // 2nd stage signature function
    void verify_partial_signature_and_output_signature(const std::string& tx_id,
                                                       const uint64_t client_id,
                                                       const std::vector<client_partial_signature_data>& partial_signatures,
                                                       std::vector<recoverable_signature>& signatures,
                                                       cosigner_sign_algorithm& algorithm);

    void get_public_key(const std::string& key_id, generated_public_key& pub_key_data) const;

private:
    bam_setup_auxilary_key_server generate_setup_secrets();
    bam_setup_metadata_server generate_setup_metadata(const byte_vector_t& setup_aad, const cosigner_sign_algorithm algorithm);

    void generate_setup_proofs(const bam_setup_auxilary_key_server& setup_keys,
                               const byte_vector_t& setup_aad,
                               byte_vector_t& paillier_blum,
                               byte_vector_t& small_factors,
                               byte_vector_t& damgard_fujisaki);

    // associates key_id with the setup_id
    // and commit to a private share
    void commit_to_share(const std::string& setup_id,
                         const std::string& key_id,
                         const uint64_t server_id,
                         const uint64_t client_id,
                         const cosigner_sign_algorithm algorithm,
                         const elliptic_curve_scalar& private_share, //the share is generated outside
                         const elliptic_curve256_point_t& expected_public_key,
                         commitments_sha256_t& B);


    void validate_tenant_id_setup(const std::string& setup_id) const;

    bam_key_persistency_server& _key_persistency;
    bam_tx_persistency_server& _tx_persistency;
};

} //namespace fireblocks::common::cosigner