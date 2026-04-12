#pragma once
#include "cosigner_export.h"
#include "bam_ecdsa_cosigner.h"
#include "crypto/zero_knowledge_proof/range_proofs.h"

struct damgard_fujisaki_public;
struct elliptic_curve256_algebra_ctx;
struct pedersen_commitment_two_generators;

namespace fireblocks::common::cosigner
{

class bam_key_persistency_client;
class bam_tx_persistency_client;
struct bam_temp_key_data_client;
struct bam_key_metadata_client;
class COSIGNER_EXPORT bam_ecdsa_cosigner_client : public bam_ecdsa_cosigner 
{
public:
    bam_ecdsa_cosigner_client(platform_service& platform_service, 
                              bam_key_persistency_client& key_persistecy,
                              bam_tx_persistency_client& tx_persistency);


    void start_new_key_generation(const std::string& setup_id, 
                                  const std::string& key_id, 
                                  const std::string& tenant_id,
                                  const uint64_t server_id,
                                  const uint64_t client_id, 
                                  const cosigner_sign_algorithm algorithm);

    void start_add_user(const std::string& setup_id, 
                        const std::string& key_id, 
                        const std::string& tenant_id,
                        const uint64_t server_id,
                        const uint64_t client_id, 
                        const cosigner_sign_algorithm algorithm,
                        const std::map<uint64_t, add_user_data>& data);

    
    // Receives server proofs and finalizes key generation
    // 1. setup completion function. Receives server generated setup data and verifies it.
    //      it was decided that the client setup verification is always done a part of the key generation
    //      so key_id and setup_id are tightly coupled. 
    //      This is the reason the client has only one persistent metadata - key metadata and thus key id
    //      is required in all function.
    // 2. Receives server commitment B and generates client proofs
    //      it actually unites two steps - temporary storing of the server commitment 
    //      and generation of the client proofs that do not depend on the commitment
    //      (but commitment has to be received and stored before the proofs are sent out)
    //      also associates key_id with tenant, algorithm and setup_id
    void verify_setup_proof_store_key_commitment_generate_key_proof(const std::string& setup_id, 
                                                                    const std::string& key_id,
                                                                    const uint64_t server_id,
                                                                    const server_setup_shared_data& setup,
                                                                    const commitments_sha256_t& B,
                                                                    client_key_shared_data& client_key_data);

    // retrieves server commitment B and verifies it. The commitment is deleted, so it cannot be reused
    void verify_key_decommitment_and_proofs(const std::string& key_id, 
                                            const uint64_t server_id,
                                            const uint64_t client_id, 
                                            const server_key_shared_data& server_message,
                                            generated_public_key& pub_key_data);

    // 1st signature generation function
    // Saves signature information and associates key with tx_id
    void prepare_for_signature(const std::string& key_id, 
                               const std::string& tx_id, 
                               const uint32_t version,
                               const uint64_t server_id,
                               const uint64_t client_id,
                               const common::cosigner::signing_data& data,
                               const std::string& matadata_json,
                               const std::set<std::string>& players_set);

    void compute_partial_signature(const std::string& tx_id, 
                                   const std::vector<server_signature_shared_data>& server_shares,
                                   std::vector<client_partial_signature_data>& partial_signatures);

private:

    void verify_setup_proof(const std::string& setup_id, 
                            const server_setup_shared_data& setup,
                            bam_key_metadata_client& client_key_metadata) const;

    void start_key_generation(const std::string& setup_id, 
                              const std::string& key_id, 
                              const std::string& tenant_id,
                              const uint64_t server_id,
                              const uint64_t client_id, 
                              const cosigner_sign_algorithm algorithm,
                              const elliptic_curve_scalar& private_share,
                              const elliptic_curve256_point_t& expected_public_key);

    void generate_share_and_proofs(const std::string& key_id, 
                                   const bam_key_metadata_client& client_key_metadata,
                                   bam_temp_key_data_client& client_temp_key_data,
                                   client_key_shared_data& client_key_message) const;

    void well_formed_signature_range_proof_generate(const paillier_commitment_public_key_t *paillier,
                                                    elliptic_curve256_algebra_ctx* algebra,
                                                    const pedersen_commitment_two_generators* ec_base,
                                                    const commitments_sha256_t& signature_add,
                                                    const elliptic_curve256_point_t& r_server,
                                                    const struct bignum_st* plaintext,
                                                    const struct bignum_st* encrypted_share,
                                                    const struct bignum_st* exponent,
                                                    struct bignum_ctx *ctx,
                                                    client_partial_signature_data &partial_signature);
    
    void validate_tenant_id_setup(const std::string& setup_id) const;

    bam_key_persistency_client& _key_persistency;
    bam_tx_persistency_client& _tx_persistency;
};

} //namespace fireblocks::common::cosigner