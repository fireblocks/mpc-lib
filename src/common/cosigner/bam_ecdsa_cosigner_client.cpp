#include "cosigner/bam_ecdsa_cosigner_client.h"
#include "cosigner/cosigner_exception.h"
#include "cosigner/platform_service.h"
#include "cosigner/bam_key_persistency_client.h"
#include "cosigner/bam_tx_persistency_client.h"
#include "crypto/commitments/damgard_fujisaki.h"
#include "crypto/zero_knowledge_proof/range_proofs.h"
#include "crypto/zero_knowledge_proof/schnorr.h"
#include "../crypto/paillier_commitment/paillier_commitment_internal.h"
#include "crypto/algebra_utils/algebra_utils.h"
#include "crypto/GFp_curve_algebra/GFp_curve_algebra.h"
#include "bam_well_formed_proof.h"
#include "cosigner_bn.h"

#include "logging/logging_t.h"
#include <cinttypes>

namespace fireblocks::common::cosigner
{

bam_ecdsa_cosigner_client::bam_ecdsa_cosigner_client(platform_service& platform_service, 
                                                     bam_key_persistency_client& key_persistecy,
                                                     bam_tx_persistency_client& tx_persistecy):
    bam_ecdsa_cosigner(platform_service),
    _key_persistency(key_persistecy),
    _tx_persistency(tx_persistecy)
{

}

void bam_ecdsa_cosigner_client::start_new_key_generation(const std::string& setup_id, 
                                                         const std::string& key_id, 
                                                         const std::string& tenant_id,
                                                         const uint64_t server_id,
                                                         const uint64_t client_id, 
                                                         const cosigner_sign_algorithm algorithm)
{
    validate_current_tenant_id(tenant_id);
    
    elliptic_curve_scalar private_share;
    generate_private_share(algorithm, private_share);
    const auto algebra = get_algebra(algorithm);

    start_key_generation(setup_id, key_id, tenant_id, server_id, client_id, algorithm, private_share, *(algebra->infinity_point(algebra)));
}

void bam_ecdsa_cosigner_client::start_add_user(const std::string& setup_id, 
                                               const std::string& key_id, 
                                               const std::string& tenant_id,
                                               const uint64_t server_id,
                                               const uint64_t client_id, 
                                               const cosigner_sign_algorithm algorithm,
                                               const std::map<uint64_t, add_user_data>& data)
{
    validate_current_tenant_id(tenant_id);

    elliptic_curve_scalar private_share;
    elliptic_curve256_point_t expected_public_key;
    
    decrypt_and_rebuild_private_share(client_id, algorithm, data, private_share, expected_public_key);

    start_key_generation(setup_id, key_id, tenant_id, server_id, client_id, algorithm, private_share, expected_public_key);
}


void bam_ecdsa_cosigner_client::start_key_generation(const std::string& setup_id, 
                                                     const std::string& key_id, 
                                                     const std::string& tenant_id,
                                                     const uint64_t server_id,
                                                     const uint64_t client_id, 
                                                     const cosigner_sign_algorithm algorithm,
                                                     const elliptic_curve_scalar& private_share,
                                                     const elliptic_curve256_point_t& expected_public_key)
{
    if (client_id == server_id)
    {
        LOG_ERROR("Client and server ids are the same");
        throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
    }

    LOG_INFO("Generating client share for key %s tenant %s server id %" PRIu64 ", client id %" PRIu64 ", algorithm %d", key_id.c_str(), tenant_id.c_str(), server_id, client_id, algorithm);    

    bam_key_metadata_client client_key_metadata(algorithm, setup_id, server_id, expected_public_key);
   
    generate_aad_for_key_gen(key_id, client_id, server_id, client_key_metadata.seed);
    
    _platform_service.mark_key_setup_in_progress(key_id);

    _key_persistency.store_tenant_id_for_setup(setup_id, tenant_id);
    _key_persistency.store_key_metadata(key_id, client_key_metadata, false); //first time storing key metadata
    _key_persistency.store_key(key_id, algorithm, private_share.data);
}

void bam_ecdsa_cosigner_client::verify_setup_proof_store_key_commitment_generate_key_proof(const std::string& setup_id, 
                                                                                           const std::string& key_id,
                                                                                           const uint64_t server_id,
                                                                                           const server_setup_shared_data& setup,
                                                                                           const commitments_sha256_t& B,
                                                                                           client_key_shared_data& client_key_message)
{
    bam_key_metadata_client client_key_metadata;
    _key_persistency.load_key_metadata(key_id, client_key_metadata);

    if (client_key_metadata.peer_id != server_id)
    {
        LOG_ERROR("Wrong server id for key %s. %" PRIu64 " != %" PRIu64, key_id.c_str(), client_key_metadata.peer_id, server_id);
        throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
    }

    if (client_key_metadata.setup_id != setup_id)
    {
        LOG_ERROR("Setup data for the key %s was originally initiated for setup %s. And now it is %s", key_id.c_str(), client_key_metadata.setup_id.c_str(), setup_id.c_str());
        throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
    }

    validate_tenant_id_setup(setup_id);

    if (client_key_metadata.paillier_commitment_pub)
    {
        LOG_ERROR("Setup data for the key %s is already stored", key_id.c_str());
        throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
    }

    verify_setup_proof(setup_id, setup, client_key_metadata);

    bam_temp_key_data_client client_temp_key_data; // client holds only temporary auxiliary key data
    memcpy(&client_temp_key_data.server_commitment[0], &B[0], sizeof(commitments_sha256_t));

    generate_share_and_proofs(key_id, client_key_metadata, client_temp_key_data, client_key_message);

    // if all of them are verified, then store the setup keys.
    _key_persistency.store_key_metadata(key_id, client_key_metadata, true);
    _key_persistency.store_key_temp_data(key_id, client_temp_key_data);
}

void bam_ecdsa_cosigner_client::verify_setup_proof(const std::string& setup_id, 
                                                   const server_setup_shared_data& setup,
                                                   bam_key_metadata_client& client_key_metadata) const
{

    // Paillier
    client_key_metadata.paillier_commitment_pub = 
        std::shared_ptr<paillier_commitment_public_key_t>(
                paillier_commitment_public_key_deserialize(1,
                                                           setup.paillier_commitment_pub.data(), 
                                                           setup.paillier_commitment_pub.size()), 
                paillier_commitment_free_public_key);

    if (!client_key_metadata.paillier_commitment_pub) 
    {
        LOG_ERROR("Failed to deserialize Paillier public key.");
        throw_paillier_exception(PAILLIER_ERROR_UNKNOWN);
    }
    
    // we'll allow Paillier keys to be at most 16 bits smaller than the expected one.
    const uint32_t paillier_public_key_size = paillier_commitment_public_bitsize(client_key_metadata.paillier_commitment_pub.get());
    if (paillier_public_key_size < cosigner_params::PAILLIER_COMMITMENT_BITSIZE) 
    {
        LOG_ERROR("Paillier commitment key size too small. %u < %u", paillier_public_key_size, cosigner_params::PAILLIER_COMMITMENT_BITSIZE);
        throw_paillier_exception(PAILLIER_ERROR_KEYLEN_TOO_SHORT);
    }
    
    // EC base
    const byte_vector_t setup_aad = generate_setup_aad_bytes(setup_id, client_key_metadata.algorithm);
    commitments_status com_status = pedersen_commitment_two_generators_base_generate(&client_key_metadata.ec_base, 
                                                                                     setup_aad.data(), 
                                                                                     (uint32_t)setup_aad.size(), 
                                                                                     get_algebra(client_key_metadata.algorithm));
    if (com_status != COMMITMENTS_SUCCESS)
    {
        LOG_ERROR("failed to generate elliptic curve base for commitments, error %d", com_status);
        throw_cosigner_exception(com_status);
    }

    // Finished restoration of data, now start verification

    // Verify the proofs
    const auto paillier_res = paillier_commitment_paillier_blum_zkp_verify(client_key_metadata.paillier_commitment_pub.get(), 
                                                                           setup_aad.data(), 
                                                                           setup_aad.size(), 
                                                                           setup.paillier_blum_zkp.data(), 
                                                                           setup.paillier_blum_zkp.size());
    if (paillier_res != PAILLIER_SUCCESS) 
    {
        LOG_ERROR("Fail to verify the Paillier Blum proof");
        throw_paillier_exception(paillier_res);
    }

    auto zkp_res = range_proof_paillier_commitment_large_factors_zkp_verify(client_key_metadata.paillier_commitment_pub.get(), 
                                                                            setup_aad.data(), 
                                                                            setup_aad.size(), 
                                                                            setup.small_factors_zkp.data(), 
                                                                            setup.small_factors_zkp.size());
    if (zkp_res != ZKP_SUCCESS) 
    {
        LOG_ERROR("Failed to verify the Paillier Large Factor proof. Error %d",  zkp_res);
        throw_cosigner_exception((zero_knowledge_proof_status)zkp_res);
    }

    zkp_res = paillier_commitment_damgard_fujisaki_parameters_zkp_verify(client_key_metadata.paillier_commitment_pub.get(), 
                                                                         setup_aad.data(), 
                                                                         setup_aad.size(), 
                                                                         setup.damgard_fujisaki_zkp.data(), 
                                                                         setup.damgard_fujisaki_zkp.size());
    if (zkp_res != ZKP_SUCCESS) 
    {
        LOG_ERROR("Failed to verify the Batch Ring Damgard Fujisaki proof. Error %d", zkp_res);
        throw_cosigner_exception((zero_knowledge_proof_status)zkp_res);
    }
}

void bam_ecdsa_cosigner_client::generate_share_and_proofs(const std::string& key_id, 
                                                          const bam_key_metadata_client& client_key_metadata,
                                                          bam_temp_key_data_client& client_temp_key_data,
                                                          client_key_shared_data& client_key_message) const
{
    // generate damgard fujisaki private ephemeral private key
    damgard_fujisaki_private* damgard_fujisaki_priv = NULL;
    ring_pedersen_status damgard_ret = damgard_fujisaki_generate_private_key(cosigner_params::TEMPORARY_DAMGARD_FUJISAKI_BITSIZE, 2, &damgard_fujisaki_priv);
    if (damgard_ret != RING_PEDERSEN_SUCCESS)
    {
        LOG_ERROR("Failed to generate damgard_fujisaki private key, error %d for key %s", damgard_ret, key_id.c_str());
        throw_cosigner_exception(damgard_ret);
    }

    client_temp_key_data.damgard_fujisaki_priv = std::shared_ptr<damgard_fujisaki_private>(damgard_fujisaki_priv, damgard_fujisaki_free_private);

    // damgard_fujisaki proof
    uint32_t proof_len = 0;
    zero_knowledge_proof_status zkp_ret = damgard_fujisaki_parameters_zkp_generate(client_temp_key_data.damgard_fujisaki_priv.get(), 
                                                   client_key_metadata.seed, 
                                                   sizeof(client_key_metadata.seed), 
                                                   cosigner_params::OPTIMIZED_DAMGARD_FUJISAKI_CHALLENGE_BITSIZE, 
                                                   NULL, 
                                                   0, 
                                                   &proof_len);
    if (zkp_ret != ZKP_INSUFFICIENT_BUFFER)
    {
        LOG_ERROR("failed to estimate size of generated damgard_fujisaki Proof, error %d for key %s", zkp_ret, key_id.c_str());
        throw_cosigner_exception(zkp_ret);
    }
    client_key_message.damgard_fujisaki_proof.resize(proof_len);
    zkp_ret = damgard_fujisaki_parameters_zkp_generate(client_temp_key_data.damgard_fujisaki_priv.get(), 
                                                   client_key_metadata.seed, 
                                                   sizeof(client_key_metadata.seed), 
                                                   cosigner_params::OPTIMIZED_DAMGARD_FUJISAKI_CHALLENGE_BITSIZE, 
                                                   client_key_message.damgard_fujisaki_proof.data(), 
                                                   proof_len, 
                                                   &proof_len);
    if (zkp_ret != ZKP_SUCCESS)
    {
        LOG_ERROR("failed to generate damgard_fujisaki Proof, error %d for key %s", zkp_ret, key_id.c_str());
        throw_cosigner_exception(zkp_ret);
    }
    else if ((uint32_t)client_key_message.damgard_fujisaki_proof.size() != proof_len)
    {
        LOG_ERROR("failed to generate Damgard Fujisaki Proof, size mismatch %u != %u", proof_len, (uint32_t)client_key_message.damgard_fujisaki_proof.size());
        throw_cosigner_exception(ZKP_UNKNOWN_ERROR);
    }
    const auto algebra = get_algebra(client_key_metadata.algorithm);

    // serialization of damgard_fujisaki public key
    uint32_t damgard_fujisaki_pub_size = 0;
    damgard_fujisaki_public_serialize(damgard_fujisaki_private_key_get_public(client_temp_key_data.damgard_fujisaki_priv.get()), NULL, 0, &damgard_fujisaki_pub_size);
    client_key_message.damgard_fujisaki_pub.resize(damgard_fujisaki_pub_size);
    if (!damgard_fujisaki_public_serialize(damgard_fujisaki_private_key_get_public(client_temp_key_data.damgard_fujisaki_priv.get()), 
                                           client_key_message.damgard_fujisaki_pub.data(), 
                                           damgard_fujisaki_pub_size, 
                                           &damgard_fujisaki_pub_size))
    {
        LOG_ERROR("Cannot serialize Damgard Fujisaki public key for key id %s.", key_id.c_str());
        throw_cosigner_exception(COMMITMENTS_INTERNAL_ERROR);
    }
    else if (damgard_fujisaki_pub_size != (uint32_t)client_key_message.damgard_fujisaki_pub.size())
    {
        LOG_ERROR("Error serialize Damgard Fujisaki public key for key id %s. Size mismatch %u != %u", key_id.c_str(), damgard_fujisaki_pub_size, (uint32_t)client_key_message.damgard_fujisaki_pub.size());
        throw_cosigner_exception(COMMITMENTS_INTERNAL_ERROR);
    }

    elliptic_curve_scalar private_share;
    cosigner_sign_algorithm algorithm;
    _key_persistency.load_key(key_id, algorithm, private_share.data);

    if (algorithm != client_key_metadata.algorithm)
    {
        LOG_ERROR("Metadata algorithm mismatch for key %s. %d != %d", key_id.c_str(), algorithm, client_key_metadata.algorithm);
        throw cosigner_exception(cosigner_exception::INTERNAL_ERROR);
    }
    
    // fill client's public share
    throw_cosigner_exception(algebra->generator_mul(algebra, &client_key_message.X, &private_share.data));

    // Generate Schnorr DLOG proof
    client_key_message.schnorr_proof.resize(sizeof(schnorr_zkp_t));
    throw_cosigner_exception(schnorr_zkp_generate(algebra, 
                                                  client_key_metadata.seed, 
                                                  sizeof(client_key_metadata.seed), 
                                                  &private_share.data, 
                                                  &client_key_message.X, 
                                                  (schnorr_zkp_t*) client_key_message.schnorr_proof.data()));
}

void bam_ecdsa_cosigner_client::verify_key_decommitment_and_proofs(const std::string& key_id, 
                                                                   const uint64_t server_id, 
                                                                   const uint64_t client_id, 
                                                                   const server_key_shared_data& server_message,
                                                                   generated_public_key& pub_key_data)
{
    bam_key_metadata_client client_key_metadata;
    bam_temp_key_data_client client_temp_key_data;
    _key_persistency.load_key_metadata(key_id, client_key_metadata);
    
    (void)client_id;

    if (client_key_metadata.peer_id != server_id)
    {
        LOG_ERROR("Wrong server id for key %s. %" PRIu64 " != %" PRIu64, key_id.c_str(), client_key_metadata.peer_id, server_id);
        throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
    }

    validate_tenant_id_setup(client_key_metadata.setup_id);

    if (!client_key_metadata.paillier_commitment_pub)
    {
        LOG_ERROR("Setup data for the key %s is not ready", key_id.c_str());
        throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
    }

    // verify that servers share is unknown
    if (!client_key_metadata.encrypted_server_share.empty())
    {
        LOG_ERROR("Already have server share for key %s.", key_id.c_str());
        throw cosigner_exception(cosigner_exception::INTERNAL_ERROR);
    }
    
    _key_persistency.load_key_temp_data_and_delete(key_id, client_temp_key_data);

    // Check server commitment
    commitments_sha256_t B;
    generate_key_commitment(client_key_metadata.seed, server_message.server_public_share, B);

    if (memcmp(client_temp_key_data.server_commitment, B, sizeof(commitments_sha256_t)) != 0) 
    {
        LOG_FATAL("Failed to verify the server key share commitment for the key %s", key_id.c_str());
        throw_cosigner_exception(ZKP_VERIFICATION_FAILED);
    }

    // Check Paillier Range proof
    const const_paillier_with_range_proof_t proof = 
    {
        server_message.encrypted_server_share.data(),
        (uint32_t) server_message.encrypted_server_share.size(),
        server_message.enc_dlog_proof.data(),
        (uint32_t) server_message.enc_dlog_proof.size()
    };

    auto algebra = get_algebra(client_key_metadata.algorithm);
    zero_knowledge_proof_status paillier_ret = paillier_commitment_exponent_zkpok_verify(client_temp_key_data.damgard_fujisaki_priv.get(),
                                                         client_key_metadata.paillier_commitment_pub.get(),
                                                         algebra,
                                                         client_key_metadata.seed,
                                                         sizeof(client_key_metadata.seed),
                                                         &server_message.server_public_share,
                                                         &proof,
                                                         /*use_extended_seed=*/1);
    if (paillier_ret != ZKP_SUCCESS)
    {
        LOG_ERROR("Failed to verify range proof small expo. for key %s. Error %d", key_id.c_str(), paillier_ret);
        throw_cosigner_exception(paillier_ret);
    }
    
    elliptic_curve256_point_t common_public_key;
    elliptic_curve_scalar private_share;
    cosigner_sign_algorithm algorithm;
    _key_persistency.load_key(key_id, algorithm, private_share.data);

    if (algorithm != client_key_metadata.algorithm)
    {
        LOG_ERROR("Metadata algorithm mismatch for key %s. %d != %d", key_id.c_str(), algorithm, client_key_metadata.algorithm);
        throw cosigner_exception(cosigner_exception::INTERNAL_ERROR);
    }
    
    //client's public key from private -> common_public_key
    throw_cosigner_exception(algebra->generator_mul(algebra, &common_public_key, &private_share.data));

    //add server's part
    throw_cosigner_exception(algebra->add_points(algebra, 
                                                 &common_public_key, 
                                                 &common_public_key, 
                                                 &server_message.server_public_share));
    if (!client_key_metadata.has_public_key())
    {
        memcpy(&client_key_metadata.public_key[0], &common_public_key[0], sizeof(elliptic_curve256_point_t));
    }
    else if (memcmp(&client_key_metadata.public_key[0], &common_public_key[0], sizeof(elliptic_curve256_point_t)) != 0)
    {
        LOG_ERROR("Public key mismatch for the key %s", key_id.c_str());
        throw_cosigner_exception(ELLIPTIC_CURVE_ALGEBRA_INVALID_POINT);
    }
    
    client_key_metadata.encrypted_server_share = server_message.encrypted_server_share;
    
    _key_persistency.store_key_metadata(key_id, client_key_metadata, true);

    if (!_key_persistency.backup_key(key_id))
    {
        LOG_ERROR("Failed to backup key %s", key_id.c_str());
        _key_persistency.delete_key_data(key_id);
        throw cosigner_exception(cosigner_exception::BACKUP_FAILED);
    }

    _platform_service.clear_key_setup_in_progress(key_id);

    pub_key_data.pub_key.assign((const char*)client_key_metadata.public_key, algebra->point_size(algebra));
    pub_key_data.algorithm = client_key_metadata.algorithm;
}

void bam_ecdsa_cosigner_client::well_formed_signature_range_proof_generate(const paillier_commitment_public_key_t *paillier,
                                                                           elliptic_curve256_algebra_ctx *algebra,
                                                                           const pedersen_commitment_two_generators *ec_base, //two points h and f
                                                                           const commitments_sha256_t& signature_aad,
                                                                           const elliptic_curve256_point_t& r_server,
                                                                           const struct bignum_st *plaintext,                  // this is u, called a in proof
                                                                           const struct bignum_st *encrypted_share,            // encrypted server share
                                                                           const struct bignum_st *exponent,                   // v, called b in proof
                                                                           struct bignum_ctx *ctx,
                                                                           client_partial_signature_data &partial_signature)
{
    
    byte_vector_t plaintext_bin;
    byte_vector_t exponent_bin;

    if (!paillier || !algebra || !ec_base || !plaintext || !encrypted_share || !exponent)
    {
        throw_cosigner_exception(ZKP_INVALID_PARAMETER);
    }
    
    bn_ctx_frame bn_ctx(ctx);
    
    BIGNUM *S = BN_CTX_get(ctx);
    BIGNUM *lambda0 = BN_CTX_get(ctx);
    

    if (!S || !lambda0)
    {
        throw_cosigner_exception(ZKP_OUT_OF_MEMORY);
    }
    
    plaintext_bin.resize(BN_num_bytes(plaintext));
    exponent_bin.resize(BN_num_bytes(exponent));

    if (!BN_bn2bin(plaintext, plaintext_bin.data()) ||
        !BN_bn2bin(exponent, exponent_bin.data()) ||
        !BN_rand(lambda0, cosigner_params::ZKPOK_OPTIM_NLAMBDA0_SIZE * 8, BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ANY))
    {
        throw_cosigner_exception(ZKP_OUT_OF_MEMORY);
    }

    throw_paillier_exception(paillier_commitment_commit_internal(paillier, plaintext, lambda0, encrypted_share, exponent, S, ctx));

    partial_signature.encrypted_partial_sig.resize(BN_num_bytes(S));
    
    if (!BN_bn2bin(S, partial_signature.encrypted_partial_sig.data()))
    {
        throw_cosigner_exception(ZKP_OUT_OF_MEMORY);
    }

    bam_well_formed_proof::generate_signature_proof(paillier, algebra, ctx, ec_base, plaintext,  encrypted_share, exponent, lambda0, S, signature_aad, plaintext_bin, exponent_bin, r_server, partial_signature.sig_proof);
}

void bam_ecdsa_cosigner_client::prepare_for_signature(const std::string& key_id, 
                                                      const std::string& tx_id, 
                                                      const uint32_t version,
                                                      const uint64_t server_id,
                                                      const uint64_t client_id,
                                                      const common::cosigner::signing_data& data,
                                                      const std::string& metadata_json,
                                                      const std::set<std::string>& players_set)
{
    LOG_INFO("Entering txid = %s", tx_id.c_str());

    _platform_service.prepare_for_signing(key_id, tx_id);

    //validate client and server id
    bam_key_metadata_client client_key_metadata;
    _key_persistency.load_key_metadata(key_id, client_key_metadata);


    if (client_key_metadata.peer_id != server_id)
    {
        LOG_ERROR("Wrong server id for key %s. %" PRIu64 " != %" PRIu64, key_id.c_str(), client_key_metadata.peer_id, server_id);
        throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
    }

    validate_tenant_id_setup(client_key_metadata.setup_id);

    // verify that servers share is unknown
    if (client_key_metadata.encrypted_server_share.empty())
    {
        LOG_ERROR("Key generation is not completed for key %s.", key_id.c_str());
        throw cosigner_exception(cosigner_exception::INTERNAL_ERROR);
    }

    const auto signature_request_data = fill_bam_signing_info_from_metadata(metadata_json, static_cast<uint32_t>(data.blocks.size()));
    if (0 == signature_request_data.size())
    {
        LOG_ERROR("Key %s, tx_id %s: Empty signature batch request", key_id.c_str(), tx_id.c_str());
        throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
    }
    else if (data.blocks.size() != signature_request_data.size()) //must not happen
    {
        LOG_ERROR("number of blocks %u is different than number of flags %u", static_cast<uint32_t>(data.blocks.size()), static_cast<uint32_t>(signature_request_data.size()));
        throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
    }

    _platform_service.on_start_signing(key_id, tx_id, data, metadata_json, players_set, platform_service::SINGLE_ROUND_SIGNATURE);
    
    auto algebra = get_algebra(client_key_metadata.algorithm);

    bam_client_signature_data client_signature_data(version, server_id, client_id, key_id, static_cast<int64_t>(_platform_service.now_msec() / 1000));
    client_signature_data.sig_data.resize(signature_request_data.size());

    for (uint32_t i = 0; i < (uint32_t)signature_request_data.size(); ++ i)
    {
        auto& sig_request = signature_request_data[i];                  // request which has to be signed
        auto& persistant_sig_data = client_signature_data.sig_data[i];  // data about the signature that the client should save
        
        persistant_sig_data.flags = sig_request.flags;
        if (data.blocks[i].data.size() != sizeof(elliptic_curve256_scalar_t))
        {
            LOG_ERROR("block %u has illegal size of %u", i, static_cast<uint32_t>(data.blocks[i].data.size()));
            throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
        }

        memcpy(persistant_sig_data.message, data.blocks[i].data.data(), sizeof(elliptic_curve256_scalar_t));
        derivation_key_delta(algebra, client_key_metadata.public_key, data.chaincode, data.blocks[i].path, persistant_sig_data.derivation_delta);
    }

    _tx_persistency.store_signature_data(tx_id, client_signature_data);
}

void bam_ecdsa_cosigner_client::compute_partial_signature(const std::string& tx_id, 
                                                          const std::vector<server_signature_shared_data>& server_shares, 
                                                          std::vector<client_partial_signature_data>& partial_signatures)
{
    elliptic_curve_scalar k, k_inv, r, v;
    elliptic_curve_scalar private_share;
    elliptic_curve_scalar derived_private_share;
    elliptic_curve256_point_t tmp;
    bam_client_signature_data client_signature_data;
    bam_key_metadata_client client_key_metadata;
    commitments_sha256_t signature_aad;
    cosigner_sign_algorithm algorithm;

    _tx_persistency.load_signature_data_and_delete(tx_id, client_signature_data);
    if (server_shares.size() != client_signature_data.sig_data.size())
    {
        LOG_ERROR("Tx_id %s: Server shares size mismatch. %u != %u", tx_id.c_str(), (uint32_t)server_shares.size(), (uint32_t) client_signature_data.sig_data.size());
        throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
    }

    _key_persistency.load_key_metadata(client_signature_data.key_id, client_key_metadata);

    validate_tenant_id_setup(client_key_metadata.setup_id);

    // verify that servers share is unknown
    if (client_key_metadata.encrypted_server_share.empty())
    {
        LOG_ERROR("Key generation is not completed for key %s.", client_signature_data.key_id.c_str());
        throw cosigner_exception(cosigner_exception::INTERNAL_ERROR);
    }

    _key_persistency.load_key(client_signature_data.key_id, algorithm, private_share.data);
    if (algorithm != client_key_metadata.algorithm)
    {
        LOG_ERROR("Metadata algorithm mismatch for tx_id %s. %d != %d", tx_id.c_str(), algorithm, client_key_metadata.algorithm);
        throw cosigner_exception(cosigner_exception::INTERNAL_ERROR);
    }
    
    BN_CTX_guard ctx;
    
    const auto algebra = get_algebra(client_key_metadata.algorithm);


    generate_aad_for_signature(client_signature_data.key_id, client_signature_data.server_signer_id, client_signature_data.client_signer_id, tx_id, signature_aad); 

    partial_signatures.resize(server_shares.size());

    // prepare server encrypted share
    BIGNUM *bn_encrypted_share = BN_CTX_get(ctx.get());
    if (!bn_encrypted_share)
    {
        throw_cosigner_exception(ZKP_OUT_OF_MEMORY);
    }
    
    if (!BN_bin2bn(client_key_metadata.encrypted_server_share.data(), client_key_metadata.encrypted_server_share.size(), bn_encrypted_share))
    {
        throw_cosigner_exception(ZKP_OUT_OF_MEMORY);
    }

    for (uint32_t i = 0; i < (uint32_t)server_shares.size(); ++ i )
    {
        auto& server_share = server_shares[i];
        auto& partial_signature = partial_signatures[i];
        auto& persistant_sig_data = client_signature_data.sig_data[i];
        
        bn_ctx_frame ctx_frame(ctx.get());
        
        // required because of the Claim 7.15 in the BAM article from 
        check_non_null_message(persistant_sig_data.message, algebra);

        // check that the server share values
        // server 'R' should not be the point at infinity
        // simply verify compressed point to check that it is legal.
        // This is a simply sanity check - zero point is not considered a valid random
        check_a_valid_point(server_share.R, algebra);

        // It is required derive private key based on public key derivation shift for the validation
        // And from now on use only derived private share
        throw_cosigner_exception(algebra->add_scalars(algebra, 
                                                      &derived_private_share.data, 
                                                      private_share.data, 
                                                      sizeof(elliptic_curve256_scalar_t), 
                                                      persistant_sig_data.derivation_delta, 
                                                      sizeof(elliptic_curve256_scalar_t)));

        // R2^derived_private_share.data == Y
        // It verifies that the server knows the discrete log of it's R
        // (because it should have calculated client's public share to the power of k to compute the Y)
        throw_cosigner_exception(algebra->point_mul(algebra, &tmp, &server_share.R, &derived_private_share.data));
        if (memcmp(tmp, server_share.Y, sizeof(elliptic_curve256_point_t)) != 0)
        {
            throw_cosigner_exception(ELLIPTIC_CURVE_ALGEBRA_INVALID_POINT);
        }

        // generate own share
        throw_cosigner_exception(algebra->rand(algebra, &k.data));                  //generate random k
        
        //set partial_signature.client_R to hold G^k_client
        throw_cosigner_exception(algebra->generator_mul(algebra, &partial_signature.client_R, &k.data));

        //set partial_signature.common_R to hold R^k_client which is G^(k_server * k_client)
        throw_cosigner_exception(algebra->point_mul(algebra, &partial_signature.common_R, &server_share.R, &k.data));

        GFp_curve_algebra_ctx_t* curve = (GFp_curve_algebra_ctx_t*)algebra->ctx;

        // To compute 'r' of the signature, we compute:
        //    R2^k1 + R1^H(X||R1||R2^k1||m)   and take the x-coordinate of it
        uint8_t overflow = 0;
        elliptic_curve256_scalar_t hash_shift; //not needed 
        //calculate corrected R
        elliptic_curve256_point_t corrected_R;
        derive_and_compute_corrected_R(algebra, tx_id, persistant_sig_data, client_key_metadata.public_key, partial_signature, tmp, hash_shift, corrected_R);

        // r = x projection of the corrected_R point
        throw_cosigner_exception(GFp_curve_algebra_get_point_projection(curve, &r.data, &corrected_R, &overflow));

        // POSITIVE_R handling (client-side)
        //
        // We cannot just “pre-correct” R and send that to the server. In this protocol
        // r is not an arbitrary choice: both parties derive it from the SAME public data,
        // namely
        //   R* = R_com  +  R_client^{H(X || R_client || R_com || m)}
        //   r  = x(R*)
        // where R_client = g^{k_client}, R_com = R_server^{k_client},
        // and the hash “shift” binds r to (X, R_client, R_com, m). The server independently
        // recomputes R* and r from (R_client, R_com, m), so any pre-massaged “positive R” we
        // send would be ignored and, if inconsistent with k1/k2, rejected.
        //
        // Enforcing positivity is therefore deterministic and symmetric: if r isn’t
        // positive, BOTH sides conceptually add R again (and again…) until it is.
        // Each addition corresponds to scaling our nonce by the same small factor t:
        //   k_client' = k_client · t
        // We must reflect this by updating k_client -> k_client' and using k_client'^{-1} when forming our
        // partial (v, u), which keeps our ZK proof and the final signature consistent
        // with the server’s recomputed r.
        //
        // Important: the server should NOT apply any extra correction to s. It just
        // runs the same positivity loop to recover the identical r and then combines
        // our well-formed partial. Our partial already “bakes in” the correction via
        // k'^{-1}; a second correction on the server would break correctness.
        if (persistant_sig_data.flags & POSITIVE_R)
        {
            uint8_t r_correction_cycles = 1;

            memcpy(tmp, corrected_R, sizeof(elliptic_curve256_point_t));      
            while (!is_positive(client_key_metadata.algorithm, r.data))
            {
                assert(r_correction_cycles < 255);
                if (r_correction_cycles == 255)
                {
                    LOG_ERROR("Failed to find a positive r in 256 iterations key_id %s, tx_id %s", client_signature_data.key_id.c_str(), tx_id.c_str());
                    throw_cosigner_exception(ELLIPTIC_CURVE_ALGEBRA_INVALID_POINT);
                }
                ++r_correction_cycles;
                throw_cosigner_exception(algebra->add_points(algebra, &corrected_R, &corrected_R, &tmp));
                throw_cosigner_exception(GFp_curve_algebra_get_point_projection(curve, &r.data, &corrected_R, &overflow));
            }

            // now update the k.data so it will hold the corrected value
            throw_cosigner_exception(algebra->mul_scalars(algebra, &k.data, k.data, sizeof(k.data), &r_correction_cycles, sizeof(r_correction_cycles)));
        }
        
        // v = k_client^(-1) * r
        // If R was modified, a modified k should be used to compute k_inv
        throw_cosigner_exception(algebra->inverse(algebra, &k_inv.data, &k.data));  //calculate k^(-1)
        throw_cosigner_exception(algebra->mul_scalars(algebra, &v.data, k_inv.data, sizeof(k_inv.data), r.data, sizeof(r.data)));

        // r is no more needed, so will be reused to hold u (now it holds the shifter projection)
        // r = r * derived_private_share
        throw_cosigner_exception(algebra->mul_scalars(algebra, &r.data, r.data, sizeof(r.data), derived_private_share.data, sizeof(derived_private_share.data)));
        // r = r + hash_to_sign = shifter_projection * derived_private_share + hash_to_sign
        throw_cosigner_exception(algebra->add_scalars(algebra, &r.data, r.data, sizeof(r.data), persistant_sig_data.message, sizeof(elliptic_curve256_scalar_t)));
        // r = r * k_client^(-1) = (shifter_projection * derived_private_share + hash_to_sign) * k_client ^ (-1)
        throw_cosigner_exception(algebra->mul_scalars(algebra, &r.data, r.data, sizeof(r.data), k_inv.data, sizeof(k_inv.data)));

        BIGNUM *bn_u_ptr = BN_CTX_get(ctx.get());
        BIGNUM *bn_expo_ptr = BN_CTX_get(ctx.get());

        if (!bn_u_ptr || !bn_expo_ptr)
        {
            throw_cosigner_exception(ZKP_OUT_OF_MEMORY);
        }

        std::unique_ptr<BIGNUM, bignum_clear> bn_u(BN_bin2bn(r.data, sizeof(r.data), bn_u_ptr), bignum_clear()); 
        std::unique_ptr<BIGNUM, bignum_clear> bn_expo(BN_bin2bn(v.data, sizeof(v.data), bn_expo_ptr), bignum_clear());

        if (!bn_u ||!bn_expo)
        {
            throw_cosigner_exception(ZKP_OUT_OF_MEMORY);
        }

        bn_randomize_with_factor(bn_u.get(), bn_u.get(), algebra->order_internal(algebra), (cosigner_params::ZKPOK_OPTIM_NA_SIZE - cosigner_params::ZKPOK_OPTIM_KAPPA_SIZE) * 8);
        bn_randomize_with_factor(bn_expo.get(), bn_expo.get(), algebra->order_internal(algebra), (cosigner_params::ZKPOK_OPTIM_NB_SIZE - cosigner_params::ZKPOK_OPTIM_KAPPA_SIZE)*8);

        // Generate proof
        well_formed_signature_range_proof_generate(client_key_metadata.paillier_commitment_pub.get(),
                                                   algebra,
                                                   &client_key_metadata.ec_base,
                                                   signature_aad,
                                                   server_share.R,
                                                   bn_u.get(),
                                                   bn_encrypted_share,
                                                   bn_expo.get(),
                                                   ctx.get(),
                                                   partial_signature);
    }
    
}

void bam_ecdsa_cosigner_client::validate_tenant_id_setup(const std::string& setup_id) const
{
    bam_ecdsa_cosigner::validate_tenant_id_setup(_key_persistency, setup_id);
}

} //namespace fireblocks::common::cosigner