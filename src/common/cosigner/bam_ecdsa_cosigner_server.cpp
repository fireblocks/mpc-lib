#include "cosigner/bam_ecdsa_cosigner_server.h"
#include "logging/logging_t.h"

#include "cosigner/cosigner_exception.h"
#include "cosigner/platform_service.h"
#include "cosigner/bam_key_persistency_server.h"
#include "cosigner/bam_tx_persistency_server.h"
#include "crypto/commitments/damgard_fujisaki.h"
#include "crypto/zero_knowledge_proof/range_proofs.h"
#include "crypto/zero_knowledge_proof/schnorr.h"
#include "crypto/GFp_curve_algebra/GFp_curve_algebra.h"
#include "utils/string_utils.h"
#include "bam_well_formed_proof.h"
#include "crypto/algebra_utils/algebra_utils.h"
#include "../crypto/paillier_commitment/paillier_commitment_internal.h"

#include <openssl/crypto.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <cinttypes>


namespace fireblocks::common::cosigner
{


bam_ecdsa_cosigner_server::bam_ecdsa_cosigner_server(platform_service& cosigner_service,
                                                     bam_key_persistency_server& key_persistecy,
                                                     bam_tx_persistency_server& tx_persistecy):
    bam_ecdsa_cosigner(cosigner_service),
    _key_persistency(key_persistecy),
    _tx_persistency(tx_persistecy)
{

}

void bam_ecdsa_cosigner_server::shutdown()
{
    _tx_persistency.shutdown();
}
void bam_ecdsa_cosigner_server::generate_setup_with_proof(const std::string& setup_id,
                                                          const std::string& tenant_id,
                                                          const cosigner_sign_algorithm algorithm,
                                                          server_setup_shared_data& serialized_setup_data)
{
    //validate tenant before generating a new setup
    validate_current_tenant_id(tenant_id);

    const byte_vector_t setup_aad = generate_setup_aad_bytes(setup_id, algorithm);

    const bam_setup_auxilary_key_server server_setup_auxilary_key = generate_setup_secrets();
    const bam_setup_metadata_server server_setup_metadata = generate_setup_metadata(setup_aad, algorithm);

    const auto paillier_commitment_pub =  paillier_commitment_private_cast_to_public(server_setup_auxilary_key.paillier_commitment_priv.get());

    uint32_t paillier_pub_size = 0;

    // Paillier Key - dont include rho
    paillier_commitment_public_key_serialize(paillier_commitment_pub, 1, NULL, 0, &paillier_pub_size);

    if (0 == paillier_pub_size)
    {
        LOG_ERROR("Cannot serialize Paillier commitment public key. Returned size is zero");
        throw_cosigner_exception(COMMITMENTS_INTERNAL_ERROR);
    }

    serialized_setup_data.paillier_commitment_pub.resize(paillier_pub_size);

    if (PAILLIER_SUCCESS != paillier_commitment_public_key_serialize(paillier_commitment_pub,
                                                                    1,
                                                                    &serialized_setup_data.paillier_commitment_pub[0],
                                                                    paillier_pub_size,
                                                                    &paillier_pub_size))
    {
        LOG_ERROR("Cannot serialize Paillier public key.");
        throw_paillier_exception(PAILLIER_ERROR_BUFFER_TOO_SHORT);
    }
    else if (paillier_pub_size != (uint32_t)serialized_setup_data.paillier_commitment_pub.size())
    {
        LOG_ERROR("Cannot serialize Paillier commitment public key. Size mismatch. %u != %u", paillier_pub_size, (uint32_t)serialized_setup_data.paillier_commitment_pub.size());
        throw_paillier_exception(PAILLIER_ERROR_UNKNOWN);
    }

    // Generate ZK proofs
    generate_setup_proofs(server_setup_auxilary_key,
                          setup_aad,
                          serialized_setup_data.paillier_blum_zkp,
                          serialized_setup_data.small_factors_zkp,
                          serialized_setup_data.damgard_fujisaki_zkp);

    _key_persistency.store_setup_auxilary_key(setup_id, server_setup_auxilary_key);
    _key_persistency.store_setup_metadata(setup_id, server_setup_metadata);
    _key_persistency.store_tenant_id_for_setup(setup_id, tenant_id);
}

bam_setup_metadata_server bam_ecdsa_cosigner_server::generate_setup_metadata(const byte_vector_t& setup_aad,
                                                                             const cosigner_sign_algorithm algorithm)
{
    bam_setup_metadata_server server_setup_metadata(algorithm);

    // Generate base commitment
    const commitments_status com_status = pedersen_commitment_two_generators_base_generate(&server_setup_metadata.ec_base,
                                                                                           setup_aad.data(),
                                                                                           (uint32_t)setup_aad.size(),
                                                                                           get_algebra(algorithm));
    if (com_status != COMMITMENTS_SUCCESS)
    {
        LOG_ERROR("failed to generate elliptic curve base for commitments, error %d", com_status);
        throw_cosigner_exception(com_status);
    }

    return server_setup_metadata;
}

bam_setup_auxilary_key_server bam_ecdsa_cosigner_server::generate_setup_secrets()
{
    bam_setup_auxilary_key_server setup_secrets;
    paillier_commitment_private_key_t* paillier_commitment_priv = NULL;

    // generate the Paillier small group private key
    long res = paillier_commitment_generate_private_key(cosigner_params::PAILLIER_COMMITMENT_BITSIZE,  &paillier_commitment_priv);
    if (res != PAILLIER_SUCCESS)
    {
        LOG_ERROR("failed to create paillier commitment key pair, error %ld", res);
        throw_paillier_exception(res);
    }
    setup_secrets.paillier_commitment_priv = std::shared_ptr<paillier_commitment_private_key_t>(paillier_commitment_priv, paillier_commitment_free_private_key);

    return setup_secrets;
}

void bam_ecdsa_cosigner_server::generate_setup_proofs(const bam_setup_auxilary_key_server& server_setup_auxilary_key,
                                                      const byte_vector_t& setup_aad,
                                                      byte_vector_t& paillier_blum,
                                                      byte_vector_t& small_factors,
                                                      byte_vector_t& damgard_fujisaki)
{
    // Since any prime strong prime big should be good
    // Simply choose the 1st prime that meets the security requirement
    // it is 2^3459 + 1169115 - the smallest 2360 bits prime
    static const uint8_t hardcoded_d[] =
    {
        0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x11, 0xd6,
        0xdb
    };

    uint32_t proof_len = 0;
    auto paillier_commitment_priv = server_setup_auxilary_key.paillier_commitment_priv.get();

    // Proof of well formed Modulus
    (void)paillier_commitment_paillier_blum_zkp_generate(paillier_commitment_priv,
                                                         setup_aad.data(),
                                                         setup_aad.size(),
                                                         NULL,
                                                         0,
                                                         &proof_len);
    if (0 == proof_len)
    {
        LOG_ERROR("Failed to generate Paillier-Blum proof, size is zero");
        throw_paillier_exception(PAILLIER_ERROR_UNKNOWN);
    }

    paillier_blum.resize(proof_len);
    const auto paillier_res = paillier_commitment_paillier_blum_zkp_generate(paillier_commitment_priv,
                                                                             setup_aad.data(),
                                                                             setup_aad.size(),
                                                                             paillier_blum.data(),
                                                                             proof_len,
                                                                             &proof_len);
    if (paillier_res != PAILLIER_SUCCESS)
    {
        LOG_ERROR("Failed to generate Paillier-Blum proof, error %ld", paillier_res);
        throw_paillier_exception(paillier_res);
    }
    else if (proof_len != (uint32_t)paillier_blum.size())
    {
        LOG_ERROR("Failed to generate Paillier-Blum proof, wrong size %u != %u", proof_len, (uint32_t)paillier_blum.size());
        throw_paillier_exception(PAILLIER_ERROR_UNKNOWN);
    }

    proof_len = 0;
    // Proof of no small factors.
    (void)range_proof_paillier_commitment_large_factors_zkp_generate(paillier_commitment_priv,
                                                                     setup_aad.data(),
                                                                     setup_aad.size(),
                                                                     hardcoded_d,
                                                                     (uint32_t)sizeof(hardcoded_d),
                                                                     NULL,
                                                                     0,
                                                                     &proof_len);

    if (0 == proof_len)
    {
        LOG_ERROR("Failed to generate Paillier Commitment Large Factors ZKP. Size is zero.");
        throw_paillier_exception(PAILLIER_ERROR_UNKNOWN);
    }

    small_factors.resize(proof_len);
    const auto paillier_zkp = range_proof_paillier_commitment_large_factors_zkp_generate(paillier_commitment_priv,
                                                                                         setup_aad.data(),
                                                                                         setup_aad.size(),
                                                                                         hardcoded_d,
                                                                                         (uint32_t)sizeof(hardcoded_d),
                                                                                         small_factors.data(),
                                                                                         proof_len,
                                                                                         &proof_len);
    if (paillier_zkp != ZKP_SUCCESS)
    {
        LOG_ERROR("failed to generate Small Factor Proof, error %d", paillier_zkp);
        throw_cosigner_exception((zero_knowledge_proof_status)paillier_zkp);
    }
    else if (proof_len > (uint32_t)small_factors.size())
    {
        LOG_ERROR("failed to generate Small Factor Proof, size mismatch %u != %u", proof_len, (uint32_t)small_factors.size());
        throw_cosigner_exception(ZKP_UNKNOWN_ERROR);
    }
    else if (proof_len < (uint32_t)small_factors.size())
    {
        LOG_WARN("generate Small Factor Proof, size mismatch %u != %u", proof_len, (uint32_t)small_factors.size());
        small_factors.resize(proof_len);
    }

    proof_len = 0;
    // Damgard Fujisaki proof
    (void)paillier_commitment_damgard_fujisaki_parameters_zkp_generate(paillier_commitment_priv,
                                                                       setup_aad.data(),
                                                                       setup_aad.size(),
                                                                       damgard_fujisaki.data(),
                                                                       0,
                                                                       &proof_len);
    if (0 == proof_len)
    {
        LOG_ERROR("Failed to generate Damgard Fujisaki parameters ZKP, size is zero");
        throw_paillier_exception(PAILLIER_ERROR_UNKNOWN);
    }

    damgard_fujisaki.resize(proof_len);
    const auto damgard_fujisaki_zkp = paillier_commitment_damgard_fujisaki_parameters_zkp_generate(paillier_commitment_priv,
                                                                                                   setup_aad.data(),
                                                                                                   setup_aad.size(),
                                                                                                   damgard_fujisaki.data(),
                                                                                                   proof_len,
                                                                                                   &proof_len);
    if (damgard_fujisaki_zkp != ZKP_SUCCESS)
    {
        LOG_ERROR("failed to generate Damgard Fujisaki Proof, error %d", damgard_fujisaki_zkp);
        throw_cosigner_exception((zero_knowledge_proof_status)damgard_fujisaki_zkp);
    }
    else if (proof_len != (uint32_t)damgard_fujisaki.size())
    {
        LOG_ERROR("failed to generate Damgard Fujisaki Proof, size mismatch %u != %u", proof_len, (uint32_t)damgard_fujisaki.size());
        throw_cosigner_exception(ZKP_UNKNOWN_ERROR);
    }
}

void bam_ecdsa_cosigner_server::commit_to_share(const std::string& setup_id,
                                                const std::string& key_id,
                                                const uint64_t server_id,
                                                const uint64_t client_id,
                                                const cosigner_sign_algorithm algorithm,
                                                const elliptic_curve_scalar& private_share,
                                                const elliptic_curve256_point_t& expected_public_key,
                                                commitments_sha256_t& B)
{
    if (client_id == server_id)
    {
        LOG_ERROR("Client and server ids are the same");
        throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
    }

    bam_key_metadata_server server_key_metadata(algorithm, setup_id, client_id, expected_public_key);
    auto algebra = get_algebra(algorithm);

    generate_aad_for_key_gen(key_id, client_id, server_id, server_key_metadata.seed);

    elliptic_curve256_point_t server_public_share;

    // compute the server public share.
    throw_cosigner_exception(algebra->generator_mul(algebra, &server_public_share, &private_share.data));

    // commitment to public key.
    generate_key_commitment(server_key_metadata.seed, server_public_share, B);

    _platform_service.mark_key_setup_in_progress(key_id);

    _key_persistency.store_key_metadata(key_id, server_key_metadata, false);
    _key_persistency.store_key(key_id, algorithm, private_share.data);
}


void bam_ecdsa_cosigner_server::add_user_and_commit(const std::string& setup_id,
                                                    const std::string& key_id,
                                                    const uint64_t server_id,
                                                    const uint64_t client_id,
                                                    const cosigner_sign_algorithm algorithm,
                                                    const std::map<uint64_t, add_user_data>& data,
                                                    commitments_sha256_t& B)
{
    elliptic_curve_scalar private_share;
    elliptic_curve256_point_t expected_public_key;
    LOG_INFO("Server committing to share for key %s server id %" PRIu64 ", client id %" PRIu64 ", algorithm %d", key_id.c_str(), server_id, client_id, algorithm);

    validate_tenant_id_setup(setup_id);


    decrypt_and_rebuild_private_share(server_id, algorithm, data, private_share, expected_public_key);

    commit_to_share(setup_id,
                    key_id,
                    server_id,
                    client_id,
                    algorithm,
                    private_share,
                    expected_public_key,
                    B);

}

void bam_ecdsa_cosigner_server::generate_share_and_commit(const std::string& setup_id,
                                                          const std::string& key_id,
                                                          const uint64_t server_id,
                                                          const uint64_t client_id,
                                                          const cosigner_sign_algorithm algorithm,
                                                          commitments_sha256_t& B)
{
    LOG_INFO("Generating server share for key %s server id %" PRIu64 ", client id %" PRIu64 ", algorithm %d", key_id.c_str(),  server_id, client_id, algorithm);

    validate_tenant_id_setup(setup_id);

    elliptic_curve_scalar private_share;
    generate_private_share(algorithm, private_share);
    const auto algebra = get_algebra(algorithm);

    commit_to_share(setup_id,
                    key_id,
                    server_id,
                    client_id,
                    algorithm,
                    private_share,
                    *(algebra->infinity_point(algebra)),
                    B);
}

void bam_ecdsa_cosigner_server::validate_tenant_id_setup(const std::string& setup_id) const
{
    bam_ecdsa_cosigner::validate_tenant_id_setup(_key_persistency, setup_id);
}

void bam_ecdsa_cosigner_server::verify_client_proofs_and_decommit_share_with_proof(const std::string& key_id,
                                                                                   const uint64_t client_id,
                                                                                   const client_key_shared_data& client_message,
                                                                                   server_key_shared_data& server_message)
{
    bam_key_metadata_server server_key_metadata;
    bam_setup_metadata_server server_setup_metadata;
    bam_setup_auxilary_key_server server_setup_auxilary_key;
    elliptic_curve_scalar private_key;

    _key_persistency.load_key_metadata(key_id, server_key_metadata);

    validate_tenant_id_setup(server_key_metadata.setup_id);

    auto algebra = get_algebra(server_key_metadata.algorithm);

    // validation to prevent replay attack
    if (!server_key_metadata.encrypted_server_share.empty())
    {
        LOG_ERROR("Already got client share for client id %" PRIu64 ", key id %s", client_id, key_id.c_str());
        throw cosigner_exception(cosigner_exception::INTERNAL_ERROR);
    }

    std::shared_ptr<damgard_fujisaki_public> damgard_fujisaki_pub(
                damgard_fujisaki_public_deserialize(client_message.damgard_fujisaki_pub.data(),
                                                    client_message.damgard_fujisaki_pub.size()),
                damgard_fujisaki_free_public);


    if (!damgard_fujisaki_pub)
    {
        LOG_ERROR("Failed to deserialize damgard fujisaki public key for client id %" PRIu64 ", key id %s", client_id, key_id.c_str());
        throw cosigner_exception(cosigner_exception::INTERNAL_ERROR);
    }

    if (damgard_fujisaki_public_size(damgard_fujisaki_pub.get()) != cosigner_params::TEMPORARY_DAMGARD_FUJISAKI_BITSIZE)
    {
        LOG_ERROR("Client Damgard Fujisaki key size %u is incorrect for client id %" PRIu64 ", key id %s", damgard_fujisaki_public_size(damgard_fujisaki_pub.get()), client_id, key_id.c_str());
        throw_cosigner_exception(RING_PEDERSEN_KEYLEN_TOO_SHORT);
    }

    zero_knowledge_proof_status damgard_ret = damgard_fujisaki_parameters_zkp_verify(damgard_fujisaki_pub.get(),
                                                      server_key_metadata.seed,
                                                      sizeof(commitments_sha256_t),
                                                      cosigner_params::OPTIMIZED_DAMGARD_FUJISAKI_CHALLENGE_BITSIZE,
                                                      client_message.damgard_fujisaki_proof.data(),
                                                      client_message.damgard_fujisaki_proof.size());
    if (damgard_ret != ZKP_SUCCESS)
    {
        LOG_ERROR("Client Damgard Fujisaki zkp verification failed for client %" PRIu64 ", key id %s. Error %d", client_id, key_id.c_str(), damgard_ret);
        throw_cosigner_exception(damgard_ret);
    }

    if (client_message.schnorr_proof.size() != sizeof(schnorr_zkp_t))
    {
        LOG_ERROR("Schnorr zkp illegal size for client %" PRIu64 ", key id %s. %u != %u", client_id, key_id.c_str(), (uint32_t)client_message.schnorr_proof.size(), (uint32_t)sizeof(schnorr_zkp_t));
        throw cosigner_exception(cosigner_exception::INTERNAL_ERROR);
    }

    zero_knowledge_proof_status schnorr_ret = schnorr_zkp_verify(algebra,
                             server_key_metadata.seed,
                             sizeof(server_key_metadata.seed),
                             &client_message.X,
                             (const schnorr_zkp_t*)client_message.schnorr_proof.data());

    if (schnorr_ret != ZKP_SUCCESS)
    {
        LOG_ERROR("Client Schnorr zkp verification failed for client %" PRIu64 ", key id %s. Error %d", client_id, key_id.c_str(), schnorr_ret);
        throw_cosigner_exception(schnorr_ret);
    }

    // Decommit share and generate proof
    _key_persistency.load_setup_metadata(server_key_metadata.setup_id, server_setup_metadata);
    if (server_setup_metadata.setup_algorithm != server_key_metadata.algorithm)
    {
        LOG_ERROR("Algorithm mismatch for client %" PRIu64 ", key id %s. %u != %u", client_id, key_id.c_str(), (uint32_t)server_setup_metadata.setup_algorithm, (uint32_t)server_key_metadata.algorithm);
        throw cosigner_exception(cosigner_exception::INTERNAL_ERROR);
    }
    cosigner_sign_algorithm algorithm;
    _key_persistency.load_key(key_id, algorithm, private_key.data);
    _key_persistency.load_setup_auxilary_key(server_key_metadata.setup_id, server_setup_auxilary_key);
    if (server_key_metadata.algorithm != algorithm)
    {
        LOG_ERROR("Metadata algorithm mismatch for key %s. %d != %d", key_id.c_str(), algorithm, server_key_metadata.algorithm);
        throw cosigner_exception(cosigner_exception::INTERNAL_ERROR);
    }

    byte_vector_t server_share(cosigner_params::ZKPOK_OPTIM_NX_SIZE); //320 bits
    utils::byte_vector_cleaner server_share_deleter(server_share);

    //must use OPENSSL_clear_free because it holds the private key, even if temporary
    std::unique_ptr<BIGNUM, bignum_clear_deleter> private_key_bn(
        BN_bin2bn(private_key.data, sizeof(elliptic_curve256_scalar_t), NULL),
        bignum_clear_deleter());

    if (!private_key_bn)
    {
        LOG_ERROR("Cannot allocate BIGNUM for the client %" PRIu64 ", the key id is %s.", client_id, key_id.c_str());
        throw cosigner_exception(cosigner_exception::NO_MEM);
    }


    // Pad-and-canonicalize the server secret for ZK:
    // We encrypt x' = x + r·q so the Paillier plaintext is an NX-byte integer
    // whose residue mod q equals the EC exponent x. This (1) matches the ZK
    // size bounds and keeps transcripts zero-knowledge, (2) fixes a canonical
    // representative of the coset x + qZ so the ciphertext/proof bind to a
    // single value, and (3) prevents homomorphic “coset hopping” or cross-
    // session linkage. The client never sees x' (only a ciphertext + ZK proof),
    // so it cannot reduce mod q to recover x.

    // private_key_bn = private_key_bn +  rand() * phi(n)
    // x' = x + r·q with x,q < 2^256 and r < 2^64.
    // Max x' = (2^256-1) + (2^64-1)(2^256-1) = 2^320 - 2^64 < 2^320.
    // Therefore x' fits in NX = 40 bytes, so BN_bn2binpad(..., 40) is safe
    bn_randomize_with_factor(private_key_bn.get(), private_key_bn.get(), algebra->order_internal(algebra), (cosigner_params::ZKPOK_OPTIM_NX_SIZE - cosigner_params::ZKPOK_OPTIM_KAPPA_SIZE) * 8);

    if (!BN_bn2binpad(private_key_bn.get(), server_share.data(), server_share.size()))
    {
        throw cosigner_exception(cosigner_exception::INTERNAL_ERROR);
    }

    paillier_with_range_proof_t* paillier_proof = NULL;

    zero_knowledge_proof_status zkp_ret = paillier_commitment_encrypt_with_exponent_zkpok_generate(damgard_fujisaki_pub.get(),
                                                                   server_setup_auxilary_key.paillier_commitment_priv.get(),
                                                                   algebra,
                                                                   server_key_metadata.seed,
                                                                   sizeof(commitments_sha256_t),
                                                                   server_share.data(),
                                                                   server_share.size(),
                                                                   /*use_extended_seed=*/1,
                                                                   &paillier_proof);
    if (zkp_ret != ZKP_SUCCESS)
    {
        LOG_ERROR("Failed to generate range proof with exponent paillier commitment. Client id %" PRIu64 ", the key id is %s.", client_id, key_id.c_str());
        throw_cosigner_exception(zkp_ret);
    }

    auto paillier_proof_guard = std::unique_ptr<paillier_with_range_proof_t, void(*)(paillier_with_range_proof_t*)>(
        paillier_proof,
        range_proof_free_paillier_with_range_proof);

    // prepare message to client
    server_message.encrypted_server_share.resize(paillier_proof->ciphertext_len);
    memcpy(server_message.encrypted_server_share.data(), paillier_proof->ciphertext, paillier_proof->ciphertext_len);

    //update key metadata and store encrypted server share.
    server_key_metadata.encrypted_server_share = server_message.encrypted_server_share;

    server_message.enc_dlog_proof.resize(paillier_proof->proof_len);
    memcpy(server_message.enc_dlog_proof.data(), paillier_proof->serialized_proof, paillier_proof->proof_len);

    elliptic_curve256_point_t joint_public_key;

    // compute the server public share.
    throw_cosigner_exception(algebra->generator_mul(algebra, &joint_public_key, &private_key.data));

    // decommit the server public share
    memcpy(server_message.server_public_share, joint_public_key, sizeof(elliptic_curve256_point_t));

    // calculate the joint public key and temporary store in joint_public_key
    elliptic_curve_algebra_status algebra_ret = algebra->add_points(algebra, &joint_public_key, &joint_public_key, &client_message.X);
    if (algebra_ret != ELLIPTIC_CURVE_ALGEBRA_SUCCESS)
    {
        LOG_ERROR("Algebra failed for for the client %" PRIu64 ", the key verify_client_proofs_and_decommit_share_with_proofid is %s. Error %d", client_id, key_id.c_str(), algebra_ret);
        throw_cosigner_exception(algebra_ret);
    }

    // check if it is the expected share for cases when we know public key in advance
    // when we are regenerating existing key the public key will be known in advance
    // so in this cases we must prevent the pub key forgery
    if (!server_key_metadata.has_public_key())
    {
        memcpy(&server_key_metadata.public_key[0], &joint_public_key[0], sizeof(elliptic_curve256_point_t));
    }
    else if (memcmp(&server_key_metadata.public_key[0], &joint_public_key[0], sizeof(elliptic_curve256_point_t)) != 0)
    {
        LOG_ERROR("Public key mismatch for the client %" PRIu64 ", the key verify_client_proofs_and_decommit_share_with_proofid is %s", client_id, key_id.c_str());
        throw_cosigner_exception(ELLIPTIC_CURVE_ALGEBRA_INVALID_POINT);
    }

    // save client's public key in the client_public_share
    static_assert(sizeof(server_key_metadata.client_public_share) == sizeof(client_message.X));
    memcpy(server_key_metadata.client_public_share, client_message.X, sizeof(server_key_metadata.client_public_share));

    _key_persistency.store_key_metadata(key_id, server_key_metadata, true);
    if (!_key_persistency.backup_key(key_id))
    {
        LOG_ERROR("Failed to backup key %s", key_id.c_str());
        _key_persistency.delete_key_data(key_id);
        throw cosigner_exception(cosigner_exception::BACKUP_FAILED);
    }

    _platform_service.clear_key_setup_in_progress(key_id);
}

void bam_ecdsa_cosigner_server::generate_signature_share(const std::string& key_id,
                                                         const std::string& tx_id,
                                                         const uint32_t version,
                                                         const uint64_t server_id,
                                                         const uint64_t client_id,
                                                         const cosigner_sign_algorithm requested_algorithm,
                                                         const common::cosigner::signing_data& data,
                                                         const std::string& metadata_json,
                                                         const std::set<std::string>& players_set,
                                                         std::vector<server_signature_shared_data>& server_commitments)
{
    LOG_INFO("Entering txid = %s", tx_id.c_str());

    _platform_service.prepare_for_signing(key_id, tx_id);

    auto server_signature_data_ptr = std::make_shared<bam_server_signature_data>(version, server_id, client_id, key_id, static_cast<int64_t>(_platform_service.now_msec() / 1000));
    auto& server_signature_data = *server_signature_data_ptr;

    bam_key_metadata_server server_key_metadata;

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

    _key_persistency.load_key_metadata(key_id, server_key_metadata);
    if (server_key_metadata.encrypted_server_share.empty())
    {
        LOG_ERROR("Key id %s tx_id %s: trying to sign while key was not fully created", key_id.c_str(), tx_id.c_str());
        throw cosigner_exception(cosigner_exception::INTERNAL_ERROR);
    }

    validate_tenant_id_setup(server_key_metadata.setup_id);

    if (requested_algorithm != server_key_metadata.algorithm)
    {
        LOG_ERROR("Key %s, tx_id %s: algorithm mismatch, requested %d but key has %d", key_id.c_str(), tx_id.c_str(), requested_algorithm, server_key_metadata.algorithm);
        throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
    }

    if (server_key_metadata.peer_id != client_id)
    {
        LOG_ERROR("Wrong client id for key %s. %" PRIu64 " != %" PRIu64, key_id.c_str(), server_key_metadata.peer_id, client_id);
        throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
    }

    _platform_service.on_start_signing(key_id, tx_id, data, metadata_json, players_set, platform_service::MULTI_ROUND_SIGNATURE);

    auto algebra = get_algebra(server_key_metadata.algorithm);
    server_commitments.resize(signature_request_data.size());
    server_signature_data.sig_data.resize(signature_request_data.size());

    for (uint32_t i = 0; i < (uint32_t)signature_request_data.size(); ++ i)
    {
        auto& sig_request = signature_request_data[i];                  // request which has to be signed
        auto& persistant_sig_data = server_signature_data.sig_data[i];  // data about the signature that the server should save
        auto& server_message = server_commitments[i];                   // the message to the client

        persistant_sig_data.flags = sig_request.flags;
        if (data.blocks[i].data.size() != sizeof(elliptic_curve256_scalar_t))
        {
            LOG_ERROR("block %u has illegal size of %u", i, static_cast<uint32_t>(data.blocks[i].data.size()));
            throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
        }
        memcpy(persistant_sig_data.message, data.blocks[i].data.data(), sizeof(elliptic_curve256_scalar_t));

        // required because of the Claim 7.15 is the BAM article
        check_non_null_message(persistant_sig_data.message, algebra);

        derivation_key_delta(algebra, server_key_metadata.public_key, data.chaincode, data.blocks[i].path, persistant_sig_data.derivation_delta);

        throw_cosigner_exception(algebra->rand(algebra, &persistant_sig_data.k.data));
        throw_cosigner_exception(algebra->generator_mul(algebra, &server_message.R, &persistant_sig_data.k.data));

        // It is required to calculate client's public key to the power of k
        // which in turn would serve as a discrete log proof of the k.
        // But it is also required to have the derivation specific proof, so commit to the derived public share
        throw_cosigner_exception(algebra->generator_mul(algebra, &server_message.Y, &persistant_sig_data.derivation_delta));
        // server_key_metadata.client_public_share hold client's public key at this point
        throw_cosigner_exception(algebra->add_points(algebra, &server_message.Y, &server_message.Y, &server_key_metadata.client_public_share));
        throw_cosigner_exception(algebra->point_mul(algebra, &server_message.Y, &server_message.Y, &persistant_sig_data.k.data));
    }

    // we don't care about storing R...
    _tx_persistency.store_signature_data(tx_id, server_signature_data_ptr);
}

void bam_ecdsa_cosigner_server::verify_partial_signature_and_output_signature(const std::string& tx_id,
                                                                              const uint64_t client_id,
                                                                              const std::vector<client_partial_signature_data>& partial_signatures,
                                                                              std::vector<recoverable_signature>& signatures,
                                                                              cosigner_sign_algorithm& algorithm)
{
    bam_setup_auxilary_key_server server_setup_auxilary_key;
    bam_setup_metadata_server server_setup_metadata;
    bam_key_metadata_server server_key_metadata;
    commitments_sha256_t signature_add;

    auto server_signature_data_ptr = _tx_persistency.load_signature_data_and_delete(tx_id);
    auto& server_signature_data = *server_signature_data_ptr;
    const auto& key_id = server_signature_data.key_id;

    _key_persistency.load_key_metadata(key_id, server_key_metadata);

    validate_tenant_id_setup(server_key_metadata.setup_id);

    if (client_id != server_signature_data.client_signer_id)
    {
        LOG_ERROR("Key %s, tx_id %s: client player id mismatch, got %" PRIu64 " expected %" PRIu64, key_id.c_str(), tx_id.c_str(), client_id, server_signature_data.client_signer_id);
        throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
    }

    _key_persistency.load_setup_auxilary_key(server_key_metadata.setup_id, server_setup_auxilary_key);
    _key_persistency.load_setup_metadata(server_key_metadata.setup_id, server_setup_metadata);

    if (server_signature_data.sig_data.size() != partial_signatures.size())
    {
        LOG_ERROR("Key %s, tx_id %s: client partial signatures size mismatch. %u != %u", key_id.c_str(), tx_id.c_str(), (uint32_t)partial_signatures.size(), (uint32_t) server_signature_data.sig_data.size());
        throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
    }

    signatures.resize(partial_signatures.size());

    // verified during key generation - here only for sanity
    assert(server_setup_metadata.setup_algorithm == server_key_metadata.algorithm);

    std::unique_ptr<BN_CTX, void (*)(BN_CTX*)> ctx(BN_CTX_new(), BN_CTX_free);
    if (!ctx)
    {
        throw_cosigner_exception(cosigner_exception::NO_MEM);
    }

    generate_aad_for_signature(server_signature_data.key_id, server_signature_data.server_signer_id, server_signature_data.client_signer_id, tx_id, signature_add);

    auto algebra = get_algebra(server_key_metadata.algorithm);

    BN_CTX_start(ctx.get());
    std::unique_ptr<BN_CTX, void (*)(BN_CTX*)> ctx_start_guard(ctx.get(), BN_CTX_end);

    BIGNUM* half_n = BN_CTX_get(ctx.get());
    BIGNUM* encrypted_share_bn = BN_CTX_get(ctx.get());
    if (!half_n || !encrypted_share_bn)
    {
        throw_cosigner_exception(cosigner_exception::NO_MEM);
    }

    if (!BN_rshift1(half_n, server_setup_auxilary_key.paillier_commitment_priv->pub.n))
    {
        LOG_ERROR("shift right failed error %lu", ERR_get_error());
        throw cosigner_exception(cosigner_exception::INTERNAL_ERROR);
    }

    if (!BN_bin2bn(server_key_metadata.encrypted_server_share.data(),  server_key_metadata.encrypted_server_share.size(), encrypted_share_bn))
    {
        LOG_ERROR("Error converting encrypted server share %lu", ERR_get_error());
        throw cosigner_exception(cosigner_exception::NO_MEM);
    }

    for (uint32_t i = 0; i < (uint32_t)partial_signatures.size(); ++ i )
    {
        BN_CTX_start(ctx.get());
        std::unique_ptr<BN_CTX, void (*)(BN_CTX*)> ctx_for_loop_guard(ctx.get(), BN_CTX_end);

        auto& signature = signatures[i];
        auto& partial_signature = partial_signatures[i];
        auto& persistant_sig_data = server_signature_data.sig_data[i];
        elliptic_curve256_point_t tmp_point;
        elliptic_curve_scalar v;

        // check that the client share is not the point at infinity
        check_a_valid_point(partial_signature.client_R, algebra);

        GFp_curve_algebra_ctx_t* curve = (GFp_curve_algebra_ctx_t*)algebra->ctx;
        // tmp_point = G^(k_client * k_server)
        throw_cosigner_exception(algebra->point_mul(algebra, &tmp_point, &partial_signature.client_R, &persistant_sig_data.k.data));

        // DH-consistency check: ensure the client’s R1 and common_share encode the SAME nonce k1.
        // We verify R1^k2 == common_share, i.e., (g^k1)^k2 == (g^k2)^k1 == g^(k1*k2).
        // Why this is critical:
        //  - Proves the client used a single k1 for both R1 and common_share (PoK w.r.t. both bases).
        //  - Prevents “chosen-R” attacks where the client tries to pick common_share to bias r.
        //  - Ensures both parties derive the same r after the hash-based shift.
        //  - This DH-tuple consistency is required by the signing protocol’s security argument
        //    (see paper: Two-round signing → compute/verify the common R; equality-of-exponents / DH consistency).
        if (memcmp(tmp_point, partial_signature.common_R, sizeof(elliptic_curve256_point_t)) != 0)
        {
            LOG_ERROR("Invalid common share point for client %" PRIu64 ", key_id %s, tx_id %s", server_signature_data.client_signer_id, key_id.c_str(), tx_id.c_str());
            throw_cosigner_exception(ELLIPTIC_CURVE_ALGEBRA_INVALID_POINT);
        }

        elliptic_curve256_scalar_t hash_shift;
        elliptic_curve256_point_t derived_public_key, corrected_R;
        derive_and_compute_corrected_R(algebra, tx_id, persistant_sig_data, server_key_metadata.public_key, partial_signature, derived_public_key, hash_shift, corrected_R);
        uint8_t overflow = 0;

        // r
        throw_cosigner_exception(GFp_curve_algebra_get_point_projection(curve, &signature.r, &corrected_R, &overflow));

        // POSITIVE_R handling (server-side)
        //
        // Do NOT trust or accept any “pre-corrected” R from the client. In this
        // protocol the x-coordinate r is fixed by public data and the server’s nonce:
        //    R* = R_com  +  R_client^{H(X || R_client || R_com || m)}
        //    r  = x(R*)
        // where R_client = g^{k_client} and R_com = R_server^{k_client}. We already
        // checked that R_com = R_client^{k_server}, so R* (and thus r) is determined
        // independently by the server. We therefore recompute the same positivity
        // loop locally: while r is not “positive”, add R_com again.
        //
        // Important cross-party invariant:
        // If t additions are needed, the CLIENT must update its nonce to k_client' = k_client·t
        // and use k_client'^{-1} when producing its encrypted partial (u, v). Its
        // well-formedness ZK proof binds (u, v) to that adjusted k_client' and to the same r.
        // See client code:
        //   bam_ecdsa_cosigner_client::compute_partial_signature(...)
        //   → the block under `if (persistant_sig_data.flags & POSITIVE_R)`
        //
        // Consequence for the server:
        // We MUST NOT apply any extra “positivity correction” to the partial or to s.
        // We simply:
        //   1) recompute r via the same deterministic loop,
        //   2) verify the client’s proof,
        //   3) decrypt u and combine as specified.
        // Any additional correction here would double-apply the factor t and break
        // correctness. The client has already baked the correction into its share.
        if (persistant_sig_data.flags & POSITIVE_R)
        {
            //check that R is good for us
            // try to correct R multiplying share by n= 2,3... untill we find the right R and remember the n
            // also correct the signature.r,
            uint8_t r_correction_cycles = 1;
            memcpy(tmp_point, corrected_R, sizeof(elliptic_curve256_point_t));
            while (!is_positive(server_key_metadata.algorithm, signature.r))
            {
                assert(r_correction_cycles < 255);
                if (r_correction_cycles == 255)
                {
                    LOG_ERROR("Failed to find a positive r in 256 iterations key_id %s, tx_id %s", key_id.c_str(), tx_id.c_str());
                    throw_cosigner_exception(ELLIPTIC_CURVE_ALGEBRA_INVALID_POINT);
                }
                ++r_correction_cycles;
                throw_cosigner_exception(algebra->add_points(algebra, &corrected_R, &corrected_R, &tmp_point));
                throw_cosigner_exception(GFp_curve_algebra_get_point_projection(curve, &signature.r, &corrected_R, &overflow));
            }
        }

        BIGNUM* encrypted_partial_signature_bn = BN_CTX_get(ctx.get());
        BIGNUM* decrypted_partial_signature_bn = BN_CTX_get(ctx.get());
        BIGNUM* hash_shift_bn = BN_CTX_get(ctx.get());
        BIGNUM* s_bn = BN_CTX_get(ctx.get());

        if (!encrypted_partial_signature_bn || !decrypted_partial_signature_bn || !hash_shift_bn || !s_bn)
        {
            throw_cosigner_exception(cosigner_exception::NO_MEM);
        }

        if (!BN_bin2bn(partial_signature.encrypted_partial_sig.data(), partial_signature.encrypted_partial_sig.size(), encrypted_partial_signature_bn))
        {
            throw_cosigner_exception(cosigner_exception::NO_MEM);
        }

        // restore server's R
        throw_cosigner_exception(algebra->generator_mul(algebra, &tmp_point, &persistant_sig_data.k.data));


        bam_well_formed_proof::verify_signature_proof(partial_signature.sig_proof,
                                                      server_setup_auxilary_key.paillier_commitment_priv.get(),
                                                      algebra,
                                                      &server_setup_metadata.ec_base,
                                                      signature_add,
                                                      encrypted_share_bn,
                                                      encrypted_partial_signature_bn,
                                                      tmp_point,
                                                      ctx.get());

        // s
        throw_cosigner_exception(algebra->add_scalars(algebra,
                                                      &hash_shift, //reuse the variable
                                                      hash_shift,
                                                      sizeof(elliptic_curve256_scalar_t),
                                                      persistant_sig_data.k.data,
                                                      sizeof(elliptic_curve256_scalar_t)));

        throw_cosigner_exception(algebra->inverse(algebra, &hash_shift, &hash_shift));

        if (!BN_bin2bn(hash_shift, sizeof(elliptic_curve256_scalar_t), hash_shift_bn))
        {
            throw_cosigner_exception(cosigner_exception::NO_MEM);
        }

        // decrypt the partial signature and store it inside the same place
        throw_paillier_exception(paillier_commitment_decrypt_openssl_internal(server_setup_auxilary_key.paillier_commitment_priv.get(),
                                                                              encrypted_partial_signature_bn,
                                                                              decrypted_partial_signature_bn,
                                                                              ctx.get()));

        // Canonicalize the Paillier plaintext before switching moduli.
        //
        // Because we work with different modulus we need to switch from mod n to mod q (order of the curve)
        // To map the value correctly we need to center the value around 0 before switching
        if (BN_cmp(decrypted_partial_signature_bn, half_n) > 0)
        {
            if (!BN_mod_sub(decrypted_partial_signature_bn,
                            decrypted_partial_signature_bn,
                            server_setup_auxilary_key.paillier_commitment_priv->pub.n,
                            algebra->order_internal(algebra),
                            ctx.get()))
            {
                LOG_ERROR("Failed to shift by N/2 error %lu", ERR_get_error());
                throw cosigner_exception(cosigner_exception::INTERNAL_ERROR);
            }
        }

        if (!BN_mod_mul(s_bn, hash_shift_bn, decrypted_partial_signature_bn, algebra->order_internal(algebra), ctx.get()))
        {
            throw_cosigner_exception(cosigner_exception::NO_MEM);
        }

        if (!BN_bn2binpad(s_bn, signature.s, sizeof(signature.s)))
        {
            throw_cosigner_exception(cosigner_exception::NO_MEM);
        }

        signature.v = (overflow ? 2 : 0) | (is_odd_point(corrected_R) ? 1 : 0);
        make_sig_s_positive(server_key_metadata.algorithm, algebra, signature);

        //Use derived public key
        elliptic_curve_algebra_status status = GFp_curve_algebra_verify_signature(curve,
                                                                                  &derived_public_key,
                                                                                  &persistant_sig_data.message,
                                                                                  &signature.r,
                                                                                  &signature.s);
        if (status != ELLIPTIC_CURVE_ALGEBRA_SUCCESS)
        {
            LOG_FATAL("failed to verify signature for client %" PRIu64 ", error %d", server_signature_data.client_signer_id, status);
            throw cosigner_exception(cosigner_exception::INTERNAL_ERROR);
        }
    }

    algorithm = server_key_metadata.algorithm;
}

void bam_ecdsa_cosigner_server::get_public_key(const std::string& key_id, generated_public_key& pub_key_data) const
{
    bam_key_metadata_server server_key_metadata;
    _key_persistency.load_key_metadata(key_id, server_key_metadata);
    auto algebra = get_algebra(server_key_metadata.algorithm);
    pub_key_data.pub_key.assign(reinterpret_cast<const char*>(server_key_metadata.public_key), algebra->point_size(algebra));
    pub_key_data.algorithm = server_key_metadata.algorithm;
}


} //namespace fireblocks::common::cosigner
