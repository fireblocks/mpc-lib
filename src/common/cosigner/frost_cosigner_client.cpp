#include <cinttypes>
#include <openssl/sha.h>
#include "utils.h"
#include "logging/logging_t.h"
#include "cosigner/mpc_globals.h"
#include "cosigner/cosigner_exception.h"
#include "cosigner/platform_service.h"
#include "cosigner/frost_cosigner_client.h"
#include "cosigner/frost_key_persistency_client.h"

namespace fireblocks::common::cosigner
{

frost_cosigner_client::frost_cosigner_client(platform_service& platform_service, frost_key_persistency_client& key_persistency)
: frost_cosigner(platform_service),
  _key_persistency(key_persistency) {}

// ============================================================
// KEY GENERATION
// ============================================================

void frost_cosigner_client::start_new_key_generation(const std::string& key_id,
                                                     const std::string& tenant_id,
                                                     const uint64_t client_id,
                                                     const uint64_t server_id,
                                                     cosigner_sign_algorithm algo)
{
    validate_current_tenant_id(tenant_id);
    validate_players_ids_key_gen(key_id, client_id, server_id);

    elliptic_curve_scalar secret;
    const elliptic_curve256_algebra_ctx_t* algebra = get_algebra(algo);
    rand_nonzero_scalar(algebra, secret.data);

    elliptic_curve256_point_t infinity_point;
    memcpy(infinity_point, algebra->infinity_point(algebra), sizeof(elliptic_curve256_point_t));

    start_key_generation(key_id, tenant_id, client_id, server_id, algo, secret, infinity_point);
}

void frost_cosigner_client::start_add_user(const std::string& key_id,
                                           const std::string& tenant_id,
                                           const uint64_t client_id,
                                           const uint64_t server_id,
                                           const cosigner_sign_algorithm algo,
                                           const std::map<uint64_t, add_user_data>& data)
{
    validate_current_tenant_id(tenant_id);
    validate_players_ids_key_gen(key_id, client_id, server_id);

    elliptic_curve_scalar secret;
    elliptic_curve256_point_t expected_public_key;
    decrypt_and_rebuild_private_share(client_id, get_algebra(algo), _platform_service, data, /*destination_n=*/2, secret, expected_public_key);

    if (is_zero_scalar(secret.data))
    {
        LOG_FATAL("Secret share reconstructed is zero for key %s, client_id %" PRIu64 ", server_id %" PRIu64, key_id.c_str(), client_id, server_id);
        throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
    }

    const elliptic_curve256_algebra_ctx_t* algebra = get_algebra(algo);
    check_a_valid_point(expected_public_key, algebra);

    start_key_generation(key_id, tenant_id, client_id, server_id, algo, secret, expected_public_key);
}

void frost_cosigner_client::start_key_generation(const std::string& key_id,
                                                 const std::string& tenant_id,
                                                 const uint64_t client_id,
                                                 const uint64_t server_id,
                                                 const cosigner_sign_algorithm algo,
                                                 const elliptic_curve_scalar& secret,
                                                 const elliptic_curve256_point_t& expected_public_key)
{
    (void)client_id; // Unused parameter
    frost_key_metadata_base key_metadata;
    key_metadata.algorithm = algo;
    key_metadata.peer_id = server_id;
    memcpy(key_metadata.public_key, expected_public_key, sizeof(elliptic_curve256_point_t));

    _platform_service.mark_key_setup_in_progress(key_id);

    _key_persistency.store_tenant_id_for_key(key_id, tenant_id);
    _key_persistency.store_key_metadata(key_id, key_metadata, false);
    _key_persistency.store_key(key_id, secret, algo);
}

void frost_cosigner_client::store_commitment_and_generate_proofs(const std::string& key_id,
                                                                 const commitments_sha256_t& B,
                                                                 const uint64_t server_id,
                                                                 frost_cosigner::key_share_public_data& message)
{
    validate_tenant_id_for_key(_key_persistency, key_id);

    elliptic_curve_scalar client_secret;
    frost_key_metadata_base key_metadata;
    _key_persistency.load_key_metadata(key_id, key_metadata);
    if (key_metadata.peer_id != server_id)
    {
        LOG_ERROR("Wrong server id for key %s. %" PRIu64 " != %" PRIu64, key_id.c_str(), key_metadata.peer_id, server_id);
        throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
    }

    _key_persistency.store_server_commitment(key_id, B);
    
    const uint64_t my_id = _platform_service.get_id_from_keyid(key_id);
    commitments_sha256_t seed;
    compute_key_generation_seed(key_id, my_id, server_id, seed);

    _key_persistency.load_key(key_id, client_secret);
    generate_share_with_schnorr_proof(key_metadata.algorithm, my_id, seed, sizeof(commitments_sha256_t), client_secret, message.X, message.schnorr_proof);
}

void frost_cosigner_client::verify_key_decommitment_and_proofs(const std::string& key_id,
                                                               const uint64_t server_id, 
                                                               const frost_cosigner::key_share_public_data& server_message, 
                                                               frost_cosigner::generated_public_key& pub_key_data)
{
    validate_tenant_id_for_key(_key_persistency, key_id);

    frost_key_metadata_base key_metadata;
    _key_persistency.load_key_metadata(key_id, key_metadata);
    
    if (key_metadata.peer_id != server_id)
    {
        LOG_ERROR("Wrong server id for key %s. %" PRIu64 " != %" PRIu64, key_id.c_str(), key_metadata.peer_id, server_id);
        throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
    }
    
    const uint64_t my_id = _platform_service.get_id_from_keyid(key_id);
    commitments_sha256_t seed;
    compute_key_generation_seed(key_id, my_id, server_id, seed);
    
    commitments_sha256_t local_commitment;
    compute_key_share_commitment(seed, server_message.X, local_commitment);
    
    commitments_sha256_t stored_comitment;
    _key_persistency.load_server_commitment_and_delete(key_id, stored_comitment);
    // compare the newly computed server commitment, with the one previously sent by the server.
    if (memcmp(local_commitment, stored_comitment, sizeof(commitments_sha256_t)) != 0)
        throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
    
    verify_share_with_schnorr_proof(key_metadata.algorithm, key_metadata.peer_id, seed, sizeof(commitments_sha256_t), server_message.X, server_message.schnorr_proof);

    auto algebra = get_algebra(key_metadata.algorithm);
    elliptic_curve_scalar client_secret;
    _key_persistency.load_key(key_id, client_secret);
    
    elliptic_curve256_point_t client_public_key;
    elliptic_curve256_point_t common_public_key;
    throw_cosigner_exception(algebra->generator_mul(algebra, &client_public_key, &client_secret.data));
    throw_cosigner_exception(algebra->add_points(algebra, &common_public_key, &client_public_key, &server_message.X));

    if (!key_metadata.has_public_key(algebra))
    {
        memcpy(key_metadata.public_key, common_public_key, sizeof(elliptic_curve256_point_t));
        _key_persistency.store_key_metadata(key_id, key_metadata, true);
    }
    else if (memcmp(key_metadata.public_key, common_public_key, sizeof(elliptic_curve256_point_t)) != 0)
    {
        LOG_ERROR("Public key mismatch for client id %" PRIu64 ", key id %s", my_id, key_id.c_str());
        throw_cosigner_exception(ELLIPTIC_CURVE_ALGEBRA_INVALID_PARAMETER);
    }

    if (!_key_persistency.backup_key(key_id))
    {
        LOG_ERROR("Failed to backup FROST key %s", key_id.c_str());
        _key_persistency.delete_key(key_id);
        throw cosigner_exception(cosigner_exception::BACKUP_FAILED);
    }

    _platform_service.clear_key_setup_in_progress(key_id);

    // Return the final combined public key and algorithm (similar to BAM pattern)
    pub_key_data.pub_key.assign(reinterpret_cast<const char*>(key_metadata.public_key), algebra->point_size(algebra));
    pub_key_data.algorithm = key_metadata.algorithm;
}

// ============================================================
// SIGNING
// ============================================================

void frost_cosigner_client::compute_partial_signature(const std::string& key_id,
                                                      const std::string& tx_id,
                                                      const uint32_t version,
                                                      const uint64_t server_id,
                                                      const uint64_t client_id,
                                                      const signing_data& data,
                                                      const std::string& metadata_json,
                                                      const std::set<std::string>& players_set,
                                                      const std::vector<frost_cosigner::server_signature_shared_data>& server_shares,
                                                      std::vector<frost_cosigner::client_partial_signature_data>& partial_signatures)
{
    LOG_INFO("Entering txid = %s", tx_id.c_str());

    _platform_service.prepare_for_signing(key_id, tx_id);

    if (data.blocks.size() == 0)
    {
        LOG_ERROR("Key %s, tx_id %s: Empty signature batch request", key_id.c_str(), tx_id.c_str());
        throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
    }
    else if (data.blocks.size() > MAX_BLOCKS_TO_SIGN)
    {
        LOG_ERROR("number of blocks: %u is bigger than the permitted amount: %u", static_cast<uint32_t>(data.blocks.size()), MAX_BLOCKS_TO_SIGN);
        throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
    }

    //validate client and server id
    frost_key_metadata_base key_metadata;
    _key_persistency.load_key_metadata(key_id, key_metadata);

    if (key_metadata.peer_id != server_id)
    {
        LOG_ERROR("Wrong server id for key %s. %" PRIu64 " != %" PRIu64, key_id.c_str(), key_metadata.peer_id, server_id);
        throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
    }

    validate_tenant_id_for_key(_key_persistency, key_id);
    validate_current_player_id(key_id, client_id);

    (void) version;

    const auto signature_request_data = fill_frost_signing_info_from_metadata(metadata_json, static_cast<uint32_t>(data.blocks.size()));
    if (data.blocks.size() != signature_request_data.size())
    {
        LOG_ERROR("number of blocks %u is different than number of flags %u", static_cast<uint32_t>(data.blocks.size()), static_cast<uint32_t>(signature_request_data.size()));
        throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
    }

    _platform_service.on_start_signing(key_id, tx_id, data, metadata_json, players_set, platform_service::SINGLE_ROUND_SIGNATURE);

    if (server_shares.size() != data.blocks.size())
    {
        LOG_ERROR("Tx_id %s: Server shares size missmatch. %u != %u", tx_id.c_str(), (uint32_t)server_shares.size(), (uint32_t) data.blocks.size());
        throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
    }
    
    elliptic_curve_scalar private_share;
    commitments_sha256_t signature_aad;

    _key_persistency.load_key(key_id, private_share);
    
    const auto algebra = get_algebra(key_metadata.algorithm);

    generate_aad_for_signature(key_id, key_metadata.peer_id, client_id, tx_id, signature_aad); 

    partial_signatures.resize(server_shares.size());

    for (uint32_t i = 0; i < (uint32_t)server_shares.size(); ++ i )
    {
        auto& server_share = server_shares[i];
        auto& partial_signature = partial_signatures[i];

        const uint32_t flags = signature_request_data[i].flags;
        const byte_vector_t& message = data.blocks[i].data;

        elliptic_curve256_scalar_t derivation_delta;
        elliptic_curve256_point_t derived_public_key;
        derivation_key_delta(algebra, key_metadata.public_key, data.chaincode, data.blocks[i].path, derivation_delta, derived_public_key);

        // Compute derived secret key
        elliptic_curve_scalar derived_client_secret;
        throw_cosigner_exception(algebra->add_scalars(algebra, &derived_client_secret.data, private_share.data, sizeof(elliptic_curve256_scalar_t), derivation_delta, sizeof(elliptic_curve256_scalar_t)));

        // BIP340: if combined derived public key has odd y, sign with -x instead of x
        if (negate_point_if_needed(algebra, derived_public_key))
        {
            static const uint8_t ZERO = 0x00;
            throw_cosigner_exception(algebra->sub_scalars(algebra, &derived_client_secret.data, &ZERO, sizeof(ZERO), derived_client_secret.data, sizeof(elliptic_curve256_scalar_t)));
        }

        elliptic_curve_scalar secret_d;
        elliptic_curve_scalar secret_e;
        rand_nonzero_scalar(algebra, secret_d.data);
        throw_cosigner_exception(algebra->generator_mul(algebra, &partial_signature.D, &secret_d.data));
        rand_nonzero_scalar(algebra, secret_e.data);
        throw_cosigner_exception(algebra->generator_mul(algebra, &partial_signature.E, &secret_e.data));

        elliptic_curve256_point_t R;
        elliptic_curve256_point_t R_client; // not needed
        elliptic_curve_scalar server_partial_hash; // not needed
        elliptic_curve_scalar client_partial_hash;

        compute_common_nonce(algebra, message, signature_aad, key_metadata.peer_id, server_share.D, server_share.E, client_id, partial_signature.D, partial_signature.E, server_partial_hash.data, client_partial_hash.data, R_client, R);
        bool negated_R = negate_point_if_needed(algebra, R);

        const bool use_keccak = flags & EDDSA_KECCAK;

        // compute c = H(X, message, R) using derived public key
        elliptic_curve256_scalar_t c_scalar;
        calc_hram(algebra, c_scalar, R, derived_public_key, message.data(), message.size(), use_keccak);

        // Now compute z2 = c.x2 + d2 + e2*r2  where r2 = client_hash
        //     c.x2 (using derived secret key)
        throw_cosigner_exception(algebra->mul_scalars(algebra, &partial_signature.s.data, c_scalar, sizeof(elliptic_curve256_scalar_t), derived_client_secret.data, sizeof(elliptic_curve256_scalar_t)));
        //     d2 + e2*r2
        throw_cosigner_exception(algebra->mul_scalars(algebra, &client_partial_hash.data, client_partial_hash.data, sizeof(elliptic_curve256_scalar_t), secret_e.data, sizeof(elliptic_curve256_scalar_t)));
        throw_cosigner_exception(algebra->add_scalars(algebra, &client_partial_hash.data, client_partial_hash.data, sizeof(elliptic_curve256_scalar_t), secret_d.data, sizeof(elliptic_curve256_scalar_t)));
        // c.x2 +/- (d2 + e2*r2)
        if (negated_R)
        {
            throw_cosigner_exception(algebra->sub_scalars(algebra, &partial_signature.s.data, partial_signature.s.data, sizeof(elliptic_curve256_scalar_t), client_partial_hash.data, sizeof(elliptic_curve256_scalar_t)));
        }
        else
        {
            throw_cosigner_exception(algebra->add_scalars(algebra, &partial_signature.s.data, partial_signature.s.data, sizeof(elliptic_curve256_scalar_t), client_partial_hash.data, sizeof(elliptic_curve256_scalar_t)));
        }
    }

}

}