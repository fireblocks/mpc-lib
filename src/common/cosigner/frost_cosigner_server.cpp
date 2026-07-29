#include <cinttypes>
#include <openssl/bn.h>
#include <openssl/sha.h>
#include "utils.h"
#include "logging/logging_t.h"
#include "cosigner/mpc_globals.h"
#include "cosigner/cosigner_exception.h"
#include "cosigner/platform_service.h"
#include "cosigner/frost_key_persistency_server.h"
#include "cosigner/frost_tx_persistency.h"
#include "cosigner/frost_cosigner_server.h"

namespace fireblocks::common::cosigner
{

frost_cosigner_server::frost_cosigner_server(platform_service& platform_service, frost_key_persistency_server& key_persistency, frost_tx_persistency& tx_persistency):
    frost_cosigner(platform_service),
    _key_persistency(key_persistency),
    _tx_persistency(tx_persistency)
{

}

void frost_cosigner_server::shutdown()
{
    _tx_persistency.shutdown();
}

// This function fromats the signature to become a `eddsa_signature` type from the R point, and s value,
// with correct endianness.
static void eddsa_signature_format(eddsa_signature& sig, const elliptic_curve256_algebra_ctx_t* ctx, const elliptic_curve256_point_t* R, const elliptic_curve256_scalar_t* s)
{
    switch (ctx->type) 
    {
        case ELLIPTIC_CURVE_ED25519:
            // s should be stored in little endian, so reverse it
            // R is stored in the first 32 bytes of a 'elliptic_curve256_point_t'
            memcpy(sig.R, *R, sizeof(ed25519_point_t));
            ed25519_algebra_be_to_le(&sig.s, s);
            return;
        case ELLIPTIC_CURVE_SECP256K1: // FALLTHROUGH
        case ELLIPTIC_CURVE_SECP256R1: // FALLTHROUGH
        case ELLIPTIC_CURVE_STARK:
            // only Rx is stored, so copy the last 32 bytes of a 'elliptic_curve256_point_t'
            // s should be stored in big endian, so simply copy it
            memcpy(sig.R, &((*R)[1]), sizeof(ed25519_point_t));
            memcpy(sig.s, *s, sizeof(ed25519_scalar_t));
            return;
        default:
            throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
    }
}

int frost_cosigner_server::validate_schnorr_signature(const elliptic_curve256_algebra_ctx_t* ctx, const eddsa_signature& cur_sig, const uint8_t* message, size_t message_len, const elliptic_curve256_point_t* derived_public_key, bool use_keccak, const byte_vector_t& prefix, const byte_vector_t& suffix)
{
    if (ctx->type == ELLIPTIC_CURVE_ED25519) 
    {
        if (!prefix.empty() || !suffix.empty()) // in eddsa there aren't supposed to be prefix and suffix
            throw_cosigner_exception(ELLIPTIC_CURVE_ALGEBRA_INVALID_PARAMETER);

        // optimized implementation for ed25519
        unsigned char raw_sig[64];
        memcpy(raw_sig, cur_sig.R, 32);
        memcpy(raw_sig + 32, cur_sig.s, 32);
        return ed25519_verify((ed25519_algebra_ctx_t *)ctx->ctx, message, message_len, raw_sig, *derived_public_key, use_keccak);
    }
    std::unique_ptr<BIGNUM, void(*)(BIGNUM*)> tmp(BN_bin2bn(cur_sig.s, sizeof(elliptic_curve256_scalar_t), NULL), BN_free);
    if (!tmp) 
        throw_cosigner_exception(ELLIPTIC_CURVE_ALGEBRA_OUT_OF_MEMORY);

    if (BN_cmp(tmp.get(), ctx->order_internal(ctx)) >= 0) 
        return 0; // s >= n -> invalid signature
        
    elliptic_curve256_point_t points[2]; // will hold {[s]G, P};
    elliptic_curve256_scalar_t scalars[2]; // will hold {1, hram};
    elliptic_curve256_point_t R = {0x02, 0x00}; // used for the equality check - only the 'even-y' is allowed
    memcpy(&R[1], cur_sig.R, sizeof(ed25519_point_t));

    // BIP340: public key is always treated as even-y; the x-coordinate alone identifies it
    elliptic_curve256_point_t pub;
    memcpy(pub, *derived_public_key, sizeof(elliptic_curve256_point_t));
    pub[0] = 0x02;

    memset(scalars[0], 0x00, sizeof(elliptic_curve256_scalar_t));
    scalars[0][sizeof(elliptic_curve256_scalar_t) - 1] = 0x01;
    calc_hram(ctx, scalars[1], R, pub, message, message_len, use_keccak, prefix, suffix);

    throw_cosigner_exception(ctx->generator_mul(ctx, &points[0], &cur_sig.s));
    memcpy(points[1], pub, sizeof(elliptic_curve256_point_t));
    points[1][0] ^= 0x01; // negate the public key so that we can compute ([s]G + [h](-P)) == R

    uint8_t result = 0;
    throw_cosigner_exception(ctx->verify_linear_combination(ctx, &R, points, scalars, 2, &result));
    return result;
}

// ============================================================
// KEY GENERATION
// ============================================================

void frost_cosigner_server::generate_share_and_commit(const std::string& key_id, const std::string& tenant_id, cosigner_sign_algorithm algo, uint64_t server_id, uint64_t client_id, commitments_sha256_t& commitment)
{
    validate_players_ids_key_gen(key_id, server_id, client_id);
    validate_current_tenant_id(tenant_id);
    const elliptic_curve256_algebra_ctx_t* algebra = get_algebra(algo);
    elliptic_curve_scalar secret;
    rand_nonzero_scalar(algebra, secret.data);

    elliptic_curve256_point_t infinity_point;
    memcpy(infinity_point, algebra->infinity_point(algebra), sizeof(elliptic_curve256_point_t));

    commit_to_share(algo, key_id, server_id, client_id, infinity_point, secret, commitment);
}


void frost_cosigner_server::add_user_and_commit(const std::string& key_id, const std::string& tenant_id, cosigner_sign_algorithm algo, uint64_t server_id, uint64_t client_id, const std::map<uint64_t, add_user_data>& data, commitments_sha256_t& commitment)
{
    LOG_INFO("Server committing to share for key %s, my_id %" PRIu64 ", client id %" PRIu64 ", algorithm %d", key_id.c_str(), server_id, client_id, algo);
    validate_players_ids_key_gen(key_id, server_id, client_id);
    validate_current_tenant_id(tenant_id);

    elliptic_curve_scalar secret;
    elliptic_curve256_point_t expected_public_key;
    decrypt_and_rebuild_private_share(server_id, get_algebra(algo), _platform_service, data, /*destination_n=*/2, secret, expected_public_key);

    if (is_zero_scalar(secret.data))
    {
        LOG_FATAL("Secret share reconstructed is zero for key %s, server_id %" PRIu64 ", client_id %" PRIu64, key_id.c_str(), server_id, client_id);
        throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
    }

    const elliptic_curve256_algebra_ctx_t* algebra = get_algebra(algo);
    check_a_valid_point(expected_public_key, algebra);

    commit_to_share(algo, key_id, server_id, client_id, expected_public_key, secret, commitment);
}

void frost_cosigner_server::commit_to_share(const cosigner_sign_algorithm algo, const std::string& key_id, uint64_t server_id, uint64_t client_id, const elliptic_curve256_point_t& expected_public_key, const elliptic_curve_scalar& secret, commitments_sha256_t& commitment)
{
    const elliptic_curve256_algebra_ctx_t* algebra = get_algebra(algo);

    frost_key_metadata_server key_metadata;
    key_metadata.algorithm = algo;
    memcpy(key_metadata.public_key, expected_public_key, sizeof(elliptic_curve256_point_t));
    key_metadata.peer_id = client_id;

    elliptic_curve256_point_t server_public_key;
    throw_cosigner_exception(algebra->generator_mul(algebra, &server_public_key, &secret.data));

    // compute seed for this key generation, this will be used for Schnorr proofs.
    commitments_sha256_t seed;
    compute_key_generation_seed(key_id, client_id, server_id, seed);

    // now commit to public share.
    compute_key_share_commitment(seed, server_public_key, commitment);

    _platform_service.mark_key_setup_in_progress(key_id);

    _key_persistency.store_tenant_id_for_key(key_id, _platform_service.get_current_tenantid());
    _key_persistency.store_key_metadata(key_id, key_metadata, false);
    _key_persistency.store_key(key_id, secret, algo);
}

void frost_cosigner_server::verify_client_proofs_and_decommit_share_with_proof(const std::string& key_id, uint64_t server_id, uint64_t client_id, const key_share_public_data& client_key_share_message , key_share_public_data& server_key_share_message)
{
    validate_tenant_id_for_key(_key_persistency, key_id);

    frost_key_metadata_server key_metadata;
    _key_persistency.load_key_metadata(key_id, key_metadata);

    if (client_id != key_metadata.peer_id)
    {
        LOG_ERROR("Wrong client id for key %s. %" PRIu64 " != %" PRIu64, key_id.c_str(), key_metadata.peer_id, client_id);
        throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);   
    }

    commitments_sha256_t seed;
    compute_key_generation_seed(key_id, client_id, server_id, seed);
    
    verify_share_with_schnorr_proof(key_metadata.algorithm, client_id, seed, sizeof(commitments_sha256_t), client_key_share_message.X, client_key_share_message.schnorr_proof);

    elliptic_curve_scalar secret;
    _key_persistency.load_key(key_id, secret);

    generate_share_with_schnorr_proof(key_metadata.algorithm, server_id, seed, sizeof(commitments_sha256_t), secret, server_key_share_message.X, server_key_share_message.schnorr_proof);

    // compute the common public key
    auto algebra = get_algebra(key_metadata.algorithm);
    
    // if an expected public key was stored in advance (add_user path), verify the computed key matches
    // to prevent public key forgery; otherwise just store it (keygen path)
    elliptic_curve256_point_t common_public_key;
    throw_cosigner_exception(algebra->add_points(algebra, &common_public_key, &server_key_share_message.X, &client_key_share_message.X));
    if (!key_metadata.has_public_key(algebra))
    {
        memcpy(key_metadata.public_key, common_public_key, sizeof(elliptic_curve256_point_t));
    }
    else if (memcmp(key_metadata.public_key, common_public_key, sizeof(elliptic_curve256_point_t)) != 0)
    {
        LOG_ERROR("Public key mismatch for client id %" PRIu64 ", key id %s", client_id, key_id.c_str());
        throw_cosigner_exception(ELLIPTIC_CURVE_ALGEBRA_INVALID_POINT);
    }

    memcpy(key_metadata.client_public_share, client_key_share_message.X, sizeof(elliptic_curve256_point_t));
    
    _key_persistency.store_key_metadata(key_id, key_metadata, true);

    if (!_key_persistency.backup_key(key_id))
    {
        LOG_ERROR("Failed to backup FROST key %s", key_id.c_str());
        _key_persistency.delete_key(key_id);
        throw cosigner_exception(cosigner_exception::BACKUP_FAILED);
    }

    _platform_service.clear_key_setup_in_progress(key_id);
}

// ============================================================
// SIGNING
// ============================================================

void frost_cosigner_server::generate_signature_share(const std::string& key_id,
                                                     const std::string& tx_id,
                                                     const uint32_t version,
                                                     uint64_t server_id,
                                                     uint64_t client_id,
                                                     const signing_data& data,
                                                     const std::string& metadata_json,
                                                     const std::set<std::string>& players_set,
                                                     cosigner_sign_algorithm requested_algorithm,
                                                     std::vector<server_signature_shared_data>& server_commitments)
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

    auto server_signature_data_ptr = std::make_shared<frost_signature_data>(version, key_id, static_cast<int64_t>(_platform_service.now_msec() / 1000));
    auto& server_signature_data = *server_signature_data_ptr;

    frost_key_metadata_server key_metadata;

    const auto signature_request_data = fill_frost_signing_info_from_metadata(metadata_json, static_cast<uint32_t>(data.blocks.size()));
    if (data.blocks.size() != signature_request_data.size()) //must not happen
    {
        LOG_ERROR("number of blocks %u is different than number of flags %u", static_cast<uint32_t>(data.blocks.size()), static_cast<uint32_t>(signature_request_data.size()));
        throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
    }

    _key_persistency.load_key_metadata(key_id, key_metadata);
    auto algebra = get_algebra(key_metadata.algorithm);
    if (!key_metadata.has_public_key(algebra))
    {
        LOG_ERROR("Key id %s tx_id %s: trying to sign while key was not fully created", key_id.c_str(), tx_id.c_str());
        throw cosigner_exception(cosigner_exception::INTERNAL_ERROR);
    }

    if (requested_algorithm != key_metadata.algorithm)
    {
        LOG_ERROR("Key %s, tx_id %s: algorithm mismatch. Key was created with algorithm %d but signing requested with algorithm %d", key_id.c_str(), tx_id.c_str(), key_metadata.algorithm, requested_algorithm);
        throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
    }

    validate_tenant_id_for_key(_key_persistency, key_id);
    validate_current_player_id(key_id, server_id);

    if (client_id != key_metadata.peer_id)
    {
        LOG_ERROR("Wrong client id for key %s. %" PRIu64 " != %" PRIu64, key_id.c_str(), key_metadata.peer_id, client_id);
        throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
    }   

    _platform_service.on_start_signing(key_id, tx_id, data, metadata_json, players_set, platform_service::MULTI_ROUND_SIGNATURE);

    server_commitments.resize(signature_request_data.size());
    server_signature_data.sig_data.resize(signature_request_data.size());

    for (uint32_t i = 0; i < (uint32_t)signature_request_data.size(); ++ i)
    {
        auto& sig_request = signature_request_data[i];                  // request which has to be signed
        auto& persistant_sig_data = server_signature_data.sig_data[i];  // data about the signature that the server should save
        auto& server_message = server_commitments[i];                   // the message to the client

        persistant_sig_data.flags = sig_request.flags;
        persistant_sig_data.message = data.blocks[i].data;

        elliptic_curve256_point_t derived_public_key; // not needed and won't be saved
        derivation_key_delta(algebra, key_metadata.public_key, data.chaincode, data.blocks[i].path, persistant_sig_data.derivation_delta, derived_public_key);

        rand_nonzero_scalar(algebra, persistant_sig_data.secret_d.data);
        throw_cosigner_exception(algebra->generator_mul(algebra, &server_message.D, &persistant_sig_data.secret_d.data));
        rand_nonzero_scalar(algebra, persistant_sig_data.secret_e.data);
        throw_cosigner_exception(algebra->generator_mul(algebra, &server_message.E, &persistant_sig_data.secret_e.data));
    }

    _tx_persistency.store_signature_data(tx_id, server_signature_data_ptr);       
}

void frost_cosigner_server::verify_partial_signature_and_output_signature(const std::string& key_id,
                                                                          const std::string& tx_id,
                                                                          uint64_t client_id,
                                                                          const std::vector<client_partial_signature_data>& partial_signatures,
                                                                          std::vector<eddsa_signature>& signatures,
                                                                          cosigner_sign_algorithm& algorithm)
{
    frost_key_metadata_server key_metadata;
    commitments_sha256_t signature_add;

    auto server_signature_data_ptr = _tx_persistency.load_signature_data_and_delete(tx_id);
    auto& server_signature_data = *server_signature_data_ptr;
    const auto& internal_key_id = server_signature_data.key_id;
    const uint64_t server_id = _platform_service.get_id_from_keyid(key_id);

    if (key_id != internal_key_id)
    {
        LOG_ERROR("Transaction: %s was called with key: %s, but internally it uses the key: %s", tx_id.c_str(), key_id.c_str(), internal_key_id.c_str());
        throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
    }

    _key_persistency.load_key_metadata(key_id, key_metadata);

    validate_tenant_id_for_key(_key_persistency, key_id);
    
    if (server_signature_data.sig_data.size() != partial_signatures.size())
    {
        LOG_ERROR("Key %s, tx_id %s: client partial signatures size missmatch. %u != %u", key_id.c_str(), tx_id.c_str(), (uint32_t)partial_signatures.size(), (uint32_t) server_signature_data.sig_data.size());
        throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
    }
    
    if (client_id != key_metadata.peer_id)
    {
        LOG_ERROR("Key %s, tx_id %s: client player id mismatch. Expected %" PRIu64 " but got %" PRIu64, key_id.c_str(), tx_id.c_str(), key_metadata.peer_id, client_id);
        throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
    }
    
    elliptic_curve_scalar server_secret;
    _key_persistency.load_key(key_id, server_secret);

    signatures.resize(partial_signatures.size());

    generate_aad_for_signature(server_signature_data.key_id, server_id, key_metadata.peer_id, tx_id, signature_add);

    auto algebra = get_algebra(key_metadata.algorithm);

    for (uint32_t i = 0; i < (uint32_t)partial_signatures.size(); ++i)
    {
        auto& signature = signatures[i];
        auto& partial_signature = partial_signatures[i];
        auto& persistant_sig_data = server_signature_data.sig_data[i];

        elliptic_curve256_point_t server_D;
        elliptic_curve256_point_t server_E;
        throw_cosigner_exception(algebra->generator_mul(algebra, &server_D, &persistant_sig_data.secret_d.data));
        throw_cosigner_exception(algebra->generator_mul(algebra, &server_E, &persistant_sig_data.secret_e.data));
        
        // compute r1 = H(server_id, message, {D1, E1, D2, E2})
        //         r2 = H(client_id, message, {D1, E1, D2, E2})
        elliptic_curve256_point_t R2;
        elliptic_curve256_point_t R;
        elliptic_curve256_scalar_t r1_scalar; 
        elliptic_curve256_scalar_t r2_scalar;
        compute_common_nonce(algebra, persistant_sig_data.message, signature_add, server_id, server_D, server_E, client_id, partial_signature.D, partial_signature.E, r1_scalar, r2_scalar, R2, R);
        bool negated_R = negate_point_if_needed(algebra, R);

        
        elliptic_curve256_point_t derived_public_key;
        elliptic_curve256_point_t derived_client_public;
        // we save delta*G into derived_public_key for temporery use
        throw_cosigner_exception(algebra->generator_mul(algebra, &derived_public_key, &persistant_sig_data.derivation_delta));
        // client derived public = client_pub + delta*G  (used to verify client's z2 contribution)
        throw_cosigner_exception(algebra->add_points(algebra, &derived_client_public, &key_metadata.client_public_share, &derived_public_key));
        // combined derived public = (server_pub + client_pub) + delta*G
        throw_cosigner_exception(algebra->add_points(algebra, &derived_public_key, &key_metadata.public_key, &derived_public_key));

        // BIP340: if combined derived public key has odd y, sign with -x instead of x
        bool negated_public_key = negate_point_if_needed(algebra, derived_public_key);
        if (negated_public_key)
            derived_client_public[0] ^= 0x01;

        const bool use_keccak = persistant_sig_data.flags & EDDSA_KECCAK;

        // compute c = H(X, message, R)
        elliptic_curve256_scalar_t c_scalar;
        calc_hram(algebra, c_scalar, R, derived_public_key, persistant_sig_data.message.data(), persistant_sig_data.message.size(), use_keccak);

        // check that g^client_z == X2^c * D2 * E2^r2
        elliptic_curve256_point_t left;
        elliptic_curve256_point_t right;
        throw_cosigner_exception(algebra->generator_mul(algebra, &left, &partial_signature.s.data));

        throw_cosigner_exception(algebra->point_mul(algebra, &right, &derived_client_public, &c_scalar));
        if (negated_R)
            R2[0] ^= 0x01; // negate R2.

        throw_cosigner_exception(algebra->add_points(algebra, &right, &right, &R2));

        if (memcmp(left, right, sizeof(elliptic_curve256_point_t)) != 0)
            throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
        
        // now compute full signature
        elliptic_curve_scalar x1_c;
        elliptic_curve_scalar e1_r1;
        elliptic_curve256_scalar_t s;
        elliptic_curve_scalar signing_server_secret = server_secret;
        if (negated_public_key)
        {
            static const uint8_t ZERO = 0x00;
            throw_cosigner_exception(algebra->sub_scalars(algebra, &signing_server_secret.data, &ZERO, sizeof(ZERO), server_secret.data, sizeof(elliptic_curve256_scalar_t)));
        }
        throw_cosigner_exception(algebra->mul_scalars(algebra, &x1_c.data, signing_server_secret.data, sizeof(elliptic_curve256_scalar_t), c_scalar, sizeof(elliptic_curve256_scalar_t)));
        throw_cosigner_exception(algebra->mul_scalars(algebra, &e1_r1.data, persistant_sig_data.secret_e.data, sizeof(elliptic_curve256_scalar_t), r1_scalar, sizeof(elliptic_curve256_scalar_t)));
        throw_cosigner_exception(algebra->add_scalars(algebra, &s, e1_r1.data, sizeof(elliptic_curve256_scalar_t), persistant_sig_data.secret_d.data, sizeof(elliptic_curve256_scalar_t)));
        if (negated_R) 
            throw_cosigner_exception(algebra->sub_scalars(algebra, &s, x1_c.data, sizeof(elliptic_curve256_scalar_t), s, sizeof(elliptic_curve256_scalar_t)));
        else 
            throw_cosigner_exception(algebra->add_scalars(algebra, &s, x1_c.data, sizeof(elliptic_curve256_scalar_t), s, sizeof(elliptic_curve256_scalar_t)));

        throw_cosigner_exception(algebra->add_scalars(algebra, &s, s, sizeof(elliptic_curve256_scalar_t), partial_signature.s.data, sizeof(elliptic_curve256_scalar_t)));

        eddsa_signature_format(signature, algebra, &R, &s);

        if (!validate_schnorr_signature(algebra, signature, persistant_sig_data.message.data(), persistant_sig_data.message.size(), &derived_public_key, use_keccak))
            throw cosigner_exception(cosigner_exception::INVALID_TRANSACTION);

    }

    algorithm = key_metadata.algorithm;
}

void frost_cosigner_server::get_public_key(const std::string& key_id, generated_public_key& pub_key_data) const
{
    frost_key_metadata_server key_metadata;
    _key_persistency.load_key_metadata(key_id, key_metadata);
    auto algebra = get_algebra(key_metadata.algorithm);
    pub_key_data.pub_key.assign(reinterpret_cast<const char*>(key_metadata.public_key), algebra->point_size(algebra));
    pub_key_data.algorithm = key_metadata.algorithm;
}


}