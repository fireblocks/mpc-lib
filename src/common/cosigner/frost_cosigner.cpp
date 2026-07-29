#include <cinttypes>
#include <cstdio>
#include <openssl/crypto.h>
#include <openssl/sha.h>
#include "cosigner/frost_cosigner.h"
#include "crypto/keccak1600/keccak1600.h"
#include "cosigner/frost_key_persistency_common.h"
#include "cosigner/platform_service.h"
#include "crypto/zero_knowledge_proof/schnorr.h"
#include "blockchain/mpc/hd_derive.h"
#include "logging/logging_t.h"

namespace fireblocks::common::cosigner
{

static const std::string FROST_SCHNORR_SALT_KEY_GEN("FROST Shnorr Key Generation AAD");
static const std::string FROST_SCHNORR_SALT_KEY_GEN_COMMITMENT("FROST Shnorr Key Generation Commitment");
static const std::string FROST_SALT_SIGNATURE("FROST Signature AAD");

const frost_cosigner::algebra_ctx_ptr frost_cosigner::_secp256k1(elliptic_curve256_new_secp256k1_algebra(), elliptic_curve256_algebra_ctx_free);
const frost_cosigner::algebra_ctx_ptr frost_cosigner::_secp256r1(elliptic_curve256_new_secp256r1_algebra(), elliptic_curve256_algebra_ctx_free);
const frost_cosigner::algebra_ctx_ptr frost_cosigner::_ed25519(elliptic_curve256_new_ed25519_algebra(), elliptic_curve256_algebra_ctx_free);
const frost_cosigner::algebra_ctx_ptr frost_cosigner::_stark(elliptic_curve256_new_stark_algebra(), elliptic_curve256_algebra_ctx_free);

frost_cosigner::frost_cosigner(platform_service& platform_service) :
        _platform_service(platform_service)
{
}

//////////////////////
// Helper Functions //
//////////////////////

void frost_cosigner::validate_current_tenant_id(const std::string& tenant_id) const
{
    if (tenant_id != _platform_service.get_current_tenantid())
    {
        LOG_ERROR("Tenant id mismatch. Request for tenant %s while current tenant is %s", tenant_id.c_str(), _platform_service.get_current_tenantid().c_str());
        throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
    }
}

void frost_cosigner::validate_tenant_id_for_key(const frost_key_persistency_common& persistency, const std::string& key_id) const
{
    std::string setup_tenant_id;
    persistency.load_tenant_id_for_key(key_id, setup_tenant_id);
    validate_current_tenant_id(setup_tenant_id);
}

void frost_cosigner::validate_current_player_id(const std::string& key_id, const uint64_t player_id) const
{
    const uint64_t my_id = _platform_service.get_id_from_keyid(key_id);
    if (my_id != player_id)
    {
        LOG_ERROR("Player id mismatch for key %s: expected %" PRIu64 " but got %" PRIu64, key_id.c_str(), my_id, player_id);
        throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
    }
}

void frost_cosigner::validate_players_ids_key_gen(const std::string& key_id, const uint64_t player_id, const uint64_t peer_id) const
{
    validate_current_player_id(key_id, player_id);

    if (player_id == peer_id)
    {
        LOG_ERROR("Client and server ids are the same");
        throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
    }
}

std::vector<frost_signing_properties> frost_cosigner::fill_frost_signing_info_from_metadata(const std::string& metadata, const uint32_t blocks_num)
{
    std::vector<frost_signing_properties> signature_request_data(blocks_num);
    _platform_service.fill_frost_signing_info_from_metadata(signature_request_data, metadata);
    return signature_request_data;
}

void frost_cosigner::generate_aad_for_signature(const std::string& key_id, uint64_t server_id, uint64_t client_id, const std::string& tx_id, commitments_sha256_t& aad)
{
    SHA256_CTX sha;
    if (!SHA256_Init(&sha))
        throw cosigner_exception(cosigner_exception::INTERNAL_ERROR);
    if (!SHA256_Update(&sha, FROST_SALT_SIGNATURE.c_str(), FROST_SALT_SIGNATURE.size()))
        throw cosigner_exception(cosigner_exception::INTERNAL_ERROR);
    if (!SHA256_Update(&sha, key_id.data(), key_id.size()))
        throw cosigner_exception(cosigner_exception::INTERNAL_ERROR);
    if (!SHA256_Update(&sha, tx_id.data(), tx_id.size()))
        throw cosigner_exception(cosigner_exception::INTERNAL_ERROR);
    if (!SHA256_Update(&sha, &server_id, sizeof(uint64_t)))
        throw cosigner_exception(cosigner_exception::INTERNAL_ERROR);
    if (!SHA256_Update(&sha, &client_id, sizeof(uint64_t)))
        throw cosigner_exception(cosigner_exception::INTERNAL_ERROR);
    if (!SHA256_Final(aad, &sha))
        throw cosigner_exception(cosigner_exception::INTERNAL_ERROR);
}

bool frost_cosigner::is_zero_scalar(const elliptic_curve256_scalar_t& s)
{
    const uint64_t *p = reinterpret_cast<const uint64_t*>(s);
    uint64_t acc = 0;
    for (size_t i = 0; i < sizeof(elliptic_curve256_scalar_t) / sizeof(uint64_t); ++i)
        acc |= p[i];
    return acc == 0;
}

void frost_cosigner::rand_nonzero_scalar(const elliptic_curve256_algebra_ctx_t* algebra, elliptic_curve256_scalar_t& out)
{
    uint32_t i = 0;
    do 
    {
        throw_cosigner_exception(algebra->rand(algebra, &out));
        if (i++ >= 256)
        {
            LOG_FATAL("Failed in generating a non-zero scalar for %u times", i);
            throw cosigner_exception(cosigner_exception::INTERNAL_ERROR);
        }
    } while (is_zero_scalar(out));
}

void frost_cosigner::check_a_valid_point(const elliptic_curve256_point_t& point, const elliptic_curve256_algebra_ctx_t* algebra)
{
    const elliptic_curve_algebra_status st = algebra->validate_non_infinity_point(algebra, &point);
    if (st != ELLIPTIC_CURVE_ALGEBRA_SUCCESS)
    {
        LOG_ERROR("Unexpected invalid point received");
        throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
    }
}


/////////////////////
//  Key Generation //
/////////////////////

void frost_cosigner::compute_key_generation_seed(const std::string& key_id, uint64_t client_id, uint64_t server_id, commitments_sha256_t& seed)
{
    SHA256_CTX sha;
    if (!SHA256_Init(&sha))
        throw cosigner_exception(cosigner_exception::NO_MEM);
    if (!SHA256_Update(&sha, FROST_SCHNORR_SALT_KEY_GEN.c_str(), FROST_SCHNORR_SALT_KEY_GEN.size()))
        throw cosigner_exception(cosigner_exception::NO_MEM);
    if (!SHA256_Update(&sha, key_id.c_str(), key_id.size()))
        throw cosigner_exception(cosigner_exception::NO_MEM);
    if (!SHA256_Update(&sha, &client_id, sizeof(uint64_t)))
        throw cosigner_exception(cosigner_exception::NO_MEM);
    if (!SHA256_Update(&sha, &server_id, sizeof(uint64_t)))
        throw cosigner_exception(cosigner_exception::NO_MEM);
    if (!SHA256_Final(seed, &sha))
        throw cosigner_exception(cosigner_exception::NO_MEM);
}

void frost_cosigner::compute_key_share_commitment(const commitments_sha256_t& seed, const elliptic_curve256_point_t& pub_key, commitments_sha256_t& commitment)
{
    SHA256_CTX sha;
    if (!SHA256_Init(&sha))
        throw cosigner_exception(cosigner_exception::NO_MEM);
    if (!SHA256_Update(&sha, FROST_SCHNORR_SALT_KEY_GEN_COMMITMENT.c_str(), FROST_SCHNORR_SALT_KEY_GEN_COMMITMENT.size()))
        throw cosigner_exception(cosigner_exception::NO_MEM);
    if (!SHA256_Update(&sha, seed, sizeof(commitments_sha256_t)))
        throw cosigner_exception(cosigner_exception::NO_MEM);
    if (!SHA256_Update(&sha, pub_key, sizeof(elliptic_curve256_point_t)))
        throw cosigner_exception(cosigner_exception::NO_MEM);
    if (!SHA256_Final(commitment, &sha))
        throw cosigner_exception(cosigner_exception::NO_MEM);
}

void frost_cosigner::generate_share_with_schnorr_proof(cosigner_sign_algorithm algo, uint64_t id, const uint8_t* seed, uint32_t seed_len, const elliptic_curve_scalar& secret, elliptic_curve256_point_t& public_key, schnorr_zkp_t& schnorr_proof)
{
    elliptic_curve256_algebra_ctx_t* algebra = get_algebra(algo);
    if (!seed)
        throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
    byte_vector_t prover_id(seed_len + sizeof(uint64_t));
    memcpy(prover_id.data(), &id, sizeof(uint64_t));
    memcpy(prover_id.data() + sizeof(uint64_t), seed, seed_len);

    throw_cosigner_exception(algebra->generator_mul(algebra, &public_key, &secret.data));
    throw_cosigner_exception(schnorr_zkp_generate(algebra, prover_id.data(), prover_id.size(), &secret.data, &public_key, &schnorr_proof));
}

void frost_cosigner::verify_share_with_schnorr_proof(cosigner_sign_algorithm algo, uint64_t id, const uint8_t* seed, uint32_t seed_len, const elliptic_curve256_point_t& public_key, const schnorr_zkp_t& schnorr_proof)
{
    elliptic_curve256_algebra_ctx_t* algebra = get_algebra(algo);
    if (!seed)
        throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
    byte_vector_t prover_id(seed_len + sizeof(uint64_t));
    memcpy(prover_id.data(), &id, sizeof(uint64_t));
    memcpy(prover_id.data() + sizeof(uint64_t), seed, seed_len);

    throw_cosigner_exception(schnorr_zkp_verify(algebra, prover_id.data(), prover_id.size(), &public_key, &schnorr_proof));
}

///////////////////////
// Key Derivation    //
///////////////////////

// Computes BIP32 derivation delta for a given path
// Following BAM's pattern: derive from ZERO private key to get the delta
void frost_cosigner::derivation_key_delta(const elliptic_curve256_algebra_ctx_t* algebra,
                                          const elliptic_curve256_point_t& public_key,
                                          const HDChaincode& chaincode,
                                          const std::vector<uint32_t>& path,
                                          elliptic_curve256_scalar_t& delta,
                                          elliptic_curve256_point_t& derived_public_key)
{
    static const elliptic_curve256_scalar_t ZERO = {0};

    if (path.size())
    {
        assert(path.size() == BIP44_PATH_LENGTH);
        hd_derive_status retval = derive_private_and_public_keys(algebra, delta, derived_public_key, public_key, ZERO, chaincode, path.data(), path.size());
        if (HD_DERIVE_SUCCESS != retval)
        {
            LOG_ERROR("Error deriving private key: %d", retval);
            throw cosigner_exception(cosigner_exception::INTERNAL_ERROR);
        }
    }
    else
    {
        memcpy(delta, ZERO, sizeof(elliptic_curve256_scalar_t));
        memcpy(derived_public_key, public_key, sizeof(elliptic_curve256_point_t));
    }
}

////////////////////////
//  Signing Functions //
////////////////////////

// Note: Some cases might require a different way to compute this value (e.g. using salt, prefix, ...)
void frost_cosigner::calc_hram(const elliptic_curve256_algebra_ctx_t* ctx,
                               elliptic_curve256_scalar_t& hram,
                               const elliptic_curve256_point_t& R,
                               const elliptic_curve256_point_t& public_key,
                               const uint8_t* message,
                               uint32_t message_size,
                               uint8_t use_keccak,
                               const byte_vector_t& prefix,
                               const byte_vector_t& suffix)
{
    if (!ctx || !message || !message_size)
        throw_cosigner_exception(ELLIPTIC_CURVE_ALGEBRA_INVALID_PARAMETER);

    if (ctx->type == ELLIPTIC_CURVE_ED25519)
    {
        throw_cosigner_exception(ed25519_calc_hram((ed25519_algebra_ctx_t *)ctx->ctx, &hram, (const ed25519_point_t*)R, (const ed25519_point_t*)public_key, message, message_size, use_keccak));
        throw_cosigner_exception(ed25519_algebra_le_to_be(&hram, &hram));
        return;
    }

    uint8_t ZERO = 0x00;
    const uint8_t *Rx = &R[1];
    const uint8_t *Pubx = &public_key[1];
    if (use_keccak)
    {
        uint8_t hash[SHA512_DIGEST_LENGTH];
        KECCAK1600_CTX hash_ctx;
        keccak1600_init(&hash_ctx, 512, KECCAK256_PAD);
        keccak1600_update(&hash_ctx, prefix.data(), prefix.size());
        keccak1600_update(&hash_ctx, Rx, 32);
        keccak1600_update(&hash_ctx, Pubx, 32);
        keccak1600_update(&hash_ctx, message, message_size);
        keccak1600_update(&hash_ctx, suffix.data(), suffix.size());
        keccak1600_final(&hash_ctx, hash);
        throw_cosigner_exception(ctx->add_scalars(ctx, &hram, hash, sizeof(hash), &ZERO, 1));
    }
    else
    {
        uint8_t hash[SHA256_DIGEST_LENGTH];
        SHA256_CTX hash_ctx;
        SHA256_Init(&hash_ctx);
        SHA256_Update(&hash_ctx, prefix.data(), prefix.size());
        SHA256_Update(&hash_ctx, Rx, 32);
        SHA256_Update(&hash_ctx, Pubx, 32);
        SHA256_Update(&hash_ctx, message, message_size);
        SHA256_Update(&hash_ctx, suffix.data(), suffix.size());
        SHA256_Final(hash, &hash_ctx);
        throw_cosigner_exception(ctx->add_scalars(ctx, &hram, hash, sizeof(hash), &ZERO, 1));
    }
}

void frost_cosigner::compute_partial_R(elliptic_curve256_algebra_ctx_t* algebra,
                                       const byte_vector_t& message,
                                       const commitments_sha256_t& sid,
                                       uint64_t id,
                                       const elliptic_curve256_point_t& D,
                                       const elliptic_curve256_point_t& E,
                                       const share_base& base,
                                       elliptic_curve256_point_t& partial_share,
                                       elliptic_curve256_scalar_t& partial_hash)
{
    uint8_t r[SHA512_DIGEST_LENGTH];
    SHA512_CTX sha;

    // the order and combination of hashed elements is different from the one given in the RFC.
    // This is intentional and serves FIREBLOCKS's design. It doesn't cause any security vulnerability (actually it's stronger as it has more elements).
    if (!SHA512_Init(&sha))
        throw cosigner_exception(cosigner_exception::INTERNAL_ERROR);
    if (!SHA512_Update(&sha, &id, sizeof(uint64_t)))
        throw cosigner_exception(cosigner_exception::INTERNAL_ERROR);
    if (!SHA512_Update(&sha, sid, sizeof(commitments_sha256_t)))
        throw cosigner_exception(cosigner_exception::INTERNAL_ERROR);
    if (!SHA512_Update(&sha, message.data(), message.size()))
        throw cosigner_exception(cosigner_exception::INTERNAL_ERROR);
    if (!SHA512_Update(&sha, base.server_D, sizeof(elliptic_curve256_point_t)))
        throw cosigner_exception(cosigner_exception::INTERNAL_ERROR);
    if (!SHA512_Update(&sha, base.server_E, sizeof(elliptic_curve256_point_t)))
        throw cosigner_exception(cosigner_exception::INTERNAL_ERROR);
    if (!SHA512_Update(&sha, base.client_D, sizeof(elliptic_curve256_point_t)))
        throw cosigner_exception(cosigner_exception::INTERNAL_ERROR);
    if (!SHA512_Update(&sha, base.client_E, sizeof(elliptic_curve256_point_t)))
        throw cosigner_exception(cosigner_exception::INTERNAL_ERROR);
    if (!SHA512_Final(r, &sha))
        throw cosigner_exception(cosigner_exception::INTERNAL_ERROR);

    static const uint8_t ZERO = 0x00;
    throw_cosigner_exception(algebra->add_scalars(algebra, &partial_hash, r, SHA512_DIGEST_LENGTH, &ZERO, sizeof(uint8_t)));

    throw_cosigner_exception(algebra->point_mul(algebra, &partial_share, &E, &partial_hash));
    throw_cosigner_exception(algebra->add_points(algebra, &partial_share, &partial_share, &D));
}

void frost_cosigner::compute_common_nonce(elliptic_curve256_algebra_ctx_t* algebra,
                                          const byte_vector_t& message,
                                          const commitments_sha256_t& sid,
                                          uint64_t id_server,
                                          const elliptic_curve256_point_t& server_D,
                                          const elliptic_curve256_point_t& server_E,
                                          uint64_t id_client,
                                          const elliptic_curve256_point_t& client_D,
                                          const elliptic_curve256_point_t& client_E,
                                          elliptic_curve256_scalar_t& server_partial_hash,
                                          elliptic_curve256_scalar_t& client_partial_hash,
                                          elliptic_curve256_point_t& client_accumulator,
                                          elliptic_curve256_point_t& common_temporary_share)
{
    elliptic_curve256_point_t server_accumulator;

    const share_base base = {server_D, server_E, client_D, client_E};
    compute_partial_R(algebra, message, sid, id_server, server_D, server_E, base, server_accumulator, server_partial_hash);
    compute_partial_R(algebra, message, sid, id_client, client_D, client_E, base, client_accumulator, client_partial_hash);
    throw_cosigner_exception(algebra->add_points(algebra, &common_temporary_share, &server_accumulator, &client_accumulator));
}

// returns 'true' if the point 'R' has been negated.
bool frost_cosigner::negate_point_if_needed(const elliptic_curve256_algebra_ctx_t* ctx, elliptic_curve256_point_t& R)
{
    if (!ctx)
        throw_cosigner_exception(ELLIPTIC_CURVE_ALGEBRA_INVALID_PARAMETER);
    switch (ctx->type) 
    {
        case ELLIPTIC_CURVE_ED25519:
            // all point are allowed in this case
            return false;
        case ELLIPTIC_CURVE_SECP256K1: // FALLTHROUGH
        case ELLIPTIC_CURVE_SECP256R1: // FALLTHROUGH
        case ELLIPTIC_CURVE_STARK:
            if (R[0] == 0x02)
                return false;
            else if (R[0] == 0x03)
            {
                // odd y, so negate the point. Done by only replacing the fist byte by '0x02'
                R[0] = 0x02;
                return true;
            }
            throw_cosigner_exception(ELLIPTIC_CURVE_ALGEBRA_INVALID_PARAMETER);
            break;
        default:
            throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
    }
    return false;
}



}
