#pragma once

#include <map>
#include <memory>
#include "cosigner_export.h"
#include "cosigner/types.h"
#include "cosigner/sign_algorithm.h"
#include "cosigner/cosigner_exception.h"
#include "crypto/zero_knowledge_proof/schnorr.h"

namespace fireblocks::common::cosigner
{

class platform_service;
class frost_key_persistency_common;

struct frost_signing_properties
{
    uint32_t flags { common::cosigner::NONE };
};

class COSIGNER_EXPORT frost_cosigner
{
public:
    // data shared between both parties during key generation
    struct key_share_public_data
    {
        key_share_public_data() = default;

        elliptic_curve256_point_t X;
        schnorr_zkp_t schnorr_proof;
    };

    // This is the message sent by the server in the first step of the signature.
    struct server_signature_shared_data
    {
        server_signature_shared_data() = default;

        elliptic_curve256_point_t D;
        elliptic_curve256_point_t E;
    };

    // This is the message sent by the client in the 2nd step of the signature. It contains the partial signature.
    struct client_partial_signature_data
    {
        client_partial_signature_data() = default;

        elliptic_curve256_point_t D;
        elliptic_curve256_point_t E;
        elliptic_curve_scalar s;
    };

    // Final public key generated after key generation completes
    using generated_public_key = two_party_generated_public_key;

    using add_user_data = additive_add_user_data;

protected:

    struct share_base
    {
        const elliptic_curve256_point_t& server_D;
        const elliptic_curve256_point_t& server_E;
        const elliptic_curve256_point_t& client_D;
        const elliptic_curve256_point_t& client_E;
    };

    explicit frost_cosigner(platform_service& platform_service);

    virtual ~frost_cosigner() = default;

    std::vector<frost_signing_properties> fill_frost_signing_info_from_metadata(const std::string& metadata, const uint32_t blocks_num);


    inline elliptic_curve256_algebra_ctx_t* get_algebra(cosigner_sign_algorithm algorithm) const
    {
        return algorithm == SCHNORR_SECP256K1 ? _secp256k1.get() :
               algorithm == SCHNORR_SECP256R1 ? _secp256r1.get() :
               algorithm == EDDSA_ED25519 ? _ed25519.get() :
               algorithm == SCHNORR_STARK ? _stark.get() :
               throw cosigner_exception(cosigner_exception::UNKNOWN_ALGORITHM);
    }

    void validate_tenant_id_for_key(const frost_key_persistency_common& persistency, const std::string& key_id) const;
    void validate_current_player_id(const std::string& key_id, const uint64_t player_id) const;
    void validate_players_ids_key_gen(const std::string& key_id, uint64_t player_id, uint64_t peer_id) const;

    void compute_key_generation_seed(const std::string& key_id, uint64_t client_id, uint64_t server_id, commitments_sha256_t& seed);
    void compute_key_share_commitment(const commitments_sha256_t& seed, const elliptic_curve256_point_t& pub_key, commitments_sha256_t& commitment);
    void generate_share_with_schnorr_proof(cosigner_sign_algorithm algo, uint64_t client_id, const uint8_t* seed, uint32_t seed_len, const elliptic_curve_scalar& secret, elliptic_curve256_point_t& public_key, schnorr_zkp_t& schnorr_proof);
    void verify_share_with_schnorr_proof(cosigner_sign_algorithm algo, uint64_t client_id, const uint8_t* seed, uint32_t seed_len, const elliptic_curve256_point_t& public_key, const schnorr_zkp_t& schnorr_proof);
    static bool is_zero_scalar(const elliptic_curve256_scalar_t& s);
    static void rand_nonzero_scalar(const elliptic_curve256_algebra_ctx_t* algebra, elliptic_curve256_scalar_t& out);
    static void check_a_valid_point(const elliptic_curve256_point_t& point, const elliptic_curve256_algebra_ctx_t* algebra);

    // BIP32 key derivation (following BAM pattern)
    void derivation_key_delta(const elliptic_curve256_algebra_ctx_t* algebra, const elliptic_curve256_point_t& public_key, const HDChaincode& chaincode, const std::vector<uint32_t>& path, elliptic_curve256_scalar_t& delta, elliptic_curve256_point_t& derived_public_key);

    static void generate_aad_for_signature(const std::string& key_id, uint64_t server_id, uint64_t client_id, const std::string& tx_id, commitments_sha256_t& aad);
    void compute_partial_R(elliptic_curve256_algebra_ctx_t* algebra, const byte_vector_t& message, const commitments_sha256_t& sid, uint64_t id, const elliptic_curve256_point_t& D, const elliptic_curve256_point_t& E, const share_base& base, elliptic_curve256_point_t& partial_share, elliptic_curve256_scalar_t& partial_hash);
    void calc_hram(const elliptic_curve256_algebra_ctx_t* ctx, elliptic_curve256_scalar_t& hram, const elliptic_curve256_point_t& R, const elliptic_curve256_point_t& public_key, const uint8_t* message, uint32_t message_size, uint8_t use_keccak, const byte_vector_t& prefix = byte_vector_t(), const byte_vector_t& suffix = byte_vector_t());
    bool negate_point_if_needed(const elliptic_curve256_algebra_ctx_t* ctx, elliptic_curve256_point_t& R);

    void validate_current_tenant_id(const std::string& tenant_id) const;

    void compute_common_nonce(elliptic_curve256_algebra_ctx_t* algebra,
                              const byte_vector_t& message,
                              const commitments_sha256_t& sid,
                              uint64_t id_player0,
                              const elliptic_curve256_point_t& player0_D,
                              const elliptic_curve256_point_t& player0_E,
                              uint64_t id_player1,
                              const elliptic_curve256_point_t& player1_D,
                              const elliptic_curve256_point_t& player1_E,
                              elliptic_curve256_scalar_t& server_partial_hash,
                              elliptic_curve256_scalar_t& client_partial_hash,
                              elliptic_curve256_point_t& client_accumulator,
                              elliptic_curve256_point_t& common_temporary_share);

    platform_service& _platform_service;

private:
    using algebra_ctx_ptr = std::unique_ptr<elliptic_curve256_algebra_ctx_t, void(*)(elliptic_curve256_algebra_ctx_t*)>;
    static const algebra_ctx_ptr _secp256k1;
    static const algebra_ctx_ptr _secp256r1;
    static const algebra_ctx_ptr _ed25519;
    static const algebra_ctx_ptr _stark;
};

}
