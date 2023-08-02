#pragma once

#include "cosigner/cmp_key_persistency.h"
#include "cosigner/platform_service.h"
#include "cosigner/types.h"
#include "crypto/zero_knowledge_proof/range_proofs.h"

#include <map>
#include <memory>

namespace fireblocks
{
namespace common
{
namespace cosigner
{

struct public_share
{
    elliptic_curve_point X;
    elliptic_curve_point schnorr_R;
};

typedef std::map<uint64_t, public_share> public_shares;

struct setup_decommitment
{
    commitments_sha256_t ack;
    commitments_sha256_t seed;
    public_share         share;
    byte_vector_t paillier_public_key;
    byte_vector_t ring_pedersen_public_key;
};

struct setup_zk_proofs
{
    elliptic_curve_scalar schnorr_s;
    byte_vector_t paillier_blum_zkp;
    byte_vector_t ring_pedersen_param_zkp;
};

struct add_user_data
{
    std::map<uint64_t, byte_vector_t> encrypted_shares;
    elliptic_curve_point public_key;
};

struct setup_data
{
    elliptic_curve_scalar k;
    commitments_sha256_t seed;
    elliptic_curve_point public_key;
    std::map<uint64_t, elliptic_curve_point> players_schnorr_R;
};

// this class implements MPC CMP key generation based on https://eprint.iacr.org/2020/492 paper
class cmp_setup_service final
{
public:
    class setup_key_persistency : public cmp_key_persistency
    {
    public:
        virtual ~setup_key_persistency() {}

        virtual void store_key(const std::string& key_id, cosigner_sign_algorithm algorithm, const elliptic_curve256_scalar_t& private_key, uint64_t ttl = 0) = 0;
        
        virtual void store_key_metadata(const std::string& key_id, const cmp_key_metadata& metadata) = 0;
        virtual void store_auxiliary_keys(const std::string& key_id, const auxiliary_keys& aux) = 0;
        virtual void store_keyid_tenant_id(const std::string& key_id, const std::string& tenant_id) = 0;
        virtual void store_setup_data(const std::string& key_id, const setup_data& metadata) = 0;
        virtual void load_setup_data(const std::string& key_id, setup_data& metadata) = 0;
        virtual void store_setup_commitments(const std::string& key_id, const std::map<uint64_t, commitment>& commitments) = 0;
        virtual void load_setup_commitments(const std::string& key_id, std::map<uint64_t, commitment>& commitments) = 0;
        virtual void delete_temporary_key_data(const std::string& key_id, bool delete_key = false) = 0;
    };

    cmp_setup_service(platform_service& service, setup_key_persistency& key_persistency) : _service(service), _key_persistency(key_persistency) {}
    void generate_setup_commitments(const std::string& key_id, const std::string& tenant_id, cosigner_sign_algorithm algorithm, const std::vector<uint64_t>& players_ids, uint8_t t, uint64_t ttl, const share_derivation_args& derive_from, commitment& setup_commitment);
    void store_setup_commitments(const std::string& key_id, const std::map<uint64_t, commitment>& commitments, setup_decommitment& decommitment);
    void generate_setup_proofs(const std::string& key_id, const std::map<uint64_t, setup_decommitment>& decommitments, setup_zk_proofs& proofs);
    void verify_setup_proofs(const std::string& key_id, const std::map<uint64_t, setup_zk_proofs>& proofs, std::map<uint64_t, byte_vector_t>& paillier_large_factor_proofs);
    void create_secret(const std::string& key_id, const std::map<uint64_t, std::map<uint64_t, byte_vector_t>>& paillier_large_factor_proofs, std::string& public_key, cosigner_sign_algorithm& algorithm);

    void add_user_request(const std::string& key_id, cosigner_sign_algorithm algorithm, const std::string& new_key_id, const std::vector<uint64_t>& players_ids, uint8_t t, add_user_data& data);
    void add_user(const std::string& tenant_id, const std::string& key_id, cosigner_sign_algorithm algorithm, uint8_t t, const std::map<uint64_t, add_user_data>& data, uint64_t ttl, commitment& setup_commitment);

private:
    // helpers
    void generate_setup_commitments(const std::string& key_id, const std::string& tenant_id, cosigner_sign_algorithm algorithm, const elliptic_curve256_algebra_ctx_t* algebra, const std::vector<uint64_t>& players_ids, 
        uint8_t t, uint64_t ttl, const elliptic_curve256_scalar_t& key, const elliptic_curve256_point_t* pubkey, commitment& setup_commitment);
    auxiliary_keys create_auxiliary_keys();
    void serialize_auxiliary_keys(const auxiliary_keys& aux, std::vector<uint8_t>& paillier_public_key, std::vector<uint8_t>& ring_pedersen_public_key);
    void deserialize_auxiliary_keys(uint64_t id, const std::vector<uint8_t>& paillier_public_key, std::shared_ptr<paillier_public_key_t>& paillier, 
        const std::vector<uint8_t>& ring_pedersen_public_key, std::shared_ptr<ring_pedersen_public_t>& ring_pedersen);
    void serialize_auxiliary_keys_zkp(const auxiliary_keys& aux, const std::vector<uint8_t>& aad, std::vector<uint8_t>& paillier_blum_zkp, std::vector<uint8_t>& ring_pedersen_param_zkp);
    
    void create_setup_decommitment(const elliptic_curve256_algebra_ctx_t* algebra, const auxiliary_keys& aux, const setup_data& metadata, setup_decommitment& decommitment);
    void create_setup_commitment(const std::string& key_id, uint64_t id, const setup_decommitment& decommitment, commitment& setup_commitment, bool verify);
    void ack_message(const std::map<uint64_t, commitment>& commitments, commitments_sha256_t* ack);
    void verify_and_load_setup_decommitments(const std::string& key_id, const std::map<uint64_t, commitment>& commitments, const std::map<uint64_t, setup_decommitment>& decommitments, std::map<uint64_t, cmp_player_info>& players_info);
    void generate_setup_proofs(const std::string& key_id, const elliptic_curve256_algebra_ctx_t* algebra, const setup_data& metadata, const commitments_sha256_t srid, setup_zk_proofs& proofs);
    void verify_setup_proofs(const std::string& key_id, const cmp_key_metadata& metadata, const std::map<uint64_t, setup_zk_proofs>& proofs);

    static std::vector<uint8_t> build_aad(const std::string& sid, uint64_t id, const commitments_sha256_t srid);
    static inline elliptic_curve256_algebra_ctx_t* get_algebra(cosigner_sign_algorithm algorithm);

    platform_service& _service;
    setup_key_persistency& _key_persistency;

    static const std::unique_ptr<elliptic_curve256_algebra_ctx_t, void(*)(elliptic_curve256_algebra_ctx_t*)> _secp256k1;
    static const std::unique_ptr<elliptic_curve256_algebra_ctx_t, void(*)(elliptic_curve256_algebra_ctx_t*)> _secp256r1;
    static const std::unique_ptr<elliptic_curve256_algebra_ctx_t, void(*)(elliptic_curve256_algebra_ctx_t*)> _ed25519;
    static const std::unique_ptr<elliptic_curve256_algebra_ctx_t, void(*)(elliptic_curve256_algebra_ctx_t*)> _stark;
};

}
}
}
