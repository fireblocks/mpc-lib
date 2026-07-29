#include <array>
#include <iostream>
#include <map>
#include <openssl/rand.h>
#include <set>
#include <shared_mutex>
#include <uuid/uuid.h>
#include <tests/catch.hpp>

#include "cosigner/sign_algorithm.h"
#include "cosigner/platform_service.h"
#include "cosigner/cosigner_exception.h"
#include "cosigner/frost_cosigner.h"
#include "cosigner/frost_cosigner_client.h"
#include "cosigner/frost_cosigner_server.h"
#include "cosigner/frost_key_persistency_client.h"
#include "cosigner/frost_key_persistency_server.h"
#include "cosigner/frost_tx_persistency.h"
#include "blockchain/mpc/hd_derive.h"

#ifndef UUID_STR_LEN
#define UUID_STR_LEN 37
#endif

namespace fbc = fireblocks::common::cosigner;

static std::string get_tenant_id()
{
    static std::string _tenant_id;
    if (_tenant_id.size() == 0)
    {
        uuid_t uid;
        _tenant_id.resize(UUID_STR_LEN);
        uuid_generate_random(uid);
        uuid_unparse(uid, _tenant_id.data());
    }

    return _tenant_id;
}

struct key_data
{
    cosigner_sign_algorithm _algorithm;
    elliptic_curve256_scalar_t private_key;
};

static const constexpr uint64_t client_id = 0x0011223344556677UL;
static const constexpr uint64_t server_id = 3213454843;

class key_persistency_service : public fbc::frost_key_persistency_server, public fbc::frost_key_persistency_client 
{
public:
    key_persistency_service(cosigner_sign_algorithm algorithm) : _algo(algorithm)  {}
    ~key_persistency_service() {}

    void store_key(const std::string& key_id, const fbc::elliptic_curve_scalar& private_key, const cosigner_sign_algorithm& algo) override
    {
        std::unique_lock lock(_mutex);
        if (_keys_shares.find(key_id) != _keys_shares.end())
            throw fbc::cosigner_exception(fbc::cosigner_exception::BAD_IMPORTED_KEY_ALREADY_EXISTS);
        key_data data;
        data._algorithm = algo;
        memcpy(data.private_key, private_key.data, sizeof(elliptic_curve256_scalar_t));
        _keys_shares.emplace(key_id, std::move(data));
    }
    void load_key(const std::string& key_id, fbc::elliptic_curve_scalar& secret_key) const override
    {
        std::shared_lock lock(_mutex);
        auto it = _keys_shares.find(key_id);
        if (it == _keys_shares.end())
            throw fbc::cosigner_exception(fbc::cosigner_exception::BAD_KEY);
        memcpy(secret_key.data, it->second.private_key, sizeof(elliptic_curve256_scalar_t));
    }

    void store_key_metadata(const std::string& key_id, const fbc::frost_key_metadata_base& metadata, bool allow_override) override
    {
        std::unique_lock lock(_mutex);
        if (!allow_override && _keys_metadata.find(key_id) != _keys_metadata.end())
            throw fbc::cosigner_exception(fbc::cosigner_exception::BAD_IMPORTED_KEY_ALREADY_EXISTS);
        static_cast<fbc::frost_key_metadata_base&>(_keys_metadata[key_id]) = metadata;
    }
    void load_key_metadata(const std::string& key_id, fbc::frost_key_metadata_base& metadata) const override
    {
        std::shared_lock lock(_mutex);
        auto it = _keys_metadata.find(key_id);
        if (it == _keys_metadata.end())
            throw fbc::cosigner_exception(fbc::cosigner_exception::BAD_KEY);
        metadata = it->second;
    }

    void store_key_metadata(const std::string& key_id, const fbc::frost_key_metadata_server& metadata, bool allow_override) override
    {
        std::unique_lock lock(_mutex);
        if (!allow_override && _keys_metadata.find(key_id) != _keys_metadata.end())
            throw fbc::cosigner_exception(fbc::cosigner_exception::BAD_IMPORTED_KEY_ALREADY_EXISTS);
        _keys_metadata[key_id] = metadata;
    }
    void load_key_metadata(const std::string& key_id, fbc::frost_key_metadata_server& metadata) const override
    {
        std::shared_lock lock(_mutex);
        auto it = _keys_metadata.find(key_id);
        if (it == _keys_metadata.end())
            throw fbc::cosigner_exception(fbc::cosigner_exception::BAD_KEY);
        metadata = it->second;
    }

    void store_server_commitment(const std::string& key_id, const commitments_sha256_t& commitment) override 
    {
        std::unique_lock lock(_mutex);
        if (_server_key_commitment.find(key_id) != _server_key_commitment.end())
            throw fbc::cosigner_exception(fbc::cosigner_exception::BAD_IMPORTED_KEY_ALREADY_EXISTS);
        _server_key_commitment[key_id];
        memcpy(_server_key_commitment[key_id], commitment, sizeof(commitments_sha256_t));
    }
    void load_server_commitment_and_delete(const std::string& key_id, commitments_sha256_t& commitment) override
    {
        std::unique_lock lock(_mutex);
        auto it = _server_key_commitment.find(key_id);
        if (it == _server_key_commitment.end())
            throw fbc::cosigner_exception(fbc::cosigner_exception::BAD_KEY);
        memcpy(commitment, it->second, sizeof(commitments_sha256_t));
        _server_key_commitment.erase(it);
    }

    void store_tenant_id_for_key(const std::string& key_id, const std::string& tenant_id) override 
    {
        std::unique_lock lock(_mutex);
        _tenant_ids[key_id] = tenant_id;
    }
    void load_tenant_id_for_key(const std::string& key_id, std::string& tenant_id) const override 
    {
        std::shared_lock lock(_mutex);
        auto it = _tenant_ids.find(key_id);
        if (it == _tenant_ids.end())
            throw fbc::cosigner_exception(fbc::cosigner_exception::BAD_KEY);
        tenant_id = it->second;
    }

    bool delete_temporary_key_data(const std::string& key_id) override 
    {
        std::unique_lock lock(_mutex);
        _keys_metadata.erase(key_id);
        return true;
    }

    bool delete_key(const std::string& key_id) override 
    {
        std::unique_lock lock(_mutex);
        _keys_shares.erase(key_id);
        _keys_metadata.erase(key_id);
        return true;
    }

    bool backup_key(const std::string& key_id) const override { return true; }

    mutable std::shared_mutex _mutex;
    std::map<std::string, key_data> _keys_shares;
    std::map<std::string, commitments_sha256_t> _server_key_commitment;
    std::map<std::string, fbc::frost_key_metadata_server> _keys_metadata;
    std::map<std::string, std::string> _tenant_ids;
    cosigner_sign_algorithm _algo;
};

class server_signing_info : public fbc::frost_tx_persistency 
{
public:
    void store_signature_data(const std::string& tx_id, const std::shared_ptr<fbc::frost_signature_data>& signature_data) override
    {
        std::unique_lock lock(_mutex);
        _data[tx_id] = signature_data;
    }
    std::shared_ptr<fbc::frost_signature_data> load_signature_data_and_delete(const std::string& tx_id) override
    {
        std::unique_lock lock(_mutex);
        auto it = _data.find(tx_id);
        if (it == _data.end())
            throw fbc::cosigner_exception(fbc::cosigner_exception::INVALID_TRANSACTION);
        auto result = it->second;
        _data.erase(it);
        return result;
    }
    bool delete_temporary_tx_data(const std::string& tx_id) override
    {
        std::unique_lock lock(_mutex);
        return _data.erase(tx_id) > 0;
    }
private:
    std::map<std::string, std::shared_ptr<fbc::frost_signature_data>> _data;
    mutable std::shared_mutex _mutex;
};

class test_frost_platform_service : public fbc::platform_service
{
public:
    explicit test_frost_platform_service(uint64_t player_id, const std::string& tenant_override = "") : _player_id(player_id), _tenant_override(tenant_override) {}
    ~test_frost_platform_service() = default;

    void gen_random(size_t len, uint8_t* random_data) const override
    {
        RAND_bytes(random_data, len);
    }
    bool backup_key(const std::string& key_id, cosigner_sign_algorithm algorithm, const elliptic_curve256_scalar_t& private_key, const fbc::cmp_key_metadata& metadata, const fbc::auxiliary_keys& aux) override {return true;}
    void derive_initial_share(const fbc::share_derivation_args& derive_from, cosigner_sign_algorithm algorithm, elliptic_curve256_scalar_t* key) const override {assert(0);}
    void on_start_signing(const std::string& key_id, const std::string& txid, const fbc::signing_data& data, const std::string& metadata_json, const std::set<std::string>& players, const signing_type signature_type) override {};
    bool is_client_id(uint64_t player_id) const override {return false;}
    virtual void fill_signing_info_from_metadata(const std::string& metadata, std::vector<uint32_t>& flags) const override {}

    virtual const std::string get_current_tenantid() const override
    {
        return _tenant_override.empty() ? get_tenant_id() : _tenant_override;
    }

    virtual uint64_t get_id_from_keyid(const std::string& key_id) const override
    {
        return _player_id;
    }

    virtual void fill_eddsa_signing_info_from_metadata(std::vector<fbc::eddsa_signature_data>& info, const std::string& metadata) const override
    {

    }

    virtual void fill_bam_signing_info_from_metadata(std::vector<fbc::bam_signing_properties>& info, const std::string& metadata) const override
    {
    }

    virtual void fill_frost_signing_info_from_metadata(std::vector<fbc::frost_signing_properties>& info, const std::string& metadata) const override
    {
        if (metadata == "keccak" && !info.empty())
            info[0].flags = fbc::EDDSA_KECCAK;
    }
    virtual fbc::byte_vector_t encrypt_for_player(const uint64_t id, const fbc::byte_vector_t& data, const std::optional<std::string>& verify_modulus = std::nullopt) const override { return data; }
    virtual fbc::byte_vector_t decrypt_message(const fbc::byte_vector_t& encrypted_data) const override { return encrypted_data; }
    virtual void prepare_for_signing(const std::string& key_id, const std::string tx_id) override {};
    virtual void mark_key_setup_in_progress(const std::string& key_id) const override {};
    virtual void clear_key_setup_in_progress(const std::string& key_id) const override {};

private:
    uint64_t _player_id;
    std::string _tenant_override;
};

void frost_key_generation(const std::string& key_id, cosigner_sign_algorithm algo, uint64_t server_id, uint64_t client_id, fbc::frost_cosigner_server& server, fbc::frost_cosigner_client& client) 
{
    // Step 0: client initializes its key share.
    REQUIRE_NOTHROW(client.start_new_key_generation(key_id, get_tenant_id(), client_id, server_id, algo));

    // Step 1.
    commitments_sha256_t B;
    REQUIRE_NOTHROW(server.generate_share_and_commit(key_id, get_tenant_id(), algo, server_id, client_id, B));

    // Step 2.
    fbc::frost_cosigner::key_share_public_data client_message;
    REQUIRE_NOTHROW(client.store_commitment_and_generate_proofs(key_id, B, server_id, client_message));

    // Step 3.
    fbc::frost_cosigner::key_share_public_data server_message;
    REQUIRE_NOTHROW(server.verify_client_proofs_and_decommit_share_with_proof(key_id, server_id, client_id, client_message, server_message));

    // Step 4.
    fbc::frost_cosigner::generated_public_key pub_key_data;
    REQUIRE_NOTHROW(client.verify_key_decommitment_and_proofs(key_id, server_id, server_message, pub_key_data));

}

void frost_sign(const std::string& key_id, const std::string& tx_id, cosigner_sign_algorithm algorithm, uint64_t server_id, uint64_t client_id, const fbc::byte_vector_t& message, fbc::frost_cosigner_server& server, fbc::frost_cosigner_client& client, const std::string& metadata_json = "", std::vector<fbc::eddsa_signature>* out_signatures = nullptr)
{
    fbc::signing_data data;
    memset(data.chaincode, 0, sizeof(data.chaincode));
    data.blocks.resize(1);
    data.blocks[0].data = message;
    data.blocks[0].path = {44, 0, 0, 0, 0};

    const std::set<std::string> players_set = {std::to_string(server_id), std::to_string(client_id)};

    printf("Signing a message of length %zu\n", message.size());

    std::vector<fbc::frost_cosigner::server_signature_shared_data> server_commitments;
    REQUIRE_NOTHROW(server.generate_signature_share(key_id, tx_id, 1, server_id, client_id, data, metadata_json, players_set, algorithm, server_commitments));

    std::vector<fbc::frost_cosigner::client_partial_signature_data> partial_signatures;
    REQUIRE_NOTHROW(client.compute_partial_signature(key_id, tx_id, 1, server_id, client_id, data, metadata_json, players_set, server_commitments, partial_signatures));

    std::vector<fbc::eddsa_signature> full_signatures;
    cosigner_sign_algorithm out_algorithm;
    REQUIRE_NOTHROW(server.verify_partial_signature_and_output_signature(key_id, tx_id, client_id, partial_signatures, full_signatures, out_algorithm));
    REQUIRE(out_algorithm == algorithm);
    REQUIRE(full_signatures.size() == partial_signatures.size());
    if (out_signatures)
        *out_signatures = full_signatures;
}

static char keyid[37] = {0};
static char txid[37] = {0};

TEST_CASE("frost")
{
    const std::pair<std::string, cosigner_sign_algorithm> supported_curves[] = {{"secp256k1", SCHNORR_SECP256K1}, {"secp256r1", SCHNORR_SECP256R1}, {"stark", SCHNORR_STARK}, {"ed25519", EDDSA_ED25519}};
    for (auto it : supported_curves)
    {
        SECTION(it.first)
        {
            cosigner_sign_algorithm algorithm = it.second;
            key_persistency_service key_service_client(algorithm);
            key_persistency_service key_service_server(algorithm);
            server_signing_info server_sign_service;
            test_frost_platform_service platform_service_server(server_id);
            test_frost_platform_service platform_service_client(client_id);

            fbc::frost_cosigner_server server(platform_service_server, key_service_server, server_sign_service);
            fbc::frost_cosigner_client client(platform_service_client, key_service_client);
            uuid_t uid;
            uuid_generate_random(uid);
            uuid_unparse(uid, keyid);

            frost_key_generation(keyid, algorithm, server_id, client_id, server, client);

            // Check that server and client agree on the public key.
            fbc::frost_key_metadata_server server_key_metadata;
            REQUIRE_NOTHROW(key_service_server.load_key_metadata(keyid, server_key_metadata));
            fbc::frost_key_metadata_base client_key_metadata;
            REQUIRE_NOTHROW(key_service_client.load_key_metadata(keyid, client_key_metadata));
            REQUIRE(memcmp(server_key_metadata.public_key, client_key_metadata.public_key, sizeof(elliptic_curve256_point_t)) == 0);

            elliptic_curve256_scalar_t hash;
            REQUIRE(RAND_bytes(hash, sizeof(hash)));
            const fbc::byte_vector_t message(hash, hash + sizeof(hash));

            SECTION("standard message size")
            {
                uuid_generate_random(uid);
                uuid_unparse(uid, txid);
                frost_sign(keyid, txid, algorithm, server_id, client_id, message, server, client);
            }

            SECTION("random length message")
            {
                uuid_generate_random(uid);
                uuid_unparse(uid, txid);
                uint8_t len_byte = 0;
                REQUIRE(RAND_bytes(&len_byte, 1));
                const size_t msg_len = 1 + (len_byte % 128);
                fbc::byte_vector_t large_msg(msg_len);
                REQUIRE(RAND_bytes(large_msg.data(), large_msg.size()));
                frost_sign(keyid, txid, algorithm, server_id, client_id, large_msg, server, client);
            }

            SECTION("keccak")
            {
                uuid_generate_random(uid);
                uuid_unparse(uid, txid);
                std::vector<fbc::eddsa_signature> signatures;
                frost_sign(keyid, txid, algorithm, server_id, client_id, message, server, client, "keccak", &signatures);

                std::unique_ptr<elliptic_curve256_algebra_ctx_t, void(*)(elliptic_curve256_algebra_ctx_t*)> algebra(
                    algorithm == EDDSA_ED25519     ? elliptic_curve256_new_ed25519_algebra()  :
                    algorithm == SCHNORR_SECP256K1 ? elliptic_curve256_new_secp256k1_algebra() :
                    algorithm == SCHNORR_SECP256R1 ? elliptic_curve256_new_secp256r1_algebra() :
                                                     elliptic_curve256_new_stark_algebra(),
                    elliptic_curve256_algebra_ctx_free);

                elliptic_curve256_point_t derived_pubkey;
                memcpy(derived_pubkey, client_key_metadata.public_key, sizeof(elliptic_curve256_point_t));
                HDChaincode chaincode = {0};
                const uint32_t path[] = {44, 0, 0, 0, 0};
                REQUIRE(HD_DERIVE_SUCCESS == derive_public_key_generic(algebra.get(), derived_pubkey, derived_pubkey, chaincode, path, 5));

                REQUIRE(signatures.size() == 1);
                REQUIRE(1 == server.validate_schnorr_signature(algebra.get(), signatures[0], message.data(), message.size(), &derived_pubkey, true));
            }
        }
    }
}

TEST_CASE("frost_attacks")
{
    const cosigner_sign_algorithm algorithm = SCHNORR_SECP256K1;

    key_persistency_service key_service_client(algorithm);
    key_persistency_service key_service_server(algorithm);
    server_signing_info server_sign_service;
    test_frost_platform_service platform_service_server(server_id);
    test_frost_platform_service platform_service_client(client_id);

    fbc::frost_cosigner_server server(platform_service_server, key_service_server, server_sign_service);
    fbc::frost_cosigner_client client(platform_service_client, key_service_client);

    uuid_t uid;
    uuid_generate_random(uid);
    uuid_unparse(uid, keyid);
    frost_key_generation(keyid, algorithm, server_id, client_id, server, client);

    elliptic_curve256_scalar_t hash;
    REQUIRE(RAND_bytes(hash, sizeof(hash)));
    const fbc::byte_vector_t message(hash, hash + sizeof(hash));
    const std::set<std::string> players_set = {std::to_string(server_id), std::to_string(client_id)};

    fbc::signing_data data;
    memset(data.chaincode, 0, sizeof(data.chaincode));
    data.blocks.resize(1);
    data.blocks[0].data = message;
    data.blocks[0].path = {44, 0, 0, 0, 0};

    uuid_generate_random(uid);
    uuid_unparse(uid, txid);

    std::vector<fbc::frost_cosigner::server_signature_shared_data> server_commitments;
    REQUIRE_NOTHROW(server.generate_signature_share(keyid, txid, 1, server_id, client_id, data, "", players_set, algorithm, server_commitments));

    std::vector<fbc::frost_cosigner::client_partial_signature_data> partial_signatures;
    REQUIRE_NOTHROW(client.compute_partial_signature(keyid, txid, 1, server_id, client_id, data, "", players_set, server_commitments, partial_signatures));
    REQUIRE(partial_signatures.size() == 1);

    std::vector<fbc::eddsa_signature> full_signatures;
    cosigner_sign_algorithm out_algorithm;

    SECTION("corrupted partial signature s value")
    {
        partial_signatures[0].s.data[0] ^= 0xFF;
        REQUIRE_THROWS(server.verify_partial_signature_and_output_signature(keyid, txid, client_id, partial_signatures, full_signatures, out_algorithm));
    }

    SECTION("corrupted D commitment from client")
    {
        partial_signatures[0].D[1] ^= 0xFF;
        REQUIRE_THROWS(server.verify_partial_signature_and_output_signature(keyid, txid, client_id, partial_signatures, full_signatures, out_algorithm));
    }

    SECTION("no server commitments")
    {
        std::vector<fbc::frost_cosigner::server_signature_shared_data> empty_commitments;
        std::vector<fbc::frost_cosigner::client_partial_signature_data> wrong_partial_sigs;
        REQUIRE_THROWS(client.compute_partial_signature(keyid, txid, 1, server_id, client_id, data, "", players_set, empty_commitments, wrong_partial_sigs));
    }

    SECTION("tampered message sent to client")
    {
        fbc::byte_vector_t tampered = message;
        tampered[0] ^= 0xFF;
        fbc::signing_data tampered_data = data;
        tampered_data.blocks[0].data = tampered;

        std::vector<fbc::frost_cosigner::client_partial_signature_data> wrong_partial_sigs;
        REQUIRE_NOTHROW(client.compute_partial_signature(keyid, txid, 1, server_id, client_id, tampered_data, "", players_set, server_commitments, wrong_partial_sigs));

        REQUIRE_THROWS(server.verify_partial_signature_and_output_signature(keyid, txid, client_id, wrong_partial_sigs, full_signatures, out_algorithm));
    }

    SECTION("block count mismatch")
    {
        std::vector<fbc::frost_cosigner::server_signature_shared_data> too_many_shares = server_commitments;
        too_many_shares.push_back(server_commitments[0]);
        std::vector<fbc::frost_cosigner::client_partial_signature_data> wrong_partial_sigs;
        REQUIRE_THROWS(client.compute_partial_signature(keyid, txid, 1, server_id, client_id, data, "", players_set, too_many_shares, wrong_partial_sigs));
    }

    // Caller-supplied key_id must match the key bound to tx_id during
    // generate_signature_share. A mismatch would let an attacker rebind a
    // partial signature to a different key downstream (e.g. in the thrift
    // response generation that uses the caller's key_id).
    SECTION("wrong key_id rejected on server verify_partial_signature_and_output_signature")
    {
        uuid_t other_uid;
        uuid_generate_random(other_uid);
        char other_keyid[37] = {0};
        uuid_unparse(other_uid, other_keyid);

        REQUIRE_THROWS_AS(
            server.verify_partial_signature_and_output_signature(other_keyid, txid, client_id, partial_signatures, full_signatures, out_algorithm),
            fbc::cosigner_exception);
    }
}

using nonce_point_bytes = std::vector<uint8_t>;

// Inserts the point into `seen` and asserts it was not already present.
// Templated on N so it accepts both 33-byte compressed EC points
// (elliptic_curve256_point_t) and 32-byte raw points (ed25519_point_t).
template <size_t N>
static void require_unique_nonce(std::set<nonce_point_bytes>& seen,
                                 const uint8_t (&p)[N],
                                 const char* label,
                                 size_t idx)
{
    INFO("nonce reuse detected: " << label << " at block " << idx);
    REQUIRE(seen.insert(nonce_point_bytes(p, p + N)).second);
}

// Nonce uniqueness in batch signing.
// Every Schnorr-family signature (all FROST curves) loses the private key if
// the per-signature nonce is reused. The batch path produces (D, E) for each
// block on both parties; all 4*N points must be distinct.
TEST_CASE("frost_nonce_uniqueness")
{
    constexpr size_t BATCH_SIZE = 1000;

    const std::pair<std::string, cosigner_sign_algorithm> supported_curves[] = {
        {"secp256k1", SCHNORR_SECP256K1},
        {"secp256r1", SCHNORR_SECP256R1},
        {"stark",     SCHNORR_STARK},
        {"ed25519",   EDDSA_ED25519}
    };

    auto run_batch_and_assert_unique_nonces = [](fbc::frost_cosigner_server& server,
                                                 fbc::frost_cosigner_client& client,
                                                 cosigner_sign_algorithm algorithm,
                                                 const std::vector<fbc::byte_vector_t>& messages)
    {
        const std::set<std::string> players_set = {std::to_string(server_id), std::to_string(client_id)};

        fbc::signing_data data;
        memset(data.chaincode, 0, sizeof(data.chaincode));
        data.blocks.resize(messages.size());
        for (size_t i = 0; i < messages.size(); ++i)
        {
            data.blocks[i].data = messages[i];
            data.blocks[i].path = {44, 0, 0, 0, 0};
        }

        uuid_t uid;
        uuid_generate_random(uid);
        uuid_unparse(uid, txid);

        std::vector<fbc::frost_cosigner::server_signature_shared_data> server_commitments;
        REQUIRE_NOTHROW(server.generate_signature_share(keyid, txid, 1, server_id, client_id, data, "", players_set, algorithm, server_commitments));
        REQUIRE(server_commitments.size() == messages.size());

        std::vector<fbc::frost_cosigner::client_partial_signature_data> partial_signatures;
        REQUIRE_NOTHROW(client.compute_partial_signature(keyid, txid, 1, server_id, client_id, data, "", players_set, server_commitments, partial_signatures));
        REQUIRE(partial_signatures.size() == messages.size());

        std::vector<fbc::eddsa_signature> full_signatures;
        cosigner_sign_algorithm out_algorithm;
        REQUIRE_NOTHROW(server.verify_partial_signature_and_output_signature(keyid, txid, client_id, partial_signatures, full_signatures, out_algorithm));
        REQUIRE(full_signatures.size() == messages.size());

        std::set<nonce_point_bytes> seen;
        for (size_t i = 0; i < messages.size(); ++i)
        {
            require_unique_nonce(seen, server_commitments[i].D, "server_D", i);
            require_unique_nonce(seen, server_commitments[i].E, "server_E", i);
            require_unique_nonce(seen, partial_signatures[i].D, "client_D", i);
            require_unique_nonce(seen, partial_signatures[i].E, "client_E", i);
            require_unique_nonce(seen, full_signatures[i].R, "final_R", i);
        }
    };

    for (auto it : supported_curves)
    {
        SECTION(it.first)
        {
            const cosigner_sign_algorithm algorithm = it.second;
            key_persistency_service key_service_client(algorithm);
            key_persistency_service key_service_server(algorithm);
            server_signing_info server_sign_service;
            test_frost_platform_service platform_service_server(server_id);
            test_frost_platform_service platform_service_client(client_id);

            fbc::frost_cosigner_server server(platform_service_server, key_service_server, server_sign_service);
            fbc::frost_cosigner_client client(platform_service_client, key_service_client);

            uuid_t uid;
            uuid_generate_random(uid);
            uuid_unparse(uid, keyid);
            frost_key_generation(keyid, algorithm, server_id, client_id, server, client);

            SECTION("1000-block batch with random hashes")
            {
                std::vector<fbc::byte_vector_t> messages(BATCH_SIZE);
                for (size_t i = 0; i < BATCH_SIZE; ++i)
                {
                    elliptic_curve256_scalar_t hash;
                    REQUIRE(RAND_bytes(hash, sizeof(hash)));
                    messages[i].assign(hash, hash + sizeof(hash));
                }
                run_batch_and_assert_unique_nonces(server, client, algorithm, messages);
            }

            SECTION("1000-block batch with duplicate hashes")
            {
                elliptic_curve256_scalar_t hash;
                REQUIRE(RAND_bytes(hash, sizeof(hash)));
                const fbc::byte_vector_t message(hash, hash + sizeof(hash));
                const std::vector<fbc::byte_vector_t> messages(BATCH_SIZE, message);
                run_batch_and_assert_unique_nonces(server, client, algorithm, messages);
            }
        }
    }
}

TEST_CASE("frost_tenant_id")
{
    const cosigner_sign_algorithm algorithm = SCHNORR_SECP256K1;

    key_persistency_service key_service_client(algorithm);
    key_persistency_service key_service_server(algorithm);
    server_signing_info server_sign_service;

    test_frost_platform_service platform_service_server(server_id);
    test_frost_platform_service platform_service_client(client_id);
    test_frost_platform_service wrong_platform_server(server_id, "wrong_tenant");
    test_frost_platform_service wrong_platform_client(client_id, "wrong_tenant");

    fbc::frost_cosigner_server server(platform_service_server, key_service_server, server_sign_service);
    fbc::frost_cosigner_client client(platform_service_client, key_service_client);
    fbc::frost_cosigner_server wrong_server(wrong_platform_server, key_service_server, server_sign_service);
    fbc::frost_cosigner_client wrong_client(wrong_platform_client, key_service_client);

    uuid_t uid;
    char local_keyid[37], local_txid[37];
    uuid_generate_random(uid);
    uuid_unparse(uid, local_keyid);

    SECTION("key gen: wrong tenant_id parameter rejected by client")
    {
        REQUIRE_THROWS(client.start_new_key_generation(local_keyid, "wrong_tenant", client_id, server_id, algorithm));
    }

    SECTION("key gen: wrong tenant rejected on client round 2")
    {
        REQUIRE_NOTHROW(client.start_new_key_generation(local_keyid, get_tenant_id(), client_id, server_id, algorithm));
        commitments_sha256_t B;
        REQUIRE_NOTHROW(server.generate_share_and_commit(local_keyid, get_tenant_id(), algorithm, server_id, client_id, B));

        fbc::frost_cosigner::key_share_public_data client_message;
        REQUIRE_THROWS(wrong_client.store_commitment_and_generate_proofs(local_keyid, B, server_id, client_message));
    }

    SECTION("key gen: wrong tenant rejected on server generate_share_and_commit")
    {
        commitments_sha256_t B;
        REQUIRE_THROWS(wrong_server.generate_share_and_commit(local_keyid, get_tenant_id(), algorithm, server_id, client_id, B));
    }

    SECTION("key gen: wrong tenant rejected on server verify step")
    {
        REQUIRE_NOTHROW(client.start_new_key_generation(local_keyid, get_tenant_id(), client_id, server_id, algorithm));
        commitments_sha256_t B;
        REQUIRE_NOTHROW(server.generate_share_and_commit(local_keyid, get_tenant_id(), algorithm, server_id, client_id, B));

        fbc::frost_cosigner::key_share_public_data client_message;
        REQUIRE_NOTHROW(client.store_commitment_and_generate_proofs(local_keyid, B, server_id, client_message));

        fbc::frost_cosigner::key_share_public_data server_message;
        REQUIRE_THROWS(wrong_server.verify_client_proofs_and_decommit_share_with_proof(local_keyid, server_id, client_id, client_message, server_message));
    }

    SECTION("key gen: wrong tenant rejected on client final step")
    {
        REQUIRE_NOTHROW(client.start_new_key_generation(local_keyid, get_tenant_id(), client_id, server_id, algorithm));
        commitments_sha256_t B;
        REQUIRE_NOTHROW(server.generate_share_and_commit(local_keyid, get_tenant_id(), algorithm, server_id, client_id, B));

        fbc::frost_cosigner::key_share_public_data client_message;
        REQUIRE_NOTHROW(client.store_commitment_and_generate_proofs(local_keyid, B, server_id, client_message));

        fbc::frost_cosigner::key_share_public_data server_message;
        REQUIRE_NOTHROW(server.verify_client_proofs_and_decommit_share_with_proof(local_keyid, server_id, client_id, client_message, server_message));

        fbc::frost_cosigner::generated_public_key pub_key_data;
        REQUIRE_THROWS(wrong_client.verify_key_decommitment_and_proofs(local_keyid, server_id, server_message, pub_key_data));
    }

    SECTION("sign")
    {
        frost_key_generation(local_keyid, algorithm, server_id, client_id, server, client);

        elliptic_curve256_scalar_t hash;
        REQUIRE(RAND_bytes(hash, sizeof(hash)));
        const fbc::byte_vector_t message(hash, hash + sizeof(hash));
        const std::set<std::string> players_set = {std::to_string(server_id), std::to_string(client_id)};

        fbc::signing_data data;
        memset(data.chaincode, 0, sizeof(data.chaincode));
        data.blocks.resize(1);
        data.blocks[0].data = message;
        data.blocks[0].path = {44, 0, 0, 0, 0};

        uuid_generate_random(uid);
        uuid_unparse(uid, local_txid);

        SECTION("wrong tenant rejected on server generate_signature_share")
        {
            std::vector<fbc::frost_cosigner::server_signature_shared_data> server_commitments;
            REQUIRE_THROWS(wrong_server.generate_signature_share(local_keyid, local_txid, 1, server_id, client_id, data, "", players_set, algorithm, server_commitments));
        }

        SECTION("wrong tenant rejected on client compute_partial_signature")
        {
            std::vector<fbc::frost_cosigner::server_signature_shared_data> server_commitments;
            REQUIRE_NOTHROW(server.generate_signature_share(local_keyid, local_txid, 1, server_id, client_id, data, "", players_set, algorithm, server_commitments));

            std::vector<fbc::frost_cosigner::client_partial_signature_data> partial_signatures;
            REQUIRE_THROWS(wrong_client.compute_partial_signature(local_keyid, local_txid, 1, server_id, client_id, data, "", players_set, server_commitments, partial_signatures));
        }

        SECTION("wrong tenant rejected on server verify_partial_signature_and_output_signature")
        {
            std::vector<fbc::frost_cosigner::server_signature_shared_data> server_commitments;
            REQUIRE_NOTHROW(server.generate_signature_share(local_keyid, local_txid, 1, server_id, client_id, data, "", players_set, algorithm, server_commitments));

            std::vector<fbc::frost_cosigner::client_partial_signature_data> partial_signatures;
            REQUIRE_NOTHROW(client.compute_partial_signature(local_keyid, local_txid, 1, server_id, client_id, data, "", players_set, server_commitments, partial_signatures));

            std::vector<fbc::eddsa_signature> full_signatures;
            cosigner_sign_algorithm out_algorithm;
            REQUIRE_THROWS(wrong_server.verify_partial_signature_and_output_signature(local_keyid, local_txid, client_id, partial_signatures, full_signatures, out_algorithm));
        }
    }
}

// Exposes protected static members of fbc::frost_cosigner for unit testing.
struct frost_test_access : public fbc::frost_cosigner
{
    explicit frost_test_access(fbc::platform_service& p) : fbc::frost_cosigner(p) {}
    using fbc::frost_cosigner::is_zero_scalar;
};

TEST_CASE("frost_is_zero_scalar")
{
    SECTION("all zeros returns true")
    {
        elliptic_curve256_scalar_t zero = {0};
        REQUIRE(frost_test_access::is_zero_scalar(zero) == true);
    }

    SECTION("bit set in each 64-bit word returns false")
    {
        // Regression guard: catches a short-circuit OR/AND regression in is_zero_scalar.
        // A non-constant-time implementation could still pass an "all zeros" test;
        // touching each word position independently exercises the OR-fold over the whole scalar.
        for (size_t word = 0; word < sizeof(elliptic_curve256_scalar_t) / sizeof(uint64_t); ++word)
        {
            elliptic_curve256_scalar_t s = {0};
            s[word * sizeof(uint64_t)] = 0x01;
            REQUIRE(frost_test_access::is_zero_scalar(s) == false);
        }
    }

    SECTION("all ones returns false")
    {
        elliptic_curve256_scalar_t all_ones;
        memset(all_ones, 0xFF, sizeof(all_ones));
        REQUIRE(frost_test_access::is_zero_scalar(all_ones) == false);
    }
}

TEST_CASE("frost_add_user_rejects_zero_share")
{
    // test_frost_platform_service::decrypt_message is the identity function,
    // so an encrypted_share of 32 zero bytes will decrypt to a zero scalar,
    // which decrypt_and_rebuild_private_share will sum into private_share = 0.
    const cosigner_sign_algorithm algorithm = EDDSA_ED25519;

    std::map<uint64_t, fbc::frost_cosigner::add_user_data> zero_share_data;
    {
        fbc::frost_cosigner::add_user_data entry;
        entry.encrypted_shares[client_id] = fbc::byte_vector_t(sizeof(elliptic_curve256_scalar_t), 0);
        entry.encrypted_shares[server_id] = fbc::byte_vector_t(sizeof(elliptic_curve256_scalar_t), 0);
        zero_share_data[server_id] = entry;
    }

    uuid_t uid;
    uuid_generate_random(uid);
    char local_keyid[37] = {0};
    uuid_unparse(uid, local_keyid);

    SECTION("client start_add_user throws on zero share")
    {
        key_persistency_service key_service_client(algorithm);
        test_frost_platform_service ps_client(client_id);
        fbc::frost_cosigner_client client(ps_client, key_service_client);

        REQUIRE_THROWS(client.start_add_user(local_keyid, get_tenant_id(), client_id, server_id, algorithm, zero_share_data));
    }

    SECTION("server add_user_and_commit throws on zero share")
    {
        key_persistency_service key_service_server(algorithm);
        server_signing_info server_sign_service;
        test_frost_platform_service ps_server(server_id);
        fbc::frost_cosigner_server server(ps_server, key_service_server, server_sign_service);

        commitments_sha256_t commitment;
        REQUIRE_THROWS(server.add_user_and_commit(local_keyid, get_tenant_id(), algorithm, server_id, client_id, zero_share_data, commitment));
    }
}

