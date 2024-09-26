#include <iostream>
#include <chrono>
#include <shared_mutex>
#include <tests/catch.hpp>

#include "cosigner/asymmetric_eddsa_cosigner_client.h"
#include "cosigner/asymmetric_eddsa_cosigner_server.h"
#include "cosigner/cosigner_exception.h"
#include "test_common.h"
#include "crypto/elliptic_curve_algebra/elliptic_curve256_algebra.h"
#include "cosigner/cmp_key_persistency.h"
#include "cosigner/mpc_globals.h"

#include <string.h>

#include <openssl/rand.h>

static const uint64_t CLIENT_ID = 12345678;
using namespace fireblocks::common::cosigner;

using Clock = std::conditional<std::chrono::high_resolution_clock::is_steady, std::chrono::high_resolution_clock,
        std::chrono::steady_clock>::type;

static elliptic_curve256_algebra_ctx_t* create_algebra(cosigner_sign_algorithm type)
{
    switch (type)
    {
        case EDDSA_ED25519: return elliptic_curve256_new_secp256k1_algebra();
        case ECDSA_SECP256R1: return elliptic_curve256_new_secp256r1_algebra();
        case ECDSA_STARK: return elliptic_curve256_new_stark_algebra();
        default: return NULL;
    }
}


class asymmetric_eddsa_platform : public platform_service
{
public:
    asymmetric_eddsa_platform(uint64_t id) : _id(id), _use_keccak(false) {}
    void set_use_keccak(bool use_keccak) {_use_keccak = use_keccak;}
private:
    void gen_random(size_t len, uint8_t* random_data) const override
    {
        RAND_bytes(random_data, len);
    }

    uint64_t now_msec() const override { return std::chrono::time_point_cast<std::chrono::milliseconds>(Clock::now()).time_since_epoch().count(); }

    const std::string get_current_tenantid() const override {return TENANT_ID;}
    uint64_t get_id_from_keyid(const std::string& key_id) const override {return _id;}
    void derive_initial_share(const share_derivation_args& derive_from, cosigner_sign_algorithm algorithm, elliptic_curve256_scalar_t* key) const override { assert(0);}
    byte_vector_t encrypt_for_player(uint64_t id, const byte_vector_t& data) const override {assert(0);}
    byte_vector_t decrypt_message(const byte_vector_t& encrypted_data) const override {assert(0);}
    bool backup_key(const std::string& key_id, cosigner_sign_algorithm algorithm, const elliptic_curve256_scalar_t& private_key, const cmp_key_metadata& metadata, const auxiliary_keys& aux) override {return true;}
    void start_signing(const std::string& key_id, const std::string& txid, const signing_data& data, const std::string& metadata_json, const std::set<std::string>& players) override {}
    void fill_signing_info_from_metadata(const std::string& metadata, std::vector<uint32_t>& flags) const override
    {
        for (auto i = flags.begin(); i != flags.end(); ++i)
            *i = _use_keccak ? EDDSA_KECCAK : 0;
    }
    bool is_client_id(uint64_t player_id) const override {return CLIENT_ID == player_id;}

    const uint64_t _id;
    bool _use_keccak;
};

class client_persistency : public asymmetric_eddsa_cosigner_client::preprocessing_persistency
{
    void create_preprocessed_data(const std::string& key_id, uint64_t size) override
    {
        std::lock_guard<std::mutex> lock(_mutex);
        if (_preprocessed_data.find(key_id) != _preprocessed_data.end())
            throw cosigner_exception(cosigner_exception::INVALID_TRANSACTION);
        _preprocessed_data.emplace(key_id, std::move(std::vector<std::array<uint8_t, sizeof(ed25519_scalar_t)>>(size)));
    }

    void store_preprocessed_data(const std::string& key_id, uint64_t index, const ed25519_scalar_t& k) override
    {
        std::lock_guard<std::mutex> lock(_mutex);
        auto it = _preprocessed_data.find(key_id);
        if (it == _preprocessed_data.end())
            throw cosigner_exception(cosigner_exception::INVALID_TRANSACTION);
        if (index >= it->second.size())
            throw cosigner_exception(cosigner_exception::INVALID_PRESIGNING_INDEX);
        memcpy(&((it->second[index])[0]), k, sizeof(ed25519_scalar_t));
    }

    void load_preprocessed_data(const std::string& key_id, uint64_t index, ed25519_scalar_t& k) override
    {
        static uint8_t ZERO[sizeof(ed25519_scalar_t)] = {0};
        std::lock_guard<std::mutex> lock(_mutex);
        auto it = _preprocessed_data.find(key_id);
        if (it == _preprocessed_data.end())
            throw cosigner_exception(cosigner_exception::INVALID_TRANSACTION);
        if (index >= it->second.size() || memcmp(&((it->second[index])[0]), ZERO, sizeof(ed25519_scalar_t)) == 0)
            throw cosigner_exception(cosigner_exception::INVALID_PRESIGNING_INDEX);
        memcpy(k, &((it->second[index])[0]), sizeof(ed25519_scalar_t));
        memset(&((it->second[index])[0]), 0, sizeof(ed25519_scalar_t));
    }

    void delete_preprocessed_data(const std::string& key_id) override
    {
        std::lock_guard<std::mutex> lock(_mutex);
        _preprocessed_data.erase(key_id);
    }

    mutable std::mutex _mutex;
    std::map<std::string, std::vector<std::array<uint8_t, sizeof(ed25519_scalar_t)>>> _preprocessed_data;
};

class server_persistency : public asymmetric_eddsa_cosigner_server::signing_persistency
{
    void create_preprocessed_data(const std::string& key_id, uint64_t size) override
    {
        std::unique_lock lock(_mutex);
        if (_preprocessed_data.find(key_id) != _preprocessed_data.end())
            throw cosigner_exception(cosigner_exception::INVALID_TRANSACTION);
        _preprocessed_data.emplace(key_id, std::move(std::vector<eddsa_commitment>(size)));
    }

    void store_preprocessed_data(const std::string& key_id, uint64_t index, const eddsa_commitment& R_commitment) override
    {
        std::unique_lock lock(_mutex);
        auto it = _preprocessed_data.find(key_id);
        if (it == _preprocessed_data.end())
            throw cosigner_exception(cosigner_exception::INVALID_TRANSACTION);
        if (index >= it->second.size())
            throw cosigner_exception(cosigner_exception::INVALID_PRESIGNING_INDEX);
        it->second[index] = R_commitment;
    }

    void load_preprocessed_data(const std::string& key_id, uint64_t index, eddsa_commitment& R_commitment) override
    {
        static uint8_t ZERO[sizeof(ed25519_scalar_t)] = {0};
        std::unique_lock lock(_mutex);
        auto it = _preprocessed_data.find(key_id);
        if (it == _preprocessed_data.end())
            throw cosigner_exception(cosigner_exception::INVALID_TRANSACTION);
        if (index >= it->second.size() || memcmp(it->second[index].data(), ZERO, sizeof(commitments_sha256_t)) == 0)
            throw cosigner_exception(cosigner_exception::INVALID_PRESIGNING_INDEX);
        R_commitment = it->second[index];
        memset(it->second[index].data(), 0, sizeof(commitments_sha256_t));
    }

    void delete_preprocessed_data(const std::string& key_id) override
    {
        std::unique_lock lock(_mutex);
        _preprocessed_data.erase(key_id);
    }

    void store_commitments(const std::string& txid, const std::map<uint64_t, std::vector<eddsa_commitment>>& commitments) override
    {
        std::unique_lock lock(_mutex);
        if (_commitments.find(txid) != _commitments.end())
            throw cosigner_exception(cosigner_exception::INVALID_TRANSACTION);
        _commitments[txid] = commitments;

    }

    void load_commitments(const std::string& txid, std::map<uint64_t, std::vector<eddsa_commitment>>& commitments) override
    {
        std::shared_lock lock(_mutex);
        auto it = _commitments.find(txid);
        if (it == _commitments.end())
            throw cosigner_exception(cosigner_exception::INVALID_TRANSACTION);
        commitments = it->second;
    }

    void delete_commitments(const std::string& txid) override
    {
        std::unique_lock lock(_mutex);
        _commitments.erase(txid);
    }

    void store_signing_data(const std::string& txid, const asymmetric_eddsa_signing_metadata& data, bool update) override
    {
        std::unique_lock lock(_mutex);
        if (!update && _signing_metadata.find(txid) != _signing_metadata.end())
            throw cosigner_exception(cosigner_exception::INVALID_TRANSACTION);
        _signing_metadata[txid] = data;
    }

    void load_signing_data(const std::string& txid, asymmetric_eddsa_signing_metadata& data) override
    {
        std::shared_lock lock(_mutex);
        auto it = _signing_metadata.find(txid);
        if (it == _signing_metadata.end())
            throw cosigner_exception(cosigner_exception::INVALID_TRANSACTION);
        data = it->second;
    }

    void delete_signing_data(const std::string& txid) override
    {
        std::unique_lock lock(_mutex);
        _signing_metadata.erase(txid);
    }


    mutable std::shared_mutex _mutex;
    std::map<std::string, std::map<uint64_t, std::vector<eddsa_commitment>>> _commitments;
    std::map<std::string, asymmetric_eddsa_signing_metadata> _signing_metadata;
    std::map<std::string, std::vector<eddsa_commitment>> _preprocessed_data;
};

struct client_info
{
    client_info(uint64_t player_id, const cmp_key_persistency& key_persistency) : id(player_id), platform_service(player_id), service(platform_service, key_persistency, persistency) {}
    uint64_t id;
    asymmetric_eddsa_platform platform_service;
    client_persistency persistency;
    asymmetric_eddsa_cosigner_client service;
};

struct server_info
{
    server_info(uint64_t id, const cmp_key_persistency& key_persistency) : platform_service(id), service(platform_service, key_persistency, persistency) {}
    asymmetric_eddsa_platform platform_service;
    server_persistency persistency;
    asymmetric_eddsa_cosigner_server service;
};

static void ecdsa_preprocess(std::map<uint64_t, std::unique_ptr<server_info>>& servers, client_info& client, const std::string& keyid, uint32_t start, uint32_t count, uint32_t total)
{
    uuid_t uid;
    char request[37] = {0};
    uuid_generate_random(uid);
    uuid_unparse(uid, request);
    std::cout << "request id = " << request << std::endl;

    std::set<uint64_t> players_ids;

    for (auto i = servers.begin(); i != servers.end(); ++i)
        players_ids.insert(i->first);
    players_ids.insert(client.id);

    std::vector<std::array<uint8_t, sizeof(commitments_sha256_t)>> R_commitments;
    REQUIRE_NOTHROW(client.service.start_signature_preprocessing(TENANT_ID, keyid, request, start, count, total, players_ids, R_commitments));

    for (auto i = servers.begin(); i != servers.end(); ++i)
    {
        REQUIRE_NOTHROW(i->second->service.store_presigning_data(keyid, request, start, count, total, players_ids, client.id, R_commitments));
        REQUIRE_THROWS_AS(i->second->service.store_presigning_data(keyid, request, start, count, total, players_ids, client.id, R_commitments), cosigner_exception);
    }
}

static void eddsa_sign(std::map<uint64_t, std::unique_ptr<server_info>>& servers, client_info& client, const std::string& keyid, uint32_t start_index, uint32_t count, const elliptic_curve256_point_t& pubkey, 
    const byte_vector_t& chaincode, const std::vector<std::vector<uint32_t>>& paths, bool use_keccak = false)
{
    uuid_t uid;
    char txid[37] = {0};
    uuid_generate_random(uid);
    uuid_unparse(uid, txid);
    std::cout << "txid id = " << txid << std::endl;

    std::set<uint64_t> players_ids;
    std::set<std::string> players_str;
    for (auto i = servers.begin(); i != servers.end(); ++i)
    {
        players_ids.insert(i->first);
        players_str.insert(std::to_string(i->first));
        i->second->platform_service.set_use_keccak(use_keccak);
    }
    client.platform_service.set_use_keccak(use_keccak);
    players_ids.insert(client.id);
    players_str.insert(std::to_string(client.id));

    REQUIRE(chaincode.size() == sizeof(HDChaincode));
    signing_data data;
    memcpy(data.chaincode, chaincode.data(), sizeof(HDChaincode));
    for (size_t i = 0; i < count; i++)
    {
        signing_block_data block;
        block.data.insert(block.data.begin(), 32, '0');
        block.path = paths[i];
        data.blocks.push_back(block);
    }

    std::map<uint64_t, std::vector<eddsa_commitment>> R_commitments;
    std::map<uint64_t, Rs_and_commitments> Rs_map;
    for (auto i = servers.begin(); i != servers.end(); ++i)
    {
        auto& R_commitment = R_commitments[i->first];
        auto& R = Rs_map[i->first];
        REQUIRE_NOTHROW(i->second->service.eddsa_sign_offline(keyid, txid, data, "", players_str, players_ids, start_index, R_commitment, R));

        std::vector<eddsa_commitment> repeat_commitments;
        Rs_and_commitments repeat_Rs;
        REQUIRE_THROWS_AS(i->second->service.eddsa_sign_offline(keyid, txid, data, "", players_str, players_ids, start_index, repeat_commitments, repeat_Rs), cosigner_exception);

        if (servers.size() == 1)
        {
            REQUIRE(R_commitment.size() == 0);
            REQUIRE(R.Rs.size() == count);
        }
        else
        {
            REQUIRE(R_commitment.size() == count);
            REQUIRE(R.Rs.size() == 0);
        }
    }

    std::map<uint64_t, Rs_and_commitments> server_Rs;
    if (servers.size() == 1)
    {
        server_Rs = std::move(Rs_map);
    }
    else
    {
        std::map<uint64_t, std::vector<elliptic_curve_point>> Rs;
        for (auto i = servers.begin(); i != servers.end(); ++i)
        {
            auto& R = Rs_map[i->first];
            REQUIRE_NOTHROW(i->second->service.decommit_r(txid, R_commitments, R.Rs));
            Rs[i->first] = R.Rs;
            REQUIRE(R.Rs.size() == count);

            std::vector<elliptic_curve_point> repeat_Rs;
            REQUIRE_THROWS_AS(i->second->service.decommit_r(txid, R_commitments, repeat_Rs), cosigner_exception);
        }

        for (auto i = servers.begin(); i != servers.end(); ++i)
        {
            uint64_t send_to_id;
            auto& R = server_Rs[i->first];
            REQUIRE_NOTHROW(i->second->service.broadcast_r(txid, Rs, R, send_to_id));
            REQUIRE(send_to_id == CLIENT_ID);

            uint64_t repeat_send_to_id;
            Rs_and_commitments repeat_R;
            REQUIRE_THROWS_AS(i->second->service.broadcast_r(txid, Rs, repeat_R, repeat_send_to_id), cosigner_exception);
        }
    }

    std::vector<eddsa_signature> partial_sigs;
    REQUIRE_NOTHROW(client.service.eddsa_sign_offline(keyid, txid, data, "", players_str, players_ids, start_index, server_Rs, partial_sigs));

    std::vector<eddsa_signature> repeat_partial_sigs;
    REQUIRE_THROWS_AS(client.service.eddsa_sign_offline(keyid, txid, data, "", players_str, players_ids, start_index, server_Rs, repeat_partial_sigs), cosigner_exception);

    std::set<uint64_t> send_to;
    std::map<uint64_t, std::vector<eddsa_signature>> sigs;
    for (auto i = servers.begin(); i != servers.end(); ++i)
    {
        auto& sig = sigs[i->first];
        bool final_signature;
        REQUIRE_NOTHROW(i->second->service.broadcast_si(txid, CLIENT_ID, MPC_PROTOCOL_VERSION, partial_sigs, sig, send_to, final_signature));
        REQUIRE(final_signature == (servers.size() == 1));

        std::vector<eddsa_signature> repeat_sigs;
        std::set<uint64_t> repeat_send_to;
        bool repeat_final_signature;
        REQUIRE_THROWS_AS(i->second->service.broadcast_si(txid, CLIENT_ID, MPC_PROTOCOL_VERSION, partial_sigs, repeat_sigs, repeat_send_to, repeat_final_signature), cosigner_exception);

        REQUIRE(send_to.size() == servers.size());
        for (auto j = servers.begin(); j != servers.end(); ++j)
        {
            REQUIRE(send_to.find(j->first) != send_to.end());
        }
    }

    std::map<uint64_t, std::vector<eddsa_signature>> final_sigs;
    if (servers.size() == 1)
    {
        final_sigs = std::move(sigs);
    }
    else
    {
        for (auto i = servers.begin(); i != servers.end(); ++i)
        {
            auto& sig = final_sigs[i->first];
            REQUIRE_NOTHROW(i->second->service.get_eddsa_signature(txid, sigs, sig));

            std::vector<eddsa_signature> repeat_sig;
            REQUIRE_THROWS_AS(i->second->service.get_eddsa_signature(txid, sigs, repeat_sig), cosigner_exception);
        }
    }

    std::unique_ptr<elliptic_curve256_algebra_ctx_t, void(*)(elliptic_curve256_algebra_ctx_t*)> algebra(elliptic_curve256_new_ed25519_algebra(), elliptic_curve256_algebra_ctx_free);
    for (size_t i = 0; i < count; i++)
    {
        PubKey derived_key;
        REQUIRE(derive_public_key_generic(algebra.get(), derived_key, pubkey, data.chaincode, paths[i].data(), paths[i].size()) == HD_DERIVE_SUCCESS);
        std::cout << "derived public_key: " << HexStr(derived_key, &derived_key[sizeof(PubKey)]) << std::endl;

        for (auto j = final_sigs.begin(); j != final_sigs.end(); ++j)
        {
            REQUIRE(data.blocks[i].data.size() == sizeof(elliptic_curve256_scalar_t));
            eddsa_signature& sig = j->second[i];
            std::cout << "sig r: " << HexStr(sig.R, &sig.R[sizeof(elliptic_curve256_scalar_t)]) << std::endl;
            std::cout << "sig s: " << HexStr(sig.s, &sig.s[sizeof(elliptic_curve256_scalar_t)]) << std::endl;

            uint8_t raw_sig[sizeof(elliptic_curve256_scalar_t) * 2];
            memcpy(raw_sig, sig.R, sizeof(elliptic_curve256_scalar_t));
            memcpy(&raw_sig[sizeof(elliptic_curve256_scalar_t)], sig.s, sizeof(elliptic_curve256_scalar_t));
            REQUIRE(ed25519_verify((ed25519_algebra_ctx_t*)algebra->ctx, data.blocks[i].data.data(), data.blocks[i].data.size(), raw_sig, derived_key, use_keccak ? 1 : 0));
        }
    }
}

TEST_CASE("asymmetric_eddsa") {
    byte_vector_t chaincode(32, '\0');
    std::vector<uint32_t> path = {44, 0, 0, 0, 0};
    char keyid[37] = {0};
    elliptic_curve256_point_t pubkey;
    players_setup_info players;

    SECTION("2/2") {
        static const uint64_t SERVER_ID = 1;
        uuid_t uid;
        uuid_generate_random(uid);
        uuid_unparse(uid, keyid);
        players[CLIENT_ID];
        players[SERVER_ID];
        create_secret(players, EDDSA_ED25519, keyid, pubkey);

        std::map<uint64_t, std::unique_ptr<server_info>> services;
        services.emplace(SERVER_ID, std::make_unique<server_info>(SERVER_ID, players[SERVER_ID]));
        client_info client(CLIENT_ID, players[CLIENT_ID]);
        ecdsa_preprocess(services, client, keyid, 0, 1000, 1000);  
        eddsa_sign(services, client, keyid, 0, 1, pubkey, chaincode, {path});
        eddsa_sign(services, client, keyid, 1, 1, pubkey, chaincode, {path}, true);
    }

    SECTION("3/3") {
        uuid_t uid;
        uuid_generate_random(uid);
        uuid_unparse(uid, keyid);
        players[CLIENT_ID];
        players[11];
        players[12];
        create_secret(players, EDDSA_ED25519, keyid, pubkey);

        std::map<uint64_t, std::unique_ptr<server_info>> services;
        for (auto i = players.begin(); i != players.end(); ++i)
        {
            if (i->first != CLIENT_ID)
                services.emplace(i->first, std::make_unique<server_info>(i->first, i->second));
        }
        
        client_info client(CLIENT_ID, players[CLIENT_ID]);
        ecdsa_preprocess(services, client, keyid, 0, 1000, 1000);  
        eddsa_sign(services, client, keyid, 0, 1, pubkey, chaincode, {path});
        eddsa_sign(services, client, keyid, 1, 1, pubkey, chaincode, {path}, true);
    }
}
