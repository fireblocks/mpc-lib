#include <iostream>
#include <chrono>
#include <shared_mutex>
#include <tests/catch.hpp>

#include "cosigner/cmp_ecdsa_online_signing_service.h"
#include "cosigner/cosigner_exception.h"
#include "test_common.h"
#include "crypto/elliptic_curve_algebra/elliptic_curve256_algebra.h"
#include "crypto/GFp_curve_algebra/GFp_curve_algebra.h"
#include "cosigner/cmp_key_persistency.h"
#include "cosigner/mpc_globals.h"

#include <string.h>

#include <openssl/rand.h>

#ifdef USE_SECP256K1
#include <secp256k1.h>
#include <secp256k1_recovery.h>
#endif

using namespace fireblocks::common::cosigner;

using Clock = std::conditional<std::chrono::high_resolution_clock::is_steady, std::chrono::high_resolution_clock,
        std::chrono::steady_clock>::type;

static elliptic_curve256_algebra_ctx_t* create_algebra(cosigner_sign_algorithm type)
{
    switch (type)
    {
        case ECDSA_SECP256K1: return elliptic_curve256_new_secp256k1_algebra();
        case ECDSA_SECP256R1: return elliptic_curve256_new_secp256r1_algebra();
        case ECDSA_STARK: return elliptic_curve256_new_stark_algebra();
        default: return NULL;
    }
}


class sign_platform : public platform_service
{
public:
    sign_platform(uint64_t id, bool positive_r) : _id(id), _positive_r(positive_r) {}
private:
    void gen_random(size_t len, uint8_t* random_data) const override
    {
        RAND_bytes(random_data, len);
    }

    uint64_t now_msec() const override { return std::chrono::time_point_cast<std::chrono::milliseconds>(Clock::now()).time_since_epoch().count(); }

    const std::string get_current_tenantid() const override {return TENANT_ID;}
    uint64_t get_id_from_keyid(const std::string& key_id) const override {return _id;}
    void derive_initial_share(const share_derivation_args& derive_from, cosigner_sign_algorithm algorithm, elliptic_curve256_scalar_t* key) const override {assert(0);}
    byte_vector_t encrypt_for_player(uint64_t id, const byte_vector_t& data) const override {assert(0);}
    byte_vector_t decrypt_message(const byte_vector_t& encrypted_data) const override {assert(0);}
    bool backup_key(const std::string& key_id, cosigner_sign_algorithm algorithm, const elliptic_curve256_scalar_t& private_key, const cmp_key_metadata& metadata, const auxiliary_keys& aux) override {return true;}
    void start_signing(const std::string& key_id, const std::string& txid, const signing_data& data, const std::string& metadata_json, const std::set<std::string>& players) override {}
    void fill_signing_info_from_metadata(const std::string& metadata, std::vector<uint32_t>& flags) const override
    {
        for (auto i = flags.begin(); i != flags.end(); ++i)
            *i = _positive_r ? POSITIVE_R : 0;
    }
    bool is_client_id(uint64_t player_id) const override {return false;}

    const uint64_t _id;
    const bool _positive_r;
};

static inline bool is_positive(const elliptic_curve256_scalar_t& n)
{
    return (n[0] & 0x80) == 0;
}

class online_signing_persistency : public cmp_ecdsa_online_signing_service::signing_persistency
{
    void store_cmp_signing_data(const std::string& txid, const cmp_signing_metadata& data) override
    {
        std::unique_lock lock(_mutex);
        if (_metadata.find(txid) != _metadata.end())
            throw cosigner_exception(cosigner_exception::INVALID_TRANSACTION);
        _metadata[txid] = data;
    }

    void load_cmp_signing_data(const std::string& txid, cmp_signing_metadata& data) const override
    {
        std::shared_lock lock(_mutex);
        auto it = _metadata.find(txid);
        if (it == _metadata.end())
            throw cosigner_exception(cosigner_exception::INVALID_TRANSACTION);
        data = it->second;
    }

    void update_cmp_signing_data(const std::string& txid, const cmp_signing_metadata& data) override
    {
        std::unique_lock lock(_mutex);
        auto it = _metadata.find(txid);
        if (it == _metadata.end())
            throw cosigner_exception(cosigner_exception::INVALID_TRANSACTION);
        it->second = data;
    }

    void delete_signing_data(const std::string& txid) override
    {
        std::unique_lock lock(_mutex);
        _metadata.erase(txid);
    }

    mutable std::shared_mutex _mutex;
    std::map<std::string, cmp_signing_metadata> _metadata;
};

struct siging_info
{
    siging_info(uint64_t id, const cmp_key_persistency& persistency, bool positive_r) : platform_service(id, positive_r), signing_service(platform_service, persistency, signing_persistency) {}
    sign_platform platform_service;
    online_signing_persistency signing_persistency;
    cmp_ecdsa_online_signing_service signing_service;
};

static void ecdsa_sign(players_setup_info& players, cosigner_sign_algorithm type, const std::string& keyid, uint32_t count, const elliptic_curve256_point_t& pubkey, 
    const byte_vector_t& chaincode, const std::vector<std::vector<uint32_t>>& paths, bool positive_r = false)
{
    uuid_t uid;
    char txid[37] = {0};
    uuid_generate_random(uid);
    uuid_unparse(uid, txid);
    std::cout << "txid id = " << txid << std::endl;

    std::map<uint64_t, std::unique_ptr<siging_info>> services;
    std::set<uint64_t> players_ids;
    std::set<std::string> players_str;
    for (auto i = players.begin(); i != players.end(); ++i)
    {
        auto info = std::make_unique<siging_info>(i->first, i->second, positive_r);
        services.emplace(i->first, std::move(info));
        players_ids.insert(i->first);
        players_str.insert(std::to_string(i->first));
    }

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

    std::map<uint64_t, std::vector<cmp_mta_request>> mta_requests;
    for (auto i = services.begin(); i != services.end(); ++i)
    {
        auto& request = mta_requests[i->first];
        REQUIRE_NOTHROW(i->second->signing_service.start_signing(keyid, txid, type, data, "", players_str, players_ids, request));

        std::vector<cmp_mta_request> repeat_requests;
        REQUIRE_THROWS_AS(i->second->signing_service.start_signing(keyid, txid, type, data, "", players_str, players_ids, repeat_requests), cosigner_exception);
    }

    std::map<uint64_t, cmp_mta_responses> mta_responses;
    for (auto i = services.begin(); i != services.end(); ++i)
    {
        auto& response = mta_responses[i->first];
        REQUIRE_NOTHROW(i->second->signing_service.mta_response(txid, mta_requests, MPC_CMP_ONLINE_VERSION, response));

        cmp_mta_responses repeat_response;
        REQUIRE_THROWS_AS(i->second->signing_service.mta_response(txid, mta_requests, MPC_CMP_ONLINE_VERSION, repeat_response), cosigner_exception);
    }
    mta_requests.clear();

    std::map<uint64_t, std::vector<cmp_mta_deltas>> deltas;
    for (auto i = services.begin(); i != services.end(); ++i)
    {
        auto& delta = deltas[i->first];
        REQUIRE_NOTHROW(i->second->signing_service.mta_verify(txid, mta_responses, delta));

        cmp_mta_responses repeat_response;
        REQUIRE_THROWS_AS(i->second->signing_service.mta_response(txid, mta_requests, MPC_CMP_ONLINE_VERSION, repeat_response), cosigner_exception);

        std::vector<cmp_mta_deltas> repeat_deltas;
        REQUIRE_THROWS_AS(i->second->signing_service.mta_verify(txid, mta_responses, repeat_deltas), cosigner_exception);
    }
    mta_responses.clear();

    std::map<uint64_t, std::vector<elliptic_curve_scalar>> sis;
    for (auto i = services.begin(); i != services.end(); ++i)
    {
        auto& si = sis[i->first];
        REQUIRE_NOTHROW(i->second->signing_service.get_si(txid, deltas, si));

        std::vector<cmp_mta_deltas> repeat_deltas;
        REQUIRE_THROWS_AS(i->second->signing_service.mta_verify(txid, mta_responses, repeat_deltas), cosigner_exception);

        std::vector<elliptic_curve_scalar> repeat_sis;
        REQUIRE_THROWS_AS(i->second->signing_service.get_si(txid, deltas, repeat_sis), std::out_of_range);
    }
    deltas.clear();

    std::vector<recoverable_signature> sigs;
    for (auto i = services.begin(); i != services.end(); ++i)
    {
        REQUIRE_NOTHROW(i->second->signing_service.get_cmp_signature(txid, sis, sigs));

        std::vector<recoverable_signature> repeat_sigs;
        REQUIRE_THROWS_AS(i->second->signing_service.get_cmp_signature(txid, sis, repeat_sigs), cosigner_exception);
    }
    sis.clear();

    std::unique_ptr<elliptic_curve256_algebra_ctx_t, void(*)(elliptic_curve256_algebra_ctx_t*)> algebra(create_algebra(type), elliptic_curve256_algebra_ctx_free);

    for (size_t i = 0; i < count; i++)
    {
        elliptic_curve256_scalar_t msg;
        REQUIRE(data.blocks[i].data.size() == sizeof(elliptic_curve256_scalar_t));
        memcpy(msg, data.blocks[i].data.data(), sizeof(elliptic_curve256_scalar_t));
        std::cout << "sig r: " << HexStr(sigs[i].r, &sigs[i].r[sizeof(elliptic_curve256_scalar_t)]) << std::endl;
        std::cout << "sig s: " << HexStr(sigs[i].s, &sigs[i].s[sizeof(elliptic_curve256_scalar_t)]) << std::endl;
        
        PubKey derived_key;
        REQUIRE(derive_public_key_generic(algebra.get(), derived_key, pubkey, data.chaincode, paths[i].data(), paths[i].size()) == HD_DERIVE_SUCCESS);
        std::cout << "derived public_key: " << HexStr(derived_key, &derived_key[sizeof(PubKey)]) << std::endl;

        REQUIRE(GFp_curve_algebra_verify_signature((GFp_curve_algebra_ctx_t*)algebra->ctx, &derived_key, &msg, &sigs[i].r, &sigs[i].s) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        if (positive_r)
        {
            REQUIRE(is_positive(sigs[i].r));
        }

#ifdef USE_SECP256K1
        std::unique_ptr<secp256k1_context, void(*)(secp256k1_context*)> secp_ctx(secp256k1_context_create(SECP256K1_CONTEXT_VERIFY), secp256k1_context_destroy);
        if (type == ECDSA_SECP256K1)
        {
            uint8_t raw_sig[sizeof(elliptic_curve256_scalar_t) * 2];
            secp256k1_ecdsa_signature sig;
            secp256k1_pubkey public_key;
            memcpy(raw_sig, sigs[i].r, sizeof(elliptic_curve256_scalar_t));
            memcpy(&raw_sig[sizeof(elliptic_curve256_scalar_t)], sigs[i].s, sizeof(elliptic_curve256_scalar_t));
            REQUIRE(secp256k1_ec_pubkey_parse(secp_ctx.get(), &public_key, derived_key, sizeof(PubKey)));
            REQUIRE(secp256k1_ecdsa_signature_parse_compact(secp_ctx.get(), &sig, raw_sig));
            REQUIRE(secp256k1_ecdsa_verify(secp_ctx.get(), &sig, msg, &public_key));
            secp256k1_ecdsa_recoverable_signature recoverable_sig;
            secp256k1_pubkey recoveredPubKey = {0};
            int retVal = secp256k1_ecdsa_recoverable_signature_parse_compact(secp_ctx.get(), &recoverable_sig, raw_sig, sigs[i].v);
            REQUIRE(secp256k1_ecdsa_recover(secp_ctx.get(), &recoveredPubKey, &recoverable_sig, msg));
            REQUIRE(memcmp(recoveredPubKey.data, public_key.data, sizeof(secp256k1_pubkey)) == 0);
        }
#endif
    }
}

struct sign_thread_data
{
    players_setup_info& players;
    const char* keyid;
    elliptic_curve256_point_t& pubkey;
};

static void* sign_thread(void* arg)
{
    sign_thread_data* param = (sign_thread_data*)arg;
    byte_vector_t chaincode(32, '\0');
    std::vector<uint32_t> path = {44, 0, 0, 0, 0};

    ecdsa_sign(param->players, ECDSA_SECP256K1, param->keyid, 1, param->pubkey, chaincode, {path});
    return NULL;
}

static char keyid[37] = {0};
static elliptic_curve256_point_t pubkey;
static players_setup_info players;

TEST_CASE("cmp_ecdsa") {
    byte_vector_t chaincode(32, '\0');
    std::vector<uint32_t> path = {44, 0, 0, 0, 0};

    SECTION("secp256k1") {  
        SECTION("create_secret") {
            uuid_t uid;
            uuid_generate_random(uid);
            uuid_unparse(uid, keyid);
            players.clear();
            players[1];
            players[2];
            create_secret(players, ECDSA_SECP256K1, keyid, pubkey);
        }

        SECTION("sign") {
            auto before = Clock::now();
            ecdsa_sign(players, ECDSA_SECP256K1, keyid, 1, pubkey, chaincode, {path});
            auto after = Clock::now();
            std::cout << "ECDSA signing took: " << std::chrono::duration_cast<std::chrono::milliseconds>(after - before).count() << " ms" << std::endl;
        }

        SECTION("add user") {  
            uuid_t uid;
            char new_keyid[37] = {0};
            uuid_generate_random(uid);
            uuid_unparse(uid, new_keyid);
            players_setup_info new_players;
            new_players[11];
            new_players[12];
            new_players[13];
            add_user(players, new_players, ECDSA_SECP256K1, keyid, new_keyid, pubkey);
            ecdsa_sign(new_players, ECDSA_SECP256K1, new_keyid, 1, pubkey, chaincode, {path});
        }

        SECTION("sign multiple") {
            const size_t COUNT = 4;
            std::vector<uint32_t> derivation_path = {44, 0, 0, 0, 0};
            std::vector<std::vector<uint32_t>> derivation_paths;

            for (size_t i = 0; i < COUNT; i++)
            {
                derivation_paths.push_back(derivation_path);
                ++derivation_path[2];
            }
            ecdsa_sign(players, ECDSA_SECP256K1, keyid, COUNT, pubkey, chaincode, derivation_paths);
        }

        SECTION("MT") {
            const size_t THREAD_COUNT = 16;
            pthread_t threads[THREAD_COUNT] = {0};

            sign_thread_data param = {players, keyid, pubkey};
            
            auto start = Clock::now();
            for (auto i = 0; i < THREAD_COUNT; i++)
                pthread_create(threads + i, NULL, sign_thread, &param);

            for (auto i = 0; i < THREAD_COUNT; i++)
                pthread_join(threads[i], NULL);
            auto finish = Clock::now();
            std::cout << "Done in " << std::chrono::duration_cast<std::chrono::milliseconds>(finish - start).count() << " ms" << std::endl;
        }

        SECTION("sign positive R") {
            // run 4 times as R has 50% chance of being negative
            for (size_t i = 0; i < 8; ++i)
                ecdsa_sign(players, ECDSA_SECP256K1, keyid, 1, pubkey, chaincode, {path}, true);;
        }

    }

    SECTION("secp256r1") {  
        uuid_t uid;
        char keyid[37] = {0};
        elliptic_curve256_point_t pubkey;
        players_setup_info players;
        uuid_generate_random(uid);
        uuid_unparse(uid, keyid);
        players[1];
        players[2];
        create_secret(players, ECDSA_SECP256R1, keyid, pubkey);
        ecdsa_sign(players, ECDSA_SECP256R1, keyid, 1, pubkey, chaincode, {path});
        char new_keyid[37] = {0};
        uuid_generate_random(uid);
        uuid_unparse(uid, new_keyid);
        players_setup_info new_players;
        new_players[11];
        new_players[12];
        new_players[13];
        add_user(players, new_players, ECDSA_SECP256R1, keyid, new_keyid, pubkey);
        ecdsa_sign(new_players, ECDSA_SECP256R1, new_keyid, 1, pubkey, chaincode, {path});
    }

    SECTION("stark") {  
        uuid_t uid;
        char keyid[37] = {0};
        elliptic_curve256_point_t pubkey;
        players_setup_info players;
        uuid_generate_random(uid);
        uuid_unparse(uid, keyid);
        players[1];
        players[2];
        create_secret(players, ECDSA_STARK, keyid, pubkey);
        ecdsa_sign(players, ECDSA_STARK, keyid, 1, pubkey, chaincode, {path});
        char new_keyid[37] = {0};
        uuid_generate_random(uid);
        uuid_unparse(uid, new_keyid);
        players_setup_info new_players;
        new_players[11];
        new_players[12];
        new_players[13];
        add_user(players, new_players, ECDSA_STARK, keyid, new_keyid, pubkey);
        ecdsa_sign(new_players, ECDSA_STARK, new_keyid, 1, pubkey, chaincode, {path});
    }
}
