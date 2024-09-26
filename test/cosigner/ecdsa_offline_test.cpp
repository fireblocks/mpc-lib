#include <chrono>
#include <iostream>
#include <mutex>
#include <shared_mutex>
#include <tests/catch.hpp>

#include "cosigner/cmp_ecdsa_offline_signing_service.h"
#include "cosigner/cosigner_exception.h"
#include "cosigner/cmp_signature_preprocessed_data.h"
#include "cosigner/cmp_offline_refresh_service.h"
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
    sign_platform(uint64_t id) : _id(id), _positive_r(false) {}
    void set_positive_r(bool positive_r) {_positive_r = positive_r;}
private:
    void gen_random(size_t len, uint8_t* random_data) const override
    {
        RAND_bytes(random_data, len);
    }

    uint64_t now_msec() const override { return std::chrono::time_point_cast<std::chrono::milliseconds>(Clock::now()).time_since_epoch().count(); }

    const std::string get_current_tenantid() const override {return TENANT_ID;}
    uint64_t get_id_from_keyid(const std::string& key_id) const override {return _id;}
    void derive_initial_share(const share_derivation_args& derive_from, cosigner_sign_algorithm algorithm, elliptic_curve256_scalar_t* key) const override {assert(0);}
    byte_vector_t encrypt_for_player(uint64_t id, const byte_vector_t& data) const override {return data;}
    byte_vector_t decrypt_message(const byte_vector_t& encrypted_data) const override {return encrypted_data;}
    bool backup_key(const std::string& key_id, cosigner_sign_algorithm algorithm, const elliptic_curve256_scalar_t& private_key, const cmp_key_metadata& metadata, const auxiliary_keys& aux) override {return true;}
    void start_signing(const std::string& key_id, const std::string& txid, const signing_data& data, const std::string& metadata_json, const std::set<std::string>& players) override {}
    void fill_signing_info_from_metadata(const std::string& metadata, std::vector<uint32_t>& flags) const override 
    {
        for (auto i = flags.begin(); i != flags.end(); ++i)
            *i = _positive_r ? POSITIVE_R : 0;
    }
    bool is_client_id(uint64_t player_id) const override {return false;}

    const uint64_t _id;
    bool _positive_r;
};

static inline bool is_positive(const elliptic_curve256_scalar_t& n)
{
    return (n[0] & 0x80) == 0;
}

static uint8_t ZERO[sizeof(cmp_signature_preprocessed_data)] = {0};
class key_refresh_persistency;

class preprocessing_persistency : public cmp_ecdsa_offline_signing_service::preprocessing_persistency
{
    void store_preprocessing_metadata(const std::string& request_id, const preprocessing_metadata& data, bool override) override
    {
        std::unique_lock lock(_mutex);
        if (!override && _metadata.find(request_id) != _metadata.end())
            throw cosigner_exception(cosigner_exception::INVALID_TRANSACTION);
        _metadata[request_id] = data;
    }

    void load_preprocessing_metadata(const std::string& request_id, preprocessing_metadata& data) const override
    {
        std::shared_lock lock(_mutex);
        auto it = _metadata.find(request_id);
        if (it == _metadata.end())
            throw cosigner_exception(cosigner_exception::INVALID_TRANSACTION);
        data = it->second;
    }

    void store_preprocessing_data(const std::string& request_id, uint64_t index, const ecdsa_signing_data& data) override
    {
        std::unique_lock lock(_mutex);
        _signing_data[request_id][index] = data;
    }

    void load_preprocessing_data(const std::string& request_id, uint64_t index, ecdsa_signing_data& data) const override
    {
        std::shared_lock lock(_mutex);
        auto it = _signing_data.find(request_id);
        if (it == _signing_data.end())
            throw cosigner_exception(cosigner_exception::INVALID_TRANSACTION);
        auto index_it = it->second.find(index);
        if (index_it == it->second.end())
            throw cosigner_exception(cosigner_exception::INVALID_TRANSACTION);
        data = index_it->second;
    }

    void delete_preprocessing_data(const std::string& request_id) override
    {
        std::unique_lock lock(_mutex);
        _metadata.erase(request_id);
        _signing_data.erase(request_id);
    }

    void create_preprocessed_data(const std::string& key_id, uint64_t size) override
    {
        std::unique_lock lock(_mutex);
        auto it = _preprocessed_data.find(key_id);
        if (it != _preprocessed_data.end())
        {
            if (it->second.size() != size)
                throw cosigner_exception(cosigner_exception::INVALID_TRANSACTION);
        }
        else
            _preprocessed_data.emplace(key_id, std::move(std::vector<cmp_signature_preprocessed_data>(size)));
    }

    void store_preprocessed_data(const std::string& key_id, uint64_t index, const cmp_signature_preprocessed_data& data) override
    {
        std::unique_lock lock(_mutex);
        auto it = _preprocessed_data.find(key_id);
        if (it == _preprocessed_data.end())
            throw cosigner_exception(cosigner_exception::INVALID_TRANSACTION);
        if (index >= it->second.size())
            throw cosigner_exception(cosigner_exception::INVALID_PRESIGNING_INDEX);
        it->second[index] = data;
    }

    void load_preprocessed_data(const std::string& key_id, uint64_t index, cmp_signature_preprocessed_data& data) override
    {
        std::unique_lock lock(_mutex);
        auto it = _preprocessed_data.find(key_id);
        if (it == _preprocessed_data.end())
            throw cosigner_exception(cosigner_exception::INVALID_TRANSACTION);
        if (index >= it->second.size() || memcmp(it->second[index].k.data, ZERO, sizeof(cmp_signature_preprocessed_data)) == 0)
            throw cosigner_exception(cosigner_exception::INVALID_PRESIGNING_INDEX);
        data = it->second[index];
        memset(it->second[index].k.data, 0, sizeof(cmp_signature_preprocessed_data));
    }

    void delete_preprocessed_data(const std::string& key_id) override
    {
        std::unique_lock lock(_mutex);
        _preprocessed_data.erase(key_id);
    }

    mutable std::shared_mutex _mutex;
    std::map<std::string, preprocessing_metadata> _metadata;
    std::map<std::string, std::map<uint64_t, ecdsa_signing_data>> _signing_data;
    std::map<std::string, std::vector<cmp_signature_preprocessed_data>> _preprocessed_data;
    friend class key_refresh_persistency;
};

class key_refresh_persistency : public cmp_offline_refresh_service::offline_refresh_key_persistency
{
public:
    key_refresh_persistency(preprocessing_persistency& preproc_persistency, cmp_setup_service::setup_key_persistency& setup_persistency) : 
        _preprocessing_persistency(preproc_persistency), _setup_persistency(setup_persistency) {}
private:
    void load_refresh_key_seeds(const std::string& request_id, std::map<uint64_t, byte_vector_t>& player_id_to_seed) const override
    {
        std::lock_guard<std::mutex> lock(_mutex);
        auto it = _seeds.find(request_id);
        if (it == _seeds.end())
            throw cosigner_exception(cosigner_exception::INVALID_TRANSACTION);
        player_id_to_seed = it->second;
    }

    void store_refresh_key_seeds(const std::string& request_id, const std::map<uint64_t, byte_vector_t>& player_id_to_seed) override
    {
        std::lock_guard<std::mutex> lock(_mutex);
        if (_seeds.find(request_id) != _seeds.end())
            throw cosigner_exception(cosigner_exception::INVALID_TRANSACTION);
        _seeds[request_id] = player_id_to_seed;
    }

    void transform_preprocessed_data_and_store_temporary(const std::string& key_id, const std::string& request_id, const cmp_offline_refresh_service::preprocessed_data_handler &fn) override
    {
        std::unique_lock lock(_preprocessing_persistency._mutex);
        auto it = _preprocessing_persistency._preprocessed_data.find(key_id);
        if (it == _preprocessing_persistency._preprocessed_data.end())
            throw cosigner_exception(cosigner_exception::INVALID_TRANSACTION);
        const auto& preprocessed_data = it->second;
        it = _temp_preprocessed_data.find(key_id);
        if (it != _temp_preprocessed_data.end())
            throw cosigner_exception(cosigner_exception::INVALID_TRANSACTION);

        std::vector<cmp_signature_preprocessed_data> temp(preprocessed_data);
        for (size_t i = 0; i < temp.size(); i++)
        {
            if (memcmp(temp[i].k.data, ZERO, sizeof(cmp_signature_preprocessed_data)) != 0)
            {
                fn(i, temp[i]);
            }
        }
        std::lock_guard<std::mutex> lg(_mutex);
        _temp_preprocessed_data[key_id] = temp;
    }

    void commit(const std::string& key_id, const std::string& request_id) override
    {
        std::unique_lock lock(_preprocessing_persistency._mutex);
        std::lock_guard<std::mutex> lg(_mutex);
        auto it = _temp_keys.find(request_id);
        if (it == _temp_keys.end())
            throw cosigner_exception(cosigner_exception::BAD_KEY);
        _preprocessing_persistency._preprocessed_data[key_id] = _temp_preprocessed_data[key_id];
        _temp_preprocessed_data.erase(key_id);
        _setup_persistency.store_key(key_id, it->second.second, it->second.first);
        _temp_keys.erase(request_id);
    }

    void delete_refresh_key_seeds(const std::string& request_id) override
    {
        std::lock_guard<std::mutex> lock(_mutex);
        _temp_preprocessed_data.erase(request_id);
    }

    void delete_temporary_key(const std::string& key_id) override
    {
        std::lock_guard<std::mutex> lock(_mutex);
        _temp_keys.erase(key_id);
    }

    void store_temporary_key(const std::string& key_id, cosigner_sign_algorithm algorithm, const elliptic_curve_scalar& private_key) override
    {
        std::lock_guard<std::mutex> lock(_mutex);
        if (_temp_keys.find(key_id) != _temp_keys.end())
            throw cosigner_exception(cosigner_exception::BAD_KEY);
        auto& val = _temp_keys[key_id];
        memcpy(val.first, private_key.data, sizeof(elliptic_curve256_scalar_t));
        val.second = algorithm;
    }

    mutable std::mutex _mutex;
    preprocessing_persistency& _preprocessing_persistency;
    cmp_setup_service::setup_key_persistency& _setup_persistency;
    std::map<std::string, std::map<uint64_t, byte_vector_t>> _seeds;
    std::map<std::string, std::vector<cmp_signature_preprocessed_data>> _temp_preprocessed_data;
    std::map<std::string, std::pair<elliptic_curve256_scalar_t, cosigner_sign_algorithm>> _temp_keys;
};

struct offline_siging_info
{
    offline_siging_info(uint64_t id, const cmp_key_persistency& key_persistency) : platform_service(id), signing_service(platform_service, key_persistency, persistency) {}
    sign_platform platform_service;
    preprocessing_persistency persistency;
    cmp_ecdsa_offline_signing_service signing_service;
};

static void ecdsa_preprocess(std::map<uint64_t, std::unique_ptr<offline_siging_info>>& services, const std::string& keyid, uint32_t start, uint32_t count, uint32_t total)
{
    uuid_t uid;
    char request[37] = {0};
    uuid_generate_random(uid);
    uuid_unparse(uid, request);
    std::cout << "request id = " << request << std::endl;

    std::set<uint64_t> players_ids;
    for (auto i = services.begin(); i != services.end(); ++i)
        players_ids.insert(i->first);

    std::map<uint64_t, std::vector<cmp_mta_request>> mta_requests;
    for (auto i = services.begin(); i != services.end(); ++i)
    {
        auto& mta_request = mta_requests[i->first];
        REQUIRE_NOTHROW(i->second->signing_service.start_ecdsa_signature_preprocessing(TENANT_ID, keyid, request, start, count, total, players_ids, mta_request));

        std::vector<cmp_mta_request> repeat_mta_requests;
        REQUIRE_THROWS_AS(i->second->signing_service.start_ecdsa_signature_preprocessing(TENANT_ID, keyid, request, start, count, total, players_ids, repeat_mta_requests), cosigner_exception);
    }

    std::map<uint64_t, cmp_mta_responses> mta_responses;
    for (auto i = services.begin(); i != services.end(); ++i)
    {
        auto& response = mta_responses[i->first];
        REQUIRE_NOTHROW(i->second->signing_service.offline_mta_response(request, mta_requests, response));

        cmp_mta_responses repeat_response;
        REQUIRE_THROWS_AS(i->second->signing_service.offline_mta_response(request, mta_requests, repeat_response), cosigner_exception);
    }
    mta_requests.clear();

    std::map<uint64_t, std::vector<cmp_mta_deltas>> deltas;
    for (auto i = services.begin(); i != services.end(); ++i)
    {
        auto& delta = deltas[i->first];
        REQUIRE_NOTHROW(i->second->signing_service.offline_mta_verify(request, mta_responses, delta));

        std::vector<cmp_mta_deltas> repeat_deltas;
        REQUIRE_THROWS_AS(i->second->signing_service.offline_mta_verify(request, mta_responses, repeat_deltas), cosigner_exception);
    }
    mta_responses.clear();

    std::map<uint64_t, std::vector<elliptic_curve_scalar>> sis;
    for (auto i = services.begin(); i != services.end(); ++i)
    {
        auto& si = sis[i->first];
        std::string key_id;
        REQUIRE_NOTHROW(i->second->signing_service.store_presigning_data(request, deltas, key_id));
        REQUIRE(key_id == keyid);

        std::string repeat_key_id;
        REQUIRE_THROWS_AS(i->second->signing_service.store_presigning_data(request, deltas, repeat_key_id), cosigner_exception);
    }
}

static void ecdsa_sign(std::map<uint64_t, std::unique_ptr<offline_siging_info>>& services, cosigner_sign_algorithm type, const std::string& keyid, uint32_t start_index, uint32_t count, const elliptic_curve256_point_t& pubkey, 
    const byte_vector_t& chaincode, const std::vector<std::vector<uint32_t>>& paths, bool positive_r = false)
{
    uuid_t uid;
    char txid[37] = {0};
    uuid_generate_random(uid);
    uuid_unparse(uid, txid);
    std::cout << "txid id = " << txid << std::endl;

    std::set<uint64_t> players_ids;
    std::set<std::string> players_str;
    for (auto i = services.begin(); i != services.end(); ++i)
    {
        players_ids.insert(i->first);
        players_str.insert(std::to_string(i->first));
        i->second->platform_service.set_positive_r(positive_r);
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

    std::map<uint64_t, std::vector<recoverable_signature>> partial_sigs;
    for (auto i = services.begin(); i != services.end(); ++i)
    {
        auto& sigs = partial_sigs[i->first];
        std::string key_id;
        REQUIRE_NOTHROW(i->second->signing_service.ecdsa_sign(keyid, txid, data, "", players_str, players_ids, start_index, sigs));

        std::vector<recoverable_signature> repeat_sigs;
        REQUIRE_THROWS_AS(i->second->signing_service.ecdsa_sign(keyid, txid, data, "", players_str, players_ids, start_index, repeat_sigs), cosigner_exception);
    }

    std::vector<recoverable_signature> sigs;
    for (auto i = services.begin(); i != services.end(); ++i)
    {
        REQUIRE_NOTHROW(i->second->signing_service.ecdsa_offline_signature(keyid, txid, type, partial_sigs, sigs));
    }

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

struct key_refresh_info
{
    key_refresh_info(uint64_t id, cmp_setup_service::setup_key_persistency& persistency, preprocessing_persistency& preproc_persistency) : 
        platform_service(id), refresh_persistency(preproc_persistency, persistency), service(platform_service, persistency, refresh_persistency) {}
    sign_platform platform_service;
    key_refresh_persistency refresh_persistency;
    cmp_offline_refresh_service service;
};

static void key_refresh(std::map<uint64_t, std::unique_ptr<key_refresh_info>>& services, const std::string& keyid, const elliptic_curve256_point_t& pubkey)
{
    uuid_t uid;
    char request[37] = {0};
    uuid_generate_random(uid);
    uuid_unparse(uid, request);
    std::cout << "request id = " << request << std::endl;

    std::set<uint64_t> players_ids;
    for (auto i = services.begin(); i != services.end(); ++i)
        players_ids.insert(i->first);

    std::map<uint64_t, std::map<uint64_t, byte_vector_t>> encrypted_seeds;
    for (auto i = services.begin(); i != services.end(); ++i)
    {
        auto& encrypted_seed = encrypted_seeds[i->first];
        REQUIRE_NOTHROW(i->second->service.refresh_key_request(TENANT_ID, keyid, request, players_ids, encrypted_seed));
    }

    std::string public_key;
    for (auto i = services.begin(); i != services.end(); ++i)
    {
        REQUIRE_NOTHROW(i->second->service.refresh_key(keyid, request, encrypted_seeds, public_key));
        REQUIRE(memcmp(pubkey, public_key.data(), public_key.size()) == 0);
    }
    encrypted_seeds.clear();

    for (auto i = services.begin(); i != services.end(); ++i)
    {
        REQUIRE_NOTHROW(i->second->service.refresh_key_fast_ack(TENANT_ID, keyid, request));
    }
}

const uint32_t BLOCK_SIZE = 10;
struct preprocess_thread_data
{
    std::map<uint64_t, std::unique_ptr<offline_siging_info>>* services;
    const char* keyid;
    uint32_t index;
    uint32_t total_count;
};

static void* preprocess_thread(void* arg)
{
    preprocess_thread_data* param = (preprocess_thread_data*)arg;
    ecdsa_preprocess(*param->services, param->keyid, param->index * BLOCK_SIZE, BLOCK_SIZE, param->total_count);
    return NULL;
}


TEST_CASE("cmp_offline_ecdsa") {
    byte_vector_t chaincode(32, '\0');
    std::vector<uint32_t> path = {44, 0, 0, 0, 0};
    char keyid[37] = {0};
    elliptic_curve256_point_t pubkey;
    players_setup_info players;

    SECTION("secp256k1") {  
        uuid_t uid;
        uuid_generate_random(uid);
        uuid_unparse(uid, keyid);
        players.clear();
        players[1];
        players[2];
        create_secret(players, ECDSA_SECP256K1, keyid, pubkey);

        std::map<uint64_t, std::unique_ptr<offline_siging_info>> services;
        for (auto i = players.begin(); i != players.end(); ++i)
        {
            auto info = std::make_unique<offline_siging_info>(i->first, i->second);
            services.emplace(i->first, std::move(info));
        }
    
        auto before = Clock::now();
        ecdsa_preprocess(services, keyid, 0, BLOCK_SIZE, BLOCK_SIZE);
        auto after = Clock::now();
        std::cout << "ECDSA preprocessing took: " << std::chrono::duration_cast<std::chrono::milliseconds>(after - before).count() << " ms" << std::endl;
    
        ecdsa_sign(services, ECDSA_SECP256K1, keyid, 0, 1, pubkey, chaincode, {path});


        char txid[37] = {0};
        uuid_generate_random(uid);
        uuid_unparse(uid, txid);
        std::set<uint64_t> players_ids;
        std::set<std::string> players_str;
        for (auto i = services.begin(); i != services.end(); ++i)
        {
            players_ids.insert(i->first);
            players_str.insert(std::to_string(i->first));
        }
        signing_data data;
        memcpy(data.chaincode, chaincode.data(), sizeof(HDChaincode));
        signing_block_data block;
        block.data.insert(block.data.begin(), 32, '0');
        block.path = path;
        data.blocks.push_back(block);
        std::vector<recoverable_signature> sigs;
        REQUIRE_THROWS_MATCHES(services.begin()->second->signing_service.ecdsa_sign(keyid, txid, data, "", players_str, players_ids, 0, sigs), cosigner_exception, 
            Catch::Matchers::Predicate<cosigner_exception>([](const cosigner_exception& e) {return e.error_code() == cosigner_exception::INVALID_PRESIGNING_INDEX;}));
        
        // run 4 times as R has 50% chance of being negative
        for (size_t i = 0; i < 4; ++i)
            ecdsa_sign(services, ECDSA_SECP256K1, keyid, i + 1, 1, pubkey, chaincode, {path}, true);

        const size_t COUNT = 4;
        std::vector<uint32_t> derivation_path = {44, 0, 0, 0, 0};
        std::vector<std::vector<uint32_t>> derivation_paths;
        for (size_t i = 0; i < COUNT; i++)
        {
            derivation_paths.push_back(derivation_path);
            ++derivation_path[2];
        }
        ecdsa_sign(services, ECDSA_SECP256K1, keyid, 5, COUNT, pubkey, chaincode, derivation_paths);

        std::map<uint64_t, std::unique_ptr<key_refresh_info>> refresh_info;
        for (auto i = players.begin(); i != players.end(); ++i)
        {
            auto info = std::make_unique<key_refresh_info>(i->first, i->second, services.at(i->first)->persistency);
            refresh_info.emplace(i->first, std::move(info));
        }
        key_refresh(refresh_info, keyid, pubkey);
        ecdsa_sign(services, ECDSA_SECP256K1, keyid, 9, 1, pubkey, chaincode, derivation_paths);
    }

    SECTION("MT") {  
        uuid_t uid;
        uuid_generate_random(uid);
        uuid_unparse(uid, keyid);
        players.clear();
        players[1];
        players[2];
        create_secret(players, ECDSA_SECP256K1, keyid, pubkey);

        std::map<uint64_t, std::unique_ptr<offline_siging_info>> services;
        for (auto i = players.begin(); i != players.end(); ++i)
        {
            auto info = std::make_unique<offline_siging_info>(i->first, i->second);
            services.emplace(i->first, std::move(info));
        }
    
        const size_t THREAD_COUNT = 8;
        pthread_t threads[THREAD_COUNT] = {0};
        preprocess_thread_data param[THREAD_COUNT];
        auto before = Clock::now();
        for (uint32_t i = 0; i < THREAD_COUNT; i++)
        {
            param[i].services = &services;
            param[i].keyid = keyid;
            param[i].index = i;
            param[i].total_count = THREAD_COUNT * BLOCK_SIZE;
            pthread_create(threads + i, NULL, preprocess_thread, &param[i]);
        }

        for (auto i = 0; i < THREAD_COUNT; i++)
            pthread_join(threads[i], NULL);

        auto after = Clock::now();
        std::cout << "ECDSA preprocessing took: " << std::chrono::duration_cast<std::chrono::milliseconds>(after - before).count() << " ms" << std::endl;
    
        std::vector<uint32_t> derivation_path = {44, 0, 0, 0, 0};
        std::vector<std::vector<uint32_t>> derivation_paths;
        for (size_t i = 0; i < 4; i++)
        {
            derivation_paths.push_back(derivation_path);
            ++derivation_path[2];
        }
        ecdsa_sign(services, ECDSA_SECP256K1, keyid, 0, derivation_paths.size(), pubkey, chaincode, derivation_paths);
    }

    SECTION("secp256r1") {
        uuid_t uid;
        uuid_generate_random(uid);
        uuid_unparse(uid, keyid);
        players.clear();
        players[11];
        players[12];
        create_secret(players, ECDSA_SECP256R1, keyid, pubkey);

        std::map<uint64_t, std::unique_ptr<offline_siging_info>> services;
        for (auto i = players.begin(); i != players.end(); ++i)
        {
            auto info = std::make_unique<offline_siging_info>(i->first, i->second);
            services.emplace(i->first, std::move(info));
        }
    
        ecdsa_preprocess(services, keyid, 0, BLOCK_SIZE, BLOCK_SIZE);
        ecdsa_sign(services, ECDSA_SECP256R1, keyid, 0, 1, pubkey, chaincode, {path});
        
        char new_keyid[37] = {0};
        uuid_generate_random(uid);
        uuid_unparse(uid, new_keyid);
        players_setup_info new_players;
        new_players[21];
        new_players[22];
        new_players[23];
        add_user(players, new_players, ECDSA_SECP256R1, keyid, new_keyid, pubkey);
        std::map<uint64_t, std::unique_ptr<offline_siging_info>> new_services;
        for (auto i = new_players.begin(); i != new_players.end(); ++i)
        {
            auto info = std::make_unique<offline_siging_info>(i->first, i->second);
            new_services.emplace(i->first, std::move(info));
        }
        ecdsa_preprocess(new_services, new_keyid, 0, BLOCK_SIZE, BLOCK_SIZE);
        ecdsa_sign(new_services, ECDSA_SECP256R1, new_keyid, 0, 1, pubkey, chaincode, {path});
    }

    SECTION("stark") {
        uuid_t uid;
        uuid_generate_random(uid);
        uuid_unparse(uid, keyid);
        players.clear();
        players[21];
        players[22];
        create_secret(players, ECDSA_STARK, keyid, pubkey);

        std::map<uint64_t, std::unique_ptr<offline_siging_info>> services;
        for (auto i = players.begin(); i != players.end(); ++i)
        {
            auto info = std::make_unique<offline_siging_info>(i->first, i->second);
            services.emplace(i->first, std::move(info));
        }
    
        ecdsa_preprocess(services, keyid, 0, BLOCK_SIZE, BLOCK_SIZE);
        ecdsa_sign(services, ECDSA_STARK, keyid, 0, 1, pubkey, chaincode, {path});
    }
}
