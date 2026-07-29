#include <iostream>
#include <chrono>
#include <shared_mutex>
#include <tests/catch.hpp>

#include "cosigner/eddsa_online_signing_service.h"
#include "cosigner/cosigner_exception.h"
#include "test_common.h"
#include "crypto/elliptic_curve_algebra/elliptic_curve256_algebra.h"
#include "crypto/GFp_curve_algebra/GFp_curve_algebra.h"
#include "cosigner/cmp_key_persistency.h"
#include "cosigner/mpc_globals.h"

#include <string.h>

#include <openssl/rand.h>

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


class eddsa_sign_platform : public platform_service
{
public:
    eddsa_sign_platform(uint64_t id, bool use_keccak) : _id(id), _use_keccak(use_keccak) {}
private:
    void gen_random(size_t len, uint8_t* random_data) const override
    {
        RAND_bytes(random_data, len);
    }

    uint64_t now_msec() const override { return std::chrono::time_point_cast<std::chrono::milliseconds>(Clock::now()).time_since_epoch().count(); }

    const std::string get_current_tenantid() const override {return TENANT_ID;}
    uint64_t get_id_from_keyid(const std::string& key_id) const override {return _id;}
    void derive_initial_share(const share_derivation_args& derive_from, cosigner_sign_algorithm algorithm, elliptic_curve256_scalar_t* key) const override {assert(0);}
    byte_vector_t encrypt_for_player(const uint64_t id, const byte_vector_t& data, const std::optional<std::string>& verify_modulus = std::nullopt) const override {return data;}
    byte_vector_t decrypt_message(const byte_vector_t& encrypted_data) const override {return encrypted_data;}
    bool backup_key(const std::string& key_id, cosigner_sign_algorithm algorithm, const elliptic_curve256_scalar_t& private_key, const cmp_key_metadata& metadata, const auxiliary_keys& aux) override {return true;}
    void on_start_signing(const std::string& key_id, const std::string& txid, const signing_data& data, const std::string& metadata_json, const std::set<std::string>& players, const signing_type signature_type) override {}
    void fill_signing_info_from_metadata(const std::string& metadata, std::vector<uint32_t>& flags) const override
    {
        for (auto i = flags.begin(); i != flags.end(); ++i)
            *i = _use_keccak ? EDDSA_KECCAK : 0;
    }
    void fill_eddsa_signing_info_from_metadata(std::vector<eddsa_signature_data>& info, const std::string& metadata) const override
    {
        for (auto& sig : info)
            sig.flags = _use_keccak ? EDDSA_KECCAK : 0;
    }
    
    void fill_bam_signing_info_from_metadata(std::vector<bam_signing_properties>& info, const std::string& metadata) const override
    {
        // Stub for tests
    }
    void fill_frost_signing_info_from_metadata(std::vector<frost_signing_properties>& info, const std::string& metadata) const override
    {
        // Stub for tests
    }
    bool is_client_id(uint64_t player_id) const override {return false;}
    void mark_key_setup_in_progress(const std::string& key_id) const override {}
    void clear_key_setup_in_progress(const std::string& key_id) const override {}
    void prepare_for_signing(const std::string& key_id, const std::string tx_id) override {}

    const uint64_t _id;
    const bool _use_keccak;
};

class eddsa_signing_persistency : public eddsa_online_signing_service::signing_persistency
{
    void store_eddsa_signing_data(const std::string& txid, const std::shared_ptr<eddsa_signing_metadata>& data) override
    {
        std::unique_lock lock(_mutex);
        if (_metadata.find(txid) != _metadata.end())
            throw cosigner_exception(cosigner_exception::INVALID_TRANSACTION);
        _metadata[txid] = *data;
    }

    std::shared_ptr<eddsa_signing_metadata> load_eddsa_signing_data(const std::string& txid) const override
    {
        std::shared_lock lock(_mutex);
        auto it = _metadata.find(txid);
        if (it == _metadata.end())
            throw cosigner_exception(cosigner_exception::INVALID_TRANSACTION);
        return std::make_shared<eddsa_signing_metadata>(it->second);
    }

    void update_eddsa_signing_data(const std::string& txid, const std::shared_ptr<eddsa_signing_metadata>& data) override
    {
        std::unique_lock lock(_mutex);
        auto it = _metadata.find(txid);
        if (it == _metadata.end())
            throw cosigner_exception(cosigner_exception::INVALID_TRANSACTION);
        it->second = *data;
    }

    void store_signing_commitments(const std::string& txid, const std::map<uint64_t, std::vector<commitment>>& commitments) override
    {
        std::unique_lock lock(_mutex);
        if (_commitments.find(txid) != _commitments.end())
            throw cosigner_exception(cosigner_exception::INVALID_TRANSACTION);
        _commitments[txid] = commitments;
    }

    void load_signing_commitments(const std::string& txid, std::map<uint64_t, std::vector<commitment>>& commitments) override
    {
        std::shared_lock lock(_mutex);
        auto it = _commitments.find(txid);
        if (it == _commitments.end())
            throw cosigner_exception(cosigner_exception::INVALID_TRANSACTION);
        commitments = it->second;
    }
    
    bool delete_eddsa_signing_data(const std::string& txid) override
    {
        std::unique_lock lock(_mutex);
        _metadata.erase(txid);
        _commitments.erase(txid);
        return true;
    }

    mutable std::shared_mutex _mutex;
    std::map<std::string, eddsa_signing_metadata> _metadata;
    std::map<std::string, std::map<uint64_t, std::vector<commitment>>>  _commitments;
};

struct eddsa_siging_info
{
    eddsa_siging_info(uint64_t id, cmp_key_persistency& persistency, bool positive_r) : platform_service(id, positive_r), signing_service(platform_service, persistency, signing_persistency) {}
    eddsa_sign_platform platform_service;
    eddsa_signing_persistency signing_persistency;
    eddsa_online_signing_service signing_service;
};

// Templated on the persistency-map value type so the same driver works for both an additive
// (CMP-setup) key (players_setup_info) and a Shamir/VSS threshold key (threshold_players_info).
template<typename PersistencyMap>
static void eddsa_sign(PersistencyMap& players,
                       const std::string& keyid,
                       uint32_t count,
                       const elliptic_curve256_point_t& pubkey,
                       const byte_vector_t& chaincode,
                       const std::vector<std::vector<uint32_t>>& paths,
                       bool keccek,
                       uint32_t version)
{
    uuid_t uid;
    char txid[37] = {0};
    uuid_generate_random(uid);
    uuid_unparse(uid, txid);
    std::cout << "txid id = " << txid << std::endl;

    std::map<uint64_t, std::unique_ptr<eddsa_siging_info>> services;
    std::set<uint64_t> players_ids;
    std::set<std::string> players_str;
    for (auto i = players.begin(); i != players.end(); ++i)
    {
        auto info = std::make_unique<eddsa_siging_info>(i->first, i->second, keccek);
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

    std::map<uint64_t, std::vector<commitment>> commitments;
    for (auto i = services.begin(); i != services.end(); ++i)
    {
        auto& commits = commitments[i->first];
        REQUIRE_NOTHROW(i->second->signing_service.start_signing(keyid, txid, data, "", players_str, players_ids, commits));

        std::vector<commitment> repeat_commitments;
        REQUIRE_THROWS_AS(i->second->signing_service.start_signing(keyid, txid, data, "", players_str, players_ids, repeat_commitments), cosigner_exception);
    }

    std::map<uint64_t, std::vector<elliptic_curve_point>> Rs;
    for (auto i = services.begin(); i != services.end(); ++i)
    {
        auto& R = Rs[i->first];
        REQUIRE_NOTHROW(i->second->signing_service.store_commitments(txid, commitments, version, R));

        std::vector<elliptic_curve_point> repeat_Rs;
        REQUIRE_THROWS_AS(i->second->signing_service.store_commitments(txid, commitments, version, repeat_Rs), cosigner_exception);
    }
    commitments.clear();

    std::map<uint64_t, std::vector<elliptic_curve_scalar>> sis;
    for (auto i = services.begin(); i != services.end(); ++i)
    {
        auto& si = sis[i->first];
        REQUIRE_NOTHROW(i->second->signing_service.broadcast_si(txid, Rs, si));

        std::vector<elliptic_curve_scalar> repeat_si;
        REQUIRE_NOTHROW(i->second->signing_service.broadcast_si(txid, Rs, repeat_si));
    }
    Rs.clear();

    std::vector<eddsa_signature> sigs;
    for (auto i = services.begin(); i != services.end(); ++i)
    {
        REQUIRE_NOTHROW(i->second->signing_service.get_eddsa_signature(txid, sis, sigs));

        std::vector<eddsa_signature> repeat_sigs;
        REQUIRE_THROWS_AS(i->second->signing_service.get_eddsa_signature(txid, sis, repeat_sigs), cosigner_exception);
    }
    sis.clear();

    std::unique_ptr<elliptic_curve256_algebra_ctx_t, void(*)(elliptic_curve256_algebra_ctx_t*)> algebra(elliptic_curve256_new_ed25519_algebra(), elliptic_curve256_algebra_ctx_free);
    for (size_t i = 0; i < count; i++)
    {
        REQUIRE(data.blocks[i].data.size() == sizeof(elliptic_curve256_scalar_t));
        std::cout << "sig r: " << HexStr(sigs[i].R, &sigs[i].R[sizeof(elliptic_curve256_scalar_t)]) << std::endl;
        std::cout << "sig s: " << HexStr(sigs[i].s, &sigs[i].s[sizeof(elliptic_curve256_scalar_t)]) << std::endl;
        
        PubKey derived_key;
        REQUIRE(derive_public_key_generic(algebra.get(), derived_key, pubkey, data.chaincode, paths[i].data(), paths[i].size()) == HD_DERIVE_SUCCESS);
        std::cout << "derived public_key: " << HexStr(derived_key, &derived_key[sizeof(PubKey)]) << std::endl;

        uint8_t raw_sig[sizeof(elliptic_curve256_scalar_t) * 2];
        memcpy(raw_sig, sigs[i].R, sizeof(elliptic_curve256_scalar_t));
        memcpy(&raw_sig[sizeof(elliptic_curve256_scalar_t)], sigs[i].s, sizeof(elliptic_curve256_scalar_t));
        REQUIRE(ed25519_verify((ed25519_algebra_ctx_t*)algebra->ctx, data.blocks[i].data.data(), data.blocks[i].data.size(), raw_sig, derived_key, keccek ? 1 : 0));
    }
}

// ---- Threshold (Shamir/VSS) EdDSA key support for tests ------------------------------------
// A self-contained threshold key (no DKG required): build a degree-(t-1) polynomial F over the
// ed25519 scalar field with F(0) = secret, give player i the evaluation F(i), and publish
// pubkey = secret*G. Metadata carries flags = THRESHOLD so the online signer applies the
// per-signer Lagrange weight (calc_w); any subset of >= t signers then reconstructs F(0).
class threshold_key_persistency : public cmp_key_persistency
{
public:
    void set(const std::string& keyid, const elliptic_curve256_scalar_t& share, const cmp_key_metadata& metadata)
    {
        _keyid = keyid;
        memcpy(_share, share, sizeof(elliptic_curve256_scalar_t));
        _metadata = metadata;
        _set = true;
    }

    bool key_exist(const std::string& key_id) const override { return _set && key_id == _keyid; }

    void load_key(const std::string& key_id, cosigner_sign_algorithm& algorithm, elliptic_curve256_scalar_t& private_key) const override
    {
        if (!key_exist(key_id))
            throw cosigner_exception(cosigner_exception::BAD_KEY);
        algorithm = _metadata.algorithm;
        memcpy(private_key, _share, sizeof(elliptic_curve256_scalar_t));
    }

    const std::string get_tenantid_from_keyid(const std::string& key_id) const override { return TENANT_ID; }

    void load_key_metadata(const std::string& key_id, cmp_key_metadata& metadata, bool full_load) const override
    {
        if (!key_exist(key_id))
            throw cosigner_exception(cosigner_exception::BAD_KEY);
        metadata = _metadata;
    }

    void load_auxiliary_keys(const std::string& key_id, auxiliary_keys& aux) const override {}

private:
    std::string _keyid;
    elliptic_curve256_scalar_t _share = {0};
    cmp_key_metadata _metadata;
    bool _set = false;
};

typedef std::map<uint64_t, threshold_key_persistency> threshold_players_info;

// Build a t-of-n Shamir/VSS threshold ed25519 key into `players`; returns pubkey = secret*G.
static void create_threshold_secret(threshold_players_info& players, const std::string& keyid, uint8_t t, elliptic_curve256_point_t& pubkey)
{
    std::unique_ptr<elliptic_curve256_algebra_ctx_t, void(*)(elliptic_curve256_algebra_ctx_t*)> algebra(elliptic_curve256_new_ed25519_algebra(), elliptic_curve256_algebra_ctx_free);
    const uint8_t n = (uint8_t)players.size();
    REQUIRE(t >= 1);
    REQUIRE(t <= n);

    // Polynomial coefficients a_0..a_{t-1}: a_0 is the secret, the rest are random.
    // (elliptic_curve_scalar wraps the raw elliptic_curve256_scalar_t C array so it is usable in a vector.)
    std::vector<elliptic_curve_scalar> coeff(t);
    for (uint8_t j = 0; j < t; ++j)
        REQUIRE(algebra->rand(algebra.get(), &coeff[j].data) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);

    REQUIRE(algebra->generator_mul(algebra.get(), &pubkey, &coeff[0].data) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);

    cmp_key_metadata metadata;
    memcpy(metadata.public_key, pubkey, sizeof(elliptic_curve256_point_t));
    metadata.algorithm = EDDSA_ED25519;
    metadata.t = t;
    metadata.n = n;
    metadata.flags = THRESHOLD;
    metadata.ttl = 0;
    for (auto& p : players)
        metadata.players_info[p.first];   // existence of each signer is all the eddsa signer checks

    // share_i = F(i), evaluated by Horner over the big-endian scalar field.
    for (auto& p : players)
    {
        elliptic_curve256_scalar_t id_be = {0};
        const uint64_t id = p.first;
        for (int b = 0; b < 8; ++b)
            id_be[sizeof(elliptic_curve256_scalar_t) - 1 - b] = (uint8_t)(id >> (8 * b));

        elliptic_curve256_scalar_t acc;
        memcpy(acc, coeff[t - 1].data, sizeof(elliptic_curve256_scalar_t));
        for (int j = (int)t - 2; j >= 0; --j)
        {
            REQUIRE(algebra->mul_scalars(algebra.get(), &acc, acc, sizeof(elliptic_curve256_scalar_t), id_be, sizeof(elliptic_curve256_scalar_t)) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
            REQUIRE(algebra->add_scalars(algebra.get(), &acc, acc, sizeof(elliptic_curve256_scalar_t), coeff[j].data, sizeof(elliptic_curve256_scalar_t)) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS);
        }
        p.second.set(keyid, acc, metadata);
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

    eddsa_sign(param->players, param->keyid, 1, param->pubkey, chaincode, {path}, false, fireblocks::common::cosigner::MPC_PROTOCOL_VERSION);
    return NULL;
}

static char keyid[37] = {0};
static elliptic_curve256_point_t pubkey;
static players_setup_info players;

TEST_CASE("eddsa") {
    byte_vector_t chaincode(32, '\0');
    std::vector<uint32_t> path = {44, 0, 0, 0, 0};

    SECTION("create_secret") {  
        players.clear();
        uuid_t uid;
        uuid_generate_random(uid);
        uuid_unparse(uid, keyid);
        players[1];
        players[2];
        create_secret(players, EDDSA_ED25519, keyid, pubkey, fireblocks::common::cosigner::MPC_PROTOCOL_VERSION);
    }

    SECTION("sign") {
        auto before = Clock::now();
        eddsa_sign(players, keyid, 1, pubkey, chaincode, {path}, false, fireblocks::common::cosigner::MPC_PROTOCOL_VERSION);
        auto after = Clock::now();
        std::cout << "EDDSA signing took: " << std::chrono::duration_cast<std::chrono::milliseconds>(after - before).count() << " ms" << std::endl;
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
        add_user(players, new_players, EDDSA_ED25519, keyid, new_keyid, pubkey, fireblocks::common::cosigner::MPC_PROTOCOL_VERSION);
        eddsa_sign(new_players, new_keyid, 1, pubkey, chaincode, {path}, false, fireblocks::common::cosigner::MPC_PROTOCOL_VERSION);
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
        eddsa_sign(players, keyid, COUNT, pubkey, chaincode, derivation_paths, false, fireblocks::common::cosigner::MPC_PROTOCOL_VERSION);
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

    SECTION("keccak") {
        // run 4 times as R has 50% chance of being negative
        for (size_t i = 0; i < 8; ++i)
            eddsa_sign(players, keyid, 1, pubkey, chaincode, {path}, true, fireblocks::common::cosigner::MPC_PROTOCOL_VERSION);;
    }
}

// Create a t-of-N Shamir/VSS threshold key over `all_ids`, then sign `count` block(s) with EVERY
// signer subset of size `subset_size` (>= t), verifying each Ed25519 signature. This exercises
// the threshold path of the online signer (the per-signer Lagrange weight, calc_w): for any
// qualifying signer set, sum over signers of w_i * F(x_i) must equal F(0) = secret. subset_size
// may exceed t (over-determined reconstruction) and ids need not be contiguous.
static void threshold_sign_all_subsets(uint8_t t, const std::vector<uint64_t>& all_ids, size_t subset_size, uint32_t count, bool keccak)
{
    REQUIRE(subset_size >= t);
    REQUIRE(subset_size <= all_ids.size());

    char keyid[37] = {0};
    uuid_t uid;
    uuid_generate_random(uid);
    uuid_unparse(uid, keyid);

    threshold_players_info all_players;
    for (auto id : all_ids)
        all_players[id];
    elliptic_curve256_point_t pubkey;
    create_threshold_secret(all_players, keyid, t, pubkey);

    byte_vector_t chaincode(32, '\0');
    std::vector<uint32_t> path = {44, 0, 0, 0, 0};
    std::vector<std::vector<uint32_t>> paths;
    for (uint32_t i = 0; i < count; ++i)
    {
        paths.push_back(path);
        ++path[2];
    }

    const size_t n = all_ids.size();
    size_t subsets_tested = 0;
    for (uint32_t mask = 0; mask < (1u << n); ++mask)
    {
        size_t bits = 0;
        for (size_t b = 0; b < n; ++b)
            if (mask & (1u << b))
                ++bits;
        if (bits != subset_size)
            continue;

        threshold_players_info signers;
        for (size_t b = 0; b < n; ++b)
            if (mask & (1u << b))
                signers[all_ids[b]] = all_players[all_ids[b]];

        eddsa_sign(signers, keyid, count, pubkey, chaincode, paths, keccak, fireblocks::common::cosigner::MPC_PROTOCOL_VERSION);
        ++subsets_tested;
    }
    REQUIRE(subsets_tested > 0);
}

TEST_CASE("eddsa_threshold") {
    SECTION("2-of-2") {
        threshold_sign_all_subsets(2, {1, 2}, 2, 1, false);
    }

    SECTION("2-of-3 every signing pair") {
        threshold_sign_all_subsets(2, {1, 2, 3}, 2, 1, false);
    }

    SECTION("2-of-3 over-determined (all 3 sign)") {
        threshold_sign_all_subsets(2, {1, 2, 3}, 3, 1, false);
    }

    SECTION("3-of-5 every signing triple") {
        threshold_sign_all_subsets(3, {1, 2, 3, 4, 5}, 3, 1, false);
    }

    SECTION("2-of-3 multiple blocks") {
        threshold_sign_all_subsets(2, {1, 2, 3}, 2, 4, false);
    }

    SECTION("2-of-3 keccak") {
        // R has ~50% chance of being negative; repeat to exercise both branches
        for (int i = 0; i < 4; ++i)
            threshold_sign_all_subsets(2, {1, 2, 3}, 2, 1, true);
    }

    SECTION("non-contiguous player ids") {
        threshold_sign_all_subsets(2, {7, 42, 1000}, 2, 1, false);
    }
}
