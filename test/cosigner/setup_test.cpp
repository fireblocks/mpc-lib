#include <chrono>
#include <iostream>
#include <tests/catch.hpp>

#include "cosigner/cosigner_exception.h"
#include "test_common.h"
#include "crypto/elliptic_curve_algebra/elliptic_curve256_algebra.h"
#include "cosigner/cmp_key_persistency.h"

#include <string.h>
#include <stdarg.h>

#include <openssl/rand.h>

extern "C" void sgx_log_printf_style(int level, const char* file, const char* function, int line, const char* message, ...)
{
    if (message)
    {
        va_list ap;
        va_start(ap, message);
        vprintf(message, ap);
        va_end(ap);
    }
    putchar('\n');
}

using namespace fireblocks::common::cosigner;

static elliptic_curve256_algebra_ctx_t* create_algebra(cosigner_sign_algorithm type)
{
    switch (type)
    {
        case ECDSA_SECP256K1: return elliptic_curve256_new_secp256k1_algebra();
        case ECDSA_SECP256R1: return elliptic_curve256_new_secp256r1_algebra();
        case EDDSA_ED25519: return elliptic_curve256_new_ed25519_algebra();
        case ECDSA_STARK: return elliptic_curve256_new_stark_algebra();
    }
    return NULL;
}

std::string setup_persistency::dump_key(const std::string& key_id) const
    {
        auto it = _keys.find(key_id);
        if (it == _keys.end())
            throw cosigner_exception(cosigner_exception::BAD_KEY);
        return HexStr(it->second.private_key, &it->second.private_key[sizeof(elliptic_curve256_scalar_t)]);
    }

bool setup_persistency::key_exist(const std::string& key_id) const
{
    return _keys.find(key_id) != _keys.end();
}

void setup_persistency::load_key(const std::string& key_id, cosigner_sign_algorithm& algorithm, elliptic_curve256_scalar_t& private_key) const
{
    auto it = _keys.find(key_id);
    if (it == _keys.end())
        throw cosigner_exception(cosigner_exception::BAD_KEY);
    memcpy(private_key, it->second.private_key, sizeof(elliptic_curve256_scalar_t));
    algorithm = it->second.algorithm;
}

const std::string setup_persistency::get_tenantid_from_keyid(const std::string& key_id) const
{
    return TENANT_ID;
}

void setup_persistency::load_key_metadata(const std::string& key_id, cmp_key_metadata& metadata, bool full_load) const
{
    auto it = _keys.find(key_id);
    if (it == _keys.end())
        throw cosigner_exception(cosigner_exception::BAD_KEY);
    metadata = it->second.metadata.value();
}

void setup_persistency::load_auxiliary_keys(const std::string& key_id, auxiliary_keys& aux) const
{
    auto it = _keys.find(key_id);
    if (it == _keys.end())
        throw cosigner_exception(cosigner_exception::BAD_KEY);
    aux = it->second.aux_keys;
}

void setup_persistency::store_key(const std::string& key_id, cosigner_sign_algorithm algorithm, const elliptic_curve256_scalar_t& private_key, uint64_t ttl)
{
    auto& info = _keys[key_id];
    memcpy(info.private_key, private_key, sizeof(elliptic_curve256_scalar_t));
    info.algorithm = algorithm;
}

void setup_persistency::store_key_metadata(const std::string& key_id, const cmp_key_metadata& metadata, bool allow_override)
{
    auto& info = _keys[key_id];
    if (!allow_override && info.metadata)
        throw cosigner_exception(cosigner_exception::INTERNAL_ERROR);

    info.metadata = metadata;
}

void setup_persistency::store_auxiliary_keys(const std::string& key_id, const auxiliary_keys& aux)
{
    auto& info = _keys[key_id];
    info.aux_keys = aux;
}

void setup_persistency::store_keyid_tenant_id(const std::string& key_id, const std::string& tenant_id) {}

void setup_persistency::store_setup_data(const std::string& key_id, const setup_data& metadata)
{
    _setup_data[key_id] = metadata;
}

void setup_persistency::load_setup_data(const std::string& key_id, setup_data& metadata)
{
    metadata = _setup_data[key_id];
}

void setup_persistency::store_setup_commitments(const std::string& key_id, const std::map<uint64_t, commitment>& commitments)
{
    if (_commitments.find(key_id) != _commitments.end())
        throw cosigner_exception(cosigner_exception::INTERNAL_ERROR);

    _commitments[key_id] = commitments;
}

void setup_persistency::load_setup_commitments(const std::string& key_id, std::map<uint64_t, commitment>& commitments)
{
    commitments = _commitments[key_id];
}

void setup_persistency::delete_temporary_key_data(const std::string& key_id, bool delete_key)
{
    _setup_data.erase(key_id);
    _commitments.erase(key_id);
    if (delete_key)
        _keys.erase(key_id);
}

class platform : public platform_service
{
public:
    platform(uint64_t id) : _id(id) {}
private:
    void gen_random(size_t len, uint8_t* random_data) const override
    {
        RAND_bytes(random_data, len);
    }

    uint64_t now_msec() const override { return std::chrono::time_point_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now()).time_since_epoch().count(); }

    const std::string get_current_tenantid() const override {return TENANT_ID;}
    uint64_t get_id_from_keyid(const std::string& key_id) const override {return _id;}
    void derive_initial_share(const share_derivation_args& derive_from, cosigner_sign_algorithm algorithm, elliptic_curve256_scalar_t* key) const override {assert(0);}
    byte_vector_t encrypt_for_player(uint64_t id, const byte_vector_t& data) const override {return data;}
    byte_vector_t decrypt_message(const byte_vector_t& encrypted_data) const override  {return encrypted_data;}
    bool backup_key(const std::string& key_id, cosigner_sign_algorithm algorithm, const elliptic_curve256_scalar_t& private_key, const cmp_key_metadata& metadata, const auxiliary_keys& aux) override {return true;}
    void start_signing(const std::string& key_id, const std::string& txid, const signing_data& data, const std::string& metadata_json, const std::set<std::string>& players) override {}
    void fill_signing_info_from_metadata(const std::string& metadata, std::vector<uint32_t>& flags) const override {assert(0);}
    bool is_client_id(uint64_t player_id) const override {return false;}

    uint64_t _id;
};

struct setup_info
{
    setup_info(uint64_t id, setup_persistency& persistency) : platform_service(id), setup_service(platform_service, persistency) {}
    platform platform_service;
    cmp_setup_service setup_service;
};

void create_secret(players_setup_info& players, cosigner_sign_algorithm type, const std::string& keyid, elliptic_curve256_point_t& pubkey)
{
    std::unique_ptr<elliptic_curve256_algebra_ctx_t, void(*)(elliptic_curve256_algebra_ctx_t*)> algebra(create_algebra(type), elliptic_curve256_algebra_ctx_free);
    const size_t PUBKEY_SIZE = algebra->point_size(algebra.get());
    memset(pubkey, 0, sizeof(elliptic_curve256_point_t));

    std::cout << "keyid = " << keyid << std::endl;
    std::vector<uint64_t> players_ids;

    std::map<uint64_t, std::unique_ptr<setup_info>> services;
    for (auto i = players.begin(); i != players.end(); ++i)
    {
        services.emplace(i->first, std::make_unique<setup_info>(i->first, i->second));
        players_ids.push_back(i->first);
    }

    std::map<uint64_t, commitment> commitments;
    for (auto i = services.begin(); i != services.end(); ++i)
    {
        commitment& commit = commitments[i->first];
        REQUIRE_NOTHROW(i->second->setup_service.generate_setup_commitments(keyid, TENANT_ID, type, players_ids, players_ids.size(), 0, {}, commit));

        commitment repeat_commit;
        REQUIRE_THROWS_AS(i->second->setup_service.generate_setup_commitments(keyid, TENANT_ID, type, players_ids, players_ids.size(), 0, {}, repeat_commit), cosigner_exception);
    }

    std::map<uint64_t, setup_decommitment> decommitments;
    for (auto i = services.begin(); i != services.end(); ++i)
    {
        setup_decommitment& decommitment = decommitments[i->first];
        REQUIRE_NOTHROW(i->second->setup_service.store_setup_commitments(keyid, commitments, decommitment));

        setup_decommitment repeat_decommitment;
        REQUIRE_THROWS_AS(i->second->setup_service.store_setup_commitments(keyid, commitments, repeat_decommitment), cosigner_exception);
    }
    commitments.clear();

    std::map<uint64_t, setup_zk_proofs> proofs;
    for (auto i = services.begin(); i != services.end(); ++i)
    {
        setup_zk_proofs& proof = proofs[i->first];
        REQUIRE_NOTHROW(i->second->setup_service.generate_setup_proofs(keyid, decommitments, proof));

        // Multiple decommitments are fine
        REQUIRE_NOTHROW(i->second->setup_service.generate_setup_proofs(keyid, decommitments, proof));
    }
    decommitments.clear();

    std::map<uint64_t, std::map<uint64_t, byte_vector_t>> paillier_large_factor_proofs;
    for (auto i = services.begin(); i != services.end(); ++i)
    {
        auto& proof = paillier_large_factor_proofs[i->first];
        REQUIRE_NOTHROW(i->second->setup_service.verify_setup_proofs(keyid, proofs, proof));

        std::map<uint64_t, byte_vector_t> repeat_proof;
        REQUIRE_NOTHROW(i->second->setup_service.verify_setup_proofs(keyid, proofs, repeat_proof));
    }
    proofs.clear();
    
    bool first = true;
    for (auto i = services.begin(); i != services.end(); ++i)
    {
        std::string public_key;
        cosigner_sign_algorithm algorithm;
        REQUIRE_NOTHROW(i->second->setup_service.create_secret(keyid, paillier_large_factor_proofs, public_key, algorithm));
        REQUIRE(algorithm == type);
        REQUIRE(public_key.size() == PUBKEY_SIZE);
        if (first)
        {
            first = false;
            memcpy(pubkey, public_key.data(), PUBKEY_SIZE);
        }
        else
        {
            REQUIRE(memcmp(pubkey, public_key.data(), PUBKEY_SIZE) == 0);
        }

        std::string repeat_public_key;
        cosigner_sign_algorithm repeat_algorithm;
        REQUIRE_NOTHROW(i->second->setup_service.create_secret(keyid, paillier_large_factor_proofs, repeat_public_key, repeat_algorithm));
    }
    paillier_large_factor_proofs.clear();
    
    std::cout << "public key: " << HexStr(pubkey, &pubkey[PUBKEY_SIZE]) << std::endl;
    for (auto i = players.begin(); i != players.end(); ++i)
    {
        std::cout << "player " << i->first << " share: " << i->second.dump_key(keyid) << std::endl;
    }
}

void add_user(players_setup_info& old_players, players_setup_info& new_players, cosigner_sign_algorithm type, const std::string& old_keyid, const std::string& new_keyid, const elliptic_curve256_point_t& pubkey)
{
    std::unique_ptr<elliptic_curve256_algebra_ctx_t, void(*)(elliptic_curve256_algebra_ctx_t*)> algebra(create_algebra(type), elliptic_curve256_algebra_ctx_free);
    const size_t PUBKEY_SIZE = algebra->point_size(algebra.get());

    std::cout << "new keyid = " << new_keyid << std::endl;
    std::vector<uint64_t> players_ids;
    std::vector<uint64_t> old_players_ids;

    std::map<uint64_t, std::unique_ptr<setup_info>> services;
    for (auto i = old_players.begin(); i != old_players.end(); ++i)
    {
        services.emplace(i->first, std::make_unique<setup_info>(i->first, i->second));
        old_players_ids.push_back(i->first);
    }
    for (auto i = new_players.begin(); i != new_players.end(); ++i)
        players_ids.push_back(i->first);
    
    std::map<uint64_t, add_user_data> add_user_request_data;
    for (auto i = services.begin(); i != services.end(); ++i)
    {
        add_user_data& data = add_user_request_data[i->first];
        REQUIRE_NOTHROW(i->second->setup_service.add_user_request(old_keyid, type, new_keyid, players_ids, players_ids.size(), data));
    }

    services.clear();
    std::map<uint64_t, commitment> commitments;
    for (auto i = new_players.begin(); i != new_players.end(); ++i)
    {
        auto info = std::make_unique<setup_info>(i->first, i->second);
        commitment& commitment = commitments[i->first];
        REQUIRE_NOTHROW(info->setup_service.add_user(TENANT_ID, new_keyid, type, players_ids.size(), add_user_request_data, 0, commitment));
        services.emplace(i->first, std::move(info));
    }

    std::map<uint64_t, setup_decommitment> decommitments;
    for (auto i = services.begin(); i != services.end(); ++i)
    {
        setup_decommitment& decommitment = decommitments[i->first];
        REQUIRE_NOTHROW(i->second->setup_service.store_setup_commitments(new_keyid, commitments, decommitment));
    }
    commitments.clear();

    std::map<uint64_t, setup_zk_proofs> proofs;
    for (auto i = services.begin(); i != services.end(); ++i)
    {
        setup_zk_proofs& proof = proofs[i->first];
        REQUIRE_NOTHROW(i->second->setup_service.generate_setup_proofs(new_keyid, decommitments, proof));
    }
    decommitments.clear();

    std::map<uint64_t, std::map<uint64_t, byte_vector_t>> paillier_large_factor_proofs;
    for (auto i = services.begin(); i != services.end(); ++i)
    {
        auto& proof = paillier_large_factor_proofs[i->first];
        REQUIRE_NOTHROW(i->second->setup_service.verify_setup_proofs(new_keyid, proofs, proof));
    }
    proofs.clear();
    
    for (auto i = services.begin(); i != services.end(); ++i)
    {
        std::string public_key;
        cosigner_sign_algorithm algorithm;
        REQUIRE_NOTHROW(i->second->setup_service.create_secret(new_keyid, paillier_large_factor_proofs, public_key, algorithm));
        REQUIRE(algorithm == type);
        REQUIRE(public_key.size() == PUBKEY_SIZE);
        REQUIRE(memcmp(pubkey, public_key.data(), PUBKEY_SIZE) == 0);
    }
    paillier_large_factor_proofs.clear();
    
    for (auto i = new_players.begin(); i != new_players.end(); ++i)
    {
        std::cout << "player " << i->first << " share: " << i->second.dump_key(new_keyid) << std::endl;
    }
}

#if 0
TEST_CASE("setup") {
    SECTION("secp256k1") {
        uuid_t uid;
        char keyid[37] = {0};
        uuid_generate_random(uid);
        uuid_unparse(uid, keyid);
        elliptic_curve256_point_t pubkey;
        players_setup_info players;
        players[1];
        players[2];
        create_secret(players, ECDSA_SECP256K1, keyid, pubkey);
    }

    SECTION("secp256r1") {
        uuid_t uid;
        char keyid[37] = {0};
        uuid_generate_random(uid);
        uuid_unparse(uid, keyid);
        elliptic_curve256_point_t pubkey;
        players_setup_info players;
        players[1];
        players[2];
        create_secret(players, ECDSA_SECP256R1, keyid, pubkey);
    }

    SECTION("ed25519") {
        uuid_t uid;
        char keyid[37] = {0};
        uuid_generate_random(uid);
        uuid_unparse(uid, keyid);
        elliptic_curve256_point_t pubkey;
        players_setup_info players;
        players[1];
        players[2];
        create_secret(players, EDDSA_ED25519, keyid, pubkey);
    }

    SECTION("stark") {
        uuid_t uid;
        char keyid[37] = {0};
        uuid_generate_random(uid);
        uuid_unparse(uid, keyid);
        elliptic_curve256_point_t pubkey;
        players_setup_info players;
        players[1];
        players[2];
        create_secret(players, ECDSA_STARK, keyid, pubkey);
    }

    SECTION("3/3") {
        uuid_t uid;
        char keyid[37] = {0};
        uuid_generate_random(uid);
        uuid_unparse(uid, keyid);
        elliptic_curve256_point_t pubkey;
        players_setup_info players;
        players[1];
        players[2];
        players[111];
        create_secret(players, ECDSA_SECP256K1, keyid, pubkey);
    }
}

TEST_CASE("add_user") {
    SECTION("secp256k1") {
        uuid_t uid;
        char keyid[37] = {0};
        uuid_generate_random(uid);
        uuid_unparse(uid, keyid);
        elliptic_curve256_point_t pubkey;
        players_setup_info players;
        players[1];
        players[2];
        create_secret(players, ECDSA_SECP256K1, keyid, pubkey);

        char new_keyid[37] = {0};
        uuid_generate_random(uid);
        uuid_unparse(uid, new_keyid);
        players_setup_info new_players;
        new_players[11];
        new_players[12];
        new_players[13];
        add_user(players, new_players, ECDSA_SECP256K1, keyid, new_keyid, pubkey);
    }

    SECTION("secp256r1") {
        uuid_t uid;
        char keyid[37] = {0};
        uuid_generate_random(uid);
        uuid_unparse(uid, keyid);
        elliptic_curve256_point_t pubkey;
        players_setup_info players;
        players[1];
        players[2];
        create_secret(players, ECDSA_SECP256R1, keyid, pubkey);

        char new_keyid[37] = {0};
        uuid_generate_random(uid);
        uuid_unparse(uid, new_keyid);
        players_setup_info new_players;
        new_players[11];
        new_players[12];
        add_user(players, new_players, ECDSA_SECP256R1, keyid, new_keyid, pubkey);
    }

    SECTION("ed25519") {
        uuid_t uid;
        char keyid[37] = {0};
        uuid_generate_random(uid);
        uuid_unparse(uid, keyid);
        elliptic_curve256_point_t pubkey;
        players_setup_info players;
        players[1];
        players[2];
        create_secret(players, EDDSA_ED25519, keyid, pubkey);

        char new_keyid[37] = {0};
        uuid_generate_random(uid);
        uuid_unparse(uid, new_keyid);
        players_setup_info new_players;
        new_players[11];
        new_players[12];
        new_players[13];
        new_players[14];
        add_user(players, new_players, EDDSA_ED25519, keyid, new_keyid, pubkey);
    }

    SECTION("stark") {
        uuid_t uid;
        char keyid[37] = {0};
        uuid_generate_random(uid);
        uuid_unparse(uid, keyid);
        elliptic_curve256_point_t pubkey;
        players_setup_info players;
        players[1];
        players[2];
        create_secret(players, ECDSA_STARK, keyid, pubkey);

        char new_keyid[37] = {0};
        uuid_generate_random(uid);
        uuid_unparse(uid, new_keyid);
        players_setup_info new_players;
        new_players[11];
        new_players[12];
        add_user(players, new_players, ECDSA_STARK, keyid, new_keyid, pubkey);
    }
}
#endif