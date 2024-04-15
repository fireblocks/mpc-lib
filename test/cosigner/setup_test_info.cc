#include <string>
#include <iostream>
#include <test_info.h>

#include "cosigner/cosigner_exception.h"
#include "cosigner/cmp_key_persistency.h"


std::string setup_persistency::dump_key(const std::string& key_id) const
    {
        auto it = _keys.find(key_id);
        if (it == _keys.end())
            throw fireblocks::common::cosigner::cosigner_exception(fireblocks::common::cosigner::cosigner_exception::BAD_KEY);
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
        throw fireblocks::common::cosigner::cosigner_exception(fireblocks::common::cosigner::cosigner_exception::BAD_KEY);
    memcpy(private_key, it->second.private_key, sizeof(elliptic_curve256_scalar_t));
    algorithm = it->second.algorithm;
}

const std::string setup_persistency::get_tenantid_from_keyid(const std::string& key_id) const
{
    return TENANT_ID;
}

void setup_persistency::load_key_metadata(const std::string& key_id, fireblocks::common::cosigner::cmp_key_metadata& metadata, bool full_load) const
{
    auto it = _keys.find(key_id);
    if (it == _keys.end())
        throw fireblocks::common::cosigner::cosigner_exception(fireblocks::common::cosigner::cosigner_exception::BAD_KEY);
    metadata = it->second.metadata;
}

void setup_persistency::load_auxiliary_keys(const std::string& key_id, fireblocks::common::cosigner::auxiliary_keys& aux) const
{
    auto it = _keys.find(key_id);
    if (it == _keys.end())
        throw fireblocks::common::cosigner::cosigner_exception(fireblocks::common::cosigner::cosigner_exception::BAD_KEY);
    aux = it->second.aux_keys;
}

void setup_persistency::store_key(const std::string& key_id, cosigner_sign_algorithm algorithm, const elliptic_curve256_scalar_t& private_key, uint64_t ttl)
{
    auto& info = _keys[key_id];
    memcpy(info.private_key, private_key, sizeof(elliptic_curve256_scalar_t));
    info.algorithm = algorithm;
}

void setup_persistency::store_key_metadata(const std::string& key_id, const fireblocks::common::cosigner::cmp_key_metadata& metadata)
{
    auto& info = _keys[key_id];
    info.metadata = metadata;
}

void setup_persistency::store_auxiliary_keys(const std::string& key_id, const fireblocks::common::cosigner::auxiliary_keys& aux)
{
    auto& info = _keys[key_id];
    info.aux_keys = aux;
}

void setup_persistency::store_keyid_tenant_id(const std::string& key_id, const std::string& tenant_id) {}

void setup_persistency::store_setup_data(const std::string& key_id, const fireblocks::common::cosigner::setup_data& metadata)
{
    _setup_data[key_id] = metadata;
}

void setup_persistency::load_setup_data(const std::string& key_id, fireblocks::common::cosigner::setup_data& metadata)
{
    metadata = _setup_data[key_id];
}

void setup_persistency::store_setup_commitments(const std::string& key_id, const std::map<uint64_t, fireblocks::common::cosigner::commitment>& commitments)
{
    _commitments[key_id] = commitments;
}

void setup_persistency::load_setup_commitments(const std::string& key_id, std::map<uint64_t, fireblocks::common::cosigner::commitment>& commitments)
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

void create_secret(players_setup_info& players, const std::string& keyid, elliptic_curve256_point_t& pubkey){
    
    // hard-coded to work only with secp256k1
    std::unique_ptr<elliptic_curve256_algebra_ctx_t, void(*)(elliptic_curve256_algebra_ctx_t*)> algebra(elliptic_curve256_new_secp256k1_algebra(), elliptic_curve256_algebra_ctx_free); 
    const size_t PUBKEY_SIZE = algebra->point_size(algebra.get());
    memset(pubkey, 0, sizeof(elliptic_curve256_point_t));

    std::cout << "keyid = " << keyid << std::endl;
    std::vector<uint64_t> players_ids;


    std::map<uint64_t, std::unique_ptr<setup_info>> services;
    for (auto i = players.begin(); i != players.end(); ++i)
    {
        std::cout << "Setting up the services  " << std::endl; 
        services.emplace(i->first, std::make_unique<setup_info>(i->first, i->second));
        players_ids.push_back(i->first);
    }

     std::map<uint64_t, fireblocks::common::cosigner::commitment> commitments;
    for (auto i = services.begin(); i != services.end(); ++i)
    {
        fireblocks::common::cosigner::commitment& commitment = commitments[i->first];
        //REQUIRE_NOTHROW(i->second->setup_service.generate_setup_commitments(keyid, TENANT_ID, type, players_ids, players_ids.size(), 0, {}, commitment));
        i->second->setup_service.generate_setup_commitments(keyid, TENANT_ID, ECDSA_SECP256K1, players_ids, players_ids.size(), 0, {}, commitment);
    }

    std::map<uint64_t, fireblocks::common::cosigner::setup_decommitment> decommitments;
    for (auto i = services.begin(); i != services.end(); ++i)
    {
        fireblocks::common::cosigner::setup_decommitment& decommitment = decommitments[i->first];
        //REQUIRE_NOTHROW(i->second->setup_service.store_setup_commitments(keyid, commitments, decommitment));
        i->second->setup_service.store_setup_commitments(keyid, commitments, decommitment);
    }
    commitments.clear();

    std::map<uint64_t, fireblocks::common::cosigner::setup_zk_proofs> proofs;
    for (auto i = services.begin(); i != services.end(); ++i)
    {
        fireblocks::common::cosigner::setup_zk_proofs& proof = proofs[i->first];
        //REQUIRE_NOTHROW(i->second->setup_service.generate_setup_proofs(keyid, decommitments, proof));
        i->second->setup_service.generate_setup_proofs(keyid, decommitments, proof);
    }
    decommitments.clear();

    std::map<uint64_t, std::map<uint64_t, fireblocks::common::cosigner::byte_vector_t>> paillier_large_factor_proofs;
    for (auto i = services.begin(); i != services.end(); ++i)
    {
        auto& proof = paillier_large_factor_proofs[i->first];
        //REQUIRE_NOTHROW(i->second->setup_service.verify_setup_proofs(keyid, proofs, proof));
        i->second->setup_service.verify_setup_proofs(keyid, proofs, proof);
    }
    proofs.clear();
    
    bool first = true;
    for (auto i = services.begin(); i != services.end(); ++i)
    {
        std::string public_key;
        cosigner_sign_algorithm algorithm;

        //REQUIRE_NOTHROW(i->second->setup_service.create_secret(keyid, paillier_large_factor_proofs, public_key, algorithm));
        i->second->setup_service.create_secret(keyid, paillier_large_factor_proofs, public_key, algorithm);
        assert(algorithm == ECDSA_SECP256K1);

        assert(public_key.size() == PUBKEY_SIZE);
        if (first)
        {
            first = false;
            memcpy(pubkey, public_key.data(), PUBKEY_SIZE);
        }
        else
        {
            assert(memcmp(pubkey, public_key.data(), PUBKEY_SIZE) == 0);
        }
    }
    paillier_large_factor_proofs.clear();
    
    std::cout << "public key: " << HexStr(pubkey, &pubkey[PUBKEY_SIZE]) << std::endl;
    for (auto i = players.begin(); i != players.end(); ++i)
    {
        std::cout << "player " << i->first << " share: " << i->second.dump_key(keyid) << std::endl;
    }
    return;
}