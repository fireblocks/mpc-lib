#include "cosigner/cmp_setup_service.h"
#include "cosigner/cosigner_exception.h"
#include "utils.h"
#include "crypto/zero_knowledge_proof/schnorr.h"
#include "logging/logging_t.h"

#include <openssl/sha.h>

#include <algorithm>

namespace fireblocks
{
namespace common
{
namespace cosigner
{

static const uint32_t PAILLIER_KEY_SIZE = sizeof(elliptic_curve256_scalar_t) * 8 * 8; // size in bits
static const uint32_t RING_PEDERSEN_KEY_SIZE = sizeof(elliptic_curve256_scalar_t) * 8 * 4; // size in bits

static inline void xor_seed(commitments_sha256_t a, const commitments_sha256_t b)
{
    uint64_t* p1 = (uint64_t*)a;
    const uint64_t* p2 = (const uint64_t*)b;

    for (size_t i = 0; i < sizeof(commitments_sha256_t) / sizeof(uint64_t); i++)
        p1[i] ^= p2[i];
}

static inline const char* to_string(cosigner_sign_algorithm algorithm)
{
    switch (algorithm)
    {
    case ECDSA_SECP256K1: return "ECDSA_SECP256K1";
    case ECDSA_SECP256R1: return "ECDSA_SECP256R1";
    case EDDSA_ED25519: return "EDDSA_ED25519";
    case ECDSA_STARK: return "ECDSA_STARK";
    default:
        return "UNKNOWN";
    }
}

const std::unique_ptr<elliptic_curve256_algebra_ctx_t, void(*)(elliptic_curve256_algebra_ctx_t*)> cmp_setup_service::_secp256k1(elliptic_curve256_new_secp256k1_algebra(), elliptic_curve256_algebra_ctx_free);
const std::unique_ptr<elliptic_curve256_algebra_ctx_t, void(*)(elliptic_curve256_algebra_ctx_t*)> cmp_setup_service::_secp256r1(elliptic_curve256_new_secp256r1_algebra(), elliptic_curve256_algebra_ctx_free);
const std::unique_ptr<elliptic_curve256_algebra_ctx_t, void(*)(elliptic_curve256_algebra_ctx_t*)> cmp_setup_service::_ed25519(elliptic_curve256_new_ed25519_algebra(), elliptic_curve256_algebra_ctx_free);
const std::unique_ptr<elliptic_curve256_algebra_ctx_t, void(*)(elliptic_curve256_algebra_ctx_t*)> cmp_setup_service::_stark(elliptic_curve256_new_stark_algebra(), elliptic_curve256_algebra_ctx_free);

void cmp_setup_service::generate_setup_commitments(const std::string& key_id, const std::string& tenant_id, cosigner_sign_algorithm algorithm, const std::vector<uint64_t>& players_ids, uint8_t t, uint64_t ttl, const share_derivation_args& derive_from, commitment& setup_commitment)
{
    const size_t n = players_ids.size();
    if (!n || !t || t > n || n > UINT8_MAX)
        throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
    
    if (t != n)
    {
        LOG_ERROR("CMP protocol doesn't support threshold signatures");
        throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
    }

    uint64_t my_id = _service.get_id_from_keyid(key_id);
    if (std::find(players_ids.begin(), players_ids.end(), my_id) == players_ids.end())
    {
        LOG_ERROR("my id (%lu) is not part of setup request, abort", my_id);
        throw cosigner_exception(cosigner_exception::BAD_KEY);
    }

    std::set<uint64_t> distinct_players_ids(players_ids.begin(), players_ids.end()); // make the players_ids list unique
    if (distinct_players_ids.size() != players_ids.size())
    {
        LOG_ERROR("Recived setup request with duplicated player id, players_ids size %lu but only %lu uniq ones", players_ids.size(), distinct_players_ids.size());
        throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
    }

    if (_key_persistency.key_exist(key_id))
    {
        LOG_ERROR("key id %s already exists", key_id.c_str());
        throw cosigner_exception(cosigner_exception::BAD_KEY);
    }

    auto algebra = get_algebra(algorithm);

    elliptic_curve256_scalar_t key;
    if (!derive_from.master_key_id.empty())
    {
        _service.derive_initial_share(derive_from, algorithm, &key);
    }
    else
    {
        elliptic_curve_algebra_status status;

        const size_t MAX_ATTEMPTS = 1024;
        size_t i = 0;
        while (i < MAX_ATTEMPTS)
        {
            _service.gen_random(sizeof(elliptic_curve256_scalar_t), key);
            status = algebra->reduce(algebra, &key, &key);
            if (status == ELLIPTIC_CURVE_ALGEBRA_SUCCESS)
                break;
            else if (status != ELLIPTIC_CURVE_ALGEBRA_INVALID_SCALAR)
            {
                LOG_ERROR("failed to create key share, error %d", status);
                throw_cosigner_exception(status);            
            }
            i++;
        }

        if (i == MAX_ATTEMPTS)
        {
            LOG_ERROR("failed to create key share");
            throw cosigner_exception(cosigner_exception::INTERNAL_ERROR);
        }
    }

    generate_setup_commitments(key_id, tenant_id, algorithm, algebra, players_ids, t, ttl, key, algebra->infinity_point(algebra), setup_commitment);
    memset_s(key, sizeof(elliptic_curve256_scalar_t), 0, sizeof(elliptic_curve256_scalar_t));
}

void cmp_setup_service::store_setup_commitments(const std::string& key_id, const std::map<uint64_t, commitment>& commitments, setup_decommitment& decommitment)
{
    verify_tenant_id(_service, _key_persistency, key_id);
    setup_data temp_data;
    _key_persistency.load_setup_data(key_id, temp_data);
    auxiliary_keys aux;
    _key_persistency.load_auxiliary_keys(key_id, aux);
    cmp_key_metadata metadata;
    _key_persistency.load_key_metadata(key_id, metadata, false);
    auto algebra = get_algebra(metadata.algorithm);

    uint64_t my_id = _service.get_id_from_keyid(key_id);
    
    // verify commitments
    if (commitments.size() != metadata.players_info.size())
    {
        LOG_ERROR("got %lu commitments but the key was created for %lu players", commitments.size(), metadata.players_info.size());
        throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
    }

    for (auto i = metadata.players_info.begin(); i != metadata.players_info.end(); ++i)
    {
        if (!commitments.count(i->first))
        {
            LOG_ERROR("missing commitment from player %lu", i->first);
            throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
        }
    }
    commitment commit = commitments.at(my_id);
    
    // create decommitments
    create_setup_decommitment(algebra, aux, temp_data, decommitment);
    create_setup_commitment(key_id, my_id, decommitment, commit, true);
    ack_message(commitments, &decommitment.ack);
    _key_persistency.store_setup_commitments(key_id, commitments);
}

void cmp_setup_service::generate_setup_proofs(const std::string& key_id, const std::map<uint64_t, setup_decommitment>& decommitments, setup_zk_proofs& proofs)
{
    verify_tenant_id(_service, _key_persistency, key_id);
    cmp_key_metadata metadata;
    _key_persistency.load_key_metadata(key_id, metadata, true);
    std::map<uint64_t, commitment> commitments;
    _key_persistency.load_setup_commitments(key_id, commitments);
    verify_and_load_setup_decommitments(key_id, commitments, decommitments, metadata.players_info);
    
    auto algebra = get_algebra(metadata.algorithm);
    setup_data temp_data;
    _key_persistency.load_setup_data(key_id, temp_data);
        
    memset(metadata.seed, 0, sizeof(commitments_sha256_t));
    for (auto i = decommitments.begin(); i != decommitments.end(); ++i)
    {
        xor_seed(metadata.seed, i->second.seed);
        temp_data.players_schnorr_R[i->first] = i->second.share.schnorr_R;
    }

    generate_setup_proofs(key_id, algebra, temp_data, metadata.seed, proofs);
    _key_persistency.store_setup_data(key_id, temp_data);
    _key_persistency.store_key_metadata(key_id, metadata);
}

void cmp_setup_service::verify_setup_proofs(const std::string& key_id, const std::map<uint64_t, setup_zk_proofs>& proofs, std::map<uint64_t, byte_vector_t>& paillier_large_factor_proofs)
{
    verify_tenant_id(_service, _key_persistency, key_id);
    cmp_key_metadata metadata;
    _key_persistency.load_key_metadata(key_id, metadata, true);
    verify_setup_proofs(key_id, metadata, proofs);
    elliptic_curve256_point_t pubkey;
    
    auto algebra = get_algebra(metadata.algorithm);
    memcpy(pubkey, *algebra->infinity_point(algebra), sizeof(elliptic_curve256_point_t));
    bool verify = memcmp(pubkey, metadata.public_key, sizeof(elliptic_curve256_point_t)) != 0; //if public key is set we should verify it
    for (auto i = metadata.players_info.begin(); i != metadata.players_info.end(); ++i)
        throw_cosigner_exception(algebra->add_points(algebra, &pubkey, &pubkey, &i->second.public_share.data));

    if (verify)
    {
        if (memcmp(pubkey, metadata.public_key, sizeof(elliptic_curve256_point_t)) != 0)
        {
            LOG_ERROR("The sum of all public key shares is different from the public key");
            throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
        }
    }
    else
        memcpy(metadata.public_key, pubkey, sizeof(elliptic_curve256_point_t));
    _key_persistency.store_key_metadata(key_id, metadata);

    uint64_t my_id = _service.get_id_from_keyid(key_id);
    auto aad = build_aad(key_id, my_id, metadata.seed);
    auxiliary_keys aux;
    _key_persistency.load_auxiliary_keys(key_id, aux);

    for (auto i = metadata.players_info.begin(); i != metadata.players_info.end(); ++i)
    {
        if (i->first == my_id)
            continue;

        uint32_t len = 0;
        range_proof_paillier_large_factors_zkp_generate(aux.paillier.get(), i->second.ring_pedersen.get(), aad.data(), aad.size(), NULL, 0, &len);
        auto& buffer = paillier_large_factor_proofs[i->first];
        buffer.resize(len);
        throw_cosigner_exception(range_proof_paillier_large_factors_zkp_generate(aux.paillier.get(), i->second.ring_pedersen.get(), aad.data(), aad.size(), buffer.data(), buffer.size(), &len));
    }
}

void cmp_setup_service::create_secret(const std::string& key_id, const std::map<uint64_t, std::map<uint64_t, byte_vector_t>>& paillier_large_factor_proofs, std::string& public_key, cosigner_sign_algorithm& algorithm)
{
    verify_tenant_id(_service, _key_persistency, key_id);
    cmp_key_metadata metadata;
    _key_persistency.load_key_metadata(key_id, metadata, true);
    
    uint64_t my_id = _service.get_id_from_keyid(key_id);
    auxiliary_keys aux;
    _key_persistency.load_auxiliary_keys(key_id, aux);

    if (paillier_large_factor_proofs.size() != metadata.players_info.size())
    {
        LOG_ERROR("got %lu proofs but the key was created for %lu players", paillier_large_factor_proofs.size(), metadata.players_info.size());
        throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
    }

    for (auto i = paillier_large_factor_proofs.begin(); i != paillier_large_factor_proofs.end(); ++i)
    {
        if (i->first == my_id)
            continue;

        auto player_it = metadata.players_info.find(i->first);
        if (player_it == metadata.players_info.end())
        {
            LOG_ERROR("player %lu is not part of key %s", i->first, key_id.c_str());
            throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
        }

        auto proof_it = i->second.find(my_id);
        if (proof_it == i->second.end())
        {
            LOG_ERROR("missing proof from player %lu", i->first);
            throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
        }
        
        auto aad = build_aad(key_id, i->first, metadata.seed);
        auto status = range_proof_paillier_large_factors_zkp_verify(player_it->second.paillier.get(), aux.ring_pedersen.get(), aad.data(), aad.size(), proof_it->second.data(), proof_it->second.size());
        if (status != ZKP_SUCCESS)
        {
            LOG_ERROR("Failed to verify player %lu paillier key has large factors, error %d", i->first, status);
            throw_cosigner_exception(status);
        }
    }
    
    auto algebra = get_algebra(metadata.algorithm);
    public_key.assign((const char*)metadata.public_key, algebra->point_size(algebra));
    _key_persistency.delete_temporary_key_data(key_id);

    cosigner_sign_algorithm algo;
    elliptic_curve_scalar key;
    _key_persistency.load_key(key_id, algo, key.data);

    LOG_INFO("backuping keyid %s..", key_id.c_str());
    if (!_service.backup_key(key_id, metadata.algorithm, key.data, metadata, aux))
    {
        LOG_ERROR("failed to backup key id %s", key_id.c_str());
        _key_persistency.delete_temporary_key_data(key_id, true);
        throw cosigner_exception(cosigner_exception::BACKUP_FAILED);
    }

    algorithm = algo;
    LOG_INFO("key share created for keyid %s, and algorithm %s", key_id.c_str(), to_string(metadata.algorithm));
}

void cmp_setup_service::add_user_request(const std::string& key_id, cosigner_sign_algorithm algorithm, const std::string& new_key_id, const std::vector<uint64_t>& players_ids, uint8_t t, add_user_data& data)
{
    verify_tenant_id(_service, _key_persistency, key_id);
    std::set<uint64_t> distinct_players_ids(players_ids.begin(), players_ids.end()); // make the players_ids list unique

    if (distinct_players_ids.size() != players_ids.size())
    {
        LOG_ERROR("Recived add user request with duplicated player id, players_ids size %lu but only %lu uniq ones", players_ids.size(), distinct_players_ids.size());
        throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
    }
    const uint8_t n = players_ids.size();

    if (t != n)
    {
        LOG_ERROR("CMP protocol doesn't support threshold signatures");
        throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
    }

    if (!_key_persistency.key_exist(key_id))
    {
        LOG_ERROR("key id %s doesn't exists", key_id.c_str());
        throw cosigner_exception(cosigner_exception::BAD_KEY);
    }

    if (_key_persistency.key_exist(new_key_id))
    {
        LOG_ERROR("key id %s already exists", new_key_id.c_str());
        throw cosigner_exception(cosigner_exception::BAD_KEY);
    }

    if (t <= 1 || t > players_ids.size())
    {
        LOG_ERROR("invalid t = %d, for keyid = %s with %lu players", t, key_id.c_str(), players_ids.size());
        throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
    }
    if (players_ids.size() > UINT8_MAX)
    {
        LOG_ERROR("got too many players %lu for keyid = %s", players_ids.size(), key_id.c_str());
        throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
    }

    cmp_key_metadata metadata;
    _key_persistency.load_key_metadata(key_id, metadata, false);

    if (metadata.algorithm != algorithm)
    {
        LOG_ERROR("key %s has algorithm %s, but the request is for algorithm %s", key_id.c_str(), to_string(metadata.algorithm), to_string(algorithm));
        throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
    }
    auto algebra = get_algebra(algorithm);

    for (auto i = players_ids.begin(); i != players_ids.end(); ++i)
        if (metadata.players_info.find(*i) != metadata.players_info.end())
        {
            LOG_ERROR("playerid %lu is already part of key, for keyid = %s", *i, key_id.c_str());
            throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
        }

    memcpy(data.public_key.data, metadata.public_key, sizeof(elliptic_curve256_point_t));

    elliptic_curve_scalar last_share;
    cosigner_sign_algorithm algo;
    _key_persistency.load_key(key_id, algo, last_share.data);
    
    for (size_t i = 0; i < (size_t)(n - 1); i++)
    {
        uint64_t id = players_ids[i];
        elliptic_curve256_scalar_t share;
        throw_cosigner_exception(algebra->rand(algebra, &share));
        throw_cosigner_exception(algebra->sub_scalars(algebra, &last_share.data, last_share.data, sizeof(elliptic_curve256_scalar_t), share, sizeof(elliptic_curve256_scalar_t)));
        data.encrypted_shares[id] = _service.encrypt_for_player(id, byte_vector_t(share, &share[sizeof(elliptic_curve256_scalar_t)]));
        memset_s(share, sizeof(elliptic_curve256_scalar_t), 0, sizeof(elliptic_curve256_scalar_t));
    }
    
    uint64_t id = players_ids[n - 1];
    data.encrypted_shares[id] = _service.encrypt_for_player(id, byte_vector_t(last_share.data, &last_share.data[sizeof(elliptic_curve256_scalar_t)]));
}

void cmp_setup_service::add_user(const std::string& tenant_id, const std::string& key_id, cosigner_sign_algorithm algorithm, uint8_t t, const std::map<uint64_t, add_user_data>& data, uint64_t ttl, commitment& setup_commitment)
{
    if (data.size() == 0)
    {
        LOG_ERROR("Got empty add user data map");
        throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
    }

    const size_t n = data.begin()->second.encrypted_shares.size();
    for (auto i = data.begin(); i != data.end(); ++i)
    {
        if (n != i->second.encrypted_shares.size())
        {
            LOG_ERROR("Number of new player (%lu) from player %lu is different from the number of players (%lu) from player %lu", i->second.encrypted_shares.size(), i->first, n, data.begin()->first);
            throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
        }
    }

    if (!n || !t || t > n || n > UINT8_MAX || n <= 1)
        throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
    
    if (t != n)
    {
        LOG_ERROR("CMP protocol doesn't support threshold signatures");
        throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
    }

    uint64_t my_id = _service.get_id_from_keyid(key_id);
    
    if (_key_persistency.key_exist(key_id))
    {
        LOG_ERROR("key id %s already exists", key_id.c_str());
        throw cosigner_exception(cosigner_exception::BAD_KEY);
    }

    elliptic_curve256_scalar_t key = {0};
    elliptic_curve256_point_t pubkey = {0};
    auto algebra = get_algebra(algorithm);
    std::vector<uint64_t> players_ids;

    bool first = true;
    for (auto i = data.begin(); i != data.end(); ++i)
    {
        if (first)
        {
            first = false;
            memcpy(pubkey, i->second.public_key.data, sizeof(elliptic_curve256_point_t));
            for (auto j = i->second.encrypted_shares.begin(); j != i->second.encrypted_shares.end(); ++j)
                players_ids.push_back(j->first);
        }
        else
        {
            if (memcmp(pubkey, i->second.public_key.data, sizeof(elliptic_curve256_point_t)) != 0)
            {
                LOG_ERROR("Public key from player %lu is different from the key sent by player %lu", i->first, data.begin()->first);
                throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
            }
            if (i->second.encrypted_shares.size() != players_ids.size())
            {
                LOG_ERROR("Number of shares from player %lu is different from the number sent by player %lu", i->first, data.begin()->first);
                throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
            }

            for (auto j = i->second.encrypted_shares.begin(); j != i->second.encrypted_shares.end(); ++j)
            {
                if (std::find(players_ids.begin(), players_ids.end(), j->first) == players_ids.end())
                {
                    LOG_ERROR("Shares for player %lu from player %lu wasn't sent by player %lu", j->first, i->first, data.begin()->first);
                    throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
                }
            }
        }

        auto it = i->second.encrypted_shares.find(my_id);
        if (it == i->second.encrypted_shares.end())
        {
            LOG_ERROR("Player %lu didnt sent share to me", i->first);
            throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
        }
        auto share = _service.decrypt_message(it->second);
        throw_cosigner_exception(algebra->add_scalars(algebra, &key, key, sizeof(elliptic_curve256_scalar_t), (const uint8_t*)share.data(), share.size()));
    }
    generate_setup_commitments(key_id, tenant_id, algorithm, algebra, players_ids, t, ttl, key, &pubkey, setup_commitment);
    memset_s(key, sizeof(elliptic_curve256_scalar_t), 0, sizeof(elliptic_curve256_scalar_t));
}

void cmp_setup_service::generate_setup_commitments(const std::string& key_id, const std::string& tenant_id, cosigner_sign_algorithm algorithm, const elliptic_curve256_algebra_ctx_t* algebra, const std::vector<uint64_t>& players_ids, 
    uint8_t t, uint64_t ttl, const elliptic_curve256_scalar_t& key, const elliptic_curve256_point_t* pubkey, commitment& setup_commitment)
{
    setup_data temp_data;
    auto status = algebra->rand(algebra, &temp_data.k.data); 
    if (status != ELLIPTIC_CURVE_ALGEBRA_SUCCESS)
    {
        LOG_ERROR("failed to create k");
        throw cosigner_exception(cosigner_exception::INTERNAL_ERROR);
    }

    throw_cosigner_exception(algebra->generator_mul(algebra, &temp_data.public_key.data, &key));
    _service.gen_random(sizeof(commitments_sha256_t), temp_data.seed);
    auxiliary_keys aux = create_auxiliary_keys();
    
    uint64_t my_id = _service.get_id_from_keyid(key_id);
    setup_decommitment decommitment;
    create_setup_decommitment(algebra, aux, temp_data, decommitment);
    create_setup_commitment(key_id, my_id, decommitment, setup_commitment, false);
    
    // store all setup data
    uint8_t n = players_ids.size();
    cmp_key_metadata metadata;
    metadata.t = t;
    metadata.n = n;
    metadata.algorithm = algorithm;
    metadata.ttl = ttl;
    for (auto i = players_ids.begin(); i != players_ids.end(); ++i)
        metadata.players_info[*i] = cmp_player_info();
    memset(metadata.seed, 0, sizeof(commitments_sha256_t));
    memcpy(metadata.public_key, *pubkey, sizeof(elliptic_curve256_point_t));
    
    _key_persistency.store_key_metadata(key_id, metadata);
    _key_persistency.store_setup_data(key_id, temp_data);
    _key_persistency.store_keyid_tenant_id(key_id, tenant_id);
    _key_persistency.store_auxiliary_keys(key_id, aux);
    _key_persistency.store_key(key_id, algorithm, key, ttl);
    LOG_INFO("created share for key %s n = %d", key_id.c_str(), n);
}

auxiliary_keys cmp_setup_service::create_auxiliary_keys()
{
    paillier_public_key_t* paillier_pub = NULL;
    paillier_private_key_t* paillier_priv = NULL;
    long paillier_res = paillier_generate_key_pair(PAILLIER_KEY_SIZE, &paillier_pub, &paillier_priv);
    if (paillier_res != PAILLIER_SUCCESS)
    {
        LOG_ERROR("failed to create paillier  key pair, error %ld", paillier_res);
        throw_paillier_exception(paillier_res);
    }
    paillier_free_public_key(paillier_pub);
    std::shared_ptr<paillier_private_key_t> paillier_key_guard(paillier_priv, paillier_free_private_key);

    ring_pedersen_public_t* ring_pedersen_pub = NULL;
    ring_pedersen_private_t* ring_pedersen_priv = NULL;
    ring_pedersen_status ring_pedersen_res = ring_pedersen_generate_key_pair(RING_PEDERSEN_KEY_SIZE, &ring_pedersen_pub, &ring_pedersen_priv);
    if (ring_pedersen_res != RING_PEDERSEN_SUCCESS)
    {
        LOG_ERROR("failed to create ring pedersen key pair, error %d", ring_pedersen_res);
        throw_cosigner_exception(ring_pedersen_res);
    }
    ring_pedersen_free_public(ring_pedersen_pub);
    std::shared_ptr<ring_pedersen_private_t> ring_pedersen_key_guard(ring_pedersen_priv, ring_pedersen_free_private);
    return {paillier_key_guard, ring_pedersen_key_guard};
}

void cmp_setup_service::serialize_auxiliary_keys(const auxiliary_keys& aux, std::vector<uint8_t>& paillier_public_key, std::vector<uint8_t>& ring_pedersen_public_key)
{
    uint32_t size;
    paillier_public_key_serialize(paillier_private_key_get_public(aux.paillier.get()), NULL, 0, &size);
    paillier_public_key.resize(size);
    if (!paillier_public_key_serialize(paillier_private_key_get_public(aux.paillier.get()), paillier_public_key.data(), size, &size))
    {
        LOG_ERROR("failed to serialize paillier public key");
        throw cosigner_exception(cosigner_exception::INTERNAL_ERROR);
    }
    
    size = 0;
    ring_pedersen_public_serialize(ring_pedersen_private_key_get_public(aux.ring_pedersen.get()), NULL, 0, &size);
    ring_pedersen_public_key.resize(size);
    if (!ring_pedersen_public_serialize(ring_pedersen_private_key_get_public(aux.ring_pedersen.get()), ring_pedersen_public_key.data(), size, &size))
    {
        LOG_ERROR("failed to serialize ring pedersen public key");
        throw cosigner_exception(cosigner_exception::INTERNAL_ERROR);
    }
}

void cmp_setup_service::deserialize_auxiliary_keys(uint64_t id, const std::vector<uint8_t>& paillier_public_key, std::shared_ptr<paillier_public_key_t>& paillier, 
    const std::vector<uint8_t>& ring_pedersen_public_key, std::shared_ptr<ring_pedersen_public_t>& ring_pedersen)
{
    paillier.reset(paillier_public_key_deserialize(paillier_public_key.data(), paillier_public_key.size()), paillier_free_public_key);
    if (!paillier)
    {
        LOG_ERROR("failed to parse paillier public key from player %lu", id);
        throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
    }
    if (paillier_public_key_size(paillier.get()) < PAILLIER_KEY_SIZE)
    {
        LOG_ERROR("paillier public key from player %lu size %u, is smaller then the minimum key size %u", id, paillier_public_key_size(paillier.get()), PAILLIER_KEY_SIZE);
        throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
    }

    ring_pedersen.reset(ring_pedersen_public_deserialize(ring_pedersen_public_key.data(), ring_pedersen_public_key.size()), ring_pedersen_free_public);
    if (!ring_pedersen)
    {
        LOG_ERROR("failed to parse ring pedersen public key from player %lu", id);
        throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
    }
    if (ring_pedersen_public_size(ring_pedersen.get()) < RING_PEDERSEN_KEY_SIZE)
    {
        LOG_ERROR("ring pedersen public key from player %lu size %u, is smaller then the minimum key size %u", id, ring_pedersen_public_size(ring_pedersen.get()), RING_PEDERSEN_KEY_SIZE);
        throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
    }
}

void cmp_setup_service::serialize_auxiliary_keys_zkp(const auxiliary_keys& aux, const std::vector<uint8_t>& aad, std::vector<uint8_t>& paillier_blum_zkp, std::vector<uint8_t>& ring_pedersen_param_zkp)
{
    uint32_t size = 0;
    paillier_generate_paillier_blum_zkp(aux.paillier.get(), aad.data(), aad.size(), NULL, 0, &size);
    paillier_blum_zkp.resize(size);
    if (paillier_generate_paillier_blum_zkp(aux.paillier.get(), aad.data(), aad.size(), paillier_blum_zkp.data(), paillier_blum_zkp.size(), &size) != PAILLIER_SUCCESS)
    {
        LOG_ERROR("failed to generate paillier blum zkp");
        throw cosigner_exception(cosigner_exception::INTERNAL_ERROR);
    }
    
    size = 0;
    ring_pedersen_parameters_zkp_generate(aux.ring_pedersen.get(), aad.data(), aad.size(), NULL, 0, &size);
    ring_pedersen_param_zkp.resize(size);
    if (ring_pedersen_parameters_zkp_generate(aux.ring_pedersen.get(), aad.data(), aad.size(), ring_pedersen_param_zkp.data(), ring_pedersen_param_zkp.size(), &size) != ZKP_SUCCESS)
    {
        LOG_ERROR("failed to generate ring pedersen parameters zkp");
        throw cosigner_exception(cosigner_exception::INTERNAL_ERROR);
    }
}

void cmp_setup_service::create_setup_decommitment(const elliptic_curve256_algebra_ctx_t* algebra, const auxiliary_keys& aux, const setup_data& metadata, setup_decommitment& decommitment)
{
    memcpy(decommitment.seed, metadata.seed, sizeof(commitments_sha256_t));
    memcpy(decommitment.share.X.data, metadata.public_key.data, sizeof(elliptic_curve256_point_t));
    throw_cosigner_exception(algebra->generator_mul(algebra, &decommitment.share.schnorr_R.data, &metadata.k.data));
    serialize_auxiliary_keys(aux, decommitment.paillier_public_key, decommitment.ring_pedersen_public_key);
}

void cmp_setup_service::create_setup_commitment(const std::string& key_id, uint64_t id, const setup_decommitment& decommitment, commitment& setup_commitment, bool verify)
{
    commitments_ctx_t* ctx;
    commitments_status (*update_fn)(commitments_ctx_t*, const void*, uint32_t);
    if (verify)
    {
        throw_cosigner_exception(commitments_ctx_verify_new(&ctx, &setup_commitment.data));
        update_fn = commitments_ctx_verify_update;
    }
    else
    {
        throw_cosigner_exception(commitments_ctx_commitment_new(&ctx));
        update_fn = commitments_ctx_commitment_update;
    }
    std::unique_ptr<commitments_ctx_t, void (*)(commitments_ctx_t*)> ctx_guard(ctx, commitments_ctx_free);
    throw_cosigner_exception(update_fn(ctx, key_id.data(), key_id.size()));
    throw_cosigner_exception(update_fn(ctx, &id, sizeof(uint64_t)));
    throw_cosigner_exception(update_fn(ctx, decommitment.seed, sizeof(commitments_sha256_t)));
    throw_cosigner_exception(update_fn(ctx, decommitment.share.X.data, sizeof(elliptic_curve256_point_t)));
    throw_cosigner_exception(update_fn(ctx, decommitment.share.schnorr_R.data, sizeof(elliptic_curve256_point_t)));
    throw_cosigner_exception(update_fn(ctx, decommitment.paillier_public_key.data(), decommitment.paillier_public_key.size()));
    throw_cosigner_exception(update_fn(ctx, decommitment.ring_pedersen_public_key.data(), decommitment.ring_pedersen_public_key.size()));

    // the commitments ctx will be freed by commitments_ctx_verify_final/commitments_ctx_commitment_final
    ctx_guard.release();

    if (verify)
    {
        auto status = commitments_ctx_verify_final(ctx);
        if (status != COMMITMENTS_SUCCESS)
        {
            LOG_ERROR("failed to verify commitment for player %lu error %d", id, status);
            throw_cosigner_exception(status);
        }
    }
    else
        throw_cosigner_exception(commitments_ctx_commitment_final(ctx, &setup_commitment.data));
}

void cmp_setup_service::ack_message(const std::map<uint64_t, commitment>& commitments, commitments_sha256_t* ack)
{
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    for (auto i = commitments.begin(); i != commitments.end(); ++i)
    {
        SHA256_Update(&ctx, &i->first, sizeof(uint64_t));
        SHA256_Update(&ctx, &i->second.data, sizeof(commitments_commitment_t));
    }
    SHA256_Final(*ack, &ctx);
}

void cmp_setup_service::verify_and_load_setup_decommitments(const std::string& key_id, const std::map<uint64_t, commitment>& commitments, const std::map<uint64_t, setup_decommitment>& decommitments, std::map<uint64_t, cmp_player_info>& players_info)
{
    if (decommitments.size() != commitments.size())
    {
        LOG_ERROR("got %lu decommitments but the key was created for %lu players", decommitments.size(), commitments.size());
        throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
    }

    commitments_sha256_t ack;
    ack_message(commitments, &ack);

    for (auto i = commitments.begin(); i != commitments.end(); ++i)
    {
        auto decommit_it = decommitments.find(i->first);
        if (decommit_it == decommitments.end())
        {
            LOG_ERROR("missing decommitment from player %lu", i->first);
            throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
        }
        commitment commit = i->second;
        create_setup_commitment(key_id, i->first, decommit_it->second, commit, true);

        if (memcmp(ack, decommit_it->second.ack, sizeof(commitments_sha256_t)) != 0)
        {
            LOG_ERROR("ack from player %lu is different from my claculated ack", i->first);
            throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
        }

        auto& info = players_info.at(i->first);
        memcpy(info.public_share.data, decommit_it->second.share.X.data, sizeof(elliptic_curve256_point_t));
        deserialize_auxiliary_keys(i->first, decommit_it->second.paillier_public_key, info.paillier, decommit_it->second.ring_pedersen_public_key, info.ring_pedersen);
    }
}

void cmp_setup_service::generate_setup_proofs(const std::string& key_id, const elliptic_curve256_algebra_ctx_t* algebra, const setup_data& metadata, const commitments_sha256_t srid, setup_zk_proofs& proofs)
{
    auto aad = build_aad(key_id, _service.get_id_from_keyid(key_id), srid);
    auxiliary_keys aux;
    _key_persistency.load_auxiliary_keys(key_id, aux);

    serialize_auxiliary_keys_zkp(aux, aad, proofs.paillier_blum_zkp, proofs.ring_pedersen_param_zkp);
    
    schnorr_zkp_t schnorr_proof;
    {
        cosigner_sign_algorithm algo;
        elliptic_curve_scalar key;
        _key_persistency.load_key(key_id, algo, key.data);
        auto status = schnorr_zkp_generate_with_custom_randomness(algebra, aad.data(), aad.size(), &key.data, &metadata.public_key.data, &metadata.k.data, &schnorr_proof);
        throw_cosigner_exception(status);
    }
    memcpy(proofs.schnorr_s.data, schnorr_proof.s, sizeof(elliptic_curve256_scalar_t));
}

void cmp_setup_service::verify_setup_proofs(const std::string& key_id, const cmp_key_metadata& metadata, const std::map<uint64_t, setup_zk_proofs>& proofs)
{
    if (proofs.size() != metadata.players_info.size())
    {
        LOG_ERROR("got %lu proofs but the key was created for %lu players", proofs.size(), metadata.players_info.size());
        throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
    }
    setup_data temp_data;
    _key_persistency.load_setup_data(key_id, temp_data);
    
    auto algebra = get_algebra(metadata.algorithm);
    uint64_t my_id = _service.get_id_from_keyid(key_id);
    for (auto i = metadata.players_info.begin(); i != metadata.players_info.end(); ++i)
    {
        auto proof = proofs.find(i->first);
        if (proof == proofs.end())
        {
            LOG_ERROR("missing proof from player %lu", i->first);
            throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
        }
        if (i->first == my_id)
            continue;

        auto aad = build_aad(key_id, i->first, metadata.seed);
        schnorr_zkp_t schnorr;
        memcpy(schnorr.R, temp_data.players_schnorr_R.at(i->first).data, sizeof(elliptic_curve256_point_t));
        memcpy(schnorr.s, proof->second.schnorr_s.data, sizeof(elliptic_curve256_scalar_t));
        auto status = schnorr_zkp_verify(algebra, aad.data(), aad.size(), &i->second.public_share.data, &schnorr);
        if (status != ZKP_SUCCESS)
        {
            LOG_ERROR("Failed to verify schnorr zkp from player %lu", i->first);
            throw_cosigner_exception(status);
        }

        auto paillier_status = paillier_verify_paillier_blum_zkp(i->second.paillier.get(), aad.data(), aad.size(), proof->second.paillier_blum_zkp.data(), proof->second.paillier_blum_zkp.size());
        if (paillier_status != PAILLIER_SUCCESS)
        {
            LOG_ERROR("Failed to verify paillier blum zkp from player %lu", i->first);
            throw_paillier_exception(paillier_status);   
        }

        status = ring_pedersen_parameters_zkp_verify(i->second.ring_pedersen.get(), aad.data(), aad.size(), proof->second.ring_pedersen_param_zkp.data(), proof->second.ring_pedersen_param_zkp.size());
        if (status != ZKP_SUCCESS)
        {
            LOG_ERROR("Failed to verify ring pedersen parameters zkp from player %lu", i->first);
            throw_cosigner_exception(status);   
        }
    }
}

std::vector<uint8_t> cmp_setup_service::build_aad(const std::string& sid, uint64_t id, const commitments_sha256_t srid)
{
    std::vector<uint8_t> ret(sid.begin(), sid.end());
    const uint8_t* p = (uint8_t*)&id;
    std::copy(p, p + sizeof(uint64_t), std::back_inserter(ret));
    p = srid;
    std::copy(p, p + sizeof(commitments_sha256_t), std::back_inserter(ret));
    return ret;
}

elliptic_curve256_algebra_ctx_t* cmp_setup_service::get_algebra(cosigner_sign_algorithm algorithm)
{
    switch (algorithm)
    {
    case ECDSA_SECP256K1: return _secp256k1.get();
    case ECDSA_SECP256R1: return _secp256r1.get();
    case EDDSA_ED25519: return _ed25519.get();
    case ECDSA_STARK: return _stark.get();
    default:
        throw cosigner_exception(cosigner_exception::UNKNOWN_ALGORITHM);
    }
}
}
}
}