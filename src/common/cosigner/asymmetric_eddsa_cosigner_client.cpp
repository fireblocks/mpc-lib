#include "cosigner/asymmetric_eddsa_cosigner_client.h"
#include "cosigner/cmp_key_persistency.h"
#include "cosigner/cosigner_exception.h"
#include "cosigner/platform_service.h"
#include "cosigner/mpc_globals.h"
#include "logging/logging_t.h"
#include "utils.h"

#include <openssl/sha.h>
#include <openssl/crypto.h>
#include <inttypes.h>

namespace fireblocks
{
namespace common
{
namespace cosigner
{

template<typename T>
static inline std::string HexStr(const T itbegin, const T itend)
{
    std::string rv;
    static const char hexmap[16] = { '0', '1', '2', '3', '4', '5', '6', '7',
                                     '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };
    rv.reserve((itend-itbegin)*3);
    for(T it = itbegin; it < itend; ++it)
    {
        unsigned char val = (unsigned char)(*it);
        rv.push_back(hexmap[val>>4]);
        rv.push_back(hexmap[val&15]);
    }

    return rv;
}

asymmetric_eddsa_cosigner_client::preprocessing_persistency::~preprocessing_persistency()
{
}

asymmetric_eddsa_cosigner_client::asymmetric_eddsa_cosigner_client(platform_service& cosigner_service, const cmp_key_persistency& key_persistency, preprocessing_persistency& preprocessing_persistency) : 
    asymmetric_eddsa_cosigner(cosigner_service, key_persistency), _preprocessing_persistency(preprocessing_persistency) {}

asymmetric_eddsa_cosigner_client::~asymmetric_eddsa_cosigner_client()
{
}

void asymmetric_eddsa_cosigner_client::start_signature_preprocessing(const std::string& tenant_id, const std::string& key_id, const std::string& request_id, uint32_t start_index, uint32_t count, uint32_t total_count, const std::set<uint64_t>& players_ids, 
    std::vector<std::array<uint8_t, sizeof(commitments_sha256_t)>>& R_commitments)
{
    LOG_INFO("Entering request id = %s", request_id.c_str());
    // verify tenant id
    if (tenant_id.compare(_key_persistency.get_tenantid_from_keyid(key_id)) != 0)
    {
        LOG_ERROR("key id %s is not part of tenant %s", key_id.c_str(), tenant_id.c_str());
        throw cosigner_exception(cosigner_exception::UNAUTHORIZED);
    }
    cmp_key_metadata metadata;
    _key_persistency.load_key_metadata(key_id, metadata, false);

    if (metadata.algorithm != EDDSA_ED25519)
    {
        LOG_ERROR("Key %s was created for algorithm %d, not for ED25519 (%d)", key_id.c_str(), metadata.algorithm, EDDSA_ED25519);
        throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
    }
    
    if (metadata.players_info.size() != players_ids.size())
    {
        LOG_ERROR("asymmetric eddsa protocol doesn't support threshold signatures, the key was created with %lu players and the signing reques is for %lu players", metadata.players_info.size(), players_ids.size());
        throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
    }

    for (auto i = players_ids.begin(); i != players_ids.end(); ++i)
    {
        if (metadata.players_info.find(*i) == metadata.players_info.end())
        {
            LOG_ERROR("Player %" PRIu64 " is not part of key %s", *i, key_id.c_str());
            throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
        }
    }

    uint64_t my_id = _service.get_id_from_keyid(key_id);
    R_commitments.reserve(count);
    ed25519_algebra_ctx_t* ed25519 = (ed25519_algebra_ctx_t*)_ctx->ctx;
    _preprocessing_persistency.create_preprocessed_data(key_id, total_count);

    for (size_t i = 0; i < count; i++)
    {
        size_t index = start_index + i;
        ed25519_scalar_t k;
        ed25519_point_t R;
        throw_cosigner_exception(ed25519_algebra_rand(ed25519, &k));
        throw_cosigner_exception(ed25519_algebra_generator_mul(ed25519, &R, &k));
        R_commitments.push_back(commit_to_r(key_id, index, my_id, R));
        _preprocessing_persistency.store_preprocessed_data(key_id, index, k);
        OPENSSL_cleanse(k, sizeof(ed25519_scalar_t));
    }
}

uint64_t asymmetric_eddsa_cosigner_client::eddsa_sign_offline(const std::string& key_id, const std::string& txid, const signing_data& data, const std::string& metadata_json, const std::set<std::string>& players, const std::set<uint64_t>& players_ids, uint64_t preprocessed_data_index,
        const std::map<uint64_t, Rs_and_commitments>& Rs, std::vector<eddsa_signature>& partial_sigs)
{
    (void)players;
    LOG_INFO("Entering txid = %s", txid.c_str());
    verify_tenant_id(_service, _key_persistency, key_id);

    cmp_key_metadata metadata;
    _key_persistency.load_key_metadata(key_id, metadata, false);

    // CMP key are created using additive secret sharing, so t must be equal to n, see cmp_setup_service::generate_setup_commitments
    if (players_ids.size() != metadata.n)
    {
        LOG_ERROR("got signing request for %lu players, but the key was created for %u/%u players", players_ids.size(), metadata.t, metadata.n);
        throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
    }

    if (players_ids.size() < 2)
    {
        LOG_ERROR("We can't do asymmetric signign with  %lu < 2 players", players_ids.size());
        throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
    }

    for (auto i = players_ids.begin(); i != players_ids.end(); ++i)
    {
        if (metadata.players_info.find(*i) == metadata.players_info.end())
        {
            LOG_ERROR("player %" PRIu64 " is not part of key %s", *i, key_id.c_str());
            throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
        }
    }

    if (Rs.size() != (size_t)(metadata.t - 1))
    {
        LOG_ERROR("got Rs from %lu players, but the key was created with t = %u players", players_ids.size(), metadata.t);
        throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
    }

    size_t blocks = data.blocks.size();
    if (blocks > MAX_BLOCKS_TO_SIGN)
    {
        LOG_ERROR("got too many blocks to sign %lu", blocks);
        throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
    }

    uint64_t my_id = _service.get_id_from_keyid(key_id);
    auto first_player = Rs.begin();

    for (auto i = Rs.begin(); i != Rs.end(); ++i)
    {
        if (i->first == my_id)
        {
            LOG_ERROR("got Rs from myself");
            throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
        }
        else if (metadata.players_info.find(i->first) == metadata.players_info.end())
        {
            LOG_ERROR("got Rs from player %" PRIu64 " who is not part of key %s", i->first, key_id.c_str());
            throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
        }
        else if (i->second.Rs.size() != blocks)
        {
            LOG_ERROR("got %lu Rs from player %" PRIu64 " but the siging request is for %lu blocks", i->second.Rs.size(), i->first, blocks);
            throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
        }

        SHA256_CTX sha;
        SHA256_Init(&sha);
        SHA256_Update(&sha, txid.data(), txid.size());
        SHA256_Update(&sha, &i->first, sizeof(uint64_t));
        for (size_t j = 0; j < i->second.Rs.size(); ++j)
        {
            SHA256_Update(&sha, i->second.Rs[j].data, sizeof(elliptic_curve256_point_t));
            if (i != first_player)
            {
                if (memcmp(first_player->second.Rs[j].data, i->second.Rs[j].data, sizeof(elliptic_curve256_point_t)) != 0)
                {
                    LOG_ERROR("R indexed %lu from player %" PRIu64 " is different from player %" PRIu64 " R", j, i->first, first_player->first);
                    throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
                }
            }
        }

        eddsa_commitment md;
        SHA256_Final(md.data(), &sha);
        if (md != i->second.R_commitment)
        {
            LOG_ERROR("R commitments %s from player %" PRIu64 " is different from claculated %s", HexStr(i->second.R_commitment.begin(), i->second.R_commitment.end()).c_str(), i->first, HexStr(md.begin(), md.end()).c_str());
            throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
        }
    }
    
    ed25519_algebra_ctx_t* ed25519 = (ed25519_algebra_ctx_t*)_ctx->ctx;

    std::vector<uint32_t> flags(blocks, 0);
    _service.fill_signing_info_from_metadata(metadata_json, flags);

    elliptic_curve_scalar key;
    cosigner_sign_algorithm algo;
    _key_persistency.load_key(key_id, algo, key.data);
    if (algo != EDDSA_ED25519 || metadata.algorithm != EDDSA_ED25519)
    {
        LOG_ERROR("Can't sign eddsa with this key (%u)", algo);
        throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
    }

    partial_sigs.reserve(first_player->second.Rs.size());
    for (size_t i = 0; i < first_player->second.Rs.size(); ++i)
    {
        elliptic_curve_scalar k;
        ed25519_point_t R;
        eddsa_signature sig;
        _preprocessing_persistency.load_preprocessed_data(key_id, preprocessed_data_index + i, k.data);
        throw_cosigner_exception(ed25519_algebra_generator_mul(ed25519, &sig.R, &k.data));
        throw_cosigner_exception(ed25519_algebra_add_points(ed25519, &R, &sig.R, (ed25519_point_t*)&first_player->second.Rs[i].data));
        ed25519_point_t derived_public_key;
        ed25519_scalar_t delta;
        derivation_key_delta(metadata.public_key, data.chaincode, data.blocks[i].path, players_ids.size(), delta, derived_public_key);
        ed25519_le_scalar_t hram;
        throw_cosigner_exception(ed25519_calc_hram(ed25519, &hram, &R, &derived_public_key, (const uint8_t*)data.blocks[i].data.data(), data.blocks[i].data.size(), flags[i] & EDDSA_KECCAK));
        elliptic_curve_scalar x;
        throw_cosigner_exception(ed25519_algebra_add_scalars(ed25519, &x.data, key.data, sizeof(elliptic_curve256_scalar_t), delta, sizeof(ed25519_scalar_t)));
        throw_cosigner_exception(ed25519_algebra_be_to_le(&x.data, &x.data));
        throw_cosigner_exception(ed25519_algebra_be_to_le(&k.data, &k.data));
        throw_cosigner_exception(ed25519_algebra_mul_add(ed25519, &sig.s, &hram, &x.data, &k.data));
        throw_cosigner_exception(ed25519_algebra_le_to_be(&sig.s, &sig.s));
        ed25519_algebra_le_to_be(&hram, &hram);
        ed25519_algebra_le_to_be(&x.data, &x.data);
        partial_sigs.push_back(sig);
    }

    return my_id;
}

}
}
}
