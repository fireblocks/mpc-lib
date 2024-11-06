#include "cosigner/eddsa_online_signing_service.h"
#include "cosigner/cosigner_exception.h"
#include "cosigner/cmp_key_persistency.h"
#include "cosigner/mpc_globals.h"
#include "cosigner/platform_service.h"
#include "utils.h"
#include "logging/logging_t.h"

#include <inttypes.h>
#include <openssl/crypto.h>

namespace fireblocks
{
namespace common
{
namespace cosigner
{

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

const std::unique_ptr<elliptic_curve256_algebra_ctx_t, void(*)(elliptic_curve256_algebra_ctx_t*)> eddsa_online_signing_service::_ed25519(elliptic_curve256_new_ed25519_algebra(), elliptic_curve256_algebra_ctx_free);

eddsa_online_signing_service::signing_persistency::~signing_persistency()
{
}

eddsa_online_signing_service::eddsa_online_signing_service(platform_service& service, const cmp_key_persistency& key_persistency, signing_persistency& preprocessing_persistency):
    _service(service),
    _key_persistency(key_persistency),
    _signing_persistency(preprocessing_persistency),
    _timing_map(service) {}


void eddsa_online_signing_service::start_signing(const std::string& key_id, const std::string& txid, const signing_data& data, const std::string& metadata_json, const std::set<std::string>& players, const std::set<uint64_t>& players_ids, std::vector<commitment>& commitments)
{
    (void)players; // UNUSED

    LOG_INFO("Entering txid = %s", txid.c_str());
    commitments.clear();
    verify_tenant_id(_service, _key_persistency, key_id);
    cmp_key_metadata metadata;
    _key_persistency.load_key_metadata(key_id, metadata, false);

    if (metadata.algorithm != EDDSA_ED25519)
    {
        LOG_ERROR("key %s has algorithm %s, but the request is for eddsa", key_id.c_str(), to_string(metadata.algorithm));
        throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);    
    }

    if (players_ids.size() != metadata.t)
    {
        LOG_ERROR("invalid number of signers for keyid = %s, txid = %s, signers = %lu", key_id.c_str(), txid.c_str(), players_ids.size());
        throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
    }
    for (auto i = players_ids.begin(); i != players_ids.end(); ++i)
    {
        if (metadata.players_info.find(*i) == metadata.players_info.end())
        {
            LOG_ERROR("playerid %" PRIu64 " not part of key, for keyid = %s, txid = %s", *i, key_id.c_str(), txid.c_str());
            throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
        }
    }

    _service.start_signing(key_id, txid, data, metadata_json, players);

#ifdef MOBILE
    _timing_map.insert(txid);
#endif

    size_t blocks = data.blocks.size();
    if (blocks > MAX_BLOCKS_TO_SIGN)
    {
        LOG_ERROR("got too many blocks to sign %lu", blocks);
        throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
    }

    LOG_INFO("Starting signing process keyid = %s, txid = %s", key_id.c_str(), txid.c_str());
    eddsa_signing_metadata info = {key_id};
    memcpy(info.chaincode, data.chaincode, sizeof(HDChaincode));
    info.signers_ids.insert(players_ids.begin(), players_ids.end());
    info.version = common::cosigner::MPC_PROTOCOL_VERSION;

    commitments.reserve(blocks);
    info.sig_data.reserve(blocks);
    
    elliptic_curve_algebra_status status = ELLIPTIC_CURVE_ALGEBRA_UNKNOWN_ERROR;
    elliptic_curve256_scalar_t k;

    for (size_t i = 0; i < blocks; i++)
    {
        size_t j = 0;
        while (j < 1024 && status != ELLIPTIC_CURVE_ALGEBRA_SUCCESS)
        {
            j++;
            status = _ed25519->rand(_ed25519.get(), &k);
        }

        if (status != ELLIPTIC_CURVE_ALGEBRA_SUCCESS)
        {
            LOG_ERROR("Failed to generate k");
            throw cosigner_exception(cosigner_exception::INTERNAL_ERROR);
        }
        
        eddsa_signature_data sigdata;
        throw_cosigner_exception(_ed25519->generator_mul(_ed25519.get(), &sigdata.R.data, &k));
        throw_cosigner_exception(ed25519_algebra_be_to_le(&sigdata.k.data, &k));
        commitment commit;
        throw_cosigner_exception(commitments_create_commitment_for_data(sigdata.R.data, sizeof(elliptic_curve256_point_t), &commit.data));
        commitments.push_back(commit);

        sigdata.message = data.blocks[i].data;
        sigdata.path = data.blocks[i].path;
        sigdata.flags = NONE;
        info.sig_data.push_back(sigdata);
    }
    OPENSSL_cleanse(k, sizeof(elliptic_curve256_scalar_t));
    std::vector<uint32_t> flags(blocks, 0);
    _service.fill_signing_info_from_metadata(metadata_json, flags);
    for (size_t i = 0; i < blocks; i++)
        info.sig_data[i].flags = flags[i];
    _signing_persistency.store_signing_data(txid, info);    
}

uint64_t eddsa_online_signing_service::store_commitments(const std::string& txid, const std::map<uint64_t, std::vector<commitment>>& commitments, uint32_t version, std::vector<elliptic_curve_point>& R)
{
    LOG_INFO("Entering txid = %s", txid.c_str());

    R.clear();
    eddsa_signing_metadata data;
    _signing_persistency.load_signing_data(txid, data);
    verify_tenant_id(_service, _key_persistency, data.key_id);
    
#ifndef MOBILE
    _timing_map.insert(txid);
#endif


    const uint64_t my_id = _service.get_id_from_keyid(data.key_id);

    if (data.signers_ids.size() != commitments.size())
    {
        LOG_ERROR("commitments size %lu is different then expected size %lu", commitments.size(), data.signers_ids.size());
        throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
    }
    for (auto i = data.signers_ids.begin(); i != data.signers_ids.end(); ++i)
    {
        if (commitments.find(*i) == commitments.end())
        {
            LOG_ERROR("commitment for player %" PRIu64 " not found in commitments list", *i);
            throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS); 
        }
    }
    for (auto i = commitments.begin(); i != commitments.end(); ++i)
    {
        if (i->second.size() != data.sig_data.size())
        {
            LOG_ERROR("commitment for player %" PRIu64 " size %lu is different from block size %lu", i->first, i->second.size(), data.sig_data.size());
            throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS); 
        }
    }

    auto my_commit = commitments.find(my_id);
    assert(my_commit != commitments.end()); //should have been validated by the previous for loop
    R.reserve(data.sig_data.size());

    for (size_t i = 0; i < data.sig_data.size(); ++i)
    {
        throw_cosigner_exception(commitments_verify_commitment(data.sig_data[i].R.data, sizeof(elliptic_curve256_point_t), &my_commit->second[i].data));
        R.push_back(data.sig_data[i].R);
    }

    if (data.version != version)
    {
        data.version = version;
        _signing_persistency.update_signing_data(txid, data);
    }
    _signing_persistency.store_signing_commitments(txid, commitments);
    return my_id;
}

uint64_t eddsa_online_signing_service::broadcast_si(const std::string& txid, const std::map<uint64_t, std::vector<elliptic_curve_point>>& Rs, std::vector<elliptic_curve_scalar>& si)
{
    LOG_INFO("Entering txid = %s", txid.c_str());
    eddsa_signing_metadata data;
    _signing_persistency.load_signing_data(txid, data);
    verify_tenant_id(_service, _key_persistency, data.key_id);

    const uint64_t my_id = _service.get_id_from_keyid(data.key_id);

    if (data.signers_ids.size() != Rs.size())
    {
        LOG_ERROR("commitments size %lu is different then expected size %lu", Rs.size(), data.signers_ids.size());
        throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
    }
    for (auto i = data.signers_ids.begin(); i != data.signers_ids.end(); ++i)
    {
        if (Rs.find(*i) == Rs.end())
        {
            LOG_ERROR("commitment for player %" PRIu64 " not found in commitments list", *i);
            throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS); 
        }
    }
    for (auto i = Rs.begin(); i != Rs.end(); ++i)
    {
        if (i->second.size() != data.sig_data.size())
        {
            LOG_ERROR("commitment for player %" PRIu64 " size %lu is different from block size %lu", i->first, i->second.size(), data.sig_data.size());
            throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS); 
        }
    }

    // validate decommitments
    std::map<uint64_t, std::vector<commitment>> commitments;
    _signing_persistency.load_signing_commitments(txid, commitments);

    for (auto i = commitments.begin(); i != commitments.end(); ++i)
    {
        auto it = Rs.find(i->first);
        if (it == Rs.end())
        {
            LOG_ERROR("R from player %" PRIu64" missing", i->first);
            throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
        }

        for (size_t j = 0; j < data.sig_data.size(); ++j)
        {
            if (commitments_verify_commitment(it->second[j].data, sizeof(elliptic_curve256_point_t), &i->second[j].data) != COMMITMENTS_SUCCESS)
            {
                LOG_ERROR("failed to verify gamma commitment for player %" PRIu64, i->first);
                throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
            }
        }
    }

    cmp_key_metadata metadata;
    _key_persistency.load_key_metadata(data.key_id, metadata, false);
    ed25519_algebra_ctx_t* ed25519 = (ed25519_algebra_ctx_t*)_ed25519->ctx;
    static const PrivKey ZERO = {0};

    for (size_t i = 0; i < data.sig_data.size(); ++i)
    {
        bool first = true;

        for (auto j = Rs.begin(); j != Rs.end(); ++j)
        {
            if (first)
            {
                memcpy(data.sig_data[i].R.data, j->second[i].data, sizeof(elliptic_curve256_point_t));
                first = false;
            }
            else
                throw_cosigner_exception(_ed25519->add_points(_ed25519.get(), &data.sig_data[i].R.data, &data.sig_data[i].R.data, &j->second[i].data));
        }

        elliptic_curve256_scalar_t delta;
        elliptic_curve256_point_t derived_public_key;
        // hd_derive_status derivation_status = derive_public_key_generic(_ed25519.get(), derived_public_key, metadata.public_key, data.chaincode, data.sig_data[i].path.data(), data.sig_data[i].path.size());
        hd_derive_status derivation_status = derive_private_and_public_keys(_ed25519.get(), delta, derived_public_key, metadata.public_key, ZERO, data.chaincode, data.sig_data[i].path.data(), data.sig_data[i].path.size());
        if (derivation_status != HD_DERIVE_SUCCESS)
        {
            LOG_ERROR("failed to derive public key for block %lu, error %d", i, derivation_status);
            throw cosigner_exception(cosigner_exception::INTERNAL_ERROR);
        }

        ed25519_le_scalar_t k;
        throw_cosigner_exception(ed25519_calc_hram(ed25519, &k, (const ed25519_point_t*)&data.sig_data[i].R.data, (const ed25519_point_t*)&derived_public_key, (const uint8_t*)data.sig_data[i].message.data(), data.sig_data[i].message.size(), data.sig_data[i].flags & EDDSA_KECCAK));

        if (data.signers_ids.size() > 1)
        {
            elliptic_curve256_scalar_t inv = {0};
            inv[sizeof(elliptic_curve256_scalar_t) - 1] = (uint8_t)data.signers_ids.size();
            throw_cosigner_exception(ed25519_algebra_inverse(ed25519, &inv, &inv));
            throw_cosigner_exception(ed25519_algebra_mul_scalars(ed25519, &delta, delta, sizeof(elliptic_curve256_scalar_t), inv, sizeof(elliptic_curve256_scalar_t)));
        }

        elliptic_curve_scalar x;
        cosigner_sign_algorithm algo;
        _key_persistency.load_key(data.key_id, algo, x.data);
        throw_cosigner_exception(ed25519_algebra_add_scalars(ed25519, &x.data, delta, sizeof(elliptic_curve256_scalar_t), x.data, sizeof(elliptic_curve256_scalar_t)));
        throw_cosigner_exception(ed25519_algebra_be_to_le(&x.data, &x.data));
        elliptic_curve_scalar s;
        throw_cosigner_exception(ed25519_algebra_mul_add(ed25519, &s.data, &k, &x.data, &data.sig_data[i].k.data));
        throw_cosigner_exception(ed25519_algebra_le_to_be(&data.sig_data[i].s.data, &s.data));
        si.push_back(data.sig_data[i].s);
    }

    _signing_persistency.update_signing_data(txid, data);

    return my_id;
}

uint64_t eddsa_online_signing_service::get_eddsa_signature(const std::string& txid, const std::map<uint64_t, std::vector<elliptic_curve_scalar>>& s, std::vector<eddsa_signature>& sig)
{
    LOG_INFO("Entering txid = %s", txid.c_str());
    eddsa_signing_metadata data;
    _signing_persistency.load_signing_data(txid, data);
    verify_tenant_id(_service, _key_persistency, data.key_id);
    uint64_t my_id = _service.get_id_from_keyid(data.key_id);

    if (s.size() != data.signers_ids.size())
    {
        LOG_ERROR("got wrong number of s, got %lu expected %lu", s.size(), data.signers_ids.size());
        throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS); 
    }
    const std::vector<elliptic_curve_scalar>* my_s = NULL;
    for (auto i = data.signers_ids.begin(); i != data.signers_ids.end(); ++i)
    {
        auto it = s.find(*i);
        if (it == s.end())
        {
            LOG_ERROR("s from player %" PRIu64 " missing", *i);
            throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
        }
        if (it->second.size() != data.sig_data.size())
        {
            LOG_ERROR("number of s (%lu) from player %" PRIu64 " is different from block size %lu", it->second.size(), *i, data.sig_data.size());
            throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS); 
        }
        if (*i == my_id)
            my_s = &it->second;
    }

    if (my_s == NULL)
    {
        LOG_ERROR("inconsistent state detected in persistent storage");
        throw cosigner_exception(cosigner_exception::INTERNAL_ERROR);
    }

    sig.clear();
    auto algebra = _ed25519.get();
    ed25519_algebra_ctx_t *ed25519 = (ed25519_algebra_ctx_t*)algebra->ctx;

    cmp_key_metadata metadata;
    _key_persistency.load_key_metadata(data.key_id, metadata, false);
    
    for (size_t index = 0; index < data.sig_data.size(); ++index)
    {
        if (memcmp(my_s->at(index).data, &data.sig_data[index].s.data, sizeof(elliptic_curve_scalar)) != 0)
        {
            LOG_ERROR("missmatch between my stored s and broadcasted s");
            throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
        }

        elliptic_curve256_scalar_t s_sum = {0};

        for (auto i = s.begin(); i != s.end(); ++i)
            throw_cosigner_exception(algebra->add_scalars(algebra, &s_sum, s_sum, sizeof(elliptic_curve256_scalar_t), i->second[index].data, sizeof(elliptic_curve256_scalar_t)));
        
        eddsa_signature cur_sig;
        memcpy(cur_sig.R, data.sig_data[index].R.data, sizeof(ed25519_point_t));
        ed25519_algebra_be_to_le(&cur_sig.s, &s_sum);

        // verify signature
        elliptic_curve256_point_t derived_public_key;
        hd_derive_status derivation_status = derive_public_key_generic(algebra, derived_public_key, metadata.public_key, data.chaincode, data.sig_data[index].path.data(), data.sig_data[index].path.size());
        if (derivation_status != HD_DERIVE_SUCCESS)
        {
            LOG_ERROR("failed to derive public key for block %lu, error %d", index, derivation_status);
            throw cosigner_exception(cosigner_exception::INTERNAL_ERROR);
        }
        unsigned char raw_sig[64];
        memcpy(raw_sig, cur_sig.R, 32);
        memcpy(raw_sig + 32, cur_sig.s, 32);
        if (ed25519_verify(ed25519, (const uint8_t*)data.sig_data[index].message.data(), data.sig_data[index].message.size(), raw_sig, derived_public_key, data.sig_data[index].flags & EDDSA_KECCAK))
        {
            LOG_INFO("Signature validated for block %lu", index);
        }
        else
        {
            LOG_FATAL("failed to verify signature for block %lu, error %d", index, derivation_status);
            throw cosigner_exception(cosigner_exception::INTERNAL_ERROR);
        }

        sig.push_back(cur_sig);
    }

    _signing_persistency.delete_signing_data(txid);

    const std::optional<const uint64_t> diff = _timing_map.extract(txid);
    if (!diff)
    {
        LOG_WARN("transaction %s is missing from timing map??", txid.c_str());
        LOG_INFO("Finished signing transaction %s", txid.c_str());
    }
    else
    {
        LOG_INFO("Finished signing %lu blocks for transaction %s (tenant %s) in %" PRIu64 "ms", sig.size(), txid.c_str(), _service.get_current_tenantid().c_str(), *diff);
    }

    return my_id;
}

}
}
}