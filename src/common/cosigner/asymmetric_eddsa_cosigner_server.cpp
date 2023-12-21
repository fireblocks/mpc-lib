#include "cosigner/asymmetric_eddsa_cosigner_server.h"
#include "cosigner/cosigner_exception.h"
#include "cosigner/cmp_key_persistency.h"
#include "cosigner/platform_service.h"
#include "cosigner/mpc_globals.h"
#include "utils.h"
#include "logging/logging_t.h"

#include <openssl/sha.h>

extern "C" int gettimeofday(struct timeval *tv, struct timezone *tz);

namespace fireblocks
{
namespace common
{
namespace cosigner
{

static uint64_t clock()
{
    timeval tv;
	gettimeofday(&tv, NULL);
    return (uint64_t)tv.tv_sec * 1000 + (uint64_t)tv.tv_usec / 1000;
}

class ed25519_scalar_cleaner
{
public:
    ed25519_scalar_cleaner(ed25519_scalar_t& secret) : _secret(secret) {}
    ~ed25519_scalar_cleaner() {memset_s(_secret, sizeof(_secret), 0, sizeof(ed25519_scalar_t));}
private:
    ed25519_scalar_t& _secret;
};


asymmetric_eddsa_cosigner_server::asymmetric_eddsa_cosigner_server(platform_service& cosigner_service, const cmp_key_persistency& key_persistency, signing_persistency& signing_persistency) :
    asymmetric_eddsa_cosigner(cosigner_service, key_persistency), _signing_persistency(signing_persistency) {}

void asymmetric_eddsa_cosigner_server::store_presigning_data(const std::string& key_id, const std::string& request_id, uint32_t start_index, uint32_t count, uint32_t total_count, const std::set<uint64_t>& players_ids,
    uint64_t sender, const std::vector<eddsa_commitment>& R_commitments)
{
    LOG_INFO("Entering request id = %s", request_id.c_str());
    // verify tenant id
    verify_tenant_id(_service, _key_persistency, key_id);

    if (R_commitments.size() != count)
    {
        LOG_ERROR("Got %lu commitments but the request is for %u blocks", R_commitments.size(), count);
        throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
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

    if (!_service.is_client_id(sender))
    {
        LOG_ERROR("client id %lu is not an mobile device", sender);
        throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
    }

    for (auto i = players_ids.begin(); i != players_ids.end(); ++i)
    {
        if (metadata.players_info.find(*i) == metadata.players_info.end())
        {
            LOG_ERROR("Player %lu is not part of key %s", *i, key_id.c_str());
            throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
        }

        if (*i != sender && _service.is_client_id(*i))
        {
            LOG_ERROR("Key %s was created with more then one client device %lu, and sender %lu", key_id.c_str(), *i, sender);
            throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
        }
    }

    _signing_persistency.create_preprocessed_data(key_id, total_count);

    for (size_t i = 0; i < count; i++)
        _signing_persistency.store_preprocessed_data(key_id, start_index + i, R_commitments[i]);
}

void asymmetric_eddsa_cosigner_server::eddsa_sign_offline(const std::string& key_id, const std::string& txid, const signing_data& data, const std::string& metadata_json, const std::set<std::string>& players, const std::set<uint64_t>& players_ids, uint64_t preprocessed_data_index,
        std::vector<eddsa_commitment>& R_commitments, Rs_and_commitments& Rs)
{
    LOG_INFO("Entering txid = %s", txid.c_str());
    verify_tenant_id(_service, _key_persistency, key_id);

    cmp_key_metadata metadata;
    _key_persistency.load_key_metadata(key_id, metadata, false);

    if (metadata.algorithm != EDDSA_ED25519)
    {
        LOG_ERROR("key %s has algorithm %d, but the request is for eddsa", key_id.c_str(), metadata.algorithm);
        throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
    }

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
            LOG_ERROR("playerid %lu not part of key, for keyid = %s, txid = %s", *i, key_id.c_str(), txid.c_str());
            throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
        }
    }

    _service.start_signing(key_id, txid, data, metadata_json, players);
    size_t blocks = data.blocks.size();
    if (blocks > MAX_BLOCKS_TO_SIGN)
    {
        LOG_ERROR("got too many blocks to sign %lu", blocks);
        throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
    }

    {
        std::lock_guard<std::mutex> lg(_timing_map_lock);
        _timing_map[txid] = clock();
    }
    
    uint64_t my_id = _service.get_id_from_keyid(key_id);

    LOG_INFO("Starting signing process keyid = %s, txid = %s", key_id.c_str(), txid.c_str());
    asymmetric_eddsa_signing_metadata info = {key_id};
    memcpy(info.chaincode, data.chaincode, sizeof(HDChaincode));
    info.signers_ids.insert(players_ids.begin(), players_ids.end());
    info.version = common::cosigner::MPC_PROTOCOL_VERSION;
    info.start_index = preprocessed_data_index;

    R_commitments.reserve(blocks);
    Rs.Rs.reserve(blocks);
    info.sig_data.reserve(blocks);

    elliptic_curve_algebra_status status = ELLIPTIC_CURVE_ALGEBRA_UNKNOWN_ERROR;
    elliptic_curve256_scalar_t k;

    for (size_t i = 0; i < blocks; i++)
    {
        size_t j = 0;
        while (j < 1024 && status != ELLIPTIC_CURVE_ALGEBRA_SUCCESS)
        {
            j++;
            status = _ctx->rand(_ctx.get(), &k);
        }

        if (status != ELLIPTIC_CURVE_ALGEBRA_SUCCESS)
        {
            LOG_ERROR("Failed to generate k");
            throw cosigner_exception(cosigner_exception::INTERNAL_ERROR);
        }

        asymmetric_eddsa_signature_data sigdata;
        throw_cosigner_exception(_ctx->generator_mul(_ctx.get(), &sigdata.R.data, &k));
        throw_cosigner_exception(ed25519_algebra_be_to_le(&sigdata.k.data, &k));

        if (metadata.n == 2)
        {
            LOG_INFO("Doing MPC 2/2 no need to send commitments");
            Rs.Rs.push_back(sigdata.R);
        }
        else
        {
            ed25519_point_t R;
            memcpy(&R, &sigdata.R.data, sizeof(ed25519_point_t));
            R_commitments.push_back(commit_to_r(txid, i + preprocessed_data_index, my_id, R));
        }

        sigdata.message = data.blocks[i].data;
        sigdata.path = data.blocks[i].path;
        sigdata.flags = NONE;
        info.sig_data.push_back(sigdata);
    }
    if (metadata.n > 2)
    {
        Rs.Rs.clear();
    }
    else
    {
        commit_to_Rs(txid, my_id, Rs.Rs, Rs.R_commitment);
    }
    memset_s(k, sizeof(elliptic_curve256_scalar_t), 0, sizeof(elliptic_curve256_scalar_t));
    std::vector<uint32_t> flags(blocks, 0);
    _service.fill_signing_info_from_metadata(metadata_json, flags);
    for (size_t i = 0; i < blocks; i++)
        info.sig_data[i].flags = flags[i];
    _signing_persistency.store_signing_data(txid, info, false);
}

uint64_t asymmetric_eddsa_cosigner_server::decommit_r(const std::string& txid, const std::map<uint64_t, std::vector<eddsa_commitment>>& commitments, std::vector<elliptic_curve_point>& Rs)
{
    LOG_INFO("Entering txid = %s", txid.c_str());
    Rs.clear();
    asymmetric_eddsa_signing_metadata data;
    _signing_persistency.load_signing_data(txid, data);
    verify_tenant_id(_service, _key_persistency, data.key_id);

    const uint64_t my_id = _service.get_id_from_keyid(data.key_id);

    if (data.signers_ids.size() - 1 != commitments.size())
    {
        LOG_ERROR("commitments size %lu is different then expected size %lu", commitments.size(), data.signers_ids.size() - 1);
        throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
    }
    for (auto i = data.signers_ids.begin(); i != data.signers_ids.end(); ++i)
    {
        if (!_service.is_client_id(*i) && commitments.find(*i) == commitments.end())
        {
            LOG_ERROR("commitment for player %lu not found in commitments list", *i);
            throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
        }
    }
    for (auto i = commitments.begin(); i != commitments.end(); ++i)
    {
        if (i->second.size() != data.sig_data.size())
        {
            LOG_ERROR("commitment for player %lu size %lu is different from block size %lu", i->first, i->second.size(), data.sig_data.size());
            throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
        }
    }

    auto my_commit = commitments.find(my_id);
    assert(my_commit != commitments.end()); //should have been validated by the previous for loop
    Rs.reserve(data.sig_data.size());

    for (size_t i = 0; i < data.sig_data.size(); ++i)
    {
        if (!verify_commit_to_r(my_commit->second[i], txid, i + data.start_index, my_id, data.sig_data[i].R.data))
        {
            LOG_ERROR("Failed to verify my commitment to block %lu", i);
            throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
        }
        Rs.push_back(data.sig_data[i].R);
    }

    _signing_persistency.store_commitments(txid, commitments);
    return my_id;
}

uint64_t asymmetric_eddsa_cosigner_server::broadcast_r(const std::string& txid, const std::map<uint64_t, std::vector<elliptic_curve_point>>& players_R, Rs_and_commitments& Rs, uint64_t& send_to)
{
    LOG_INFO("Entering txid = %s", txid.c_str());
    Rs.Rs.clear();
    asymmetric_eddsa_signing_metadata data;
    _signing_persistency.load_signing_data(txid, data);
    verify_tenant_id(_service, _key_persistency, data.key_id);

    const uint64_t my_id = _service.get_id_from_keyid(data.key_id);

    if (data.signers_ids.size() - 1 != players_R.size())
    {
        LOG_ERROR("Rs size %lu is different then expected size %lu", players_R.size(), data.signers_ids.size() - 1);
        throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
    }
    for (auto i = data.signers_ids.begin(); i != data.signers_ids.end(); ++i)
    {
        if (_service.is_client_id(*i))
            send_to = *i;
        else if (players_R.find(*i) == players_R.end())
        {
            LOG_ERROR("Rs for player %lu not found in Rs list", *i);
            throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
        }
    }
    for (auto i = players_R.begin(); i != players_R.end(); ++i)
    {
        if (i->second.size() != data.sig_data.size())
        {
            LOG_ERROR("Rs for player %lu size %lu is different from block size %lu", i->first, i->second.size(), data.sig_data.size());
            throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
        }
    }

    std::map<uint64_t, std::vector<eddsa_commitment>> commitments;
    _signing_persistency.load_commitments(txid, commitments);
    for (auto i = commitments.begin(); i != commitments.end(); ++i)
    {
        auto it = players_R.find(i->first);
        if (it == players_R.end())
        {
            LOG_ERROR("R from player %lu missing", i->first);
            throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
        }

        for (size_t j = 0; j < data.sig_data.size(); ++j)
        {
            if (!verify_commit_to_r(i->second[j], txid, j + data.start_index, i->first, it->second[j].data))
            {
                LOG_ERROR("Failed to verify commitment from player %lu to block %lu", i->first, j);
                throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
            }

            if (i->first != my_id)
            {
                throw_cosigner_exception(_ctx->add_points(_ctx.get(), &data.sig_data[j].R.data, &data.sig_data[j].R.data, &it->second[j].data));
            }
        }
    }
    _signing_persistency.delete_commitments(txid);

    Rs.Rs.reserve(data.sig_data.size());
    for (size_t i = 0; i < data.sig_data.size(); ++i)
        Rs.Rs.push_back(data.sig_data[i].R);
    commit_to_Rs(txid, my_id, Rs.Rs, Rs.R_commitment);
    _signing_persistency.store_signing_data(txid, data, true);

    return my_id;
}

uint64_t asymmetric_eddsa_cosigner_server::broadcast_si(const std::string& txid, uint64_t sender, uint32_t version, const std::vector<eddsa_signature>& partial_sigs, std::vector<eddsa_signature>& sigs, std::set<uint64_t>& send_to, bool& final_signature)
{
    (void)version;
    LOG_INFO("Entering txid = %s", txid.c_str());
    sigs.clear();
    asymmetric_eddsa_signing_metadata data;
    _signing_persistency.load_signing_data(txid, data);
    verify_tenant_id(_service, _key_persistency, data.key_id);

    const uint64_t my_id = _service.get_id_from_keyid(data.key_id);

    if (data.signers_ids.find(sender) == data.signers_ids.end())
    {
        LOG_ERROR("player %lu is not part of signers list", sender);
        throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
    }

    if (partial_sigs.size() != data.sig_data.size())
    {
        LOG_ERROR("partial sigs from player %lu size %lu is different from block size %lu", sender, partial_sigs.size(), data.sig_data.size());
        throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
    }
    ed25519_algebra_ctx_t* ed25519 = (ed25519_algebra_ctx_t*)_ctx->ctx;

    cmp_key_metadata metadata;
    _key_persistency.load_key_metadata(data.key_id, metadata, false);

    auto sender_info = metadata.players_info.find(sender);
    if (sender_info == metadata.players_info.end())
    {
        LOG_ERROR("player %lu is not part of key %s", sender, data.key_id.c_str());
        assert(0);
        throw cosigner_exception(cosigner_exception::INTERNAL_ERROR);
    }

    elliptic_curve_scalar key;
    cosigner_sign_algorithm algo;
    _key_persistency.load_key(data.key_id, algo, key.data);
    if (algo != EDDSA_ED25519)
    {
        LOG_ERROR("Can't sign eddsa with this key (%u)", algo);
        throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
    }

    const bool final_sig = data.signers_ids.size() == 2;
    send_to = data.signers_ids;
    send_to.erase(sender);

    uint64_t min_signer_id = *send_to.begin();
    if (my_id == min_signer_id)
    {
        LOG_INFO("My id %lu is the min id, will add client s to my s", my_id);
    }

    sigs.reserve(data.sig_data.size());
    for (size_t i = 0; i < partial_sigs.size(); ++i)
    {
        eddsa_commitment commitment;
        _signing_persistency.load_preprocessed_data(data.key_id, data.start_index + i, commitment);
        if (!verify_commit_to_r(commitment, data.key_id, i + data.start_index, sender, partial_sigs[i].R))
        {
            LOG_ERROR("Failed to verify commitment from player %lu to block %lu", sender, i);
            throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
        }
        eddsa_signature sig;
        throw_cosigner_exception(ed25519_algebra_add_points(ed25519, &sig.R, (ed25519_point_t*)&data.sig_data[i].R.data, &partial_sigs[i].R));

        ed25519_point_t derived_public_key;
        ed25519_scalar_t delta;
        derivation_key_delta(metadata.public_key, data.chaincode, data.sig_data[i].path, data.signers_ids.size(), delta, derived_public_key);
        ed25519_le_scalar_t hram;
        throw_cosigner_exception(ed25519_calc_hram(ed25519, &hram, &sig.R, &derived_public_key, (const uint8_t*)data.sig_data[i].message.data(), data.sig_data[i].message.size(), data.sig_data[i].flags & EDDSA_KECCAK));
        if (!verify_client_s(partial_sigs[i].R, partial_sigs[i].s, hram, sender_info->second.public_share, delta))
        {
            LOG_ERROR("Failed to verify the signature s sent by client %lu for block %lu txid %s", sender, i, txid.c_str());
            throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
        }
        ed25519_scalar_t x;
        throw_cosigner_exception(ed25519_algebra_add_scalars(ed25519, &x, key.data, sizeof(elliptic_curve256_scalar_t), delta, sizeof(ed25519_scalar_t)));
        ed25519_scalar_cleaner xcleaner(x);
        throw_cosigner_exception(ed25519_algebra_be_to_le(&x, &x));
        throw_cosigner_exception(ed25519_algebra_mul_add(ed25519, &sig.s, &hram, &x, &data.sig_data[i].k.data));

        if (final_sig)
        {
            // send the full signature
            ed25519_le_scalar_t s;
            throw_cosigner_exception(ed25519_algebra_be_to_le(&s, &partial_sigs[i].s));
            throw_cosigner_exception(ed25519_algebra_add_le_scalars(ed25519, &sig.s, &sig.s, &s));

            unsigned char raw_sig[64];
            memcpy(raw_sig, sig.R, 32);
            memcpy(raw_sig + 32, sig.s, 32);
            if (ed25519_verify(ed25519, (const uint8_t*)data.sig_data[i].message.data(), data.sig_data[i].message.size(), raw_sig, derived_public_key, data.sig_data[i].flags & EDDSA_KECCAK))
            {
                LOG_INFO("Signature validated for block %lu", i);
            }
            else
            {
                LOG_FATAL("failed to verify signature for block %lu", i);
                throw cosigner_exception(cosigner_exception::INTERNAL_ERROR);
            }
        }
        else
        {
            throw_cosigner_exception(ed25519_algebra_le_to_be(&sig.s, &sig.s));
            if (my_id == min_signer_id)
                throw_cosigner_exception(ed25519_algebra_add_scalars(ed25519, &sig.s, sig.s, sizeof(ed25519_scalar_t), partial_sigs[i].s, sizeof(ed25519_scalar_t)));
            memcpy(data.sig_data[i].R.data, sig.R, sizeof(ed25519_point_t));

        }
        sigs.push_back(sig);
    }

    if (final_sig)
    {
        _signing_persistency.delete_signing_data(txid);

        std::lock_guard<std::mutex> time_lock(_timing_map_lock);
        auto timing_it = _timing_map.find(txid);
        if (timing_it == _timing_map.end())
        {
            LOG_WARN("transaction %s is missing from timing map??", txid.c_str());
            LOG_INFO("Finished signing trnsaction %s", txid.c_str());
        }
        else
        {
            uint64_t diff = (clock() - timing_it->second);
            _timing_map.erase(timing_it);
            LOG_INFO("Finished signing %lu blocks for transaction %s (tenanat %s) in %lums", data.signers_ids.size(), txid.c_str(), _service.get_current_tenantid().c_str(), diff);
        }
    }
    else
        _signing_persistency.store_signing_data(txid, data, true);
    final_signature = final_sig;

    return my_id;
}

uint64_t asymmetric_eddsa_cosigner_server::get_eddsa_signature(const std::string& txid, const std::map<uint64_t, std::vector<eddsa_signature>>& partial_sigs, std::vector<eddsa_signature>& sigs)
{
    LOG_INFO("Entering txid = %s", txid.c_str());
    sigs.clear();
    asymmetric_eddsa_signing_metadata data;
    _signing_persistency.load_signing_data(txid, data);
    verify_tenant_id(_service, _key_persistency, data.key_id);
    const uint64_t my_id = _service.get_id_from_keyid(data.key_id);

    if (partial_sigs.size() != data.signers_ids.size() - 1)
    {
        LOG_ERROR("got wrong number of s, got %lu expected %lu", partial_sigs.size(), data.signers_ids.size() - 1);
        throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
    }

    for (auto i = data.signers_ids.begin(); i != data.signers_ids.end(); ++i)
    {
        auto it = partial_sigs.find(*i);
        if (_service.is_client_id(*i))
            continue;
        if (it == partial_sigs.end())
        {
            LOG_ERROR("partial sig for player %lu not found in Rs list", *i);
            throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
        }
        if (it->second.size() != data.sig_data.size())
        {
            LOG_ERROR("number of s (%lu) from player %lu is different from block size %lu", it->second.size(), *i, data.sig_data.size());
            throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
        }
    }

    ed25519_algebra_ctx_t *ed25519 = (ed25519_algebra_ctx_t*)_ctx->ctx;

    cmp_key_metadata metadata;
    _key_persistency.load_key_metadata(data.key_id, metadata, false);
    
    for (size_t index = 0; index < data.sig_data.size(); ++index)
    {
        eddsa_signature cur_sig;
        memcpy(cur_sig.R, data.sig_data[index].R.data, sizeof(ed25519_point_t));
        memset(&cur_sig.s, 0, sizeof(ed25519_scalar_t));
        for (auto i = partial_sigs.begin(); i != partial_sigs.end(); ++i)
        {
            if (memcmp(cur_sig.R, i->second[index].R, sizeof(ed25519_point_t)) != 0)
            {
                LOG_ERROR("R from player %lu is different from stored R", i->first);
                throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
            }
            ed25519_le_scalar_t s;
            throw_cosigner_exception(ed25519_algebra_be_to_le(&s, &i->second[index].s));
            throw_cosigner_exception(ed25519_algebra_add_le_scalars(ed25519, &cur_sig.s, &cur_sig.s, &s));
        }

        // verify signature
        elliptic_curve256_point_t derived_public_key;
        hd_derive_status derivation_status = derive_public_key_generic(_ctx.get(), derived_public_key, metadata.public_key, data.chaincode, data.sig_data[index].path.data(), data.sig_data[index].path.size());
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
            LOG_FATAL("failed to verify signature for block %lu", index);
            throw cosigner_exception(cosigner_exception::INTERNAL_ERROR);
        }

        sigs.push_back(cur_sig);
    }

    _signing_persistency.delete_signing_data(txid);

    std::lock_guard<std::mutex> time_lock(_timing_map_lock);
    auto timing_it = _timing_map.find(txid);
    if (timing_it == _timing_map.end())
    {
        LOG_WARN("transaction %s is missing from timing map??", txid.c_str());
        LOG_INFO("Finished signing trnsaction %s", txid.c_str());
    }
    else
    {
        uint64_t diff = (clock() - timing_it->second);
        _timing_map.erase(timing_it);
        LOG_INFO("Finished signing %lu blocks for transaction %s (tenanat %s) in %lums", sigs.size(), txid.c_str(), _service.get_current_tenantid().c_str(), diff);
    }

    return my_id;
}

bool asymmetric_eddsa_cosigner_server::verify_client_s(const ed25519_point_t& R, const ed25519_scalar_t& s, const ed25519_le_scalar_t& hram, const elliptic_curve_point& public_share, const ed25519_scalar_t& delta)
{
    elliptic_curve256_point_t p1, p2;
    ed25519_scalar_t e;
    throw_cosigner_exception(ed25519_algebra_le_to_be(&e, &hram));
    throw_cosigner_exception(_ctx->generator_mul(_ctx.get(), &p1, &s));

    throw_cosigner_exception(_ctx->generator_mul(_ctx.get(), &p2, &delta));
    throw_cosigner_exception(_ctx->add_points(_ctx.get(), &p2, &p2, &public_share.data));
    throw_cosigner_exception(_ctx->point_mul(_ctx.get(), &p2, &p2, &e));
    elliptic_curve256_point_t R_point;
    memcpy(R_point, R, sizeof(ed25519_point_t));
    R_point[sizeof(elliptic_curve256_point_t) - 1] = 0;
    throw_cosigner_exception(_ctx->add_points(_ctx.get(), &p2, &p2, &R_point));

    return memcmp(p1, p2, sizeof(elliptic_curve256_point_t)) == 0;
}

void asymmetric_eddsa_cosigner_server::cancel_signing(const std::string& txid)
{
    _signing_persistency.delete_commitments(txid);
    _signing_persistency.delete_signing_data(txid);
}

void asymmetric_eddsa_cosigner_server::commit_to_Rs(const std::string& txid, uint64_t id, const std::vector<elliptic_curve_point>& Rs, eddsa_commitment& commitment)
{
    SHA256_CTX sha;
    SHA256_Init(&sha);
    SHA256_Update(&sha, txid.data(), txid.size());
    SHA256_Update(&sha, &id, sizeof(uint64_t));
    for (size_t i = 0; i < Rs.size(); ++i)
    {
        SHA256_Update(&sha, Rs[i].data, sizeof(elliptic_curve256_point_t));
    }
    SHA256_Final(commitment.data(), &sha);
}

}
}
}
