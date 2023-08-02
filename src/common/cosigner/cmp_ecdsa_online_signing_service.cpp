#include "cosigner/cmp_ecdsa_online_signing_service.h"
#include "cosigner/cmp_key_persistency.h"
#include "cosigner/platform_service.h"
#include "cosigner/mpc_globals.h"
#include "mta.h"
#include "crypto/GFp_curve_algebra/GFp_curve_algebra.h"
#include "crypto/zero_knowledge_proof/range_proofs.h"
#include "utils.h"
#include "logging/logging_t.h"

namespace fireblocks
{
namespace common
{
namespace cosigner
{

#ifdef DEBUG
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
#endif

extern "C" int gettimeofday(struct timeval *tv, struct timezone *tz);

static inline uint64_t clock()
{
    timeval tv;
	gettimeofday(&tv, NULL);
    return (uint64_t)tv.tv_sec * 1000 + (uint64_t)tv.tv_usec / 1000;
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

void cmp_ecdsa_online_signing_service::start_signing(const std::string& key_id, const std::string& txid, cosigner_sign_algorithm algorithm, const signing_data& data, const std::string& metadata_json, const std::set<std::string>& players, const std::set<uint64_t>& players_ids, std::vector<cmp_mta_request>& mta_requests)
{
    LOG_INFO("Entering txid = %s", txid.c_str());
    verify_tenant_id(_service, _key_persistency, key_id);
    cmp_key_metadata metadata;
    _key_persistency.load_key_metadata(key_id, metadata, true);

    if ((algorithm != ECDSA_SECP256K1 && algorithm != ECDSA_SECP256R1 && algorithm != ECDSA_STARK) || metadata.algorithm != algorithm)
    {
        LOG_ERROR("key %s has algorithm %s, but the request is for ECDSA %s", key_id.c_str(), to_string(metadata.algorithm), to_string(algorithm));
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
            LOG_ERROR("playerid %lu not part of key, for keyid = %s, txid = %s", *i, key_id.c_str(), txid.c_str());
            throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
        }
    }

    size_t blocks = data.blocks.size();
    if (blocks > MAX_BLOCKS_TO_SIGN)
    {
        LOG_ERROR("got too many blocks to sign %lu", blocks);
        throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
    }

    for (size_t i = 0; i < blocks; i++)
    {
        if (data.blocks[i].data.size() != sizeof(elliptic_curve256_scalar_t))
        {
            LOG_ERROR("invalid data size data size for block %lu, data must be 32 bytes", i);
            throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
        }
    }

    _service.start_signing(key_id, txid, data, metadata_json, players);

#ifdef MOBILE
    {
        std::lock_guard<std::mutex> lg(_timing_map_lock);
        _timing_map[txid] = clock();
    }
#endif

    LOG_INFO("Starting signing process keyid = %s, txid = %s", key_id.c_str(), txid.c_str());
    cmp_signing_metadata info = {key_id};
    memcpy(info.chaincode, data.chaincode, sizeof(HDChaincode));
    info.signers_ids.insert(players_ids.begin(), players_ids.end());
    info.version = common::cosigner::MPC_PROTOCOL_VERSION;

    mta_requests.reserve(blocks);
    info.sig_data.reserve(blocks);

    uint64_t my_id = _service.get_id_from_keyid(key_id);
    const auto paillier = metadata.players_info.at(my_id).paillier;
    auto aad = build_aad(key_id + txid, my_id, metadata.seed);

    auto algebra = get_algebra(metadata.algorithm);

    for (size_t i = 0; i < blocks; i++)
    {
        cmp_signature_data sig_data;
        memcpy(sig_data.message, data.blocks[i].data.data(), sizeof(elliptic_curve256_scalar_t));
        sig_data.path = data.blocks[i].path;
        sig_data.flags = NONE;
        cmp_mta_request msg = create_mta_request(sig_data, algebra, my_id, aad, metadata, paillier);
        mta_requests.push_back(std::move(msg));
        info.sig_data.push_back(std::move(sig_data));
    }
    std::vector<uint32_t> flags(blocks, 0);
    _service.fill_signing_info_from_metadata(metadata_json, flags);
    for (size_t i = 0; i < blocks; i++)
        info.sig_data[i].flags = flags[i];
    _signing_persistency.store_cmp_signing_data(txid, info);
}

uint64_t cmp_ecdsa_online_signing_service::mta_response(const std::string& txid, const std::map<uint64_t, std::vector<cmp_mta_request>>& requests, uint32_t version, cmp_mta_responses& response)
{
    (void)version;
    LOG_INFO("Entering txid = %s", txid.c_str());
    cmp_signing_metadata metadata;
    _signing_persistency.load_cmp_signing_data(txid, metadata);
    verify_tenant_id(_service, _key_persistency, metadata.key_id);

    if (requests.size() != metadata.signers_ids.size())
    {
        LOG_ERROR("got %lu mta requests but the request is for %lu players", requests.size(), metadata.signers_ids.size());
        throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
    }

#ifndef MOBILE
    {
        std::lock_guard<std::mutex> lg(_timing_map_lock);
        _timing_map[txid] = clock();
    }
#endif

    ack_mta_request(metadata.sig_data.size(), requests, metadata.signers_ids, metadata.ack);
    memcpy(response.ack, metadata.ack, sizeof(commitments_sha256_t));
    _signing_persistency.update_cmp_signing_data(txid, metadata);
    cmp_key_metadata key_md;
    _key_persistency.load_key_metadata(metadata.key_id, key_md, true);
    auto algebra = get_algebra(key_md.algorithm);
    auxiliary_keys aux;
    _key_persistency.load_auxiliary_keys(metadata.key_id, aux);

    uint64_t my_id = _service.get_id_from_keyid(metadata.key_id);

    for (auto req_it = requests.begin(); req_it != requests.end(); ++req_it)
    {
        if (req_it->first == my_id)
            continue;
        auto aad = build_aad(metadata.key_id + txid, req_it->first, key_md.seed);
        for (size_t i = 0; i < metadata.sig_data.size(); i++)
        {
            auto my_proof = req_it->second[i].mta_proofs.find(my_id);
            if (my_proof == req_it->second[i].mta_proofs.end())
            {
                LOG_ERROR("Player %lu didn't send k rddh proof to me in block %lu", req_it->first, i);
                throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
            }
            paillier_with_range_proof_t proof = {(uint8_t*)req_it->second[i].mta.message.data(), (uint32_t)req_it->second[i].mta.message.size(), (uint8_t*)my_proof->second.data(), (uint32_t)my_proof->second.size()};
            auto status = range_proof_diffie_hellman_zkpok_verify(aux.ring_pedersen.get(), key_md.players_info.at(req_it->first).paillier.get(), algebra, aad.data(), aad.size(),
                &req_it->second[i].Z.data, &req_it->second[i].A.data, &req_it->second[i].B.data, &proof);
            if (status != ZKP_SUCCESS)
            {
                LOG_ERROR("Failed to verify k rddh proof from player %lu block %lu, error %d", req_it->first, i, status);
                throw_cosigner_exception(status);
            }
        }
    }

    elliptic_curve_scalar key;
    cosigner_sign_algorithm algo;
    _key_persistency.load_key(metadata.key_id, algo, key.data);
    auto aad = build_aad(metadata.key_id + txid, my_id, key_md.seed);

    for (size_t i = 0; i < metadata.sig_data.size(); i++)
    {
        cmp_signature_data& data = metadata.sig_data[i];
        cmp_mta_response resp = create_mta_response(data, algebra, my_id, aad, key_md, requests, i, key, aux);
        response.response.push_back(std::move(resp));
    }
    _signing_persistency.update_cmp_signing_data(txid, metadata);
    return my_id;
}

uint64_t cmp_ecdsa_online_signing_service::mta_verify(const std::string& txid, const std::map<uint64_t, cmp_mta_responses>& mta_responses, std::vector<cmp_mta_deltas>& deltas)
{
    LOG_INFO("Entering txid = %s", txid.c_str());
    cmp_signing_metadata metadata;
    _signing_persistency.load_cmp_signing_data(txid, metadata);
    verify_tenant_id(_service, _key_persistency, metadata.key_id);

    if (mta_responses.size() != metadata.signers_ids.size())
    {
        LOG_ERROR("got %lu mta responses but the request is for %lu players", mta_responses.size(), metadata.signers_ids.size());
        throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
    }

    uint64_t my_id = _service.get_id_from_keyid(metadata.key_id);
    auxiliary_keys aux;
    _key_persistency.load_auxiliary_keys(metadata.key_id, aux);
    cmp_key_metadata key_md;
    _key_persistency.load_key_metadata(metadata.key_id, key_md, true);
    auto algebra = get_algebra(key_md.algorithm);

    for (auto i = metadata.signers_ids.begin(); i != metadata.signers_ids.end(); ++i)
    {
        auto it = mta_responses.find(*i);
        if (it == mta_responses.end())
        {
            LOG_ERROR("missing mta response from player %lu", *i);
            throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
        }
        if (it->first != my_id && it->second.response.size() != metadata.sig_data.size())
        {
            LOG_ERROR("got %lu mta responses from player %lu, but the request is for %lu presigning data", it->second.response.size(), *i, metadata.sig_data.size());
            throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
        }
        if (memcmp(it->second.ack, metadata.ack, sizeof(commitments_sha256_t)) != 0)
        {
            LOG_ERROR("got wrong ack from player %lu", *i);
            throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
        }
    }

    std::string uuid = metadata.key_id + txid;
    std::map<uint64_t, mta::response_verifier> verifers;
    for (auto it = mta_responses.begin(); it != mta_responses.end(); ++it)
    {
        if (it->first == my_id)
            continue;
        const auto& other = key_md.players_info.at(it->first);
        auto aad = build_aad(uuid, it->first, key_md.seed);

        mta::response_verifier verifer(it->first, algebra, aad, aux.paillier, other.paillier, aux.ring_pedersen);
        verifers.emplace(it->first, std::move(verifer));
    }

    auto aad = build_aad(uuid, my_id, key_md.seed);
    for (size_t i = 0; i < metadata.sig_data.size(); i++)
    {
        cmp_signature_data& data = metadata.sig_data[i];
        cmp_mta_deltas delta = cmp_ecdsa_signing_service::mta_verify(data, algebra, my_id, uuid, aad, key_md, mta_responses, i, aux, verifers);
        deltas.push_back(std::move(delta));
    }

    for (auto it = mta_responses.begin(); it != mta_responses.end(); ++it)
    {
        if (it->first == my_id)
            continue;
        verifers.at(it->first).verify();
    }

    _signing_persistency.update_cmp_signing_data(txid, metadata);
    return my_id;
}

uint64_t cmp_ecdsa_online_signing_service::get_si(const std::string& txid, const std::map<uint64_t, std::vector<cmp_mta_deltas>>& deltas, std::vector<elliptic_curve_scalar>& sis)
{
    LOG_INFO("Entering txid = %s", txid.c_str());
    cmp_signing_metadata metadata;
    _signing_persistency.load_cmp_signing_data(txid, metadata);
    verify_tenant_id(_service, _key_persistency, metadata.key_id);
    uint64_t my_id = _service.get_id_from_keyid(metadata.key_id);

    cmp_key_metadata key_md;
    _key_persistency.load_key_metadata(metadata.key_id, key_md, false);

    if (key_md.algorithm != ECDSA_SECP256K1 && key_md.algorithm != ECDSA_SECP256R1 && key_md.algorithm != ECDSA_STARK)
    {
        LOG_ERROR("Can't use key type %d for ECDSA", key_md.algorithm);
        throw cosigner_exception(cosigner_exception::BAD_KEY);
    }
    auto algebra = get_algebra(key_md.algorithm);

    for (auto i = metadata.signers_ids.begin(); i != metadata.signers_ids.end(); ++i)
    {
        if (*i == my_id)
            continue;
        auto it = deltas.find(*i);
        if (it == deltas.end())
        {
            LOG_ERROR("missing delta from player %lu", *i);
            throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
        }
        if (it->second.size() != metadata.sig_data.size())
        {
            LOG_ERROR("got %lu delta from player %lu, but the request is for %lu presigning data", it->second.size(), *i, metadata.sig_data.size());
            throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
        }
    }

    std::string uuid = metadata.key_id + txid;
    GFp_curve_algebra_ctx_t* curve = (GFp_curve_algebra_ctx_t*)algebra->ctx;

    elliptic_curve_scalar key;
    cosigner_sign_algorithm algo;
    _key_persistency.load_key(metadata.key_id, algo, key.data);

    for (size_t i = 0; i < metadata.sig_data.size(); i++)
    {
        cmp_signature_data& data = metadata.sig_data[i];
        calc_R(data, data.R, algebra, my_id, uuid, key_md, deltas, i);

#ifdef DEBUG
        elliptic_curve256_point_t derived_public_key;
        hd_derive_status derivation_status = derive_public_key_generic(algebra, derived_public_key, key_md.public_key, metadata.chaincode, data.path.data(), data.path.size());
        if (derivation_status != HD_DERIVE_SUCCESS)
        {
            LOG_ERROR("failed to derive public key for block %lu, error %d", i, derivation_status);
            throw cosigner_exception(cosigner_exception::INTERNAL_ERROR);
        }
        LOG_INFO("derived public key: %s", HexStr(derived_public_key, &derived_public_key[33]).c_str());
#endif

        const elliptic_curve_scalar delta = derivation_key_delta(algebra, key_md.public_key, metadata.chaincode, data.path);

        elliptic_curve256_scalar_t r;
        elliptic_curve_scalar s;
        uint8_t overflow = 0;
        throw_cosigner_exception(GFp_curve_algebra_get_point_projection(curve, &r, &data.R.data, &overflow));

        elliptic_curve256_point_t R;
        memcpy(R, data.R.data, sizeof(elliptic_curve256_point_t));

        uint8_t counter = 1;
        while (data.flags & POSITIVE_R && !is_positive(key_md.algorithm, r) && counter)
        {
            ++counter;
            throw_cosigner_exception(GFp_curve_algebra_add_points(curve, &R, &data.R.data, &R));
            throw_cosigner_exception(GFp_curve_algebra_get_point_projection(curve, &r, &R, &overflow));
        }

        if (!counter)
        {
            LOG_ERROR("failed to found positive R, WTF???");
            throw cosigner_exception(cosigner_exception::INTERNAL_ERROR);
        }

        LOG_INFO("calculating sig with R' = R * %u", counter);
        memcpy(data.R.data, R, sizeof(elliptic_curve256_point_t));

        // clac sig.s = k(m + r * delta) +r(k * x + Chi)
        elliptic_curve256_scalar_t tmp;
        throw_cosigner_exception(GFp_curve_algebra_mul_scalars(curve, &tmp, r, sizeof(elliptic_curve256_scalar_t), delta.data, sizeof(elliptic_curve256_scalar_t)));
        throw_cosigner_exception(GFp_curve_algebra_add_scalars(curve, &tmp, tmp, sizeof(elliptic_curve256_scalar_t), data.message, sizeof(elliptic_curve256_scalar_t)));
        throw_cosigner_exception(GFp_curve_algebra_mul_scalars(curve, &s.data, tmp, sizeof(elliptic_curve256_scalar_t), data.k.data, sizeof(elliptic_curve256_scalar_t)));

        throw_cosigner_exception(GFp_curve_algebra_mul_scalars(curve, &tmp, data.k.data, sizeof(elliptic_curve256_scalar_t), key.data, sizeof(elliptic_curve256_scalar_t)));
        throw_cosigner_exception(GFp_curve_algebra_add_scalars(curve, &tmp, tmp, sizeof(elliptic_curve256_scalar_t), data.chi.data, sizeof(elliptic_curve256_scalar_t)));
        throw_cosigner_exception(GFp_curve_algebra_mul_scalars(curve, &tmp, tmp, sizeof(elliptic_curve256_scalar_t), r, sizeof(elliptic_curve256_scalar_t)));
        throw_cosigner_exception(GFp_curve_algebra_add_scalars(curve, &s.data, s.data, sizeof(elliptic_curve256_scalar_t), tmp, sizeof(elliptic_curve256_scalar_t)));
        if (counter > 1)
        {
            elliptic_curve256_scalar_t counter_inverse = {0};
            counter_inverse[sizeof(elliptic_curve256_scalar_t) - 1] = counter;
            throw_cosigner_exception(GFp_curve_algebra_inverse(curve, &counter_inverse, &counter_inverse));
            throw_cosigner_exception(GFp_curve_algebra_mul_scalars(curve, &s.data, s.data, sizeof(elliptic_curve256_scalar_t), counter_inverse, sizeof(elliptic_curve256_scalar_t)));
        }
        sis.push_back(s);
    }
    _signing_persistency.update_cmp_signing_data(txid, metadata);
    return my_id;
}

uint64_t cmp_ecdsa_online_signing_service::get_cmp_signature(const std::string& txid, const std::map<uint64_t, std::vector<elliptic_curve_scalar>>& s, std::vector<recoverable_signature>& full_sig)
{
    LOG_INFO("Entering txid = %s", txid.c_str());
    cmp_signing_metadata metadata;
    _signing_persistency.load_cmp_signing_data(txid, metadata);
    verify_tenant_id(_service, _key_persistency, metadata.key_id);
    uint64_t my_id = _service.get_id_from_keyid(metadata.key_id);

    if (s.size() != metadata.signers_ids.size())
    {
        LOG_ERROR("got wrong number of s, got %lu expected %lu", s.size(), metadata.signers_ids.size());
        throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
    }
    for (auto i = metadata.signers_ids.begin(); i != metadata.signers_ids.end(); ++i)
    {
        auto it = s.find(*i);
        if (it == s.end())
        {
            LOG_ERROR("s from player %lu missing", *i);
            throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
        }
        if (it->second.size() != metadata.sig_data.size())
        {
            LOG_ERROR("number of s (%lu) from player %lu is different from block size %lu", it->second.size(), *i, metadata.sig_data.size());
            throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
        }
    }

    full_sig.clear();

    cmp_key_metadata key_md;
    _key_persistency.load_key_metadata(metadata.key_id, key_md, false);

    if (key_md.algorithm != ECDSA_SECP256K1 && key_md.algorithm != ECDSA_SECP256R1 && key_md.algorithm != ECDSA_STARK)
    {
        LOG_ERROR("Can't use key type %d for ECDSA", key_md.algorithm);
        throw cosigner_exception(cosigner_exception::BAD_KEY);
    }

    auto algebra = get_algebra(key_md.algorithm);
    GFp_curve_algebra_ctx_t* curve = (GFp_curve_algebra_ctx_t*)algebra->ctx;

    for (size_t i = 0; i < metadata.sig_data.size(); ++i)
    {
        cmp_signature_data& data = metadata.sig_data[i];
        recoverable_signature sig = {{0}, {0}, 0};
        uint8_t overflow = 0;
        throw_cosigner_exception(GFp_curve_algebra_get_point_projection(curve, &sig.r, &data.R.data, &overflow));
        sig.v = (overflow ? 2 : 0) | (is_odd_point(data.R.data) ? 1 : 0);

        for (auto it = s.begin(); it != s.end(); ++it)
            throw_cosigner_exception(GFp_curve_algebra_add_scalars(curve, &sig.s, sig.s, sizeof(elliptic_curve256_scalar_t), it->second[i].data, sizeof(elliptic_curve256_scalar_t)));
        make_sig_s_positive(key_md.algorithm, algebra, sig);

        // verify signature
        elliptic_curve256_point_t derived_public_key;
        hd_derive_status derivation_status = derive_public_key_generic(algebra, derived_public_key, key_md.public_key, metadata.chaincode, data.path.data(), data.path.size());
        if (derivation_status != HD_DERIVE_SUCCESS)
        {
            LOG_ERROR("failed to derive public key for block %lu, error %d", i, derivation_status);
            throw cosigner_exception(cosigner_exception::INTERNAL_ERROR);
        }
        
        elliptic_curve_algebra_status status = GFp_curve_algebra_verify_signature(curve, &derived_public_key, &data.message, &sig.r, &sig.s);
        if (status != ELLIPTIC_CURVE_ALGEBRA_SUCCESS)
        {
            LOG_FATAL("failed to verify signature for block %lu, error %d", i, status);
            throw cosigner_exception(cosigner_exception::INTERNAL_ERROR);
        }
        LOG_INFO("Signature validated for block %lu", i);
        full_sig.push_back(sig);
    }

    _signing_persistency.delete_signing_data(txid);

    std::lock_guard<std::mutex> time_lock(_timing_map_lock);
    auto timing_it = _timing_map.find(txid);
    if (timing_it == _timing_map.end())
    {
        LOG_WARN("transaction %s is missing from timing map??", txid.c_str());
        LOG_INFO("Finished signing transaction %s", txid.c_str());
    }
    else
    {
        uint64_t diff = (clock() - timing_it->second);
        _timing_map.erase(timing_it);
        LOG_INFO("Finished signing %lu blocks for transaction %s (tenanat %s) in %lums", full_sig.size(), txid.c_str(), _service.get_current_tenantid().c_str(), diff);
    }

    return my_id;
}

void cmp_ecdsa_online_signing_service::cancel_signing(const std::string& txid)
{
    _signing_persistency.delete_signing_data(txid);
}

}
}
}
