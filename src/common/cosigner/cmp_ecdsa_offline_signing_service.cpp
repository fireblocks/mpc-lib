#include "cosigner/cmp_ecdsa_offline_signing_service.h"
#include "cosigner/cmp_signature_preprocessed_data.h"
#include "cosigner/cmp_key_persistency.h"
#include "cosigner/platform_service.h"
#include "mta.h"
#include "utils.h"
#include "crypto/GFp_curve_algebra/GFp_curve_algebra.h"
#include "crypto/zero_knowledge_proof/range_proofs.h"
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

void cmp_ecdsa_offline_signing_service::start_ecdsa_signature_preprocessing(const std::string& tenant_id, const std::string& key_id, const std::string& request_id, uint32_t start_index, uint32_t count, uint32_t total_count, const std::set<uint64_t>& players_ids, std::vector<cmp_mta_request>& mta_requests)
{
    LOG_INFO("Entering request id = %s", request_id.c_str());
    // verify tenant id
    if (tenant_id.compare(_key_persistency.get_tenantid_from_keyid(key_id)) != 0)
    {
        LOG_ERROR("key id %s is not part of tenant %s", key_id.c_str(), tenant_id.c_str());
        throw cosigner_exception(cosigner_exception::UNAUTHORIZED);
    }
    cmp_key_metadata metadata;
    _key_persistency.load_key_metadata(key_id, metadata, true);
    
    if (metadata.players_info.size() != players_ids.size())
    {
        LOG_ERROR("CMP protocol doesn't support threshold signatures, the key was created with %lu players and the signing reques is for %lu players", metadata.players_info.size(), players_ids.size());
        throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
    }

    for (auto i = players_ids.begin(); i != players_ids.end(); ++i)
    {
        if (metadata.players_info.find(*i) == metadata.players_info.end())
        {
            LOG_ERROR("Player %lu is not part of key %s", *i, key_id.c_str());
            throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
        }
    }

    _preprocessing_persistency.create_preprocessed_data(key_id, total_count);

    preprocessing_metadata processing_metadata = {key_id, metadata.algorithm, players_ids, start_index, count};
    _preprocessing_persistency.store_preprocessing_metadata(request_id, processing_metadata);

    uint64_t my_id = _service.get_id_from_keyid(key_id);
    const auto paillier = metadata.players_info.at(my_id).paillier;
    auto aad = build_aad(key_id + request_id, my_id, metadata.seed);

    auto algebra = get_algebra(metadata.algorithm);
    
    for (size_t i = 0; i < count; i++)
    {
        ecdsa_signing_data data;
        cmp_mta_request msg = create_mta_request(data, algebra, my_id, aad, metadata, paillier);
        _preprocessing_persistency.store_preprocessing_data(request_id, start_index + i, data);
        mta_requests.push_back(std::move(msg));
    }
}

uint64_t cmp_ecdsa_offline_signing_service::offline_mta_response(const std::string& request_id, const std::map<uint64_t, std::vector<cmp_mta_request>>& requests, cmp_mta_responses& response)
{
    LOG_INFO("Entering request id = %s", request_id.c_str());
    preprocessing_metadata metadata;
    _preprocessing_persistency.load_preprocessing_metadata(request_id, metadata);
    verify_tenant_id(_service, _key_persistency, metadata.key_id);

    if (requests.size() != metadata.players_ids.size())
    {
        LOG_ERROR("got %lu mta requests but the request is for %lu players", requests.size(), metadata.players_ids.size());
        throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
    }

    ack_mta_request(metadata.count, requests, metadata.players_ids, metadata.ack);
    memcpy(response.ack, metadata.ack, sizeof(commitments_sha256_t));
    _preprocessing_persistency.store_preprocessing_metadata(request_id, metadata, true);
    auto algebra = get_algebra(metadata.algorithm);
    cmp_key_metadata key_md;
    _key_persistency.load_key_metadata(metadata.key_id, key_md, true);
    auxiliary_keys aux;
    _key_persistency.load_auxiliary_keys(metadata.key_id, aux);

    uint64_t my_id = _service.get_id_from_keyid(metadata.key_id);
    
    for (auto req_it = requests.begin(); req_it != requests.end(); ++req_it)
    {
        if (req_it->first == my_id)
            continue;
        auto aad = build_aad(metadata.key_id + request_id, req_it->first, key_md.seed);
        for (size_t i = 0; i < metadata.count; i++)
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
    auto aad = build_aad(metadata.key_id + request_id, my_id, key_md.seed);

    for (size_t i = 0; i < metadata.count; i++)
    {
        ecdsa_signing_data data;
        _preprocessing_persistency.load_preprocessing_data(request_id, metadata.start_index + i, data);
        cmp_mta_response resp = create_mta_response(data, algebra, my_id, aad, key_md, requests, i, key, aux);
        _preprocessing_persistency.store_preprocessing_data(request_id, metadata.start_index + i, data);
        response.response.push_back(std::move(resp));
    }
    return my_id;
}

uint64_t cmp_ecdsa_offline_signing_service::offline_mta_verify(const std::string& request_id, const std::map<uint64_t, cmp_mta_responses>& mta_responses, std::vector<cmp_mta_deltas>& deltas)
{
    LOG_INFO("Entering request id = %s", request_id.c_str());
    preprocessing_metadata metadata;
    _preprocessing_persistency.load_preprocessing_metadata(request_id, metadata);
    verify_tenant_id(_service, _key_persistency, metadata.key_id);

    if (mta_responses.size() != metadata.players_ids.size())
    {
        LOG_ERROR("got %lu mta responses but the request is for %lu players", mta_responses.size(), metadata.players_ids.size());
        throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
    }

    uint64_t my_id = _service.get_id_from_keyid(metadata.key_id);
    auxiliary_keys aux;
    _key_persistency.load_auxiliary_keys(metadata.key_id, aux);
    cmp_key_metadata key_md;
    _key_persistency.load_key_metadata(metadata.key_id, key_md, true);
    auto algebra = get_algebra(metadata.algorithm);

    for (auto i = metadata.players_ids.begin(); i != metadata.players_ids.end(); ++i)
    {
        auto it = mta_responses.find(*i);
        if (it == mta_responses.end())
        {
            LOG_ERROR("missing mta response from player %lu", *i);
            throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
        }
        if (it->first != my_id && it->second.response.size() != metadata.count)
        {
            LOG_ERROR("got %lu mta responses from player %lu, but the request is for %u presigning data", it->second.response.size(), *i, metadata.count);
            throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
        }
        if (memcmp(it->second.ack, metadata.ack, sizeof(commitments_sha256_t)) != 0)
        {
            LOG_ERROR("got wrong ack from player %lu", *i);
            throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
        }
    }

    std::string uuid = metadata.key_id + request_id;
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
    for (size_t i = 0; i < metadata.count; i++)
    {
        ecdsa_signing_data data;
        _preprocessing_persistency.load_preprocessing_data(request_id, metadata.start_index + i, data);
        cmp_mta_deltas delta = mta_verify(data, algebra, my_id, uuid, aad, key_md, mta_responses, i, aux, verifers);
        deltas.push_back(std::move(delta));
        _preprocessing_persistency.store_preprocessing_data(request_id, metadata.start_index + i, data);
    }

    for (auto it = mta_responses.begin(); it != mta_responses.end(); ++it)
    {
        if (it->first == my_id)
            continue;
        verifers.at(it->first).verify();
    }
    
    return my_id;
}

uint64_t cmp_ecdsa_offline_signing_service::store_presigning_data(const std::string& request_id, const std::map<uint64_t, std::vector<cmp_mta_deltas>>& deltas, std::string& key_id)
{
    LOG_INFO("Entering request id = %s", request_id.c_str());
    preprocessing_metadata metadata;
    _preprocessing_persistency.load_preprocessing_metadata(request_id, metadata);
    verify_tenant_id(_service, _key_persistency, metadata.key_id);
    uint64_t my_id = _service.get_id_from_keyid(metadata.key_id);

    // auxiliary_keys aux;
    // load_auxiliary_keys(metadata.key_id, aux);
    cmp_key_metadata key_md;
    _key_persistency.load_key_metadata(metadata.key_id, key_md, false);
    auto algebra = get_algebra(metadata.algorithm);

    for (auto i = metadata.players_ids.begin(); i != metadata.players_ids.end(); ++i)
    {
        if (*i == my_id)
            continue;
        auto it = deltas.find(*i);
        if (it == deltas.end())
        {
            LOG_ERROR("missing delta from player %lu", *i);
            throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
        }
        if (it->second.size() != metadata.count)
        {
            LOG_ERROR("got %lu delta from player %lu, but the request is for %u presigning data", it->second.size(), *i, metadata.count);
            throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
        }
    }

    std::string uuid = metadata.key_id + request_id;
    for (size_t i = 0; i < metadata.count; i++)
    {
        ecdsa_signing_data data;
        _preprocessing_persistency.load_preprocessing_data(request_id, metadata.start_index + i, data);

        elliptic_curve_point R;
        calc_R(data, R, algebra, my_id, uuid, key_md, deltas, i);
        cmp_signature_preprocessed_data sig_data = {data.k, data.chi, R};
        _preprocessing_persistency.store_preprocessed_data(metadata.key_id, metadata.start_index + i, sig_data);
    }

    _preprocessing_persistency.delete_preprocessing_data(request_id);
    key_id = metadata.key_id;
    LOG_INFO("Done preprocessing request %s, for key %s", request_id.c_str(), metadata.key_id.c_str());
    return my_id;
}

void cmp_ecdsa_offline_signing_service::ecdsa_sign(const std::string& key_id, const std::string& txid, const signing_data& data, const std::string& metadata_json, const std::set<std::string>& players, const std::set<uint64_t>& players_ids, uint64_t preprocessed_data_index, std::vector<recoverable_signature>& partial_sigs)
{
    (void)players; // UNUSED

    LOG_INFO("Entering txid = %s", txid.c_str());
    verify_tenant_id(_service, _key_persistency, key_id);

    cmp_key_metadata metadata;
    _key_persistency.load_key_metadata(key_id, metadata, false);

    if (players_ids.size() < metadata.t || players_ids.size() > metadata.n)
    {
        LOG_ERROR("got signing request for %lu players, but the key was created for %u/%u players", players_ids.size(), metadata.t, metadata.n);
        throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
    }

    for (auto i = players_ids.begin(); i != players_ids.end(); ++i)
    {
        if (metadata.players_info.find(*i) == metadata.players_info.end())
        {
            LOG_ERROR("player %lu is not part of key %s", *i, key_id.c_str());
            throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
        }
    }

    _service.start_signing(key_id, txid, data, metadata_json, players);

    elliptic_curve_scalar key;
    cosigner_sign_algorithm algo;
    _key_persistency.load_key(key_id, algo, key.data);
    if ((algo != ECDSA_SECP256K1 && algo != ECDSA_SECP256R1 && algo != ECDSA_STARK) || metadata.algorithm != algo)
    {
        LOG_ERROR("Can't sign ecdsa with this key (%u)", algo);
        throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
    }

    std::vector<uint32_t> flags(data.blocks.size(), 0);
    _service.fill_signing_info_from_metadata(metadata_json, flags);

    if (flags.size() != data.blocks.size())
    {
        LOG_ERROR("sig info size %lu is different from number of blocks to sign %lu", flags.size(), data.blocks.size());
        throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
    }

    auto algebra = get_algebra(algo);
    GFp_curve_algebra_ctx_t* curve = (GFp_curve_algebra_ctx_t*)algebra->ctx;
    for (size_t i = 0; i < data.blocks.size(); i++)
    {
        if (sizeof(elliptic_curve256_scalar_t) != data.blocks[i].data.size())
        {
            LOG_ERROR("invalid data size data size for block %lu, data must be 32 bytes", i);
            throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
        }

        cmp_signature_preprocessed_data preprocessed_data;
        _preprocessing_persistency.load_preprocessed_data(key_id, preprocessed_data_index + i, preprocessed_data);

#ifdef DEBUG
        elliptic_curve256_point_t derived_public_key;
        hd_derive_status derivation_status = derive_public_key_generic(algebra, derived_public_key, metadata.public_key, data.chaincode, data.blocks[i].path.data(), data.blocks[i].path.size());
        if (derivation_status != HD_DERIVE_SUCCESS)
        {
            LOG_ERROR("failed to derive public key for block %lu, error %d", i, derivation_status);
            throw cosigner_exception(cosigner_exception::INTERNAL_ERROR);
        }
        LOG_INFO("derived public key: %s", HexStr(derived_public_key, &derived_public_key[33]).c_str());
#endif

        const elliptic_curve_scalar delta = derivation_key_delta(algebra, metadata.public_key, data.chaincode, data.blocks[i].path);
        
        recoverable_signature sig = {{0}, {0}, 0};
        uint8_t overflow = 0;
        throw_cosigner_exception(GFp_curve_algebra_get_point_projection(curve, &sig.r, &preprocessed_data.R.data, &overflow));

        elliptic_curve256_point_t R;
        memcpy(R, preprocessed_data.R.data, sizeof(elliptic_curve256_point_t));
        
        uint8_t counter = 1;
        while (flags[i] & POSITIVE_R && !is_positive(algo, sig.r) && counter)
        {
            ++counter;
            throw_cosigner_exception(GFp_curve_algebra_add_points(curve, &R, &preprocessed_data.R.data, &R));
            throw_cosigner_exception(GFp_curve_algebra_get_point_projection(curve, &sig.r, &R, &overflow));
        }

        // the probability of not getting positive r after 255 attemps is 1/2^255
        if (!counter)
        {
            LOG_ERROR("failed to found positive R, WTF???");
            throw cosigner_exception(cosigner_exception::INTERNAL_ERROR); 
        }

        LOG_INFO("calculating sig with R' = R * %u", counter);
        
        // clac sig.s = k(m + r * delta) +r(k * x + Chi)
        elliptic_curve256_scalar_t tmp;
        throw_cosigner_exception(GFp_curve_algebra_mul_scalars(curve, &tmp, sig.r, sizeof(elliptic_curve256_scalar_t), delta.data, sizeof(elliptic_curve256_scalar_t)));
        throw_cosigner_exception(GFp_curve_algebra_add_scalars(curve, &tmp, tmp, sizeof(elliptic_curve256_scalar_t), (const uint8_t*)data.blocks[i].data.data(), data.blocks[i].data.size()));
        throw_cosigner_exception(GFp_curve_algebra_mul_scalars(curve, &sig.s, tmp, sizeof(elliptic_curve256_scalar_t), preprocessed_data.k.data, sizeof(elliptic_curve256_scalar_t)));

        throw_cosigner_exception(GFp_curve_algebra_mul_scalars(curve, &tmp, preprocessed_data.k.data, sizeof(elliptic_curve256_scalar_t), key.data, sizeof(elliptic_curve256_scalar_t)));
        throw_cosigner_exception(GFp_curve_algebra_add_scalars(curve, &tmp, tmp, sizeof(elliptic_curve256_scalar_t), preprocessed_data.chi.data, sizeof(elliptic_curve256_scalar_t)));
        throw_cosigner_exception(GFp_curve_algebra_mul_scalars(curve, &tmp, tmp, sizeof(elliptic_curve256_scalar_t), sig.r, sizeof(elliptic_curve256_scalar_t)));
        throw_cosigner_exception(GFp_curve_algebra_add_scalars(curve, &sig.s, sig.s, sizeof(elliptic_curve256_scalar_t), tmp, sizeof(elliptic_curve256_scalar_t)));
        if (counter > 1)
        {
            elliptic_curve256_scalar_t counter_inverse = {0};
            counter_inverse[sizeof(elliptic_curve256_scalar_t) - 1] = counter;
            throw_cosigner_exception(GFp_curve_algebra_inverse(curve, &counter_inverse, &counter_inverse));
            throw_cosigner_exception(GFp_curve_algebra_mul_scalars(curve, &sig.s, sig.s, sizeof(elliptic_curve256_scalar_t), counter_inverse, sizeof(elliptic_curve256_scalar_t)));
        }
        sig.v = (overflow ? 2 : 0) | (is_odd_point(R) ? 1 : 0);
        partial_sigs.push_back(sig);
    }
}

uint64_t cmp_ecdsa_offline_signing_service::ecdsa_offline_signature(const std::string& key_id, const std::string& txid, cosigner_sign_algorithm algorithm, const std::map<uint64_t, std::vector<recoverable_signature>>& partial_sigs, std::vector<recoverable_signature>& sigs)
{
    LOG_INFO("Entering txid = %s", txid.c_str());
    if (partial_sigs.empty())
    {
        LOG_ERROR("Got 0 signatures for txid %s", txid.c_str());
        throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
    }

    const auto first_player = partial_sigs.begin();
    size_t count = first_player->second.size();

    if (!count)
    {
        LOG_ERROR("Got 0 signatures from player %lu, txid %s", first_player->first, txid.c_str());
        throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
    }
    if ((algorithm != ECDSA_SECP256K1 && algorithm != ECDSA_SECP256R1 && algorithm != ECDSA_STARK))
    {
        LOG_ERROR("Can't sign ecdsa with algorithm %d", algorithm);
        throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
    }
    sigs.clear();

    auto algebra = get_algebra(algorithm);
    for (auto i = partial_sigs.begin(); i != partial_sigs.end(); ++i)
    {
        if (i->second.size() != count)
        {
            LOG_ERROR("Got %lu signatures from player %lu but %lu from player %lu, txid %s", count, first_player->first, i->second.size(), i->first, txid.c_str());
            throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
        }
    }

    for (size_t i = 0; i < count; i++)
    {
        recoverable_signature sig = first_player->second[i];
        for (auto it = partial_sigs.begin(); it != partial_sigs.end(); ++it)
        {
            if (it == first_player)
                continue;
            if (memcmp(first_player->second[i].r, it->second[i].r, sizeof(elliptic_curve256_scalar_t)) != 0)
            {
                LOG_ERROR("r value from player %lu is different from player %lu r, txid %s", first_player->first, it->first, txid.c_str());
                throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);   
            }
            if (first_player->second[i].v != it->second[i].v)
            {
                LOG_ERROR("v value from player %lu is different from player %lu v, txid %s", first_player->first, it->first, txid.c_str());
                throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);   
            }
            throw_cosigner_exception(algebra->add_scalars(algebra, &sig.s, sig.s, sizeof(elliptic_curve256_scalar_t), it->second[i].s, sizeof(elliptic_curve256_scalar_t)));
        }
        make_sig_s_positive(algorithm, algebra, sig);
        sigs.push_back(sig);
    }
    return _service.get_id_from_keyid(key_id);
}

void cmp_ecdsa_offline_signing_service::cancel_preprocessing(const std::string& request_id)
{
    _preprocessing_persistency.delete_preprocessing_data(request_id);
}

}
}
}