#include "cosigner/cmp_ecdsa_signing_service.h"
#include "cosigner/cmp_key_persistency.h"
#include "mta.h"
#include "crypto/GFp_curve_algebra/GFp_curve_algebra.h"
#include "crypto/zero_knowledge_proof/diffie_hellman_log.h"
#include "crypto/zero_knowledge_proof/range_proofs.h"
#include "logging/logging_t.h"

#include <openssl/sha.h>

#include <inttypes.h>

namespace fireblocks
{
namespace common
{
namespace cosigner
{

const std::unique_ptr<elliptic_curve256_algebra_ctx_t, void(*)(elliptic_curve256_algebra_ctx_t*)> cmp_ecdsa_signing_service::_secp256k1(elliptic_curve256_new_secp256k1_algebra(), elliptic_curve256_algebra_ctx_free);
const std::unique_ptr<elliptic_curve256_algebra_ctx_t, void(*)(elliptic_curve256_algebra_ctx_t*)> cmp_ecdsa_signing_service::_secp256r1(elliptic_curve256_new_secp256r1_algebra(), elliptic_curve256_algebra_ctx_free);
const std::unique_ptr<elliptic_curve256_algebra_ctx_t, void(*)(elliptic_curve256_algebra_ctx_t*)> cmp_ecdsa_signing_service::_stark(elliptic_curve256_new_stark_algebra(), elliptic_curve256_algebra_ctx_free);

cmp_ecdsa_signing_service::~cmp_ecdsa_signing_service()
{
}

cmp_mta_request cmp_ecdsa_signing_service::create_mta_request(ecdsa_signing_data& data, const elliptic_curve256_algebra_ctx_t* algebra, uint64_t my_id, const std::vector<uint8_t>& aad, const cmp_key_metadata& metadata, const std::shared_ptr<paillier_public_key_t>& paillier)
{
    throw_cosigner_exception(algebra->rand(algebra, &data.k.data));
    throw_cosigner_exception(algebra->rand(algebra, &data.a.data));
    throw_cosigner_exception(algebra->rand(algebra, &data.b.data));
    throw_cosigner_exception(algebra->rand(algebra, &data.gamma.data));
    throw_cosigner_exception(algebra->mul_scalars(algebra, &data.delta.data, data.k.data, sizeof(elliptic_curve256_scalar_t), data.gamma.data, sizeof(elliptic_curve256_scalar_t)));
    memset(data.chi.data, 0, sizeof(elliptic_curve256_scalar_t));

    throw_cosigner_exception(algebra->generator_mul(algebra, &data.GAMMA.data, &data.gamma.data));

    cmp_mta_request msg;
    throw_cosigner_exception(algebra->generator_mul(algebra, &msg.A.data, &data.a.data));
    throw_cosigner_exception(algebra->generator_mul(algebra, &msg.B.data, &data.b.data));
    elliptic_curve256_scalar_t tmp;
    throw_cosigner_exception(algebra->mul_scalars(algebra, &tmp, data.a.data, sizeof(elliptic_curve256_scalar_t), data.b.data, sizeof(elliptic_curve256_scalar_t)));
    throw_cosigner_exception(algebra->add_scalars(algebra, &tmp, tmp, sizeof(elliptic_curve256_scalar_t), data.k.data, sizeof(elliptic_curve256_scalar_t)));
    throw_cosigner_exception(algebra->generator_mul(algebra, &msg.Z.data, &tmp));
    msg.mta = mta::request(my_id, algebra, data.k, data.gamma, data.a, data.b, aad, paillier, metadata.players_info, msg.mta_proofs, data.G_proofs);

    data.mta_request = msg.mta.message;
    return msg;
}

void cmp_ecdsa_signing_service::ack_mta_request(uint32_t count, const std::map<uint64_t, std::vector<cmp_mta_request>>& requests, const std::set<uint64_t>& players_ids, commitments_sha256_t& ack)
{
    SHA256_CTX ctx;
    SHA256_Init(&ctx);

    for (auto i = players_ids.begin(); i != players_ids.end(); ++i)
    {
        auto it = requests.find(*i);
        if (it == requests.end())
        {
            LOG_ERROR("missing commitment from player %" PRIu64, *i);
            throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
        }
        else if (it->second.size() != count)
        {
            LOG_ERROR("got %lu mta requests from player %" PRIu64 ", but the request is for %" PRIu32 " presigning data", it->second.size(), *i, count);
            throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
        }
        SHA256_Update(&ctx, &it->first, sizeof(uint64_t));
        for (auto j = it->second.begin(); j < it->second.end(); ++j)
        {
            SHA256_Update(&ctx, j->A.data, sizeof(elliptic_curve256_point_t));
            SHA256_Update(&ctx, j->B.data, sizeof(elliptic_curve256_point_t));
            SHA256_Update(&ctx, j->Z.data, sizeof(elliptic_curve256_point_t));
            SHA256_Update(&ctx, j->mta.message.data(), j->mta.message.size());
            SHA256_Update(&ctx, j->mta.commitment.data(), j->mta.commitment.size());

            for (auto k = j->mta_proofs.begin(); k != j->mta_proofs.end(); ++k)
            {
                SHA256_Update(&ctx, &k->first, sizeof(uint64_t));
                SHA256_Update(&ctx, k->second.data(), k->second.size());
            }
        }
    }
    SHA256_Final(ack, &ctx);
}

cmp_mta_response cmp_ecdsa_signing_service::create_mta_response(ecdsa_signing_data& data, const elliptic_curve256_algebra_ctx_t* algebra, uint64_t my_id, const std::vector<uint8_t>& aad, const cmp_key_metadata& metadata,
    const std::map<uint64_t, std::vector<cmp_mta_request>>& requests, size_t index, const elliptic_curve_scalar& key, const auxiliary_keys& aux_keys)
{
    cmp_mta_response resp;
    resp.GAMMA = data.GAMMA;

    for (auto j = data.G_proofs.begin(); j != data.G_proofs.end(); ++j)
        resp.gamma_proofs[j->first] = std::move(j->second);
    data.G_proofs.clear();

    for (auto req_it = requests.begin(); req_it != requests.end(); ++req_it)
    {
        if (req_it->first == my_id)
            continue;
        const auto& other = metadata.players_info.at(req_it->first);
        auto& gamma_mta = resp.k_gamma_mta[req_it->first];
        auto beta = mta::answer_mta_request(algebra, req_it->second[index].mta, data.gamma.data, sizeof(elliptic_curve256_scalar_t), aad, aux_keys.paillier, other.paillier, other.ring_pedersen, gamma_mta);
        throw_cosigner_exception(algebra->sub_scalars(algebra, &data.delta.data, data.delta.data, sizeof(elliptic_curve256_scalar_t), beta.data, sizeof(elliptic_curve256_scalar_t)));
        auto& x_mta = resp.k_x_mta[req_it->first];
        beta = mta::answer_mta_request(algebra, req_it->second[index].mta, key.data, sizeof(elliptic_curve256_scalar_t), aad, aux_keys.paillier, other.paillier, other.ring_pedersen, x_mta);
        throw_cosigner_exception(algebra->sub_scalars(algebra, &data.chi.data, data.chi.data, sizeof(elliptic_curve256_scalar_t), beta.data, sizeof(elliptic_curve256_scalar_t)));
        auto& pub = data.public_data[req_it->first];
        pub.A = req_it->second[index].A;
        pub.B = req_it->second[index].B;
        pub.Z = req_it->second[index].Z;

        pub.gamma_commitment = std::move(req_it->second[index].mta.commitment);
    }
    return resp;
}

cmp_mta_deltas cmp_ecdsa_signing_service::mta_verify(
    ecdsa_signing_data& data, //this block singing data
    const elliptic_curve256_algebra_ctx_t* algebra, 
    uint64_t my_id,
    const std::string& uuid, 
    const std::vector<uint8_t>& aad, //this party's aad
    const cmp_key_metadata& metadata, //all parties public metadata (public share, paillier, rind pedersen)
    const std::map<uint64_t, cmp_mta_responses>& mta_responses, //all responses from all parties
    size_t index,           //this block (message) index
    const auxiliary_keys& aux_keys, 
    std::map<uint64_t, std::unique_ptr<mta::base_response_verifier> >& verifiers)
{
    //iterate over all responses from all signers
    for (auto it = mta_responses.begin(); it != mta_responses.end(); ++it)
    {
        if (it->first == my_id)
            continue;
        const auto& other = metadata.players_info.at(it->first);
        auto other_aad = build_aad(uuid, it->first, metadata.seed);
        auto& pub = data.public_data.at(it->first);
        pub.GAMMA = it->second.response[index].GAMMA;
        auto& proof_for_me = it->second.response[index].gamma_proofs.at(my_id);
        paillier_with_range_proof_t proof = {pub.gamma_commitment.data(), (uint32_t)pub.gamma_commitment.size(), (uint8_t*)proof_for_me.data(), (uint32_t)proof_for_me.size()};
        auto status = range_proof_exponent_zkpok_verify(aux_keys.ring_pedersen.get(), other.paillier.get(), algebra, other_aad.data(), other_aad.size(), &pub.GAMMA.data, &proof);
        if (status != ZKP_SUCCESS)
        {
            LOG_ERROR("Failed to verify gamma log proof from player %" PRIu64 " block %lu, error %d", it->first, index, status);
            throw_cosigner_exception(status);
        }
        pub.gamma_commitment.clear();
        cmp_mta_message& gamma_mta = const_cast<cmp_mta_message&>(it->second.response[index].k_gamma_mta.at(my_id));
        verifiers.at(it->first)->process(data.mta_request, gamma_mta, pub.GAMMA);
        auto alpha = mta::decrypt_mta_response(it->first, algebra, std::move(gamma_mta.message), aux_keys.paillier);
        throw_cosigner_exception(algebra->add_scalars(algebra, &data.delta.data, data.delta.data, sizeof(elliptic_curve256_scalar_t), alpha.data, sizeof(elliptic_curve256_scalar_t)));
        cmp_mta_message& x_mta = const_cast<cmp_mta_message&>(it->second.response[index].k_x_mta.at(my_id));
        verifiers.at(it->first)->process(data.mta_request, x_mta, other.public_share);
        alpha = mta::decrypt_mta_response(it->first, algebra, std::move(x_mta.message), aux_keys.paillier);
        throw_cosigner_exception(algebra->add_scalars(algebra, &data.chi.data, data.chi.data, sizeof(elliptic_curve256_scalar_t), alpha.data, sizeof(elliptic_curve256_scalar_t)));
        throw_cosigner_exception(algebra->add_points(algebra, &data.GAMMA.data, &data.GAMMA.data, &pub.GAMMA.data));

    }
    data.mta_request.clear();

    cmp_mta_deltas delta = {data.delta};
    throw_cosigner_exception(algebra->point_mul(algebra, &delta.DELTA.data, &data.GAMMA.data, &data.k.data));
    diffie_hellman_log_public_data_t pub;
    throw_cosigner_exception(algebra->generator_mul(algebra, &pub.A, &data.a.data));
    throw_cosigner_exception(algebra->generator_mul(algebra, &pub.B, &data.b.data));
    elliptic_curve256_scalar_t tmp;
    throw_cosigner_exception(algebra->mul_scalars(algebra, &tmp, data.a.data, sizeof(elliptic_curve256_scalar_t), data.b.data, sizeof(elliptic_curve256_scalar_t)));
    throw_cosigner_exception(algebra->add_scalars(algebra, &tmp, tmp, sizeof(elliptic_curve256_scalar_t), data.k.data, sizeof(elliptic_curve256_scalar_t)));
    throw_cosigner_exception(algebra->generator_mul(algebra, &pub.C, &tmp));
    memcpy(pub.X, delta.DELTA.data, sizeof(elliptic_curve256_point_t));
    diffie_hellman_log_zkp_t proof;
    throw_cosigner_exception(diffie_hellman_log_zkp_generate(algebra, aad.data(), aad.size(), &data.GAMMA.data, &data.k.data, &data.a.data, &data.b.data, &pub, &proof));
    delta.proof.insert(delta.proof.begin(), (uint8_t*)&proof, (uint8_t*)(&proof + 1));
    return delta;
}

void cmp_ecdsa_signing_service::calc_R(ecdsa_signing_data& data, elliptic_curve_point& R, const elliptic_curve256_algebra_ctx_t* algebra, uint64_t my_id, const std::string& uuid, const cmp_key_metadata& metadata,
        const std::map<uint64_t, std::vector<cmp_mta_deltas>>& deltas, size_t index)
{
    elliptic_curve256_point_t DELTA;
    throw_cosigner_exception(algebra->point_mul(algebra, &DELTA, &data.GAMMA.data, &data.k.data));

    for (auto it = deltas.begin(); it != deltas.end(); ++it)
    {
        if (it->first == my_id)
            continue;
        if (it->second[index].proof.size() != sizeof(diffie_hellman_log_zkp_t))
        {
            LOG_ERROR("ddh proof from player %" PRIu64 " block %lu has wrong size %lu", it->first, index, it->second[index].proof.size());
            throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
        }
        auto aad = build_aad(uuid, it->first, metadata.seed);
        diffie_hellman_log_public_data_t pub;
        memcpy(pub.A, data.public_data.at(it->first).A.data, sizeof(elliptic_curve256_point_t));
        memcpy(pub.B, data.public_data.at(it->first).B.data, sizeof(elliptic_curve256_point_t));
        memcpy(pub.C, data.public_data.at(it->first).Z.data, sizeof(elliptic_curve256_point_t));
        memcpy(pub.X, it->second[index].DELTA.data, sizeof(elliptic_curve256_point_t));

        auto status = diffie_hellman_log_zkp_verify(algebra, aad.data(), aad.size(), &data.GAMMA.data, &pub, (diffie_hellman_log_zkp_t*)it->second[index].proof.data());
        if (status != ZKP_SUCCESS)
        {
            LOG_ERROR("Failed to verify ddh proof from player %" PRIu64 " block %lu, error %d", it->first, index, status);
            throw_cosigner_exception(status);
        }
        throw_cosigner_exception(algebra->add_scalars(algebra, &data.delta.data, data.delta.data, sizeof(elliptic_curve256_scalar_t), it->second[index].delta.data, sizeof(elliptic_curve256_scalar_t)));
        throw_cosigner_exception(algebra->add_points(algebra, &DELTA, &DELTA, &it->second[index].DELTA.data));
    }

    uint8_t res = 0;
    throw_cosigner_exception(algebra->verify(algebra, data.delta.data, sizeof(elliptic_curve256_scalar_t), &DELTA, &res));
    if (!res)
    {
        LOG_ERROR("Failed to verify that g^delta == DELTA");
        throw cosigner_exception(cosigner_exception::INTERNAL_ERROR);
    }
    throw_cosigner_exception(algebra->inverse(algebra, &data.delta.data, &data.delta.data));
    throw_cosigner_exception(algebra->point_mul(algebra, &R.data, &data.GAMMA.data, &data.delta.data));
    data.public_data.clear();
}

std::vector<uint8_t> cmp_ecdsa_signing_service::build_aad(const std::string& sid, uint64_t id, const commitments_sha256_t srid)
{
    std::vector<uint8_t> ret(sid.begin(), sid.end());
    const uint8_t* p = (uint8_t*)&id;
    std::copy(p, p + sizeof(uint64_t), std::back_inserter(ret));
    p = srid;
    std::copy(p, p + sizeof(commitments_sha256_t), std::back_inserter(ret));
    return ret;
}

elliptic_curve_scalar cmp_ecdsa_signing_service::derivation_key_delta(const elliptic_curve256_algebra_ctx_t* algebra, const elliptic_curve256_point_t& public_key, const HDChaincode& chaincode, const std::vector<uint32_t>& path)
{
    static const PrivKey ZERO = {0};
    elliptic_curve_scalar derived_privkey;
    if (path.size()) 
    {
        assert(path.size() == BIP44_PATH_LENGTH);
        hd_derive_status retval = derive_private_key_generic(algebra, derived_privkey.data, public_key, ZERO, chaincode, path.data(), path.size()); //derive 0 to get the derivation delta
        if (HD_DERIVE_SUCCESS != retval)
        {
            LOG_ERROR("Error deriving private key: %d", retval);
            throw cosigner_exception(cosigner_exception::INTERNAL_ERROR);
        }
    }
    else
        memcpy(derived_privkey.data, ZERO, sizeof(elliptic_curve_scalar));
    return derived_privkey;
}

void cmp_ecdsa_signing_service::make_sig_s_positive(cosigner_sign_algorithm algorithm, elliptic_curve256_algebra_ctx_t* algebra, recoverable_signature& sig)
{
    // calling is_positive as optimization for not calling GFp_curve_algebra_abs unless needed
    if (!is_positive(algorithm, sig.s))
    {
        uint8_t parity = sig.s[31] & 1;
        throw_cosigner_exception(GFp_curve_algebra_abs((GFp_curve_algebra_ctx_t*)algebra->ctx, &sig.s, &sig.s));
        sig.v ^= (parity ^ (sig.s[31] & 1));
    }
}

}
}
}