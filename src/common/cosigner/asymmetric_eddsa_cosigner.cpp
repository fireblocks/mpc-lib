#include "cosigner/asymmetric_eddsa_cosigner.h"
#include "cosigner/cmp_key_persistency.h"
#include "cosigner/cosigner_exception.h"
#include "cosigner/platform_service.h"
#include "logging/logging_t.h"

#include <openssl/sha.h>

namespace fireblocks
{
namespace common
{
namespace cosigner
{

const std::unique_ptr<elliptic_curve256_algebra_ctx_t, void(*)(elliptic_curve256_algebra_ctx_t*)> asymmetric_eddsa_cosigner::_ctx(elliptic_curve256_new_ed25519_algebra(), elliptic_curve256_algebra_ctx_free);

asymmetric_eddsa_cosigner::asymmetric_eddsa_cosigner(platform_service& cosigner_service, const cmp_key_persistency& key_persistency) : 
    _service(cosigner_service), _key_persistency(key_persistency)
{
    if (!_ctx)
    {
        LOG_ERROR("Failed to create ed25519 algebra");
        throw cosigner_exception(cosigner_exception::NO_MEM);
    }
}

void asymmetric_eddsa_cosigner::derivation_key_delta(const elliptic_curve256_point_t& public_key, const HDChaincode& chaincode, const std::vector<uint32_t>& path, uint8_t split_factor, 
        ed25519_scalar_t& delta, ed25519_point_t& derived_pubkey)
{
    static const PrivKey ZERO = {0};
    if (path.size()) 
    {
        assert(path.size() == BIP44_PATH_LENGTH);
        PubKey tmp_derived_pubkey;
        hd_derive_status retval = derive_private_and_public_keys(_ctx.get(), delta, tmp_derived_pubkey, public_key, ZERO, chaincode, path.data(), path.size()); //derive 0 to get the derivation delta
        if (HD_DERIVE_SUCCESS != retval)
        {
            LOG_ERROR("Error deriving private key: %d", retval);
            throw cosigner_exception(cosigner_exception::INTERNAL_ERROR);
        }
        memcpy(derived_pubkey, tmp_derived_pubkey, sizeof(ed25519_point_t));

        if (split_factor > 1)
        {
            elliptic_curve256_scalar_t inv = {0};
            inv[sizeof(elliptic_curve256_scalar_t) - 1] = split_factor;
            throw_cosigner_exception(_ctx->inverse(_ctx.get(), &inv, &inv));
            throw_cosigner_exception(_ctx->mul_scalars(_ctx.get(), &delta, delta, sizeof(elliptic_curve256_scalar_t), inv, sizeof(elliptic_curve256_scalar_t)));
        }
    }
    else
    {
        memcpy(delta, ZERO, sizeof(elliptic_curve256_scalar_t));
        memcpy(derived_pubkey, public_key, sizeof(elliptic_curve256_point_t));
    }
}

eddsa_commitment asymmetric_eddsa_cosigner::commit_to_r(const std::string& id, uint32_t index, uint64_t player_id, const ed25519_point_t& R)
{
    SHA256_CTX sha;
    SHA256_Init(&sha);
    SHA256_Update(&sha, id.c_str(), id.size());
    SHA256_Update(&sha, &index, sizeof(uint32_t));
    SHA256_Update(&sha, &player_id, sizeof(uint64_t));
    SHA256_Update(&sha, R, sizeof(ed25519_point_t));
    eddsa_commitment commitment;
    SHA256_Final(commitment.data(), &sha);
    return commitment;
}

bool asymmetric_eddsa_cosigner::verify_commit_to_r(const eddsa_commitment& commitment, const std::string& id, uint32_t index, uint64_t player_id, const ed25519_point_t& R)
{
    eddsa_commitment calculated_commitment = commit_to_r(id, index, player_id, R);
    return calculated_commitment == commitment;
}

bool asymmetric_eddsa_cosigner::verify_commit_to_r(const eddsa_commitment& commitment, const std::string& id, uint32_t index, uint64_t player_id, const elliptic_curve256_point_t& R)
{
    return verify_commit_to_r(commitment, id, index, player_id, (const ed25519_point_t&)R);
}

}
}
}
