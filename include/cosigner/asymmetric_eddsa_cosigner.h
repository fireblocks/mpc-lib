#pragma once

#include "cosigner_export.h"

#include "crypto/ed25519_algebra/ed25519_algebra.h"
#include "blockchain/mpc/hd_derive.h"
#include "cosigner/types.h"

#include <string.h>

#include <array>
#include <memory>
#include <set>
#include <string>
#include <vector>

namespace fireblocks
{
namespace common
{
namespace cosigner
{

class cmp_key_persistency;
class platform_service;

static constexpr size_t SHA256_HASH_SIZE = 32;
typedef std::array<uint8_t, SHA256_HASH_SIZE> eddsa_commitment;
static_assert(sizeof(eddsa_commitment) == SHA256_HASH_SIZE);

struct Rs_and_commitments
{
    std::vector<elliptic_curve_point> Rs;
    eddsa_commitment R_commitment;
};

class COSIGNER_EXPORT asymmetric_eddsa_cosigner
{
public:
    asymmetric_eddsa_cosigner(platform_service& cosigner_service, const cmp_key_persistency& key_persistency);
    virtual ~asymmetric_eddsa_cosigner() {}

protected:
    void derivation_key_delta(const elliptic_curve256_point_t& public_key, const HDChaincode& chaincode, const std::vector<uint32_t>& path, uint8_t split_factor, 
        ed25519_scalar_t& delta, ed25519_point_t& derived_pubkey);
    eddsa_commitment commit_to_r(const std::string& id, uint32_t index, uint64_t player_id, const ed25519_point_t& R);
    bool verify_commit_to_r(const eddsa_commitment& commitment, const std::string& id, uint32_t index, uint64_t player_id, const ed25519_point_t& R);
    bool verify_commit_to_r(const eddsa_commitment& commitment, const std::string& id, uint32_t index, uint64_t player_id, const elliptic_curve256_point_t& R);

    platform_service& _service;
    const cmp_key_persistency& _key_persistency;
    static const std::unique_ptr<elliptic_curve256_algebra_ctx_t, void (*)(elliptic_curve256_algebra_ctx_t*)> _ctx;
};

}
}
}
