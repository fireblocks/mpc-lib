#pragma once

#include "cosigner_export.h"

#include "cosigner/types.h"
#include "cosigner/key_persistency_base.h"

#include <map>
#include <memory>
#include <string>

struct paillier_public_key;
struct paillier_private_key;
struct ring_pedersen_private;
struct ring_pedersen_public;

namespace fireblocks
{
namespace common
{
namespace cosigner
{

struct cmp_player_info
{
    elliptic_curve_point public_share;
    std::shared_ptr<struct paillier_public_key> paillier;
    std::shared_ptr<struct ring_pedersen_public> ring_pedersen;
};

struct cmp_key_metadata : public key_metadata_base
{
    uint8_t t;                              // number of players needed for signature
    uint8_t n;                              // total number of players
    uint32_t flags;                         // algorithm specific flags
    uint64_t ttl;                           // 
    commitments_sha256_t seed;              // Usually product of hash of some state which is considered random
    std::map<uint64_t, cmp_player_info> players_info;
};

struct auxiliary_keys
{
    std::shared_ptr<struct paillier_private_key> paillier;
    std::shared_ptr<struct ring_pedersen_private> ring_pedersen;
};

class COSIGNER_EXPORT cmp_key_persistency
{
public:
    virtual ~cmp_key_persistency() {}
    virtual bool key_exist(const std::string& key_id) const = 0;
    // This function should throw cosigner_exception::BAD_KEY if key doesn't exist
    virtual void load_key(const std::string& key_id, cosigner_sign_algorithm& algorithm, elliptic_curve256_scalar_t& private_key) const = 0;
    virtual const std::string get_tenantid_from_keyid(const std::string& key_id) const = 0;

    virtual void load_key_metadata(const std::string& key_id, cmp_key_metadata& metadata, bool full_load) const = 0;
    virtual void load_auxiliary_keys(const std::string& key_id, auxiliary_keys& aux) const = 0;
};

}
}
}
