#pragma once

#include "cosigner/key_persistency_base.h"
#include "cosigner/types.h"
#include "crypto/elliptic_curve_algebra/elliptic_curve256_algebra.h"

namespace fireblocks::common::cosigner
{

struct frost_key_metadata_base : public key_metadata_base
{
    uint64_t peer_id;  // The other party's player ID: client stores server_id, server stores client_id (mirrors BAM's peer_id)

    // Returns true if a known public key was stored in advance (e.g. add_user path).
    // In the flow of the from-scratch key generation, the public key is set to the infinity point,
    // so the check is whether the public key is equal to the infinity point
    bool has_public_key(const elliptic_curve256_algebra_ctx_t* algebra) const
    {
        return memcmp(public_key, algebra->infinity_point(algebra), sizeof(elliptic_curve256_point_t)) != 0;
    }
};


}
