#pragma once

#include "cosigner/frost_key_persistency_structures.h"

namespace fireblocks::common::cosigner
{

struct frost_key_metadata_server : public frost_key_metadata_base
{
    using frost_key_metadata_base::frost_key_metadata_base;

    frost_key_metadata_server() = default;

    elliptic_curve256_point_t client_public_share{0};
};



}
