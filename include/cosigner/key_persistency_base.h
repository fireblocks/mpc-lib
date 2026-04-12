#pragma once

#include "cosigner/types.h"
namespace fireblocks::common::cosigner
{

struct key_metadata_base
{
    key_metadata_base() = default;
    key_metadata_base(cosigner_sign_algorithm algo) : algorithm(algo) {}
    elliptic_curve256_point_t public_key{0};                                // public key of all players
    cosigner_sign_algorithm algorithm{(cosigner_sign_algorithm)-1};         // signing algorithm
};

}