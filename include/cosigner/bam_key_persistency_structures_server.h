#pragma once

#include "bam_key_persistency_structures.h"
#include "crypto/paillier_commitment/paillier_commitment.h"
#include "crypto/commitments/damgard_fujisaki.h"
#include <memory>

namespace fireblocks::common::cosigner
{

using bam_setup_metadata_server = bam_setup_metadata_base;

struct bam_setup_auxilary_key_server 
{
    bam_setup_auxilary_key_server() = default;
    std::shared_ptr<paillier_commitment_private_key_t> paillier_commitment_priv;
};

// In BAM server does not hold any key specific auxiliary data.
// Instead - auxiliary key data is per "setup" on the server side
struct bam_key_metadata_server : public bam_key_metadata_base
{
    using bam_key_metadata_base::bam_key_metadata_base;
    
    bam_key_metadata_server() = default;
 
    elliptic_curve256_point_t client_public_share { 0 }; 
};



}
