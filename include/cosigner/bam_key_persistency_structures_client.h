#pragma once

#include "bam_key_persistency_structures.h"

#include "crypto/paillier_commitment/paillier_commitment.h"
#include "crypto/commitments/damgard_fujisaki.h"
#include "crypto/commitments/commitments.h"
#include "cosigner/sign_algorithm.h"

#include <memory>

namespace fireblocks::common::cosigner
{


struct bam_key_metadata_client : public bam_setup_metadata_base, public bam_key_metadata_base
{
    bam_key_metadata_client() = default;
    bam_key_metadata_client(const cosigner_sign_algorithm _algo, 
                            const std::string _setup_id, 
                            const uint64_t _peer_id,
                            const elliptic_curve256_point_t& _pub_key):
        bam_setup_metadata_base(_algo),
        bam_key_metadata_base(_algo, _setup_id, _peer_id, _pub_key)
    {

    }
    std::shared_ptr<paillier_commitment_public_key_t> paillier_commitment_pub;
};

struct bam_temp_key_data_client
{
    commitments_sha256_t server_commitment;                          // this is server public commitment
    std::shared_ptr<damgard_fujisaki_private> damgard_fujisaki_priv; // this is a secret of the client    
};

}