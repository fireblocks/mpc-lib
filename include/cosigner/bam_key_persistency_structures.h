#pragma once

#include "crypto/commitments/commitments.h"
#include "crypto/commitments/pedersen.h"
#include "cosigner/key_persistency_base.h"
#include "cosigner/sign_algorithm.h"
#include "cosigner/types.h"
#include <string>
#include <cstdint>

namespace fireblocks::common::cosigner
{
    
struct bam_setup_metadata_base 
{
    bam_setup_metadata_base() = default;
    bam_setup_metadata_base(const cosigner_sign_algorithm _algo) : setup_algorithm(_algo) {}

    //algorithm is required because because ec_base is points on a specific curve
    pedersen_commitment_two_generators_t ec_base { {0}, {0} };
    cosigner_sign_algorithm setup_algorithm{(cosigner_sign_algorithm)-1};
};

struct bam_key_metadata_base : public key_metadata_base
{
    bam_key_metadata_base() = default;
    bam_key_metadata_base(const cosigner_sign_algorithm _algo, 
                          const std::string _setup_id, 
                          const uint64_t _peer_id,
                          const elliptic_curve256_point_t& _pub_key);

    commitments_sha256_t seed;              // Hash over key_id, client_id, server_id and some constant string
    byte_vector_t encrypted_server_share;   // Saved by client to generate partial signature.
                                            // Used by server to create full signature (otherwise would require re-encryption)
                                            // In server the presence of this value also serves as an indicator that the key generation is completed (prevents replay attack)
    std::string setup_id;                   // A unique identifier of the setup to which this key belongs
    uint64_t peer_id;                       // server id for the client and client id for the server
    bool has_public_key() const { return public_key[0] != 0; } // BAM is ECDSA and it's public key starts always from 0x2 or 0x3
};


}