#include "cosigner/bam_key_persistency_structures.h"


namespace fireblocks::common::cosigner
{

bam_key_metadata_base::bam_key_metadata_base(const cosigner_sign_algorithm _algo, 
                                             const std::string _setup_id, 
                                             const uint64_t _peer_id,
                                             const elliptic_curve256_point_t& _pub_key):
        key_metadata_base(_algo),
        setup_id(_setup_id),
        peer_id(_peer_id)
{
    memcpy(public_key, _pub_key, sizeof(public_key));
}



}
