#pragma once

#include "bam_tx_persistency_structures.h"
#include "cosigner/types.h"

namespace fireblocks::common::cosigner
{

// server generates ephemeral "k", sends data to client 
// and need to known it's k when client's response is received
// this data is temporal and stored for the duration of a transaction signing
struct bam_server_single_signature_data : public bam_single_signature_data_base
{
    bam_server_single_signature_data() = default;
    elliptic_curve_scalar k;          // "k" ephemeral share of the server
};

typedef bam_signature_metadata_base<bam_server_single_signature_data> bam_server_signature_data;

}