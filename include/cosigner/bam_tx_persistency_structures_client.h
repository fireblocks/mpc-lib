#pragma once

#include "bam_tx_persistency_structures.h"

namespace fireblocks::common::cosigner
{

typedef bam_single_signature_data_base bam_client_single_signature_data;

typedef bam_signature_metadata_base<bam_client_single_signature_data> bam_client_signature_data;


}