#pragma once
#include <string>

#include "bam_tx_persistency_common.h"
#include "bam_tx_persistency_structures_client.h"

namespace fireblocks::common::cosigner
{

class bam_tx_persistency_client : public bam_tx_persistency_common
{
public:
    virtual ~bam_tx_persistency_client() = default;
    
    virtual void store_signature_data(const std::string& tx_id, const bam_client_signature_data& signature_data) = 0;
    virtual void load_signature_data_and_delete(const std::string& tx_id, bam_client_signature_data& signature_data) = 0;
};
}
