#pragma once
#include "bam_tx_persistency_common.h"
#include "bam_tx_persistency_structures_server.h"
#include <memory>

namespace fireblocks::common::cosigner
{

class bam_tx_persistency_server: public bam_tx_persistency_common
{

public:
    virtual ~bam_tx_persistency_server() = default;

    // handle temporary signature state
    virtual void store_signature_data(const std::string& tx_id, const std::shared_ptr<bam_server_signature_data>& signature_data) = 0;
    virtual std::shared_ptr<bam_server_signature_data> load_signature_data_and_delete(const std::string& tx_id) = 0;
};

}
