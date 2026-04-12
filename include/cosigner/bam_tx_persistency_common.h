#pragma once

#include <string>

namespace fireblocks::common::cosigner
{

class bam_tx_persistency_common
{
public:
    virtual ~bam_tx_persistency_common()  = default;

    virtual bool delete_temporary_tx_data(const std::string& tx_id) = 0;
    virtual void shutdown() {}

};

}