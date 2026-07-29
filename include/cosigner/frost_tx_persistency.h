#pragma once

#include "cosigner/frost_tx_persistency_structures.h"
#include <memory>
#include <string>

namespace fireblocks::common::cosigner
{

class frost_tx_persistency
{
public:
    virtual ~frost_tx_persistency()  = default;

    virtual void store_signature_data(const std::string& tx_id, const std::shared_ptr<frost_signature_data>& signature_data) = 0;
    virtual std::shared_ptr<frost_signature_data> load_signature_data_and_delete(const std::string& tx_id) = 0;
    virtual bool delete_temporary_tx_data(const std::string& tx_id) = 0;
    virtual void shutdown() {}


};

}
