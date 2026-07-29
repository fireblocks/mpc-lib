#pragma once


#include "cosigner/types.h"
#include "cosigner/frost_key_persistency_common.h"
#include "cosigner/frost_key_persistency_structures_server.h"

namespace fireblocks::common::cosigner
{

class frost_key_persistency_server : public frost_key_persistency_common
{
public:
    virtual ~frost_key_persistency_server() = default;

    virtual void store_key_metadata(const std::string& key_id, const frost_key_metadata_server& metadata, bool allow_override) = 0;
    virtual void load_key_metadata(const std::string& key_id, frost_key_metadata_server& metadata) const = 0;
};

}
