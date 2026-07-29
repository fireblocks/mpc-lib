#pragma once


#include "cosigner/types.h"
#include "cosigner/frost_key_persistency_common.h"
#include "cosigner/frost_key_persistency_structures.h"

namespace fireblocks::common::cosigner
{

class frost_key_persistency_client : public frost_key_persistency_common
{
public:
    virtual ~frost_key_persistency_client() = default;

    virtual void store_key_metadata(const std::string& key_id, const frost_key_metadata_base& metadata, bool allow_override) = 0;
    virtual void load_key_metadata(const std::string& key_id, frost_key_metadata_base& metadata) const = 0;

    virtual void store_server_commitment(const std::string& key_id, const commitments_sha256_t& commitment) = 0;
    virtual void load_server_commitment_and_delete(const std::string& key_id, commitments_sha256_t& commitment) = 0;
};

}
