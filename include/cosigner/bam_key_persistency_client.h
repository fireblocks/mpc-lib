#pragma once

#include "bam_key_persistency_common.h"
#include "bam_key_persistency_structures_client.h"

namespace fireblocks::common::cosigner
{

class bam_key_persistency_client : public bam_key_persistency_common
{

public:
    virtual ~bam_key_persistency_client() = default;

    virtual void store_key_metadata(const std::string& key_id, const bam_key_metadata_client& metadata, const bool overwrite) = 0;
    virtual void load_key_metadata(const std::string& key_id, bam_key_metadata_client& metadata) const = 0;

    virtual void store_key_temp_data(const std::string& key_id,  const bam_temp_key_data_client& temp_key_data_client) = 0;
    virtual void load_key_temp_data_and_delete(const std::string& key_id, bam_temp_key_data_client& temp_key_data_client) = 0;


};

} //namespace fireblocks::common::cosigner
