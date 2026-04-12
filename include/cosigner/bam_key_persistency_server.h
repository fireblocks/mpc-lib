#pragma once

#include "bam_key_persistency_common.h"
#include "bam_key_persistency_structures_server.h"

namespace fireblocks::common::cosigner
{

class bam_key_persistency_server : public bam_key_persistency_common
{

public:
    virtual ~bam_key_persistency_server() = default;
    
    virtual void store_setup_metadata(const std::string& setup_id,  const bam_setup_metadata_server& setup_metadata) = 0;
    virtual void load_setup_metadata(const std::string& setup_id, bam_setup_metadata_server& setup_metadata) const = 0;

    virtual void store_setup_auxilary_key(const std::string& setup_id,  const bam_setup_auxilary_key_server& setup_aux_key) = 0;
    virtual void load_setup_auxilary_key(const std::string& setup_id, bam_setup_auxilary_key_server& setup_aux_key) const = 0;

    virtual void store_key_metadata(const std::string& key_id, const bam_key_metadata_server& metadata, const bool overwrite) = 0;
    virtual void load_key_metadata(const std::string& key_id, bam_key_metadata_server& metadata) const = 0;
};

}
