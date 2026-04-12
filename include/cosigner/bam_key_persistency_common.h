#pragma once

#include "cosigner/types.h"
#include <string>
#include "crypto/elliptic_curve_algebra/elliptic_curve256_algebra.h"

namespace fireblocks::common::cosigner
{

class bam_key_persistency_common
{
public:
    virtual ~bam_key_persistency_common()  = default;

    virtual void store_key(const std::string& key_id, const cosigner_sign_algorithm algorithm, const elliptic_curve256_scalar_t& private_key) = 0;
    virtual void load_key(const std::string& key_id, cosigner_sign_algorithm &algorithm,  elliptic_curve256_scalar_t& private_key) const = 0;
    
    virtual void store_tenant_id_for_setup(const std::string& setup_id, const std::string& tenant_id) = 0;
    virtual void load_tenant_id_for_setup(const std::string& setup_id, std::string& tenant_id) const = 0;
    
    virtual bool delete_temporary_key_data(const std::string& key_id) = 0;
    virtual bool delete_key_data(const std::string& key_id) = 0;
    virtual bool delete_setup_data(const std::string& setup_id) = 0;

    virtual bool backup_key(const std::string& key_id) const = 0;
};

}