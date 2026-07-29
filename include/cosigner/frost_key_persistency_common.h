#pragma once

#include <string>
#include "cosigner/types.h"
#include "cosigner/frost_key_persistency_structures.h"

namespace fireblocks::common::cosigner
{

class frost_key_persistency_common
{
public:
    virtual ~frost_key_persistency_common() = default;

    virtual void store_key(const std::string& key_id, const elliptic_curve_scalar& secret_key, const cosigner_sign_algorithm& algo) = 0;
    virtual void load_key(const std::string& key_id, elliptic_curve_scalar& secret_key) const = 0;
    virtual void store_tenant_id_for_key(const std::string& key_id, const std::string& tenant_id) = 0;
    virtual void load_tenant_id_for_key(const std::string& key_id, std::string& tenant_id) const = 0;

    virtual bool delete_temporary_key_data(const std::string& key_id) = 0;
    virtual bool delete_key(const std::string& key_id) = 0;
    virtual bool backup_key(const std::string& key_id) const = 0;
};

}
