#include "utils.h"
#include "cosigner/cmp_key_persistency.h"
#include "cosigner/cosigner_exception.h"
#include "cosigner/platform_service.h"
#include "logging/logging_t.h"

namespace fireblocks
{
namespace common
{
namespace cosigner
{

void verify_tenant_id(const platform_service& service, const cmp_key_persistency& key_persistency, const std::string& key_id)
{
    const std::string tenant_id = service.get_current_tenantid();
    if (tenant_id.compare(key_persistency.get_tenantid_from_keyid(key_id)) != 0)
    {
        LOG_ERROR("key id %s is not part of tenant %s", key_id.c_str(), tenant_id.c_str());
        throw cosigner_exception(cosigner_exception::UNAUTHORIZED);
    }
}

}
}
}