#pragma once

#include <string>

namespace fireblocks
{
namespace common
{
namespace cosigner
{

class platform_service;
class cmp_key_persistency;

void verify_tenant_id(const platform_service& service, const cmp_key_persistency& key_persistency, const std::string& key_id);

}
}
}