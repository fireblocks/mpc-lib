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

template<typename T>
std::string HexStr(const T itbegin, const T itend)
{
    std::string rv;
    static const char hexmap[16] = { '0', '1', '2', '3', '4', '5', '6', '7',
                                     '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };
    rv.reserve((itend-itbegin)*3);
    for(T it = itbegin; it < itend; ++it)
    {
        unsigned char val = (unsigned char)(*it);
        rv.push_back(hexmap[val>>4]);
        rv.push_back(hexmap[val&15]);
    }

    return rv;
}


}
}
}