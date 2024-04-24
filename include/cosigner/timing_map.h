#pragma once

#include <map>
#include <mutex>
#include <optional>
#include "cosigner/platform_service.h"
namespace fireblocks
{
namespace common
{
namespace cosigner
{

class TimingMap final
{
public:
    TimingMap(platform_service& platform_service);
    ~TimingMap() = default;

    TimingMap(const TimingMap&) = delete;
    TimingMap(TimingMap&&) = delete;
    TimingMap& operator=(const TimingMap&) = delete;
    TimingMap& operator=(TimingMap&&) = delete;

    void insert(const std::string& key);
    const std::optional<const uint64_t> extract(const std::string& key);
    void erase(const std::string& key);
    
private:
    const std::optional<const uint64_t> extract_impl(const std::string& key);
    std::mutex _lock;
    std::map<std::string, uint64_t> _data;
    platform_service& _time_service;
};

}
}
}