#include "cosigner/timing_map.h"

namespace fireblocks
{
namespace common
{
namespace cosigner
{

TimingMap::TimingMap(platform_service& platform_service):
    _time_service(platform_service)
{

}
void TimingMap::insert(const std::string& key)
{
    std::unique_lock<std::mutex> guard(_lock);
#ifdef DEBUG
    // Unit tests may call some phase handlers more then once to test replays
    if (_data.find(key) == _data.end())
#endif
    _data[key] = _time_service.now_msec();
}

void TimingMap::erase(const std::string& key)
{
    std::unique_lock<std::mutex> guard(_lock);
    _data.erase(key);
}

const std::optional<const uint64_t> TimingMap::extract_impl(const std::string& key)
{
    std::unique_lock<std::mutex> guard(_lock);
    auto iterator = _data.find(key);
    if (iterator == _data.end())
    {
        return std::nullopt;
    }
    const uint64_t value = iterator->second;
    
    _data.erase(iterator);
    return value;
}

const std::optional<const uint64_t> TimingMap::extract(const std::string& key)
{
    const std::optional<uint64_t> extracted = extract_impl(key);
    if (!extracted)
    {
        return std::nullopt;
    }
    const uint64_t diff = (_time_service.now_msec() - *extracted);
    return diff;
}

}
}
}