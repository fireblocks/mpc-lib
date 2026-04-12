#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include <openssl/crypto.h>

namespace fireblocks::common::utils
{

typedef std::vector<unsigned char> byte_vector_t;

template <typename T>
class container_cleaner
{
public:
    [[nodiscard]] explicit container_cleaner(T& secret) : _secret(secret) {}
    ~container_cleaner() {OPENSSL_cleanse(&_secret[0], _secret.size());}

    container_cleaner(const container_cleaner&) = delete;
    container_cleaner& operator=(const container_cleaner&) = delete;
    container_cleaner(container_cleaner&&) = delete;
    container_cleaner& operator=(container_cleaner&&) = delete;

    T& operator*() { return _secret; }
private:
    T& _secret;
};

using string_cleaner = container_cleaner<std::string>;
using byte_vector_cleaner = container_cleaner<byte_vector_t>;

}
