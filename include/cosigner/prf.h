#pragma once

#include "crypto/commitments/commitments.h"
#include <openssl/sha.h>

#include <string>

namespace fireblocks
{
namespace common
{
namespace cosigner
{

class prf
{
public:

    prf(const commitments_sha256_t& seed, const std::string& aad){
        SHA256_Init(&_ctx);
        SHA256_Update(&_ctx, seed, sizeof(commitments_sha256_t));
        SHA256_Update(&_ctx, aad.data(), aad.size());
    }

    void run(uint64_t id, commitments_sha256_t& random){
        SHA256_CTX ctx = _ctx;
        SHA256_Update(&ctx, &id, sizeof(uint64_t));
        SHA256_Final(random, &ctx);
    }

private:
    SHA256_CTX _ctx;
};

}
}
}
