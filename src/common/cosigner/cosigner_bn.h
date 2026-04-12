#pragma once
#include <openssl/bn.h>

namespace fireblocks::common::cosigner
{

struct bn_ctx_frame
{
    [[nodiscard]] explicit bn_ctx_frame(BN_CTX* ctx) : _ctx(ctx) {BN_CTX_start(_ctx);}
    ~bn_ctx_frame() {if (_ctx) BN_CTX_end(_ctx);}
    bn_ctx_frame(const bn_ctx_frame&) = delete;
    bn_ctx_frame(bn_ctx_frame&&) = delete;
    bn_ctx_frame& operator=(const bn_ctx_frame&) = delete;
    bn_ctx_frame& operator=(bn_ctx_frame&&) = delete;
    
    void reset() 
    {
        if (_ctx) 
            BN_CTX_end(_ctx);
        _ctx = NULL;
    }
    BN_CTX* _ctx;
};


class BN_CTX_guard
{
public:
    [[nodiscard]] explicit BN_CTX_guard(bool secure = false)
    {
        _ctx = secure ? BN_CTX_secure_new() : BN_CTX_new();
        if (!_ctx)
            throw_cosigner_exception(cosigner_exception::NO_MEM);
        BN_CTX_start(_ctx);
    }
    
    ~BN_CTX_guard()
    {
        BN_CTX_end(_ctx);
        BN_CTX_free(_ctx);
    }

    [[nodiscard]] BN_CTX* get() const {return _ctx;}

    BN_CTX_guard(const BN_CTX_guard&) = delete;
    BN_CTX_guard& operator=(const BN_CTX_guard&) = delete;
    BN_CTX_guard(BN_CTX_guard&&) = delete;
    BN_CTX_guard& operator=(BN_CTX_guard&&) = delete;
private:
    BN_CTX* _ctx;
};

template <typename T>
class container_cleaner;

template<>
class container_cleaner<bignum_st*>
{
public:
    [[nodiscard]] explicit container_cleaner<bignum_st*>(bignum_st* secret) : _secret(secret) {}
    ~container_cleaner<bignum_st*>() {BN_clear(_secret);}
    container_cleaner<bignum_st*>(const container_cleaner<bignum_st*>&) = delete;
    container_cleaner<bignum_st*>& operator=(const container_cleaner<bignum_st*>&) = delete;
    container_cleaner<bignum_st*>(container_cleaner<bignum_st*>&&) = delete;
    container_cleaner<bignum_st*>& operator=(container_cleaner<bignum_st*>&&) = delete;
    
private:
    bignum_st* _secret;
};

using bignum_cleaner = container_cleaner<bignum_st*>;

}