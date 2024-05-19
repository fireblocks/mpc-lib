#include "crypto/keccak1600/keccak1600.h"

#include <string.h>

size_t SHA3_absorb(uint64_t A[5][5], const unsigned char *inp, size_t len,
                   size_t r);
void SHA3_squeeze(uint64_t A[5][5], unsigned char *out, size_t len, size_t r);

int keccak1600_init(KECCAK1600_CTX *ctx, size_t md_size_in_bits, unsigned char pad)
{
    size_t bsz = (KECCAK1600_WIDTH - md_size_in_bits * 2) / 8;
    if (bsz <= sizeof(ctx->buf)) {
        memset(ctx->A, 0, sizeof(ctx->A));

        ctx->num = 0;
        ctx->block_size = bsz;
        ctx->md_size = md_size_in_bits / 8;
        ctx->pad = pad;

        return 1;
    }

    return 0;
}

int keccak1600_update(KECCAK1600_CTX *ctx, const uint8_t *inp, size_t len)
{        
    size_t bsz = ctx->block_size;
    size_t num, rem;

    if (len == 0)
        return 1;

    if ((num = ctx->num) != 0) {      /* process intermediate buffer? */
        rem = bsz - num;

        if (len < rem) {
            memcpy(ctx->buf + num, inp, len);
            ctx->num += len;
            return 1;
        }
        /*
         * We have enough data to fill or overflow the intermediate
         * buffer. So we append |rem| bytes and process the block,
         * leaving the rest for later processing...
         */
        memcpy(ctx->buf + num, inp, rem);
        inp += rem, len -= rem;
        (void)SHA3_absorb(ctx->A, ctx->buf, bsz, bsz);
        ctx->num = 0;
        /* ctx->buf is processed, ctx->num is guaranteed to be zero */
    }

    if (len >= bsz)
        rem = SHA3_absorb(ctx->A, inp, len, bsz);
    else
        rem = len;

    if (rem) {
        memcpy(ctx->buf, inp + len - rem, rem);
        ctx->num = rem;
    }

    return 1;
}

int keccak1600_final(KECCAK1600_CTX *ctx, unsigned char *md)
{    
    size_t bsz = ctx->block_size;
    size_t num = ctx->num;

    /*
     * Pad the data with 10*1. Note that |num| can be |bsz - 1|
     * in which case both byte operations below are performed on
     * same byte...
     */
    memset(ctx->buf + num, 0, bsz - num);
    ctx->buf[num] = ctx->pad;
    ctx->buf[bsz - 1] |= 0x80;

    (void)SHA3_absorb(ctx->A, ctx->buf, bsz, bsz);

    SHA3_squeeze(ctx->A, md, ctx->md_size, bsz);

    return 1;
}