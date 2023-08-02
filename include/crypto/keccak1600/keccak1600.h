#ifndef __KECCAK1600_H__
#define __KECCAK1600_H__

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif //__cplusplus

#define KECCAK256_PAD    '\x01'
#define SHA3_FIPS202_PAD '\x06'  // https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf (B.2, q>2)

#define KECCAK1600_WIDTH 1600

typedef struct {
    uint64_t A[5][5];
    size_t block_size;          /* cached ctx->digest->block_size */
    size_t md_size;             /* output length, variable in XOF */
    size_t num;                 /* used bytes in below buffer */
    unsigned char buf[KECCAK1600_WIDTH / 8 - 32];
    unsigned char pad;
} KECCAK1600_CTX;

int keccak1600_init(KECCAK1600_CTX *ctx, size_t md_size_in_bits, unsigned char pad);
int keccak1600_update(KECCAK1600_CTX *ctx, const uint8_t *inp, size_t len);
int keccak1600_final(KECCAK1600_CTX *ctx, unsigned char *md);

#ifdef __cplusplus
}
#endif //__cplusplus

#endif // __KECCAK1600_H__
