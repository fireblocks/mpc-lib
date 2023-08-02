#ifndef __DRNG_H__
#define __DRNG_H__

#ifdef __cplusplus
extern "C" {
#endif //__cplusplus

#include <stdint.h>

typedef struct drng drng_t;

typedef enum
{
    DRNG_SUCCESS               =  0,
    DRNG_INTERNAL_ERROR        = -1,
    DRNG_INVALID_PARAMETER     = -2,
    DRNG_OUT_OF_MEMORY         = -3,
} drng_status;

/* This module implements deterministic pseudo random number generator, it should be used only for sampling deterministic randomness
   For true randomness you should use openssl RAND_bytes function or sgx_read_rand if used inside SGX */
drng_status drng_new(const uint8_t *seed, uint32_t seed_len, drng_t **rng);
drng_status drng_read_deterministic_rand(drng_t *rng, uint8_t *rand, uint32_t length_in_bytes);
void drng_free(drng_t *rng);

#ifdef __cplusplus
}
#endif //__cplusplus

#endif // __DRNG_H__