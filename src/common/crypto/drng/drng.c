#include "crypto/drng/drng.h"
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>
#include <openssl/crypto.h>

struct drng
{
    uint8_t data[SHA512_DIGEST_LENGTH / 2];
    uint8_t seed[SHA512_DIGEST_LENGTH / 2];
    uint8_t pos;
};

drng_status drng_new(const uint8_t *seed, uint32_t seed_len, drng_t **rng)
{
    drng_t *local_rng = NULL;

    if (!seed || !seed_len || !rng)
    {
        return DRNG_INVALID_PARAMETER;
    }
        
    local_rng = malloc(sizeof(drng_t));

    if (!local_rng)
    {
        return DRNG_OUT_OF_MEMORY;
    }
        
    
    local_rng->pos = 0;
    SHA512(seed, seed_len, local_rng->data); // data and seed are continuous in memory so SHA512 function will initialize both the data and the seed for the next operation
    *rng = local_rng;
    return DRNG_SUCCESS;
}

void drng_free(drng_t *rng)
{
    if (rng)
    {
        OPENSSL_cleanse(rng, sizeof(drng_t));
        free(rng);
    }
}

drng_status drng_read_deterministic_rand(drng_t *rng, uint8_t *rand, uint32_t length_in_bytes)
{
    if (!rng || !rand || !length_in_bytes)
    {
        return DRNG_INVALID_PARAMETER;
    }
        

    // prevent buffer overflow / memory corruption in case rand buffer points to the drng data structure
    if ((rand >= rng->data && rand <= (uint8_t*)(rng + 1)) ||
        (rand < rng->data && rand + length_in_bytes > (uint8_t*)rng))
    {
        return DRNG_INVALID_PARAMETER;
    }
        
    // since rng->pos is always <= sizeof(rng->data)
    while (length_in_bytes > sizeof(rng->data) - rng->pos)
    {
        const uint8_t size = sizeof(rng->data) - rng->pos;
        memcpy(rand, rng->data + rng->pos, size);
        rand += size;
        length_in_bytes -= size;
        rng->pos = 0;
        SHA512(rng->seed, sizeof(rng->seed), rng->data);
    }

    memcpy(rand, rng->data + rng->pos, length_in_bytes);
    rng->pos += length_in_bytes;

    return DRNG_SUCCESS;
}
