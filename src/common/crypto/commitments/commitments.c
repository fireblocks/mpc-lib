#include "crypto/commitments/commitments.h"

#include <string.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>

struct commitments_ctx
{
    commitments_sha256_t commitment;
    SHA256_CTX ctx;
    uint8_t verifier;
};

commitments_status commitments_create_commitment_for_data(const uint8_t *data, uint32_t data_len, commitments_commitment_t *commitment)
{
    SHA256_CTX ctx;
    if (!data || !data_len || !commitment)
        return COMMITMENTS_INVALID_PARAMETER;
    if (!RAND_bytes(commitment->salt, sizeof(commitments_sha256_t)))
        return COMMITMENTS_INTERNAL_ERROR;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, commitment->salt, sizeof(commitments_sha256_t));
    SHA256_Update(&ctx, data, data_len);
    SHA256_Final(commitment->commitment, &ctx);
    return COMMITMENTS_SUCCESS;
}

commitments_status commitments_verify_commitment(const uint8_t *data, uint32_t data_len, const commitments_commitment_t *commitment)
{
    commitments_sha256_t hash;
    SHA256_CTX ctx;
    if (!data || !data_len || !commitment)
        return COMMITMENTS_INVALID_PARAMETER;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, commitment->salt, sizeof(commitments_sha256_t));
    SHA256_Update(&ctx, data, data_len);
    SHA256_Final(hash, &ctx);
    return CRYPTO_memcmp(hash, commitment->commitment, sizeof(commitments_sha256_t)) ? COMMITMENTS_INVALID_COMMITMENT : COMMITMENTS_SUCCESS;
}

commitments_status commitments_ctx_commitment_new(commitments_ctx_t **ctx)
{
    commitments_ctx_t *local_ctx;
    if (!ctx)
        return COMMITMENTS_INVALID_PARAMETER;
    *ctx = NULL;

    local_ctx = (commitments_ctx_t*)malloc(sizeof(commitments_ctx_t));
    if (!local_ctx)
        return COMMITMENTS_OUT_OF_MEMORY;
    if (!RAND_bytes(local_ctx->commitment, sizeof(commitments_sha256_t)))
    {
        free(local_ctx);
        return COMMITMENTS_INTERNAL_ERROR;
    }
    local_ctx->verifier = 0;
    SHA256_Init(&local_ctx->ctx);
    SHA256_Update(&local_ctx->ctx, local_ctx->commitment, sizeof(commitments_sha256_t));
    *ctx = local_ctx;
    return COMMITMENTS_SUCCESS;
}

commitments_status commitments_ctx_commitment_update(commitments_ctx_t *ctx, const void *data, uint32_t data_len)
{
    if (!ctx || !data || !data_len)
        return COMMITMENTS_INVALID_PARAMETER;
    if (ctx->verifier)
        return COMMITMENTS_INVALID_CONTEXT;
    SHA256_Update(&ctx->ctx, data, data_len);
    return COMMITMENTS_SUCCESS;
}

commitments_status commitments_ctx_commitment_final(commitments_ctx_t *ctx, commitments_commitment_t *commitment)
{
    if (!ctx || !commitment)
        return COMMITMENTS_INVALID_PARAMETER;
    if (ctx->verifier)
        return COMMITMENTS_INVALID_CONTEXT;
    memcpy(commitment->salt, ctx->commitment, sizeof(commitments_sha256_t));
    SHA256_Final(commitment->commitment, &ctx->ctx);
    free(ctx);
    return COMMITMENTS_SUCCESS;
}

commitments_status commitments_ctx_verify_new(commitments_ctx_t **ctx, const commitments_commitment_t *commitment)
{
    commitments_ctx_t *local_ctx;
    if (!ctx || !commitment)
        return COMMITMENTS_INVALID_PARAMETER;
    *ctx = NULL;

    local_ctx = (commitments_ctx_t*)malloc(sizeof(commitments_ctx_t));
    if (!local_ctx)
        return COMMITMENTS_OUT_OF_MEMORY;
    local_ctx->verifier = 1;
    memcpy(local_ctx->commitment, commitment->commitment, sizeof(commitments_sha256_t));
    SHA256_Init(&local_ctx->ctx);
    SHA256_Update(&local_ctx->ctx, commitment->salt, sizeof(commitments_sha256_t));
    *ctx = local_ctx;
    return COMMITMENTS_SUCCESS;
}

commitments_status commitments_ctx_verify_update(commitments_ctx_t *ctx, const void *data, uint32_t data_len)
{
    if (!ctx || !data || !data_len)
        return COMMITMENTS_INVALID_PARAMETER;
    if (!ctx->verifier)
        return COMMITMENTS_INVALID_CONTEXT;
    SHA256_Update(&ctx->ctx, data, data_len);
    return COMMITMENTS_SUCCESS;
}

commitments_status commitments_ctx_verify_final(commitments_ctx_t *ctx)
{
    commitments_sha256_t hash;
    commitments_status ret;
    if (!ctx)
        return COMMITMENTS_INVALID_PARAMETER;
    if (!ctx->verifier)
        return COMMITMENTS_INVALID_CONTEXT;
    SHA256_Final(hash, &ctx->ctx);
    ret = CRYPTO_memcmp(hash, ctx->commitment, sizeof(commitments_sha256_t)) ? COMMITMENTS_INVALID_COMMITMENT : COMMITMENTS_SUCCESS;
    free(ctx);
    return ret;
}

void commitments_ctx_free(commitments_ctx_t *ctx)
{
    if (ctx)
        free(ctx);
}
