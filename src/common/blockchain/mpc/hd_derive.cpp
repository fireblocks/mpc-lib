#include <string>
#include <assert.h>
#include <map>

#include <openssl/evp.h>
#include <openssl/hmac.h>

#include "blockchain/mpc/hd_derive.h"

#include <string.h>

const uint32_t BIP44 = 0x0000002c;

typedef unsigned char hmac_sha_result[64];

inline bool is_hardened(uint32_t child_num)
{
    return (child_num >> 31) != 0;
}

// copied from bitcoin and modified
static hd_derive_status BIP32Hash(hmac_sha_result output, const HDChaincode chainCode, unsigned int nChild, unsigned char header, const unsigned char data[32])
{
    unsigned int output_len = 64;
    unsigned char num[4];
    hd_derive_status retval = HD_DERIVE_ERROR_HASH;

    num[0] = (nChild >> 24) & 0xFF;
    num[1] = (nChild >> 16) & 0xFF;
    num[2] = (nChild >>  8) & 0xFF;
    num[3] = (nChild >>  0) & 0xFF;

    HMAC_CTX* ctx = HMAC_CTX_new();
    if (ctx == NULL){
        goto end_bip32_hash;
    }
    if (1 != HMAC_Init_ex(ctx, chainCode, CHAIN_CODE_SIZE_BYTES, EVP_sha512(), NULL)) {
        goto end_bip32_hash;
    }

    if (1 != HMAC_Update(ctx, &header, 1)) {
        goto end_bip32_hash;
    }
    if (1 != HMAC_Update(ctx, data, 32)) {
        goto end_bip32_hash;
    }
    if (1 != HMAC_Update(ctx, num, 4)) {
        goto end_bip32_hash;
    }

    if (1 != HMAC_Final(ctx, output, &output_len)) {
        goto end_bip32_hash;
    }

    retval = HD_DERIVE_SUCCESS;

    end_bip32_hash:
        if (ctx != NULL){
            HMAC_CTX_free(ctx);
        }
        return retval;
}

static hd_derive_status hash_for_derive(hmac_sha_result out, const PubKey pubkey, const PrivKey privkey, const HDChaincode chaincode, uint32_t child_num)
{
    if (is_hardened(child_num)) {
        return BIP32Hash(out, chaincode, child_num, 0, privkey);
    }
    return BIP32Hash(out, chaincode, child_num, pubkey[0], &(pubkey[1]));
}

static hd_derive_status derive_next_key_level_(const elliptic_curve256_algebra_ctx_t* ctx, PubKey derived_pubkey, PrivKey derived_privkey, HDChaincode derived_chaincode, const PubKey *pubkey, const PrivKey privkey, 
    const HDChaincode chaincode, uint32_t child_num, bool derive_private) {
    hmac_sha_result hash;
    elliptic_curve256_point_t tmp_point;

    if (is_hardened(child_num) && !derive_private) {
        return HD_DERIVE_ERROR_HARDENED_PUBLIC;
    }

    hd_derive_status retval = hash_for_derive(hash, *pubkey, privkey, chaincode, child_num);
    if (HD_DERIVE_SUCCESS != retval){
        return retval;
    }
    memcpy(derived_chaincode, &(hash[32]), 32);
    memcpy(tmp_point, pubkey, COMPRESSED_PUBLIC_KEY_SIZE);
    if (ELLIPTIC_CURVE_ALGEBRA_SUCCESS != ctx->generator_mul_data(ctx, hash, 32, &tmp_point))
        return HD_DERIVE_ERROR_ADDING_TWEAK_TO_PUB;
    if (ELLIPTIC_CURVE_ALGEBRA_SUCCESS != ctx->add_points(ctx, &tmp_point, pubkey, &tmp_point))
        return HD_DERIVE_ERROR_ADDING_TWEAK_TO_PUB;
    memcpy(derived_pubkey, tmp_point, COMPRESSED_PUBLIC_KEY_SIZE);

    // derive next private key level, if we're deriving private keys
    if (derive_private) {
        elliptic_curve256_scalar_t tmp_priv;
        if (ELLIPTIC_CURVE_ALGEBRA_SUCCESS != ctx->add_scalars(ctx, &tmp_priv, privkey, PRIVATE_KEY_SIZE, hash, 32))
            return HD_DERIVE_ERROR_ADDING_TWEAK_TO_PRIV;
        memcpy(derived_privkey, tmp_priv, PRIVATE_KEY_SIZE);
        OPENSSL_cleanse(tmp_priv, PRIVATE_KEY_SIZE);
    }
    return HD_DERIVE_SUCCESS;
}

hd_derive_status derive_public_key_generic(const elliptic_curve256_algebra_ctx_t *ctx, PubKey derived_key, const PubKey pubkey, const HDChaincode chaincode, const uint32_t* path, const uint32_t path_len) {
    PrivKey unused;
    PubKey temp_pubkey;
    HDChaincode next_chain_code;

    if (!path || !path_len)
    {
        memcpy(derived_key, pubkey, COMPRESSED_PUBLIC_KEY_SIZE);
        return HD_DERIVE_SUCCESS;
    }
    memcpy(temp_pubkey, pubkey, COMPRESSED_PUBLIC_KEY_SIZE);

    HDChaincode current_chain_code;
    memcpy(current_chain_code, chaincode, CHAIN_CODE_SIZE_BYTES);

    for (uint32_t i=0; i < path_len; i++){
        hd_derive_status retval = derive_next_key_level_(ctx, derived_key, unused, next_chain_code, &temp_pubkey, unused, current_chain_code, path[i], false);
        if (HD_DERIVE_SUCCESS != retval){
            return retval;
        }
        memcpy(temp_pubkey, derived_key, COMPRESSED_PUBLIC_KEY_SIZE);
        memcpy(current_chain_code, next_chain_code, CHAIN_CODE_SIZE_BYTES);
    }

    return HD_DERIVE_SUCCESS;
}

hd_derive_status derive_private_key_generic(const elliptic_curve256_algebra_ctx_t *ctx, PrivKey derived_privkey, const PubKey pubkey, const PrivKey privkey, const HDChaincode chaincode, const uint32_t* path, const uint32_t path_len) {
    PubKey derived_pubkey;
    return derive_private_and_public_keys(ctx, derived_privkey, derived_pubkey, pubkey, privkey, chaincode, path, path_len);
}

hd_derive_status derive_private_and_public_keys(const elliptic_curve256_algebra_ctx_t *ctx, PrivKey derived_privkey, PubKey derived_pubkey, const PubKey pubkey, const PrivKey privkey, const HDChaincode chaincode, 
    const uint32_t* path, const uint32_t path_len) {
    PubKey temp_pubkey;

    if (!path || !path_len)
    {
        memcpy(derived_privkey, privkey, PRIVATE_KEY_SIZE);
        return HD_DERIVE_SUCCESS;
    }
    memcpy(temp_pubkey, pubkey, COMPRESSED_PUBLIC_KEY_SIZE);

    PrivKey temp_privkey;
    memcpy(temp_privkey, privkey, PRIVATE_KEY_SIZE);

    HDChaincode current_chain_code;
    HDChaincode next_chain_code;
    memcpy(current_chain_code, chaincode, CHAIN_CODE_SIZE_BYTES);

    hd_derive_status retval = HD_DERIVE_ERROR_GENERAL;
    for (uint32_t i=0; i < path_len; i++){
        hd_derive_status retval = derive_next_key_level_(ctx, derived_pubkey, derived_privkey, next_chain_code, &temp_pubkey, temp_privkey, current_chain_code, path[i], true);
        if (HD_DERIVE_SUCCESS != retval)
        {
            goto cleanup;
        }
        memcpy(temp_pubkey, derived_pubkey, COMPRESSED_PUBLIC_KEY_SIZE);
        memcpy(temp_privkey, derived_privkey, PRIVATE_KEY_SIZE);
        memcpy(current_chain_code, next_chain_code, CHAIN_CODE_SIZE_BYTES);
    }

    retval = HD_DERIVE_SUCCESS;

cleanup:
    OPENSSL_cleanse(temp_privkey, PRIVATE_KEY_SIZE);
    OPENSSL_cleanse(temp_pubkey, COMPRESSED_PUBLIC_KEY_SIZE);
    return retval;
}

hd_derive_status build_bip44_path(Bip44Path path, uint32_t asset_num, uint32_t account, uint32_t change, uint32_t addr_index) {
    path[0] = BIP44; //purpose
    path[1] = asset_num;
    path[2] = account;
    path[3] = change;
    path[4] = addr_index;
    return HD_DERIVE_SUCCESS;
}
