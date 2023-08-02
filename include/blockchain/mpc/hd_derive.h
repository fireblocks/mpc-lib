#ifndef __HD_DERIVE_H__
#define __HD_DERIVE_H__

#include <assert.h>
#include <stdint.h>
#include "crypto/elliptic_curve_algebra/elliptic_curve256_algebra.h"

#ifdef __cplusplus
extern "C" {
#endif //__cplusplus

const unsigned int COMPRESSED_PUBLIC_KEY_SIZE  = 33;
const unsigned int UNCOMPRESSED_PUBLIC_KEY_SIZE = 65;
const uint8_t UNCOMPRESSED_PUBLIC_KEY_PREFIX = 0x04;
const unsigned int EDDSA_PUBLIC_KEY_SIZE = 32;
const unsigned int PRIVATE_KEY_SIZE = 32;
const unsigned int CHAIN_CODE_SIZE_BYTES = 32;
const unsigned int BIP44_PATH_LENGTH = 5;
typedef unsigned char HDChaincode[CHAIN_CODE_SIZE_BYTES];
typedef unsigned char PubKey[COMPRESSED_PUBLIC_KEY_SIZE];
typedef unsigned char PrivKey[PRIVATE_KEY_SIZE];

typedef enum
{
    HD_DERIVE_SUCCESS                       =  0,
    HD_DERIVE_ERROR_HASH                    = -1,
    HD_DERIVE_ERROR_OUT_OF_MEMORY           = -2,
    HD_DERIVE_ERROR_HARDENED_PUBLIC         = -3,
    HD_DERIVE_ERROR_SECP                    = -4,
    HD_DERIVE_ERROR_BAD_PUBKEY              = -5,
    HD_DERIVE_ERROR_ADDING_TWEAK_TO_PUB     = -6,
    HD_DERIVE_ERROR_BAD_DERIVED_PUBKEY      = -7,
    HD_DERIVE_ERROR_ADDING_TWEAK_TO_PRIV    = -8,
    HD_DERIVE_ERROR_BAD_DERIVED_PUBKEY_SIZE = -9,
    HD_DERIVE_ERROR_GENERAL                 = -10
} hd_derive_status;

inline uint32_t bip32_hardened_index(uint32_t idx)
{
    assert(idx < 1U<<31);
    return (1U<<31) + idx;
}

// TODO: Refactor receive allocated int[BIP44_PATH_LENGTH] path
hd_derive_status build_bip44_path(uint32_t** path, uint32_t* path_len, uint32_t asset_num, uint32_t account, uint32_t change = 0, uint32_t addr_index = 0);
hd_derive_status derive_public_key_generic(const elliptic_curve256_algebra_ctx_t *ctx, PubKey derived_key, const PubKey pubkey, const HDChaincode chaincode, const uint32_t* path, const uint32_t path_len);
hd_derive_status derive_private_key_generic(const elliptic_curve256_algebra_ctx_t *ctx, PrivKey derived_privkey, const PubKey pubkey, const PrivKey privkey, const HDChaincode chaincode, const uint32_t* path, const uint32_t path_len);
hd_derive_status derive_private_and_public_keys(const elliptic_curve256_algebra_ctx_t *ctx, PrivKey derived_privkey, PubKey derived_pubkey, const PubKey pubkey, const PrivKey privkey, const HDChaincode chaincode, const uint32_t* path, const uint32_t path_len);

#ifdef __cplusplus
}
#endif //__cplusplus

#endif // __HD_DERIVE_H__