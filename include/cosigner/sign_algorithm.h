#ifndef __SIGN_ALGORITHM_H__
#define __SIGN_ALGORITHM_H__

typedef enum
{
    ECDSA_SECP256K1,
    EDDSA_ED25519,
    ECDSA_SECP256R1,
    ECDSA_STARK,
} cosigner_sign_algorithm;

#endif