#ifndef __SIGN_ALGORITHM_H__
#define __SIGN_ALGORITHM_H__

typedef enum
{
    ECDSA_SECP256K1,
    EDDSA_ED25519,
    ECDSA_SECP256R1,
    ECDSA_STARK,
    SCHNORR_SECP256K1, // Schnorr signature on secp256k1
    SCHNORR_SECP256R1, // Schnorr signature on secp256r1
    SCHNORR_STARK      // Schnorr signature on stark
} cosigner_sign_algorithm;

#endif