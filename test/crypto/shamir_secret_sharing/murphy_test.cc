#include <iostream>
#include "crypto/shamir_secret_sharing/verifiable_secret_sharing.h"
#include "crypto/elliptic_curve_algebra/elliptic_curve256_algebra.h"
#include <openssl/bn.h>

#include <memory>

std::unique_ptr<elliptic_curve256_algebra_ctx_t, void (*)(elliptic_curve256_algebra_ctx_t*)> secp256k1(elliptic_curve256_new_secp256k1_algebra(), elliptic_curve256_algebra_ctx_free);

int main(int argc, char*argv[]){
    std::cout << "hello" << std::endl; 

    const unsigned char secret[33] = "01234567890123456789012345678912";
    unsigned char secret2[33] = {0};
    verifiable_secret_sharing_t *shamir;
    shamir_secret_share_t share[3];
    uint32_t size;

    if (verifiable_secret_sharing_split(secp256k1.get(), secret, sizeof(secret) - 1, 3, 5, &shamir) 
            == VERIFIABLE_SECRET_SHARING_SUCCESS){
            
        std::cout << "sucess of some description" << std::endl;
    }

    return 0; 
}