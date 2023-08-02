#define OPENSSL_USE_NODELETE 
#define L_ENDIAN 
#define OPENSSL_PIC 
#define OPENSSL_CPUID_OBJ 
#define OPENSSL_IA32_SSE2 
#define OPENSSL_BN_ASM_MONT 
#define OPENSSL_BN_ASM_MONT5 
#define OPENSSL_BN_ASM_GF2m 
#define SHA1_ASM 
#define SHA256_ASM 
#define SHA512_ASM 
#if defined(__x86_64__)
#define X25519_ASM
#endif

#include <openssl/crypto.h>