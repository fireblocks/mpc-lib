#ifndef __ZKP_CONSTRAINTS_INTERNAL_H__
#define __ZKP_CONSTRAINTS_INTERNAL_H__

#include "crypto/elliptic_curve_algebra/elliptic_curve256_algebra.h"
#include "crypto/algebra_utils/algebra_utils.h"

// Parameter sizes for zero-knowledge proof optimizations

static inline CONSTEXPR uint32_t ZKPOK_OPTIM_KAPPA_SIZE()
{
    return sizeof(elliptic_curve256_scalar_t);
}

static inline CONSTEXPR uint32_t ZKPOK_OPTIM_L_SIZE(const uint32_t n_bitlen)
{
    return get_min_secure_exponent_size(n_bitlen) / 8;
}

static inline CONSTEXPR uint32_t ZKPOK_OPTIM_NU_SIZE(const uint32_t n_bitlen)
{
    (void)n_bitlen;
    // always return 8 bytes (ie 64 bits)
    return 8;
}

static inline CONSTEXPR uint32_t ZKPOK_OPTIM_NX_SIZE(const uint32_t n_bitlen)
{
    return ZKPOK_OPTIM_KAPPA_SIZE() + ZKPOK_OPTIM_NU_SIZE(n_bitlen);
}

static inline CONSTEXPR uint32_t ZKPOK_OPTIM_EPSILON_SIZE(const uint32_t n_bitlen)
{
    return ZKPOK_OPTIM_L_SIZE(n_bitlen) + ZKPOK_OPTIM_NU_SIZE(n_bitlen);
}

static inline CONSTEXPR uint32_t ZKPOK_OPTIM_SMALL_GROUP_EXPONENT_BITS(const uint32_t n_bitlen)
{
    return ((2 * ZKPOK_OPTIM_L_SIZE(n_bitlen) + ZKPOK_OPTIM_NU_SIZE(n_bitlen)) * 8);
}

static inline CONSTEXPR uint32_t ZKPOK_OPTIM_NLAMBDA_SIZE(const uint32_t n_bitlen)
{
    return (2 * ZKPOK_OPTIM_L_SIZE(n_bitlen) + ZKPOK_OPTIM_NU_SIZE(n_bitlen) );
}


#endif //__ZKP_CONSTRAINTS_INTERNAL_H__