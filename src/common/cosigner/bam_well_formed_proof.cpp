#include "bam_well_formed_proof.h"

#include <openssl/sha.h>
#include <openssl/bn.h>
#include <openssl/err.h>

#include "cosigner/bam_ecdsa_cosigner.h"
#include "cosigner_bn.h"
#include "logging/logging_t.h"
#include "../crypto/paillier_commitment/paillier_commitment_internal.h"

namespace fireblocks::common::cosigner::bam_well_formed_proof
{
using cosigner_params = bam_ecdsa_cosigner::cosigner_params;

namespace //anonymous namespace
{
struct well_formed_signature_proof 
{
    explicit well_formed_signature_proof(struct bignum_ctx* ctx) :
        bn_ctx(ctx)
    {        
        D = BN_CTX_get(ctx);
        z1 = BN_CTX_get(ctx);
        z2 = BN_CTX_get(ctx);
        w2 = BN_CTX_get(ctx);

        if (!D || !z1 || !z2 || !w2)
        {
            throw cosigner_exception(cosigner_exception::NO_MEM);
        }
    }

    struct bignum_st* D;
    elliptic_curve256_point_t U;
    elliptic_curve256_point_t V;
    struct bignum_st* z1 { nullptr };
    struct bignum_st* z2 { nullptr };
    elliptic_curve256_scalar_t w0;
    struct bignum_st* w2 { nullptr };
private:
    bn_ctx_frame bn_ctx;
};

static uint32_t signature_proof_size(const uint32_t paillier_commitment_n_size)
{
    return sizeof(uint32_t) +                                                                                           // size of the paillier public key
            2 * paillier_commitment_n_size +                                                                            // sizeof(D)
            sizeof(elliptic_curve256_point_t) +                                                                         // sizeof(U)
            sizeof(elliptic_curve256_point_t) +                                                                         // sizeof(V)
            cosigner_params::ZKPOK_OPTIM_NA_SIZE + ZKPOK_OPTIM_EPSILON_SIZE(paillier_commitment_n_size * 8) +           // sizeof(z1)
            cosigner_params::ZKPOK_OPTIM_NB_SIZE + ZKPOK_OPTIM_EPSILON_SIZE(paillier_commitment_n_size * 8) +           // sizeof(z2)
            sizeof(elliptic_curve256_scalar_t) +                                                                        // sizeof(w0)
            cosigner_params::ZKPOK_OPTIM_NLAMBDA0_SIZE + ZKPOK_OPTIM_EPSILON_SIZE(paillier_commitment_n_size * 8);      // sizeof(w2)
}

void serialize_well_formed_proof(const uint32_t paillier_commitment_n_bitsize, const well_formed_signature_proof& proof, byte_vector_t &serialized)
{
    const uint32_t paillier_size = (paillier_commitment_n_bitsize + 7) / 8;
    serialized.resize(signature_proof_size(paillier_size));
    
    uint8_t* ptr = serialized.data();

    *(uint32_t *)ptr = paillier_size;
    ptr += sizeof(uint32_t);
    
    if (BN_bn2binpad(proof.D, ptr, 2 * paillier_size) <= 0)
    {
        throw_cosigner_exception(ZKP_UNKNOWN_ERROR);
    }
    ptr += 2 * paillier_size;

    memcpy(ptr, proof.U, sizeof(elliptic_curve256_point_t));
    ptr += sizeof(elliptic_curve256_point_t);

    memcpy(ptr, proof.V, sizeof(elliptic_curve256_point_t));
    ptr += sizeof(elliptic_curve256_point_t);

    if (BN_bn2binpad(proof.z1, ptr, cosigner_params::ZKPOK_OPTIM_NA_SIZE + ZKPOK_OPTIM_EPSILON_SIZE(paillier_commitment_n_bitsize)) <= 0)
    {
        throw_cosigner_exception(ZKP_UNKNOWN_ERROR);
    }
    ptr += cosigner_params::ZKPOK_OPTIM_NA_SIZE + ZKPOK_OPTIM_EPSILON_SIZE(paillier_commitment_n_bitsize);

    if (BN_bn2binpad(proof.z2, ptr, cosigner_params::ZKPOK_OPTIM_NB_SIZE + ZKPOK_OPTIM_EPSILON_SIZE(paillier_commitment_n_bitsize)) <= 0)
    {
        throw_cosigner_exception(ZKP_UNKNOWN_ERROR);
    }
    ptr += cosigner_params::ZKPOK_OPTIM_NB_SIZE + ZKPOK_OPTIM_EPSILON_SIZE(paillier_commitment_n_bitsize);

    memcpy(ptr, proof.w0, sizeof(elliptic_curve256_scalar_t));
    ptr += sizeof(elliptic_curve256_scalar_t);

    if (BN_bn2binpad(proof.w2, ptr, cosigner_params::ZKPOK_OPTIM_NLAMBDA0_SIZE + ZKPOK_OPTIM_EPSILON_SIZE(paillier_commitment_n_bitsize)) <= 0)
    {
        throw_cosigner_exception(ZKP_UNKNOWN_ERROR);
    }
    ptr += cosigner_params::ZKPOK_OPTIM_NLAMBDA0_SIZE + ZKPOK_OPTIM_EPSILON_SIZE(paillier_commitment_n_bitsize);

    assert(ptr == serialized.data() + serialized.size());
}

void deserialize_well_formed_proof(const uint32_t paillier_commitment_n_bitsize, well_formed_signature_proof& proof, const byte_vector_t& serialized)
{
    const uint32_t expected_paillier_commitment_size = (paillier_commitment_n_bitsize + 7) / 8;

    const uint8_t* ptr = serialized.data();

    const uint32_t expected_signature_size = signature_proof_size(expected_paillier_commitment_size);

    if (expected_signature_size > serialized.size())
    {
        LOG_ERROR("Error in deserialize_well_formed_proof. Size mismatch %u != %u", expected_signature_size, (uint32_t)serialized.size());
        throw_cosigner_exception(ZKP_VERIFICATION_FAILED);
    }
    
    const uint32_t paillier_size = *(const uint32_t *)ptr;
    ptr += sizeof(uint32_t);

    if (paillier_size != expected_paillier_commitment_size)
    {
        LOG_ERROR("Error in deserialize_well_formed_proof. Size of n mismatch %u != %u", paillier_size, expected_paillier_commitment_size);
        throw_cosigner_exception(ZKP_VERIFICATION_FAILED);
    }

    if (!BN_bin2bn(ptr, 2 * paillier_size, proof.D))
    {
        throw_cosigner_exception(ZKP_VERIFICATION_FAILED);
    }
    ptr += 2 * paillier_size;

    memcpy(proof.U, ptr, sizeof(elliptic_curve256_point_t));
    ptr += sizeof(elliptic_curve256_point_t);

    memcpy(proof.V, ptr, sizeof(elliptic_curve256_point_t));
    ptr += sizeof(elliptic_curve256_point_t);

    if (!BN_bin2bn(ptr, cosigner_params::ZKPOK_OPTIM_NA_SIZE + ZKPOK_OPTIM_EPSILON_SIZE(paillier_commitment_n_bitsize), proof.z1))
    {
        throw_cosigner_exception(ZKP_VERIFICATION_FAILED);
    }
    ptr += (cosigner_params::ZKPOK_OPTIM_NA_SIZE + ZKPOK_OPTIM_EPSILON_SIZE(paillier_commitment_n_bitsize));

    if (!BN_bin2bn(ptr, cosigner_params::ZKPOK_OPTIM_NB_SIZE + ZKPOK_OPTIM_EPSILON_SIZE(paillier_commitment_n_bitsize), proof.z2))
    {
        throw_cosigner_exception(ZKP_VERIFICATION_FAILED);
    }
    ptr += cosigner_params::ZKPOK_OPTIM_NB_SIZE + ZKPOK_OPTIM_EPSILON_SIZE(paillier_commitment_n_bitsize);

    memcpy(proof.w0, ptr, sizeof(elliptic_curve256_scalar_t));
    ptr += sizeof(elliptic_curve256_scalar_t);

    if (!BN_bin2bn(ptr, cosigner_params::ZKPOK_OPTIM_NLAMBDA0_SIZE + ZKPOK_OPTIM_EPSILON_SIZE(paillier_commitment_n_bitsize), proof.w2))
    {
        throw_cosigner_exception(ZKP_OUT_OF_MEMORY);
    }
    ptr += cosigner_params::ZKPOK_OPTIM_NLAMBDA0_SIZE + ZKPOK_OPTIM_EPSILON_SIZE(paillier_commitment_n_bitsize);

    assert(expected_signature_size == (uint32_t)(ptr - serialized.data()));
}


static byte_vector_t compute_e(const well_formed_signature_proof& proof,
                               const struct bignum_st* S,
                               const struct bignum_st* encrypted_share,
                               const commitments_sha256_t& signature_aad,
                               const pedersen_commitment_two_generators_t& ec_base,
                               const paillier_commitment_public_key_t& paillier,
                               const elliptic_curve256_point_t& r_server)
{
    byte_vector_t ret(sizeof(commitments_sha256_t));
    SHA256_CTX ctx;
    if (!SHA256_Init(&ctx))
    {
        throw_cosigner_exception(ZKP_OUT_OF_MEMORY);
    }
        
    if (!SHA256_Update(&ctx, &signature_aad[0], sizeof(commitments_sha256_t)) ||
        !SHA256_Update(&ctx, ec_base.h, sizeof(elliptic_curve256_point_t)) ||
        !SHA256_Update(&ctx, ec_base.f, sizeof(elliptic_curve256_point_t)))
    {
        throw_cosigner_exception(ZKP_OUT_OF_MEMORY);
    }

    const uint32_t paillier_size = BN_num_bytes(paillier.n);
    const uint32_t paillier_size_n2 = BN_num_bytes(paillier.n2);
    
    assert(paillier_size_n2 > paillier_size);

    byte_vector_t tmp(paillier_size_n2); // use maximum size in advance
    if (BN_bn2binpad(paillier.n, tmp.data(), paillier_size) != (int)paillier_size || 
        !SHA256_Update(&ctx, tmp.data(), paillier_size))
    {
        throw_cosigner_exception(ZKP_OUT_OF_MEMORY);
    }

    assert(BN_num_bytes(paillier.t) <= (int)paillier_size);
    if (BN_bn2binpad(paillier.t, tmp.data(), paillier_size) != (int)paillier_size || 
        !SHA256_Update(&ctx, tmp.data(), paillier_size))
    {
        throw_cosigner_exception(ZKP_OUT_OF_MEMORY);
    }

    assert(BN_num_bytes(paillier.s) <= (int)paillier_size);
    if (BN_bn2binpad(paillier.s, tmp.data(), paillier_size) != (int)paillier_size || 
        !SHA256_Update(&ctx, tmp.data(), paillier_size))
    {
        throw_cosigner_exception(ZKP_OUT_OF_MEMORY);
    }

    if (BN_bn2binpad(S, tmp.data(), paillier_size_n2) != (int)paillier_size_n2 ||
        !SHA256_Update(&ctx, tmp.data(), paillier_size_n2))
    {
        throw_cosigner_exception(ZKP_OUT_OF_MEMORY);
    }

    if (BN_bn2binpad(encrypted_share, tmp.data(), paillier_size_n2) != (int)paillier_size_n2 ||
        !SHA256_Update(&ctx, tmp.data(), paillier_size_n2))
    {
        throw_cosigner_exception(ZKP_OUT_OF_MEMORY);
    }

    if (!SHA256_Update(&ctx, &r_server[0], sizeof(elliptic_curve256_point_t)))
    {
        throw_cosigner_exception(ZKP_OUT_OF_MEMORY);
    }

    if (!SHA256_Update(&ctx, proof.U, sizeof(proof.U)) ||
        !SHA256_Update(&ctx, proof.V, sizeof(proof.V)))
    {
        throw_cosigner_exception(ZKP_OUT_OF_MEMORY);
    }        
    
    assert(BN_num_bytes(proof.D) <= (int)paillier_size_n2);
    if (BN_bn2binpad(proof.D, tmp.data(), paillier_size_n2) != (int)paillier_size_n2 || 
        !SHA256_Update(&ctx, tmp.data(), paillier_size_n2))
    {
        throw_cosigner_exception(ZKP_OUT_OF_MEMORY);
    }
    
    if (!SHA256_Final(ret.data(), &ctx))
    {
        throw_cosigner_exception(ZKP_OUT_OF_MEMORY);
    }
    return ret;
}


} //anonymous namespace

void generate_signature_proof(const paillier_commitment_public_key_t *paillier,
                              elliptic_curve256_algebra_ctx *algebra,
                              struct bignum_ctx *ctx,
                              const pedersen_commitment_two_generators_t *ec_base,  //two points h and f
                              const struct bignum_st *plaintext,                  // this is u, called a in proof
                              const struct bignum_st *encrypted_share,            // encrypted server share
                              const struct bignum_st *exponent,                   // v, called b in proof
                              const struct bignum_st *lambda0,                      // same lambda0 used in the partial signature encryption
                              const struct bignum_st* S,                            // partial signature
                              const commitments_sha256_t& signature_aad,
                              const byte_vector_t& plaintext_bin,                   // plaintext binary
                              const byte_vector_t& exponent_bin,                    // exponent binary
                              const elliptic_curve256_point_t& r_server,
                              byte_vector_t &serialized)
{
    if (!paillier || !algebra || !ec_base || !lambda0 || !plaintext_bin.size() || !exponent_bin.size())
    {
        throw_cosigner_exception(ZKP_INVALID_PARAMETER);
    }

    well_formed_signature_proof well_formed_proof(ctx); //also starts the bn context

    elliptic_curve_scalar gamma;
    elliptic_curve_scalar gamma_p;

    BIGNUM *alpha = BN_CTX_get(ctx);
    BIGNUM *beta = BN_CTX_get(ctx);
    BIGNUM *lambda_p = BN_CTX_get(ctx);
    BIGNUM *e = BN_CTX_get(ctx);

    if (!alpha || !beta || !lambda_p || !e)
    {
        throw_cosigner_exception(ZKP_OUT_OF_MEMORY);
    }

    // generate all random parameters
    if (algebra->rand(algebra, &gamma.data) != ELLIPTIC_CURVE_ALGEBRA_SUCCESS ||         // generate random gamma
        algebra->rand(algebra, &gamma_p.data)!= ELLIPTIC_CURVE_ALGEBRA_SUCCESS ||        // generate random gamma_p
        !BN_rand(alpha,   (cosigner_params::ZKPOK_OPTIM_NA_SIZE          + cosigner_params::ZKPOK_OPTIM_EPSILON_SIZE) * 8, BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ANY) ||
        !BN_rand(beta,    (cosigner_params::ZKPOK_OPTIM_NB_SIZE          + cosigner_params::ZKPOK_OPTIM_EPSILON_SIZE) * 8, BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ANY) ||
        !BN_rand(lambda_p,(cosigner_params::ZKPOK_OPTIM_NLAMBDA0_SIZE    + cosigner_params::ZKPOK_OPTIM_EPSILON_SIZE) * 8, BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ANY)
    )
    {
        throw_cosigner_exception(ZKP_OUT_OF_MEMORY);
    }

    auto ret = pedersen_commitment_two_generators_create_commitment(&well_formed_proof.U, 
                                                                    ec_base,
                                                                    plaintext_bin.data(),
                                                                    plaintext_bin.size(),
                                                                    exponent_bin.data(),
                                                                    exponent_bin.size(),
                                                                    gamma.data,
                                                                    sizeof(gamma.data),
                                                                    algebra);
    if (ret != COMMITMENTS_SUCCESS)
    {
        LOG_ERROR("Error creating elliptic curve commitment. Error %d", ret);
        throw_cosigner_exception((commitments_status)ret);
    }

    // Generate V / B / D
    byte_vector_t alpha_bin, beta_bin;
    
    
    alpha_bin.resize(BN_num_bytes(alpha));
    beta_bin.resize(BN_num_bytes(beta));

    if (!BN_bn2bin(alpha, alpha_bin.data()) || 
        !BN_bn2bin(beta, beta_bin.data()))
    {
        throw_cosigner_exception(ZKP_OUT_OF_MEMORY);
    }

    ret = pedersen_commitment_two_generators_create_commitment(&well_formed_proof.V, 
                                                               ec_base,
                                                               alpha_bin.data(), // alpha
                                                               alpha_bin.size(), 
                                                               beta_bin.data(),  // beta
                                                               beta_bin.size(), 
                                                               gamma_p.data,
                                                               sizeof(gamma_p.data),
                                                               algebra);
    if (ret != COMMITMENTS_SUCCESS)
    {
        LOG_ERROR("Error creating elliptic curve commitment. Error %d", ret);
        throw_cosigner_exception((commitments_status)ret);
    }

    throw_paillier_exception(paillier_commitment_commit_internal(paillier, alpha, lambda_p, encrypted_share, beta, well_formed_proof.D, ctx));

    // compute e from all previous data.
    auto e_bin = compute_e(well_formed_proof, S, encrypted_share, signature_aad, *ec_base, *paillier, r_server);

    assert(e_bin.size() >= cosigner_params::ZKPOK_OPTIM_L_SIZE);

    e_bin.resize(cosigner_params::ZKPOK_OPTIM_L_SIZE);
    
    if (!BN_bin2bn(e_bin.data(), e_bin.size(), e))
    {
        throw_cosigner_exception(ZKP_OUT_OF_MEMORY);
    }

    if (!BN_mul(well_formed_proof.z1, e, plaintext, ctx)      ||  // z1 = e * a
        !BN_add(well_formed_proof.z1, well_formed_proof.z1, alpha)  ||  // z1 = e * a + alpha
        !BN_mul(well_formed_proof.z2, e, exponent, ctx)       ||  // z2 = e * b
        !BN_add(well_formed_proof.z2, well_formed_proof.z2, beta)   ||  // z2 = e * b + beta
        !BN_mul(well_formed_proof.w2, e, lambda0, ctx)        ||  // w2 = e * lambda0
        !BN_add(well_formed_proof.w2, well_formed_proof.w2, lambda_p))  // w2 = e * lambda0 + lambda_p
    {
        throw_cosigner_exception(ZKP_OUT_OF_MEMORY);
    }
        

    //compute w0 = e * gamma + gammp_p in scalar field
    throw_cosigner_exception(algebra->mul_scalars(algebra, &well_formed_proof.w0, e_bin.data(), e_bin.size(), gamma.data, sizeof(gamma.data)));
    throw_cosigner_exception(algebra->add_scalars(algebra, &well_formed_proof.w0, well_formed_proof.w0, sizeof(well_formed_proof.w0), gamma_p.data, sizeof(gamma_p.data)));

    serialize_well_formed_proof(cosigner_params::PAILLIER_COMMITMENT_BITSIZE , well_formed_proof, serialized);
}

void verify_signature_proof(const byte_vector_t& serialized,
                            const paillier_commitment_private_key_t* paillier,
                            elliptic_curve256_algebra_ctx* algebra,
                            const pedersen_commitment_two_generators_t* ec_base,
                            const commitments_sha256_t& signature_aad,
                            const struct bignum_st* encrypted_share,   // encrypted share of the server
                            const struct bignum_st* encrypted_signature, // encrypted partial signature from client
                            const elliptic_curve256_point_t& r_server,
                            struct bignum_ctx* ctx)
{
    BIGNUM *tmp1 = NULL, *tmp2 = NULL, *e_bn = NULL;
    
    well_formed_signature_proof proof(ctx); // also starts the bn context

    if (is_coprime_fast(encrypted_signature, paillier->pub.n, ctx) != 1) 
    {
        throw_cosigner_exception(ZKP_VERIFICATION_FAILED);
    }
    
    deserialize_well_formed_proof(cosigner_params::PAILLIER_COMMITMENT_BITSIZE, proof, serialized);

    tmp1 = BN_CTX_get(ctx);
    tmp2 = BN_CTX_get(ctx);
    e_bn = BN_CTX_get(ctx);
    if (!tmp1 || !tmp2 || !e_bn)
    {
        throw_cosigner_exception(ZKP_OUT_OF_MEMORY);
    }
        
    if (!BN_set_bit(tmp1, (cosigner_params::ZKPOK_OPTIM_NA_SIZE + cosigner_params::ZKPOK_OPTIM_EPSILON_SIZE) * 8) ||
        BN_cmp(proof.z1, tmp1) >= 0)
    {
        throw_cosigner_exception(ZKP_VERIFICATION_FAILED);
    }
    
    BN_zero(tmp1);
    
    if (!BN_set_bit(tmp1, (cosigner_params::ZKPOK_OPTIM_NB_SIZE + cosigner_params::ZKPOK_OPTIM_EPSILON_SIZE) * 8) ||
        BN_cmp(proof.z2, tmp1) >= 0)
    {
        throw_cosigner_exception(ZKP_VERIFICATION_FAILED);
    }

    auto e_bin = compute_e(proof, encrypted_signature, encrypted_share, signature_aad, *ec_base, paillier->pub, r_server);
    assert(e_bin.size() >= cosigner_params::ZKPOK_OPTIM_L_SIZE);

    e_bin.resize(cosigner_params::ZKPOK_OPTIM_L_SIZE);
    if (!BN_bin2bn(e_bin.data(), e_bin.size(), e_bn))
    {
        throw_cosigner_exception(ZKP_OUT_OF_MEMORY);
    }
        
    uint8_t zero = 0;
    elliptic_curve256_scalar_t e_scalar;
    throw_cosigner_exception(algebra->add_scalars(algebra, &e_scalar, e_bin.data(), e_bin.size(), &zero, sizeof(uint8_t)));

    elliptic_curve256_point_t ec_left_commitment;
    elliptic_curve256_point_t ec_rigth_commitment;

    byte_vector_t z1_bin(BN_num_bytes(proof.z1));
    byte_vector_t z2_bin(BN_num_bytes(proof.z2));
    byte_vector_t w2_bin(BN_num_bytes(proof.w2));

    if (!BN_bn2bin(proof.z1, z1_bin.data()) ||
        !BN_bn2bin(proof.z2, z2_bin.data()) ||
        !BN_bn2bin(proof.w2, w2_bin.data()))
    {
        throw_cosigner_exception(ZKP_OUT_OF_MEMORY);
    }
        

    // Check that g^z1 * f^z2 * f^w0 == V.U^e
    throw_cosigner_exception(
        pedersen_commitment_two_generators_create_commitment(&ec_left_commitment,
                                                             ec_base,
                                                             z1_bin.data(), 
                                                             z1_bin.size(),
                                                             z2_bin.data(), 
                                                             z2_bin.size(),
                                                             proof.w0, 
                                                             sizeof(proof.w0),
                                                             algebra));

    throw_cosigner_exception(algebra->point_mul(algebra, &ec_rigth_commitment, &proof.U, &e_scalar));
    throw_cosigner_exception(algebra->add_points(algebra, &ec_rigth_commitment, &ec_rigth_commitment, &proof.V));

    if (memcmp(ec_left_commitment, ec_rigth_commitment, sizeof(elliptic_curve256_point_t)) != 0)
    {
        LOG_ERROR("ec_left does not equal ec_right commitment");
        throw_cosigner_exception(ZKP_VERIFICATION_FAILED);
    }
        
    // Check that Enc(z1, rho^w2). E^z2 = D.S^e [N^2]
    // We will check this equality mod p^2 AND mod q^2. If one of them does not hold, then
    // the proof verification has failed.

    auto ret = paillier_commitment_commit_with_private_internal(paillier, proof.z1, proof.w2, encrypted_share, proof.z2, tmp1, ctx);
    if (ret != PAILLIER_SUCCESS)
    {
        LOG_ERROR("paillier_commitment_commit_with_private_internal failed with error %ld", ret);
        throw_paillier_exception(ret);
    }
    
    if (!BN_mod_exp_mont(tmp2, encrypted_signature, e_bn, paillier->pub.n2, ctx, paillier->pub.mont_n2) ||
        !BN_mod_mul(tmp2, tmp2, proof.D, paillier->pub.n2, ctx))
    {
        throw_cosigner_exception(ZKP_UNKNOWN_ERROR);
    }
    
    if (BN_cmp(tmp1, tmp2) != 0) 
    {
        LOG_ERROR("verification failed.");
        throw_cosigner_exception(ZKP_VERIFICATION_FAILED);
    }
}





}