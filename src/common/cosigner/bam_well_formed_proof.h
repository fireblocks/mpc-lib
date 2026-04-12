#pragma once
#include <cstdint>
#include "crypto/elliptic_curve_algebra/elliptic_curve256_algebra.h"
#include "crypto/commitments/commitments.h"
#include "crypto/paillier_commitment/paillier_commitment.h"
#include "crypto//commitments/pedersen.h"
#include "utils/string_utils.h"

struct bignum_st;
struct bignum_ctx;

namespace fireblocks::common::cosigner::bam_well_formed_proof
{
    using byte_vector_t = common::utils::byte_vector_t;

    void generate_signature_proof(const paillier_commitment_public_key_t *paillier,
                                  elliptic_curve256_algebra_ctx *algebra,
                                  struct bignum_ctx *ctx,
                                  const pedersen_commitment_two_generators_t *ec_base,  //two points h and f
                                  const struct bignum_st *plaintext,                    // this is u, called a in proof
                                  const struct bignum_st *encrypted_share,              // encrypted server share
                                  const struct bignum_st *exponent,                     // v, called b in proof
                                  const struct bignum_st *lambda0,                      // same lambda0 used in the partial signature encryption
                                  const struct bignum_st* S,                            // partial signature
                                  const commitments_sha256_t& signature_aad,
                                  const byte_vector_t& plaintext_bin,                   // plaintext binary
                                  const byte_vector_t& exponent_bin,                    // exponent binary
                                  const elliptic_curve256_point_t& r_server,
                                  byte_vector_t &serialized);

    void verify_signature_proof(const byte_vector_t& serialized,
                                const paillier_commitment_private_key_t* paillier,
                                elliptic_curve256_algebra_ctx *algebra,
                                const pedersen_commitment_two_generators_t* ec_base,
                                const commitments_sha256_t& signature_aad,
                                const struct bignum_st* encrypted_share,   // encrypted share of the server
                                const struct bignum_st* encrypted_signature, // encrypted partial signature from client
                                const elliptic_curve256_point_t& r_server,
                                struct bignum_ctx* ctx);


} //namespace fireblocks::common::cosigner::bam_well_formed_proof

