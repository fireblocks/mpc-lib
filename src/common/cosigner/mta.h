#pragma once

#include "cosigner/types.h"
#include "cosigner/cmp_ecdsa_signing_service.h"
#include "crypto/paillier/paillier.h"
#include "crypto/commitments/ring_pedersen.h"

#include <memory>
#include <map>

struct bignum_st;
struct bignum_ctx;
struct bn_mont_ctx_st;

namespace fireblocks
{
namespace common
{
namespace cosigner
{

struct cmp_player_info;

namespace mta
{

cmp_mta_message request(uint64_t my_id, const elliptic_curve256_algebra_ctx_t* algebra, const elliptic_curve_scalar& k, const elliptic_curve_scalar& gamma, const elliptic_curve_scalar& a, const elliptic_curve_scalar& b, 
    const byte_vector_t& aad, const std::shared_ptr<paillier_public_key_t>& paillier, const std::map<uint64_t, cmp_player_info>& players, std::map<uint64_t, byte_vector_t>& proofs, std::map<uint64_t, byte_vector_t>& G_proofs);
elliptic_curve_scalar answer_mta_request(const elliptic_curve256_algebra_ctx_t* algebra, const cmp_mta_message& request, const uint8_t* secret, uint32_t secret_size, const byte_vector_t& aad, 
    const std::shared_ptr<paillier_private_key_t>& my_key, const std::shared_ptr<paillier_public_key_t>& paillier, const std::shared_ptr<ring_pedersen_public_t>& ring_pedersen, cmp_mta_message& response);
elliptic_curve_scalar decrypt_mta_response(uint64_t other_id, const elliptic_curve256_algebra_ctx_t* algebra, byte_vector_t&& response, const std::shared_ptr<paillier_private_key_t>& my_key);

struct mta_range_zkp;

class response_verifier
{
public:
    response_verifier(uint64_t other_id, const elliptic_curve256_algebra_ctx_t* algebra, const byte_vector_t& aad, const std::shared_ptr<paillier_private_key_t>& my_key, 
        const std::shared_ptr<paillier_public_key_t>& paillier, const std::shared_ptr<ring_pedersen_private_t>& ring_pedersen);
    response_verifier(response_verifier&& other);
    ~response_verifier();

    void process(const byte_vector_t& request, cmp_mta_message& response, const elliptic_curve_point& public_point);
    void verify();
private:
    void process_paillier(const bignum_st* e, const bignum_st* request, bignum_st* response, const bignum_st* commitment, const mta_range_zkp& proof);
    void process_ring_pedersen(const bignum_st* e, const mta_range_zkp& proof);

    const uint64_t _other_id;
    const elliptic_curve256_algebra_ctx_t* _algebra;
    const byte_vector_t _aad;
    const std::shared_ptr<paillier_private_key_t> _my_paillier;
    const std::shared_ptr<ring_pedersen_private_t> _my_ring_pedersen;
    const std::shared_ptr<paillier_public_key_t> _other_paillier;

    static const size_t BATCH_STATISTICAL_SECURITY = 5;
    bignum_st* _mta_ro[BATCH_STATISTICAL_SECURITY];
    bignum_st* _mta_B[BATCH_STATISTICAL_SECURITY];
    bignum_st* _commitment_ro[BATCH_STATISTICAL_SECURITY];
    bignum_st* _commitment_B[BATCH_STATISTICAL_SECURITY];
    bignum_st* _pedersen_t_exp;
    bignum_st* _pedersen_B;
    std::unique_ptr<bignum_ctx, void (*)(bignum_ctx*)> _ctx;
    std::unique_ptr<bn_mont_ctx_st, void (*)(bn_mont_ctx_st*)> _my_mont;
    std::unique_ptr<bn_mont_ctx_st, void (*)(bn_mont_ctx_st*)> _other_mont;
};


}
}
}
}