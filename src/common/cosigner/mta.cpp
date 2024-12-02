#include "mta.h"
#include "cosigner/cmp_key_persistency.h"
#include "cosigner/cosigner_exception.h"
#include "crypto/zero_knowledge_proof/range_proofs.h"
#include "crypto/drng/drng.h"
#include "../crypto/paillier/paillier_internal.h"

#ifndef TEST_ONLY
#include "logging/logging_t.h"
#else
#define LOG_ERROR(message, ...) printf((message), ##__VA_ARGS__);putchar('\n')
#endif

#include <openssl/bn.h>
#include <openssl/rand.h>
#include <openssl/err.h>

#include <assert.h>
#include <inttypes.h>

namespace fireblocks
{
namespace common
{
namespace cosigner
{
namespace mta
{

static const uint32_t MTA_ZKP_EPSILON_SIZE = 2 * sizeof(elliptic_curve256_scalar_t);
static const char MTA_ZKP_SALT[] = "Affine Operation with Group Commitment in Range ZK";
static const uint32_t BETA_HIDING_FACTOR = 5;

struct [[nodiscard]] bn_ctx_frame
{
    explicit bn_ctx_frame(BN_CTX* ctx) : _ctx(ctx) {BN_CTX_start(ctx);}
    ~bn_ctx_frame() {if (_ctx) BN_CTX_end(_ctx);}
    bn_ctx_frame(const bn_ctx_frame&) = delete;
    bn_ctx_frame(bn_ctx_frame&&) = delete;
    bn_ctx_frame& operator=(const bn_ctx_frame&) = delete;
    bn_ctx_frame& operator=(bn_ctx_frame&&) = delete;
    
    void reset() 
    {
        if (_ctx) 
            BN_CTX_end(_ctx);
        _ctx = NULL;
    }
    BN_CTX* _ctx;
};

struct mta_range_zkp
{
    BIGNUM* A;
    BIGNUM* By;
    BIGNUM* E;
    BIGNUM* F;
    BIGNUM* S;
    BIGNUM* T;
    BIGNUM* z1;
    BIGNUM* z2;
    BIGNUM* z3;
    BIGNUM* z4;
    BIGNUM* w;
    BIGNUM* wy;
    elliptic_curve256_point_t Bx;

    mta_range_zkp(BN_CTX* ctx): A(BN_CTX_get(ctx)), By(BN_CTX_get(ctx)), E(BN_CTX_get(ctx)), F(BN_CTX_get(ctx)), S(BN_CTX_get(ctx)), T(BN_CTX_get(ctx)), 
        z1(BN_CTX_get(ctx)), z2(BN_CTX_get(ctx)), z3(BN_CTX_get(ctx)), z4(BN_CTX_get(ctx)), w(BN_CTX_get(ctx)), wy(BN_CTX_get(ctx))
    {
        if (!A || !By || !E || !F || !z1 || !z2 || !z3 || !z4 || !w || !wy)
            throw cosigner_exception(cosigner_exception::NO_MEM);
    }
};

static inline void genarate_mta_range_zkp_seed(const cmp_mta_message& response, const mta_range_zkp& proof, const std::vector<uint8_t>& aad, uint8_t *seed)
{
    SHA256_CTX ctx;
    
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, MTA_ZKP_SALT, sizeof(MTA_ZKP_SALT));
    SHA256_Update(&ctx, aad.data(), aad.size());
    SHA256_Update(&ctx, response.message.data(), response.message.size());
    SHA256_Update(&ctx, response.commitment.data(), response.commitment.size());
    uint32_t max_size = std::max(BN_num_bytes(proof.A), BN_num_bytes(proof.By)); // we assome the the paillier n is larger then ring pedersen n
    std::vector<uint8_t> n(max_size);
    BN_bn2bin(proof.A, n.data());
    SHA256_Update(&ctx, n.data(), BN_num_bytes(proof.S));
    SHA256_Update(&ctx, proof.Bx, sizeof(elliptic_curve256_point_t));
    BN_bn2bin(proof.By, n.data());
    SHA256_Update(&ctx, n.data(), BN_num_bytes(proof.By));
    if ((uint32_t)BN_num_bytes(proof.E) > max_size) // should never happen
        n.resize(BN_num_bytes(proof.E));
    BN_bn2bin(proof.E, n.data());
    SHA256_Update(&ctx, n.data(), BN_num_bytes(proof.E));
    BN_bn2bin(proof.F, n.data());
    SHA256_Update(&ctx, n.data(), BN_num_bytes(proof.F));
    BN_bn2bin(proof.S, n.data());
    SHA256_Update(&ctx, n.data(), BN_num_bytes(proof.S));
    BN_bn2bin(proof.T, n.data());
    SHA256_Update(&ctx, n.data(), BN_num_bytes(proof.T));
    SHA256_Final(seed, &ctx);
}

static inline uint32_t exponent_zkpok_serialized_size(const ring_pedersen_public_t* ring_pedersen, const paillier_private_key_t* private_key, const paillier_public_key_t* public_key)
{
    return 
        sizeof(uint32_t) + // sizeof(ring_pedersen->n)
        sizeof(uint32_t) + // sizeof(private_key->n)
        sizeof(uint32_t) + // sizeof(public_key->n)
        2 * BN_num_bytes(public_key->n) + // sizeof(A)
        sizeof(elliptic_curve256_point_t) + // sizeof(Bx)
        2 * BN_num_bytes(private_key->pub.n) + // sizeof(By)
        4 * BN_num_bytes(ring_pedersen->n) + // sizeof(E) + sizeof(F) + sizeof(S) + sizeof(T)
        MTA_ZKP_EPSILON_SIZE + sizeof(elliptic_curve256_scalar_t) + 1 + // sizeof(z1)
        MTA_ZKP_EPSILON_SIZE + sizeof(elliptic_curve256_scalar_t) * BETA_HIDING_FACTOR + 1 + // sizeof(z2)
        MTA_ZKP_EPSILON_SIZE + sizeof(elliptic_curve256_scalar_t) + BN_num_bytes(ring_pedersen->n) + 1 + // sizeof(z3)
        MTA_ZKP_EPSILON_SIZE + sizeof(elliptic_curve256_scalar_t) + BN_num_bytes(ring_pedersen->n) + 1 + // sizeof(z4)
        BN_num_bytes(public_key->n) + // sizeof(w)
        BN_num_bytes(private_key->pub.n); // sizeof(wy)
}

static inline std::vector<uint8_t> serialize_mta_range_zkp(const mta_range_zkp& proof, const ring_pedersen_public_t* ring_pedersen, const paillier_private_key_t* private_key, const paillier_public_key_t* public_key)
{
    const uint32_t ring_pedersen_n_size = BN_num_bytes(ring_pedersen->n);
    const uint32_t paillier_priv_n_size = BN_num_bytes(private_key->pub.n);
    const uint32_t paillier_pub_n_size = BN_num_bytes(public_key->n);
    std::vector<uint8_t> ret(exponent_zkpok_serialized_size(ring_pedersen, private_key, public_key));
    uint8_t *ptr = ret.data();
    *(uint32_t*)ptr = ring_pedersen_n_size;
    ptr += sizeof(uint32_t);
    *(uint32_t*)ptr = paillier_priv_n_size;
    ptr += sizeof(uint32_t);
    *(uint32_t*)ptr = paillier_pub_n_size;
    ptr += sizeof(uint32_t);
    BN_bn2binpad(proof.A, ptr, paillier_pub_n_size * 2);
    ptr += paillier_pub_n_size * 2;
    memcpy(ptr, proof.Bx, sizeof(elliptic_curve256_point_t));
    ptr += sizeof(elliptic_curve256_point_t);
    BN_bn2binpad(proof.By, ptr, paillier_priv_n_size * 2);
    ptr += paillier_priv_n_size * 2;
    BN_bn2binpad(proof.E, ptr, ring_pedersen_n_size);
    ptr += ring_pedersen_n_size;
    BN_bn2binpad(proof.F, ptr, ring_pedersen_n_size);
    ptr += ring_pedersen_n_size;
    BN_bn2binpad(proof.S, ptr, ring_pedersen_n_size);
    ptr += ring_pedersen_n_size;
    BN_bn2binpad(proof.T, ptr, ring_pedersen_n_size);
    ptr += ring_pedersen_n_size;

    BN_bn2binpad(proof.z1, ptr, MTA_ZKP_EPSILON_SIZE + sizeof(elliptic_curve256_scalar_t) + 1);
    ptr += MTA_ZKP_EPSILON_SIZE + sizeof(elliptic_curve256_scalar_t) + 1;
    BN_bn2binpad(proof.z2, ptr, MTA_ZKP_EPSILON_SIZE + sizeof(elliptic_curve256_scalar_t) * BETA_HIDING_FACTOR + 1);
    ptr += MTA_ZKP_EPSILON_SIZE + sizeof(elliptic_curve256_scalar_t) * BETA_HIDING_FACTOR + 1;
    BN_bn2binpad(proof.z3, ptr, MTA_ZKP_EPSILON_SIZE + sizeof(elliptic_curve256_scalar_t) + BN_num_bytes(ring_pedersen->n) + 1);
    ptr += MTA_ZKP_EPSILON_SIZE + sizeof(elliptic_curve256_scalar_t) + BN_num_bytes(ring_pedersen->n) + 1;
    BN_bn2binpad(proof.z4, ptr, MTA_ZKP_EPSILON_SIZE + sizeof(elliptic_curve256_scalar_t) + BN_num_bytes(ring_pedersen->n) + 1);
    ptr += MTA_ZKP_EPSILON_SIZE + sizeof(elliptic_curve256_scalar_t) + BN_num_bytes(ring_pedersen->n) + 1;
    BN_bn2binpad(proof.w, ptr, paillier_pub_n_size);
    ptr += paillier_pub_n_size;
    BN_bn2binpad(proof.wy, ptr, paillier_priv_n_size);
    ptr += paillier_priv_n_size;
    assert(ptr == ret.data() + ret.size());
    return ret;
}

static inline void deserialize_mta_range_zkp(std::vector<uint8_t> buff, const ring_pedersen_public_t* ring_pedersen, const paillier_private_key_t* private_key, const paillier_public_key_t* public_key, mta_range_zkp& proof)
{
    if (buff.size() != exponent_zkpok_serialized_size(ring_pedersen, private_key, public_key))
    {
        LOG_ERROR("Invlid buffer size %lu, expected %u", buff.size(), exponent_zkpok_serialized_size(ring_pedersen, private_key, public_key));
        throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
    }
    const uint32_t ring_pedersen_n_size = BN_num_bytes(ring_pedersen->n);
    const uint32_t paillier_priv_n_size = BN_num_bytes(private_key->pub.n);
    const uint32_t paillier_pub_n_size = BN_num_bytes(public_key->n);
    const uint8_t *ptr = buff.data();
    if (*(uint32_t*)ptr != ring_pedersen_n_size)
    {
        LOG_ERROR("Wrong ring pedersen key size %u, expected %u", *(uint32_t*)ptr, ring_pedersen_n_size);
        throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
    }
    ptr += sizeof(uint32_t);
    if (*(uint32_t*)ptr != paillier_priv_n_size)
    {
        LOG_ERROR("Wrong paillier private key size %u, expected %u", *(uint32_t*)ptr, paillier_priv_n_size);
        throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
    }
    ptr += sizeof(uint32_t);
    if (*(uint32_t*)ptr != paillier_pub_n_size)
    {
        LOG_ERROR("Wrong paillier public key size %u, expected %u", *(uint32_t*)ptr, paillier_pub_n_size);
        throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
    }
    ptr += sizeof(uint32_t);
    BN_bin2bn(ptr, paillier_pub_n_size * 2, proof.A);
    ptr += paillier_pub_n_size * 2;
    memcpy(proof.Bx, ptr, sizeof(elliptic_curve256_point_t));
    ptr += sizeof(elliptic_curve256_point_t);
    BN_bin2bn(ptr, paillier_priv_n_size * 2, proof.By);
    ptr += paillier_priv_n_size * 2;
    BN_bin2bn(ptr, ring_pedersen_n_size, proof.E);
    ptr += ring_pedersen_n_size;
    BN_bin2bn(ptr, ring_pedersen_n_size, proof.F);
    ptr += ring_pedersen_n_size;
    BN_bin2bn(ptr, ring_pedersen_n_size, proof.S);
    ptr += ring_pedersen_n_size;
    BN_bin2bn(ptr, ring_pedersen_n_size, proof.T);
    ptr += ring_pedersen_n_size;

    BN_bin2bn(ptr, MTA_ZKP_EPSILON_SIZE + sizeof(elliptic_curve256_scalar_t) + 1, proof.z1);
    ptr += MTA_ZKP_EPSILON_SIZE + sizeof(elliptic_curve256_scalar_t) + 1;
    BN_bin2bn(ptr, MTA_ZKP_EPSILON_SIZE + sizeof(elliptic_curve256_scalar_t) * BETA_HIDING_FACTOR + 1, proof.z2);
    ptr += MTA_ZKP_EPSILON_SIZE + sizeof(elliptic_curve256_scalar_t) * BETA_HIDING_FACTOR + 1;
    BN_bin2bn(ptr, MTA_ZKP_EPSILON_SIZE + sizeof(elliptic_curve256_scalar_t) + BN_num_bytes(ring_pedersen->n) + 1, proof.z3);
    ptr += MTA_ZKP_EPSILON_SIZE + sizeof(elliptic_curve256_scalar_t) + BN_num_bytes(ring_pedersen->n) + 1;
    BN_bin2bn(ptr, MTA_ZKP_EPSILON_SIZE + sizeof(elliptic_curve256_scalar_t) + BN_num_bytes(ring_pedersen->n) + 1, proof.z4);
    ptr += MTA_ZKP_EPSILON_SIZE + sizeof(elliptic_curve256_scalar_t) + BN_num_bytes(ring_pedersen->n) + 1;
    BN_bin2bn(ptr, paillier_pub_n_size, proof.w);
    ptr += paillier_pub_n_size;
    BN_bin2bn(ptr, paillier_priv_n_size, proof.wy);
    buff.clear();
}

static std::vector<uint8_t> mta_range_generate_zkp(const elliptic_curve256_algebra_ctx_t* algebra, const ring_pedersen_public_t* ring_pedersen, const paillier_private_key_t* private_key, const paillier_public_key_t* public_key, 
    const std::vector<uint8_t>& aad, const BIGNUM* x, const BIGNUM* y, const BIGNUM* mta_request, const BIGNUM* mta_response_r, const paillier_ciphertext_t* commitment, const cmp_mta_message& response)
{
    std::unique_ptr<BN_CTX, void (*)(BN_CTX*)> ctx(BN_CTX_new(), BN_CTX_free);

    if (!ctx)
        throw cosigner_exception(cosigner_exception::NO_MEM);
    
    if (is_coprime_fast(mta_response_r, public_key->n, ctx.get()) != 1)
    {
        LOG_ERROR("mta response r is not coprime to verifier paillier public key");
        throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
    }

    if (is_coprime_fast(commitment->r, private_key->pub.n, ctx.get()) != 1)
    {
        LOG_ERROR("commitment r is not coprime to prover paillier public key");
        throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
    }

    bn_ctx_frame ctx_guard(ctx.get());
    BIGNUM* alpha = BN_CTX_get(ctx.get());
    BIGNUM* beta = BN_CTX_get(ctx.get());
    BIGNUM* r = BN_CTX_get(ctx.get());
    BIGNUM* ry = BN_CTX_get(ctx.get());
    BIGNUM* gamma = BN_CTX_get(ctx.get());
    BIGNUM* delta = BN_CTX_get(ctx.get());
    BIGNUM* mu = BN_CTX_get(ctx.get());
    BIGNUM* nu = BN_CTX_get(ctx.get());
    BIGNUM* e = BN_CTX_get(ctx.get());
    BIGNUM* tmp = BN_CTX_get(ctx.get());
    
    if (!alpha || !beta|| !r || !ry || !gamma || !delta || !mu || !nu || !e || !tmp)
        throw cosigner_exception(cosigner_exception::NO_MEM);

    mta_range_zkp proof(ctx.get());

    const BIGNUM* q = algebra->order_internal(algebra);

    if (!BN_set_bit(tmp, (sizeof(elliptic_curve256_scalar_t) + MTA_ZKP_EPSILON_SIZE) * 8) || !BN_rand_range(alpha, tmp))
    {
        LOG_ERROR("Failed to rand alpha error %lu", ERR_get_error());
        throw cosigner_exception(cosigner_exception::INTERNAL_ERROR);
    }

    if (!BN_set_bit(tmp, BN_num_bits(y) + MTA_ZKP_EPSILON_SIZE * 8) || !BN_rand_range(beta, tmp))
    {
        LOG_ERROR("Failed to rand beta error %lu", ERR_get_error());
        throw cosigner_exception(cosigner_exception::INTERNAL_ERROR);
    }

    if (!BN_lshift(tmp, ring_pedersen->n, sizeof(elliptic_curve256_scalar_t) * 8) || !BN_rand_range(mu, tmp) || !BN_rand_range(nu, tmp))
    {
        LOG_ERROR("Failed to rand mu error %lu", ERR_get_error());
        throw cosigner_exception(cosigner_exception::INTERNAL_ERROR);
    }

    if (!BN_lshift(tmp, tmp, MTA_ZKP_EPSILON_SIZE * 8) || !BN_rand_range(gamma, tmp) || !BN_rand_range(delta, tmp))
    {
        LOG_ERROR("Failed to rand gamma error %lu", ERR_get_error());
        throw cosigner_exception(cosigner_exception::INTERNAL_ERROR);
    }

    long paillier_status;
    do
    {
        if (!BN_rand_range(r, public_key->n))
        {
            LOG_ERROR("Failed to rand r error %lu", ERR_get_error());
            throw cosigner_exception(cosigner_exception::INTERNAL_ERROR);
        }
        paillier_status = paillier_encrypt_openssl_internal(public_key, proof.A, r, beta, ctx.get());
    } while (paillier_status == PAILLIER_ERROR_INVALID_RANDOMNESS);
    
    if (paillier_status != PAILLIER_SUCCESS)
    {
        LOG_ERROR("Failed to encrypt beta error %ld", paillier_status);
        throw cosigner_exception(cosigner_exception::INTERNAL_ERROR);
    }

    if (!BN_mod_exp(tmp, mta_request, alpha, public_key->n2, ctx.get()) || !BN_mod_mul(proof.A, proof.A, tmp, public_key->n2, ctx.get()))
    {
        LOG_ERROR("Failed to calc A error %lu", ERR_get_error());
        throw cosigner_exception(cosigner_exception::INTERNAL_ERROR);
    }

    do
    {
        if (!BN_rand_range(ry, public_key->n))
        {
            LOG_ERROR("Failed to rand ry error %lu", ERR_get_error());
            throw cosigner_exception(cosigner_exception::INTERNAL_ERROR);
        }
        paillier_status = paillier_encrypt_openssl_internal(&private_key->pub, proof.By, ry, beta, ctx.get());
    } while (paillier_status == PAILLIER_ERROR_INVALID_RANDOMNESS);
    
    if (paillier_status != PAILLIER_SUCCESS)
    {
        LOG_ERROR("Failed to encrypt beta error %ld", paillier_status);
        throw cosigner_exception(cosigner_exception::INTERNAL_ERROR);
    }

    auto rp_status = ring_pedersen_create_commitment_internal(ring_pedersen, alpha, gamma, proof.E, ctx.get());
    if (rp_status != RING_PEDERSEN_SUCCESS)
    {
        LOG_ERROR("Failed to create alpha commitment error %d", rp_status);
        throw cosigner_exception(cosigner_exception::INTERNAL_ERROR);
    }
    rp_status = ring_pedersen_create_commitment_internal(ring_pedersen, x, mu, proof.S, ctx.get());
    if (rp_status != RING_PEDERSEN_SUCCESS)
    {
        LOG_ERROR("Failed to create x commitment error %d", rp_status);
        throw cosigner_exception(cosigner_exception::INTERNAL_ERROR);
    }
    rp_status = ring_pedersen_create_commitment_internal(ring_pedersen, beta, delta, proof.F, ctx.get());
    if (rp_status != RING_PEDERSEN_SUCCESS)
    {
        LOG_ERROR("Failed to create beta commitment error %d", rp_status);
        throw cosigner_exception(cosigner_exception::INTERNAL_ERROR);
    }
    rp_status = ring_pedersen_create_commitment_internal(ring_pedersen, y, nu, proof.T, ctx.get());
    if (rp_status != RING_PEDERSEN_SUCCESS)
    {
        LOG_ERROR("Failed to create y commitment error %d", rp_status);
        throw cosigner_exception(cosigner_exception::INTERNAL_ERROR);
    }
    
    elliptic_curve256_scalar_t alpha_bin;
    if (!BN_mod(tmp, alpha, q, ctx.get()))
    {
        LOG_ERROR("Failed to to alpha mod q error %lu", ERR_get_error());
        throw cosigner_exception(cosigner_exception::INTERNAL_ERROR);
    }
    
    BN_bn2binpad(tmp, alpha_bin, sizeof(elliptic_curve256_scalar_t));
    auto status = algebra->generator_mul(algebra, &proof.Bx, &alpha_bin);
    if (status != ELLIPTIC_CURVE_ALGEBRA_SUCCESS)
    {
        LOG_ERROR("Failed to calc Bx error %d", status);
        throw cosigner_exception(cosigner_exception::INTERNAL_ERROR);
    }

    // sample e
    uint8_t seed[SHA256_DIGEST_LENGTH];
    genarate_mta_range_zkp_seed(response, proof, aad, seed);

    drng_t* rng = NULL;
    if (drng_new(seed, SHA256_DIGEST_LENGTH, &rng) != DRNG_SUCCESS)
    {
        LOG_ERROR("Failed to create drng");
        throw cosigner_exception(cosigner_exception::NO_MEM);
    }
    std::unique_ptr<drng_t, void (*)(drng_t*)> drng_guard(rng, drng_free);

    do
    {
        elliptic_curve256_scalar_t val;
        drng_read_deterministic_rand(rng, val, sizeof(elliptic_curve256_scalar_t));
        if (!BN_bin2bn(val, sizeof(elliptic_curve256_scalar_t), e))
        {
            LOG_ERROR("Failed to load e, error %lu", ERR_get_error());
            throw cosigner_exception(cosigner_exception::NO_MEM);
        }
    } while (BN_cmp(e, q) >= 0);
    drng_guard.reset();

    if (!BN_mul(proof.z1, e, x, ctx.get()) || !BN_add(proof.z1, proof.z1, alpha))
    {
        LOG_ERROR("Failed to calc z1, error %lu", ERR_get_error());
        throw cosigner_exception(cosigner_exception::INTERNAL_ERROR);
    }
    if (!BN_mul(proof.z2, e, y, ctx.get()) || !BN_add(proof.z2, proof.z2, beta))
    {
        LOG_ERROR("Failed to calc z2, error %lu", ERR_get_error());
        throw cosigner_exception(cosigner_exception::INTERNAL_ERROR);
    }
    if (!BN_mul(proof.z3, e, mu, ctx.get()) || !BN_add(proof.z3, proof.z3, gamma))
    {
        LOG_ERROR("Failed to calc z3, error %lu", ERR_get_error());
        throw cosigner_exception(cosigner_exception::INTERNAL_ERROR);
    }
    if (!BN_mul(proof.z4, e, nu, ctx.get()) || !BN_add(proof.z4, proof.z4, delta))
    {
        LOG_ERROR("Failed to calc z4, error %lu", ERR_get_error());
        throw cosigner_exception(cosigner_exception::INTERNAL_ERROR);
    }

    if (!BN_mod_exp(proof.w, mta_response_r, e, public_key->n, ctx.get()) || !BN_mod_mul(proof.w, proof.w, r, public_key->n, ctx.get()))
    {
        LOG_ERROR("Failed to calc w, error %lu", ERR_get_error());
        throw cosigner_exception(cosigner_exception::INTERNAL_ERROR);
    }
    if (!BN_mod_exp(proof.wy, commitment->r, e, private_key->pub.n, ctx.get()) || !BN_mod_mul(proof.wy, proof.wy, ry, private_key->pub.n, ctx.get()))
    {
        LOG_ERROR("Failed to calc wy, error %lu", ERR_get_error());
        throw cosigner_exception(cosigner_exception::INTERNAL_ERROR);
    }

    return serialize_mta_range_zkp(proof, ring_pedersen, private_key, public_key);
}

//implements phase 1 of ECDSA signing
//Since the cmp_mta_message has a common part for all parties and a specific part for each party 
//this function prefills the common part and creates a map of proofs to feel the remaining part for each party individually.
cmp_mta_message request(const uint64_t my_id, 
                        const elliptic_curve256_algebra_ctx_t* algebra, 
                        const elliptic_curve_scalar& k,                         //signing secret (randomness), saved on ecdsa_preprocessing_data state
                        const elliptic_curve_scalar& gamma,                     //signing secret (required for MtA), saved on ecdsa_preprocessing_data state
                        const elliptic_curve_scalar& a,                         //secret used for Rddh proof, saved on ecdsa_preprocessing_data state
                        const elliptic_curve_scalar& b,                         //secret used for Rddh proof, saved on ecdsa_preprocessing_data state
                        const byte_vector_t& aad,                               //additional authenticated data
                        const std::shared_ptr<paillier_public_key_t>& paillier, //from key setup
                        const std::map<uint64_t, cmp_player_info>& players,     //maps all parties (players) ids to parameters from key setup phase
                        std::map<uint64_t, byte_vector_t>& proofs,              //output map all all parties (players) ids to Rddh proof messages
                        std::map<uint64_t, byte_vector_t>& G_proofs)            //output map all all parties (players) ids to "log" proof messages
{
    cmp_mta_message mta;
    paillier_ciphertext_t *ciphertext = NULL; //will hold paillier encrypted k. Called K in the document
    long status = paillier_encrypt_to_ciphertext(paillier.get(), k.data, sizeof(elliptic_curve256_scalar_t), &ciphertext);

    //create self releasing guard in case of an exception thrown in the context
    std::unique_ptr<paillier_ciphertext_t, void (*)(paillier_ciphertext_t*)> ciphertext_guard(ciphertext, paillier_free_ciphertext);
    if (status != PAILLIER_SUCCESS)
    {
        LOG_ERROR("Failed to encrypt k status: %ld", status);
        throw cosigner_exception(cosigner_exception::INTERNAL_ERROR);
    }
    
    paillier_ciphertext_t *commitment = NULL;
    status = paillier_encrypt_to_ciphertext(paillier.get(), gamma.data, sizeof(elliptic_curve256_scalar_t), &commitment);
    std::unique_ptr<paillier_ciphertext_t, void (*)(paillier_ciphertext_t*)> commitment_guard(commitment, paillier_free_ciphertext);
    if (status != PAILLIER_SUCCESS)
    {
        LOG_ERROR("Failed to encrypt gamma status: %ld", status);
        throw cosigner_exception(cosigner_exception::INTERNAL_ERROR);
    }
    
    for (auto i = players.begin(); i != players.end(); ++i)
    {
        if (i->first == my_id)
            continue;
        uint32_t len = 0;
        range_proof_diffie_hellman_zkpok_generate(i->second.ring_pedersen.get(), paillier.get(), algebra, aad.data(), aad.size(), &k.data, &a.data, &b.data, ciphertext, NULL, 0, &len);
        auto& proof = proofs[i->first];
        proof.resize(len);
        auto status = range_proof_diffie_hellman_zkpok_generate(i->second.ring_pedersen.get(), paillier.get(), algebra, aad.data(), aad.size(), &k.data, &a.data, &b.data, ciphertext, proof.data(), proof.size(), &len);
        if (status != ZKP_SUCCESS)
        {
            LOG_ERROR("Failed to generate rddh zkp status: %d", status);
            throw cosigner_exception(cosigner_exception::INTERNAL_ERROR);
        }

        len = 0;
        range_proof_paillier_exponent_zkpok_generate(i->second.ring_pedersen.get(), paillier.get(), algebra, aad.data(), aad.size(), &gamma.data, commitment, NULL, 0, &len);
        auto& G_proof = G_proofs[i->first];
        G_proof.resize(len);
        status = range_proof_paillier_exponent_zkpok_generate(i->second.ring_pedersen.get(), paillier.get(), algebra, aad.data(), aad.size(), &gamma.data, commitment, G_proof.data(), G_proof.size(), &len);
        if (status != ZKP_SUCCESS)
        {
            LOG_ERROR("Failed to generate log zkp status: %d", status);
            throw cosigner_exception(cosigner_exception::INTERNAL_ERROR);
        }
    }
    mta.message.resize(BN_num_bytes(ciphertext->ciphertext));
    BN_bn2bin(ciphertext->ciphertext, mta.message.data());
    ciphertext_guard.reset();
    mta.commitment.resize(BN_num_bytes(commitment->ciphertext));
    BN_bn2bin(commitment->ciphertext, mta.commitment.data());
    return mta;
}

elliptic_curve_scalar answer_mta_request(const elliptic_curve256_algebra_ctx_t* algebra, const cmp_mta_message& request, const uint8_t* secret, uint32_t secret_size, const byte_vector_t& aad, 
    const std::shared_ptr<paillier_private_key_t>& my_key, const std::shared_ptr<paillier_public_key_t>& paillier, const std::shared_ptr<ring_pedersen_public_t>& ring_pedersen, cmp_mta_message& response)
{
    if (!secret || !secret_size || !my_key || !paillier || !ring_pedersen)
        throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
    byte_vector_t beta(secret_size * BETA_HIDING_FACTOR);
    response.message.resize(BN_num_bytes(paillier->n2));
    if (RAND_bytes(beta.data(), secret_size * BETA_HIDING_FACTOR) != 1)
    {
        LOG_ERROR("Failed to rand beta error %lu", ERR_get_error());
        throw cosigner_exception(cosigner_exception::INTERNAL_ERROR);
    }
    uint32_t len = 0;
    auto status = paillier_mul(paillier.get(), request.message.data(), request.message.size(), secret, secret_size, response.message.data(), response.message.size(), &len);
    if (status != PAILLIER_SUCCESS)
    {
        LOG_ERROR("Failed to mul ciphertext status: %ld", status);
        throw cosigner_exception(cosigner_exception::INTERNAL_ERROR);
    }
    
    paillier_ciphertext_t* ciphertext = NULL;
    status = paillier_encrypt_to_ciphertext(paillier.get(), beta.data(), beta.size(), &ciphertext);
    if (status != PAILLIER_SUCCESS)
    {
        LOG_ERROR("Failed to encrypt beta status: %ld", status);
        throw cosigner_exception(cosigner_exception::INTERNAL_ERROR);
    }
    std::unique_ptr<paillier_ciphertext_t, void (*)(paillier_ciphertext_t*)> ciphertext_guard(ciphertext, paillier_free_ciphertext);
    byte_vector_t tmp(BN_num_bytes(ciphertext->ciphertext));
    BN_bn2bin(ciphertext->ciphertext, tmp.data());
    status = paillier_add(paillier.get(), response.message.data(), len, tmp.data(), tmp.size(), response.message.data(), response.message.size(), &len);
    if (status != PAILLIER_SUCCESS)
    {
        LOG_ERROR("Failed to add beta from ciphertext status: %ld", status);
        throw cosigner_exception(cosigner_exception::INTERNAL_ERROR);
    }
    response.message.resize(len);

    paillier_ciphertext_t* commitment = NULL;
    status = paillier_encrypt_to_ciphertext(&my_key->pub, beta.data(), beta.size(), &commitment);
    if (status != PAILLIER_SUCCESS)
    {
        LOG_ERROR("Failed to encrypt commitment status: %ld", status);
        throw cosigner_exception(cosigner_exception::INTERNAL_ERROR);
    }
    std::unique_ptr<paillier_ciphertext_t, void (*)(paillier_ciphertext_t*)> commitment_guard(commitment, paillier_free_ciphertext);
    response.commitment.resize(BN_num_bytes(commitment->ciphertext));
    BN_bn2bin(commitment->ciphertext, response.commitment.data());
    
    std::unique_ptr<BIGNUM, void (*)(BIGNUM*)> x(BN_bin2bn(secret, secret_size, NULL), BN_clear_free);
    std::unique_ptr<BIGNUM, void (*)(BIGNUM*)> y(BN_bin2bn(beta.data(), beta.size(), NULL), BN_clear_free);
    std::unique_ptr<BIGNUM, void (*)(BIGNUM*)> req(BN_bin2bn(request.message.data(), request.message.size(), NULL), BN_free);
    if (!x || !y || !req)
        throw cosigner_exception(cosigner_exception::NO_MEM);

    response.proof = mta_range_generate_zkp(algebra, ring_pedersen.get(), my_key.get(), paillier.get(), aad, x.get(), y.get(), req.get(), ciphertext->r, commitment, response);
    const BIGNUM* q = algebra->order_internal(algebra);
    std::unique_ptr<BN_CTX, void (*)(BN_CTX*)> ctx(BN_CTX_new(), BN_CTX_free);
    if (!ctx)
        throw cosigner_exception(cosigner_exception::NO_MEM);
    if (!BN_mod(y.get(), y.get(), q, ctx.get()))
    {
        LOG_ERROR("Failed to calc beta error %lu", ERR_get_error());
        throw cosigner_exception(cosigner_exception::INTERNAL_ERROR);
    }
    elliptic_curve_scalar ret;
    BN_bn2binpad(y.get(), ret.data, sizeof(elliptic_curve256_scalar_t));
    return ret;
}

elliptic_curve_scalar decrypt_mta_response(uint64_t other_id, const elliptic_curve256_algebra_ctx_t* algebra, byte_vector_t&& response, const std::shared_ptr<paillier_private_key_t>& my_key)
{
    std::unique_ptr<BN_CTX, void (*)(BN_CTX*)> ctx(BN_CTX_new(), BN_CTX_free);

    if (!ctx)
        throw cosigner_exception(cosigner_exception::NO_MEM);
    bn_ctx_frame ctx_guard(ctx.get());
    BIGNUM* resp = BN_CTX_get(ctx.get());
    BIGNUM* tmp = BN_CTX_get(ctx.get());
    std::unique_ptr<BIGNUM, void (*)(BIGNUM*)> alpha(BN_new(), BN_clear_free);
    if (!resp || !alpha || !tmp || !BN_bin2bn(response.data(), response.size(), resp))
        throw cosigner_exception(cosigner_exception::NO_MEM);
    response.clear();
    
    auto status = paillier_decrypt_openssl_internal(my_key.get(), resp, alpha.get(), ctx.get());
    if (status != PAILLIER_SUCCESS)
    {
        LOG_ERROR("Failed to decrypt mta response from player %" PRIu64 ", error %ld", other_id, status);
        throw cosigner_exception(cosigner_exception::INTERNAL_ERROR);
    }
    if (!BN_rshift1(tmp, my_key->pub.n))
    {
        LOG_ERROR("shift right failed error %lu", ERR_get_error());
        throw cosigner_exception(cosigner_exception::INTERNAL_ERROR);
    }
    const BIGNUM* q = algebra->order_internal(algebra);
    if (BN_cmp(alpha.get(), tmp) > 0)
    {
        if (!BN_mod_sub(alpha.get(), alpha.get(), my_key->pub.n, q, ctx.get()))
        {
            LOG_ERROR("Failed to calc alpha minus n error %lu", ERR_get_error());
            throw cosigner_exception(cosigner_exception::INTERNAL_ERROR);
        }
    }
    else if (!BN_mod(alpha.get(), alpha.get(), q, ctx.get()))
    {
        LOG_ERROR("Failed to calc alpha error %lu", ERR_get_error());
        throw cosigner_exception(cosigner_exception::INTERNAL_ERROR);
    }
    ctx_guard.reset();
    ctx.reset();

    elliptic_curve_scalar ret;
    BN_bn2binpad(alpha.get(), ret.data, sizeof(elliptic_curve256_scalar_t));
    return ret;
}

base_response_verifier::base_response_verifier(const uint64_t other_id, 
                                               const elliptic_curve256_algebra_ctx_t* algebra, 
                                               const byte_vector_t& aad, 
                                               const std::shared_ptr<paillier_private_key_t>& my_key, 
                                               const std::shared_ptr<paillier_public_key_t>& paillier, 
                                               const std::shared_ptr<ring_pedersen_private_t>& ring_pedersen) : 
        _other_id(other_id), 
        _algebra(algebra), 
        _aad(aad), 
        _my_paillier(my_key), 
        _my_ring_pedersen(ring_pedersen), 
        _other_paillier(paillier),
        _ctx(BN_CTX_new(), BN_CTX_free), 
        _my_mont(BN_MONT_CTX_new(), BN_MONT_CTX_free), 
        _other_mont(BN_MONT_CTX_new(), BN_MONT_CTX_free)
{
    if (!_ctx || !_my_mont || !_other_mont)
        throw cosigner_exception(cosigner_exception::NO_MEM);

    BN_CTX_start(_ctx.get());

    if (!BN_MONT_CTX_set(_my_mont.get(), _my_paillier->pub.n2, _ctx.get()))
    {
        LOG_ERROR("Failed to init montgomery context, error %lu", ERR_get_error());
        throw cosigner_exception(cosigner_exception::NO_MEM);
    }
    if (!BN_MONT_CTX_set(_other_mont.get(), _other_paillier->n2, _ctx.get()))
    {
        LOG_ERROR("Failed to init montgomery context, error %lu", ERR_get_error());
        throw cosigner_exception(cosigner_exception::NO_MEM);
    }
}

base_response_verifier::~base_response_verifier()
{
    if (_ctx)
    {
        BN_CTX_end(_ctx.get());
    }
}

batch_response_verifier::batch_response_verifier(
        uint64_t other_id, 
        const elliptic_curve256_algebra_ctx_t* algebra, 
        const byte_vector_t& aad, 
        const std::shared_ptr<paillier_private_key_t>& my_key, 
        const std::shared_ptr<paillier_public_key_t>& paillier, 
        const std::shared_ptr<ring_pedersen_private_t>& ring_pedersen) :
    base_response_verifier(other_id, algebra, aad, my_key, paillier, ring_pedersen)
{

    for (size_t i = 0; i < BATCH_STATISTICAL_SECURITY; i++)
    {
        _mta_ro[i] = BN_CTX_get(_ctx.get());
        _mta_B[i] = BN_CTX_get(_ctx.get());
        _commitment_ro[i] = BN_CTX_get(_ctx.get());
        _commitment_B[i] = BN_CTX_get(_ctx.get());

        if (!_mta_ro[i] || !_mta_B[i] || !_commitment_ro[i] || !_commitment_B[i])
        {
            LOG_ERROR("Failed to alloc batch bignums");
            throw cosigner_exception(cosigner_exception::NO_MEM);
        }

        BN_one(_mta_ro[i]);
        BN_one(_mta_B[i]);
        BN_one(_commitment_ro[i]);
        BN_one(_commitment_B[i]);
    }

    _pedersen_t_exp = BN_CTX_get(_ctx.get());
    _pedersen_B = BN_CTX_get(_ctx.get());

    if (!_pedersen_t_exp || !_pedersen_B)
    {
        LOG_ERROR("Failed to alloc pedersen bignums");
        throw cosigner_exception(cosigner_exception::NO_MEM);
    }
    BN_one(_pedersen_B);

}

void batch_response_verifier::process(
    const byte_vector_t& request, //this is mta_request from ecdsa_preprocessing_data, K sent by the other party
    cmp_mta_message& response, 
    const elliptic_curve_point& public_point)
{
    bn_ctx_frame frame_guard(_ctx.get());

    BIGNUM* mta_request = BN_CTX_get(_ctx.get());
    BIGNUM* mta_response = BN_CTX_get(_ctx.get());
    BIGNUM* commitment = BN_CTX_get(_ctx.get());
    if (!mta_request || !mta_response || !commitment ||
        !BN_bin2bn(request.data(), request.size(), mta_request) || 
        !BN_bin2bn(response.message.data(), response.message.size(), mta_response) || 
        !BN_bin2bn(response.commitment.data(), response.commitment.size(), commitment))
    {
        throw cosigner_exception(cosigner_exception::NO_MEM);
    }

    BIGNUM* e = BN_CTX_get(_ctx.get());
    
    if (!e)
        throw cosigner_exception(cosigner_exception::NO_MEM);
    mta_range_zkp proof(_ctx.get());
    deserialize_mta_range_zkp(response.proof, &_my_ring_pedersen->pub, _my_paillier.get(), _other_paillier.get(), proof);
    response.proof.clear();

    // start with range check
    if ((size_t)BN_num_bytes(proof.z1) > sizeof(elliptic_curve256_scalar_t) + MTA_ZKP_EPSILON_SIZE)
    {
        LOG_ERROR("player %" PRIu64 " z1 (%d bits) is out of range", _other_id, BN_num_bits(proof.z1));
        throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
    }
    if ((size_t)BN_num_bytes(proof.z2) > sizeof(elliptic_curve256_scalar_t) * BETA_HIDING_FACTOR + MTA_ZKP_EPSILON_SIZE)
    {
        LOG_ERROR("player %" PRIu64 " z2 (%d bits) is out of range", _other_id, BN_num_bits(proof.z2));
        throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
    }

    // sample e
    uint8_t seed[SHA256_DIGEST_LENGTH];
    genarate_mta_range_zkp_seed(response, proof, _aad, seed);
    response.commitment.clear();

    drng_t* rng = NULL;
    if (drng_new(seed, SHA256_DIGEST_LENGTH, &rng) != DRNG_SUCCESS)
    {
        LOG_ERROR("Failed to create drng");
        throw cosigner_exception(cosigner_exception::NO_MEM);
    }
    std::unique_ptr<drng_t, void (*)(drng_t*)> drng_guard(rng, drng_free);

    const BIGNUM* q = _algebra->order_internal(_algebra);
    elliptic_curve256_scalar_t val;
    do
    {
        drng_read_deterministic_rand(rng, val, sizeof(elliptic_curve256_scalar_t));
        if (!BN_bin2bn(val, sizeof(elliptic_curve256_scalar_t), e))
        {
            LOG_ERROR("Failed to load e, error %lu", ERR_get_error());
            throw cosigner_exception(cosigner_exception::NO_MEM);
        }
    } while (BN_cmp(e, q) >= 0);
    drng_guard.reset();

    elliptic_curve256_point_t p1, p2;
    {
        std::vector<uint8_t> bin(BN_num_bytes(proof.z1));
        BN_bn2bin(proof.z1, bin.data());
        auto status = _algebra->generator_mul_data(_algebra, bin.data(), bin.size(), &p1);
        if (status != ELLIPTIC_CURVE_ALGEBRA_SUCCESS)
        {
            LOG_ERROR("Failed to calc g^z1, error %d", status);
            throw cosigner_exception(cosigner_exception::INTERNAL_ERROR);
        }
    }
    auto status = _algebra->point_mul(_algebra, &p2, &public_point.data, &val);
    if (status != ELLIPTIC_CURVE_ALGEBRA_SUCCESS)
    {
        LOG_ERROR("Failed to calc X^e, error %d", status);
        throw cosigner_exception(cosigner_exception::INTERNAL_ERROR);
    }
    status = _algebra->add_points(_algebra, &p2, &proof.Bx, &p2);
    if (status != ELLIPTIC_CURVE_ALGEBRA_SUCCESS)
    {
        LOG_ERROR("Failed to calc Bx*X^e, error %d", status);
        throw cosigner_exception(cosigner_exception::INTERNAL_ERROR);
    }

    if (memcmp(p1, p2, sizeof(elliptic_curve256_point_t)) != 0)
    {
        LOG_ERROR("Failed to verify Bx*X^e == g^z1 for player %" PRIu64, _other_id);
        throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
    }
    process_paillier(e, mta_request, mta_response, commitment, proof);
    process_ring_pedersen(e, proof);
}

void batch_response_verifier::verify()
{
    bn_ctx_frame frame_guard(_ctx.get());

    BIGNUM* tmp = BN_CTX_get(_ctx.get());
    
    if (!tmp)
        throw cosigner_exception(cosigner_exception::NO_MEM);

    // verify paillier
    for (size_t i = 0; i < BATCH_STATISTICAL_SECURITY; i++)
    {
        if (!BN_mod_exp_mont(tmp, _mta_ro[i], _my_paillier->pub.n, _my_paillier->pub.n2, _ctx.get(), _my_mont.get()))
        {
            LOG_ERROR("Failed to calc ro^N, error %lu", ERR_get_error());
            throw cosigner_exception(cosigner_exception::INTERNAL_ERROR);
        }
        if (BN_cmp(tmp, _mta_B[i]) != 0)
        {
            LOG_ERROR("Failed to verify mta ro^N == B for player %" PRIu64, _other_id);
            throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
        }

        if (!BN_mod_exp_mont(tmp, _commitment_ro[i], _other_paillier->n, _other_paillier->n2, _ctx.get(), _other_mont.get()))
        {
            LOG_ERROR("Failed to calc ro^N, error %lu", ERR_get_error());
            throw cosigner_exception(cosigner_exception::INTERNAL_ERROR);
        }
        if (BN_cmp(tmp, _commitment_B[i]) != 0)
        {
            LOG_ERROR("Failed to verify commitment ro^N == B for player %" PRIu64, _other_id);
            throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
        }
    }

    // verify ring pedersen
    if (!BN_mod(_pedersen_t_exp, _pedersen_t_exp, _my_ring_pedersen->phi_n, _ctx.get()) || 
        !BN_mod_exp_mont(_pedersen_t_exp, _my_ring_pedersen->pub.t, _pedersen_t_exp, _my_ring_pedersen->pub.n, _ctx.get(), _my_ring_pedersen->pub.mont))
    {
        LOG_ERROR("Failed to calc t^exp_t, error %lu", ERR_get_error());
        throw cosigner_exception(cosigner_exception::INTERNAL_ERROR);
    }

    if (BN_cmp(_pedersen_t_exp, _pedersen_B) != 0)
    {
        LOG_ERROR("Failed to verify commitment t^exp_t == B for player %" PRIu64, _other_id);
        throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
    }
}

void batch_response_verifier::process_paillier(const BIGNUM* e, const BIGNUM* request, BIGNUM* response, const BIGNUM* commitment, const mta_range_zkp& proof)
{
    bn_ctx_frame frame_guard(_ctx.get());

    BIGNUM* tmp1 = BN_CTX_get(_ctx.get());
    BIGNUM* tmp2 = BN_CTX_get(_ctx.get());
    BIGNUM* B = BN_CTX_get(_ctx.get());
    BIGNUM* gamma = BN_CTX_get(_ctx.get());
    
    if (!tmp1 || !tmp2 || !B || !gamma)
    {
        throw cosigner_exception(cosigner_exception::NO_MEM);
    }

    if (is_coprime_fast(response, _my_paillier->pub.n, _ctx.get()) != 1)
    {
        LOG_ERROR("response is not a valid ciphertext");
        throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
    }

    if (is_coprime_fast(proof.A, _my_paillier->pub.n, _ctx.get()) != 1)
    {
        LOG_ERROR("proof A is not a valid ciphertext");
        throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
    }

    if (is_coprime_fast(commitment, _other_paillier->n, _ctx.get()) != 1)
    {
        LOG_ERROR("commitment is not a valid ciphertext");
        throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
    }

    if (is_coprime_fast(proof.By, _other_paillier->n, _ctx.get()) != 1)
    {
        LOG_ERROR("proof By is not a valid ciphertext");
        throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
    }

    uint8_t random[2 * BATCH_STATISTICAL_SECURITY];
    if (!RAND_bytes(random, 2 * BATCH_STATISTICAL_SECURITY * sizeof(uint8_t)))
    {
        LOG_ERROR("Failed to get random number, error %lu", ERR_get_error());
        throw cosigner_exception(cosigner_exception::INTERNAL_ERROR);
    }
    
    // first mta verification
    if (!BN_mod_inverse(tmp1, request, _my_paillier->pub.n2, _ctx.get()))
    {
        LOG_ERROR("Failed to calc C^-1, error %lu", ERR_get_error());
        throw cosigner_exception(cosigner_exception::INTERNAL_ERROR);
    }
    if (!BN_mod_exp2_mont(tmp1, tmp1, proof.z1, response, e, _my_paillier->pub.n2, _ctx.get(), _my_mont.get()))
    {
        LOG_ERROR("Failed to calc C^-z1*D^e, error %lu", ERR_get_error());
        throw cosigner_exception(cosigner_exception::INTERNAL_ERROR);
    }
    
    if (!BN_mul(tmp2, _my_paillier->pub.n, proof.z2, _ctx.get()) || !BN_sub(tmp2, _my_paillier->pub.n2, tmp2) || !BN_add_word(tmp2, 1))
    {
        LOG_ERROR("Failed to calc 1-N*z2, error %lu", ERR_get_error());
        throw cosigner_exception(cosigner_exception::INTERNAL_ERROR);
    }
    if (!BN_mod_mul(tmp1, tmp1, proof.A, _my_paillier->pub.n2, _ctx.get()) || !BN_mod_mul(B, tmp1, tmp2, _my_paillier->pub.n2, _ctx.get()))
    {
        LOG_ERROR("Failed to calc D^e*C^-z1*A*(1-N*z2), error %lu", ERR_get_error());
        throw cosigner_exception(cosigner_exception::INTERNAL_ERROR);
    }
        
    for (size_t i = 0; i < BATCH_STATISTICAL_SECURITY; i++)
    {
        if (!BN_set_word(gamma, random[i * 2]))
        {
            LOG_ERROR("Failed to set random number, error %lu", ERR_get_error());
            throw cosigner_exception(cosigner_exception::NO_MEM);
        }
        if (!BN_mod_exp_mont(tmp1, B, gamma, _my_paillier->pub.n2, _ctx.get(), _my_mont.get()))
        {
            LOG_ERROR("Failed to calc B, error %lu", ERR_get_error());
            throw cosigner_exception(cosigner_exception::INTERNAL_ERROR);
        }
        if (!BN_mod_mul(_mta_B[i], _mta_B[i], tmp1, _my_paillier->pub.n2, _ctx.get()))
        {
            LOG_ERROR("Failed to calc B product, error %lu", ERR_get_error());
            throw cosigner_exception(cosigner_exception::INTERNAL_ERROR);
        }

        if (!BN_mod_exp_mont(tmp2, proof.w, gamma, _my_paillier->pub.n2, _ctx.get(), _my_mont.get()))
        {
            LOG_ERROR("Failed to calc ro, error %lu", ERR_get_error());
            throw cosigner_exception(cosigner_exception::INTERNAL_ERROR);
        }
        if (!BN_mod_mul(_mta_ro[i], _mta_ro[i], tmp2, _my_paillier->pub.n2, _ctx.get()))
        {
            LOG_ERROR("Failed to calc ro product, error %lu", ERR_get_error());
            throw cosigner_exception(cosigner_exception::INTERNAL_ERROR);
        }
    }

    // second mta verification
    if (!BN_mod_exp_mont(tmp1, commitment, e, _other_paillier->n2, _ctx.get(), _other_mont.get()) || !BN_mod_mul(tmp1, tmp1, proof.By, _other_paillier->n2, _ctx.get()))
    {
        LOG_ERROR("Failed to calc Y^e*By, error %lu", ERR_get_error());
        throw cosigner_exception(cosigner_exception::INTERNAL_ERROR);
    }
    if (!BN_mul(tmp2, _other_paillier->n, proof.z2, _ctx.get()) || !BN_sub(tmp2, _other_paillier->n2, tmp2) || !BN_add_word(tmp2, 1))
    {
        LOG_ERROR("Failed to calc 1-N*z2, error %lu", ERR_get_error());
        throw cosigner_exception(cosigner_exception::INTERNAL_ERROR);
    }
    if (!BN_mod_mul(B, tmp1, tmp2, _other_paillier->n2, _ctx.get()))
    {
        LOG_ERROR("Failed to calc Y^e*By*(1-N*z2), error %lu", ERR_get_error());
        throw cosigner_exception(cosigner_exception::INTERNAL_ERROR);
    }

    for (size_t i = 0; i < BATCH_STATISTICAL_SECURITY; i++)
    {
        if (!BN_set_word(gamma, random[i * 2 + 1]))
        {
            LOG_ERROR("Failed to set random number, error %lu", ERR_get_error());
            throw cosigner_exception(cosigner_exception::NO_MEM);
        }
        if (!BN_mod_exp_mont(tmp1, B, gamma, _other_paillier->n2, _ctx.get(), _other_mont.get()))
        {
            LOG_ERROR("Failed to calc B, error %lu", ERR_get_error());
            throw cosigner_exception(cosigner_exception::INTERNAL_ERROR);
        }
        if (!BN_mod_mul(_commitment_B[i], _commitment_B[i], tmp1, _other_paillier->n2, _ctx.get()))
        {
            LOG_ERROR("Failed to calc B product, error %lu", ERR_get_error());
            throw cosigner_exception(cosigner_exception::INTERNAL_ERROR);
        }

        if (!BN_mod_exp_mont(tmp2, proof.wy, gamma, _other_paillier->n2, _ctx.get(), _other_mont.get()))
        {
            LOG_ERROR("Failed to calc ro, error %lu", ERR_get_error());
            throw cosigner_exception(cosigner_exception::INTERNAL_ERROR);
        }
        if (!BN_mod_mul(_commitment_ro[i], _commitment_ro[i], tmp2, _other_paillier->n2, _ctx.get()))
        {
            LOG_ERROR("Failed to calc ro product, error %lu", ERR_get_error());
            throw cosigner_exception(cosigner_exception::INTERNAL_ERROR);
        }
    }
}

void batch_response_verifier::process_ring_pedersen(const BIGNUM* e, const mta_range_zkp& proof)
{
    bn_ctx_frame frame_guard(_ctx.get());

    BIGNUM* tmp1 = BN_CTX_get(_ctx.get());
    BIGNUM* tmp2 = BN_CTX_get(_ctx.get());
    uint8_t gamma[2 * sizeof(uint64_t)];

    if (!tmp1 || !tmp2)
    {
        throw cosigner_exception(cosigner_exception::NO_MEM);
    }
    
    if (!RAND_bytes(gamma, 2 * sizeof(uint64_t)))
    {
        LOG_ERROR("Failed to get random number, error %lu", ERR_get_error());
        throw cosigner_exception(cosigner_exception::INTERNAL_ERROR);
    }
    gamma[0] &= 0xffffffffff; // 40bits
    gamma[1] &= 0xffffffffff; // 40bits

    auto rp_status = ring_pedersen_init_montgomery(&_my_ring_pedersen->pub, _ctx.get());
    if (rp_status != RING_PEDERSEN_SUCCESS)
    {
        LOG_ERROR("Failed to init ring pedersen motgomery context, error %d", rp_status);
        throw cosigner_exception(cosigner_exception::NO_MEM);
    }

    // s^z1*t^z3 == E*S^e
    if (!BN_mod_mul(tmp1, _my_ring_pedersen->lamda, proof.z1, _my_ring_pedersen->phi_n, _ctx.get()) || !BN_mod_add(tmp1, tmp1, proof.z3, _my_ring_pedersen->phi_n, _ctx.get()))
    {
        LOG_ERROR("Failed to calc lamda*x+r, error %lu", ERR_get_error());
        throw cosigner_exception(cosigner_exception::INTERNAL_ERROR);
    }
    if (!BN_mul_word(tmp1, gamma[0]))
    {
        LOG_ERROR("Failed to calc (lamda*x+r)*random64, error %lu", ERR_get_error());
        throw cosigner_exception(cosigner_exception::INTERNAL_ERROR);
    }
    if (!BN_add(_pedersen_t_exp, _pedersen_t_exp, tmp1))
    {
        LOG_ERROR("Failed to calc sum t exponant, error %lu", ERR_get_error());
        throw cosigner_exception(cosigner_exception::INTERNAL_ERROR);
    }

    if (!BN_set_word(tmp1, gamma[0]) || !BN_mod_mul(tmp2, tmp1, e, _my_ring_pedersen->phi_n, _ctx.get()))
    {
        LOG_ERROR("Failed to calc e*gamma, error %lu", ERR_get_error());
        throw cosigner_exception(cosigner_exception::INTERNAL_ERROR);
    }
    if (!BN_mod_exp2_mont(tmp1, proof.E, tmp1, proof.S, tmp2, _my_ring_pedersen->pub.n, _ctx.get(), _my_ring_pedersen->pub.mont))
    {
        LOG_ERROR("Failed to calc E^gamma*S^(e*gamma), error %lu", ERR_get_error());
        throw cosigner_exception(cosigner_exception::INTERNAL_ERROR);
    }
    if (!BN_mod_mul(_pedersen_B, _pedersen_B, tmp1, _my_ring_pedersen->pub.n, _ctx.get()))
    {
        LOG_ERROR("Failed to calc ro product, error %lu", ERR_get_error());
        throw cosigner_exception(cosigner_exception::INTERNAL_ERROR);
    }


    // s^z2*t^z4 == F*T^e
    if (!BN_mod_mul(tmp1, _my_ring_pedersen->lamda, proof.z2, _my_ring_pedersen->phi_n, _ctx.get()) || !BN_mod_add(tmp1, tmp1, proof.z4, _my_ring_pedersen->phi_n, _ctx.get()))
    {
        LOG_ERROR("Failed to calc lamda*x+r, error %lu", ERR_get_error());
        throw cosigner_exception(cosigner_exception::INTERNAL_ERROR);
    }
    if (!BN_mul_word(tmp1, gamma[1]))
    {
        LOG_ERROR("Failed to calc (lamda*x+r)*random64, error %lu", ERR_get_error());
        throw cosigner_exception(cosigner_exception::INTERNAL_ERROR);
    }
    if (!BN_add(_pedersen_t_exp, _pedersen_t_exp, tmp1))
    {
        LOG_ERROR("Failed to calc sum t exponant, error %lu", ERR_get_error());
        throw cosigner_exception(cosigner_exception::INTERNAL_ERROR);
    }

    if (!BN_set_word(tmp1, gamma[1]) || !BN_mod_mul(tmp2, tmp1, e, _my_ring_pedersen->phi_n, _ctx.get()))
    {
        LOG_ERROR("Failed to calc e*gamma, error %lu", ERR_get_error());
        throw cosigner_exception(cosigner_exception::INTERNAL_ERROR);
    }
    if (!BN_mod_exp2_mont(tmp1, proof.F, tmp1, proof.T, tmp2, _my_ring_pedersen->pub.n, _ctx.get(), _my_ring_pedersen->pub.mont))
    {
        LOG_ERROR("Failed to calc E^gamma*S^(e*gamma), error %lu", ERR_get_error());
        throw cosigner_exception(cosigner_exception::INTERNAL_ERROR);
    }
    if (!BN_mod_mul(_pedersen_B, _pedersen_B, tmp1, _my_ring_pedersen->pub.n, _ctx.get()))
    {
        LOG_ERROR("Failed to calc ro product, error %lu", ERR_get_error());
        throw cosigner_exception(cosigner_exception::INTERNAL_ERROR);
    }
}

void single_response_verifier::process_ring_pedersen(const BIGNUM* e, const mta_range_zkp& proof)
{
    bn_ctx_frame frame_guard(_ctx.get());

    BIGNUM* tmp1 = BN_CTX_get(_ctx.get());
    BIGNUM* tmp2 = BN_CTX_get(_ctx.get());

    if (!tmp1 || !tmp2)
    {
        throw cosigner_exception(cosigner_exception::NO_MEM);
    }

    auto rp_status = ring_pedersen_init_montgomery(&_my_ring_pedersen->pub, _ctx.get());
    if (rp_status != RING_PEDERSEN_SUCCESS)
    {
        LOG_ERROR("Failed to init ring pedersen motgomery context, error %d", rp_status);
        throw cosigner_exception(cosigner_exception::NO_MEM);
    }

    // s^z1*t^z3 == E*S^e
    // tmp1 = z1* lamda + z3   
    if (!BN_mod_mul(tmp1, _my_ring_pedersen->lamda, proof.z1, _my_ring_pedersen->phi_n, _ctx.get()) || 
        !BN_mod_add(tmp1, tmp1, proof.z3, _my_ring_pedersen->phi_n, _ctx.get()))
    {
        LOG_ERROR("Failed to calc lamda*z1+z3, error %lu", ERR_get_error());
        throw cosigner_exception(cosigner_exception::INTERNAL_ERROR);
    }

    //tmp1 = t^(lamda * z1 + z3)
    if (!BN_mod_exp_mont(tmp1, _my_ring_pedersen->pub.t, tmp1, _my_ring_pedersen->pub.n, _ctx.get(), _my_ring_pedersen->pub.mont))
    {
        LOG_ERROR("Failed to calc t^(lamda * z1 + z3), error %lu", ERR_get_error());
        throw cosigner_exception(cosigner_exception::INTERNAL_ERROR);
    }

    //tmp2 = S^e
    if (!BN_mod_exp_mont(tmp2, proof.S, e, _my_ring_pedersen->pub.n, _ctx.get(), _my_ring_pedersen->pub.mont))
    {
        LOG_ERROR("Failed to calc S^e, error %lu", ERR_get_error());
        throw cosigner_exception(cosigner_exception::INTERNAL_ERROR);
    }

    //tmp2 = tmp2 * E = E * S^e
    if (!BN_mod_mul(tmp2, tmp2, proof.E, _my_ring_pedersen->pub.n, _ctx.get()))
    {
        LOG_ERROR("Failed to calc E * S^e), error %lu", ERR_get_error());
        throw cosigner_exception(cosigner_exception::INTERNAL_ERROR);
    }
    
    //compare tmp1 and tmp2
    if (0 != BN_cmp(tmp1, tmp2))
    {
        LOG_ERROR("s^z1*t^z3 != E * S^e)");
        throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
    }

    // s^z2*t^z4 == F*T^e
    // tmp1 = z2* lamda + z4
    if (!BN_mod_mul(tmp1, _my_ring_pedersen->lamda, proof.z2, _my_ring_pedersen->phi_n, _ctx.get()) || 
        !BN_mod_add(tmp1, tmp1, proof.z4, _my_ring_pedersen->phi_n, _ctx.get()))
    {
        LOG_ERROR("Failed to calc z2* lamda + z4, error %lu", ERR_get_error());
        throw cosigner_exception(cosigner_exception::INTERNAL_ERROR);
    }

    //tmp1 = t^(lamda * z2 + z4)
    if (!BN_mod_exp_mont(tmp1, _my_ring_pedersen->pub.t, tmp1, _my_ring_pedersen->pub.n, _ctx.get(), _my_ring_pedersen->pub.mont))
    {
        LOG_ERROR("Failed to calc t^(lamda * z2 + z4), error %lu", ERR_get_error());
        throw cosigner_exception(cosigner_exception::INTERNAL_ERROR);
    }

    //tmp2 = T^e
    if (!BN_mod_exp_mont(tmp2, proof.T, e, _my_ring_pedersen->pub.n, _ctx.get(), _my_ring_pedersen->pub.mont))
    {
        LOG_ERROR("Failed to calc T^e, error %lu", ERR_get_error());
        throw cosigner_exception(cosigner_exception::INTERNAL_ERROR);
    }

    //tmp2 = tmp2 * F = F * T^e
    if (!BN_mod_mul(tmp2, tmp2, proof.F, _my_ring_pedersen->pub.n, _ctx.get()))
    {
        LOG_ERROR("Failed to calc F * T^e), error %lu", ERR_get_error());
        throw cosigner_exception(cosigner_exception::INTERNAL_ERROR);
    }
    
    //compare tmp1 and tmp2
    if (0 != BN_cmp(tmp1, tmp2))
    {
        LOG_ERROR("s^z2*t^z4 != F * T^e)");
        throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
    }
}

void single_response_verifier::process_paillier(
    const BIGNUM* e, 
    const BIGNUM* request,         //C in the document, actually here passed encrypted K
    const BIGNUM* response,        //D in the document, homomorphic calculation k*(x or gamma) + beta 
    const BIGNUM* commitment,      //Y in the document, paillier encrypted my parties beta as commitment
    const mta_range_zkp& proof)
{
    bn_ctx_frame frame_guard(_ctx.get());
        
    BIGNUM* tmp1 = BN_CTX_get(_ctx.get());
    BIGNUM* tmp2 = BN_CTX_get(_ctx.get());
    
    if (!tmp1 || !tmp2)
    {
        throw cosigner_exception(cosigner_exception::NO_MEM);
    }

    if (is_coprime_fast(response, _my_paillier->pub.n, _ctx.get()) != 1)
    {
        LOG_ERROR("response is not a valid ciphertext");
        throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
    }

    if (is_coprime_fast(proof.A, _my_paillier->pub.n, _ctx.get()) != 1)
    {
        LOG_ERROR("proof A is not a valid ciphertext");
        throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
    }

    if (is_coprime_fast(commitment, _other_paillier->n, _ctx.get()) != 1)
    {
        LOG_ERROR("commitment is not a valid ciphertext");
        throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
    }

    if (is_coprime_fast(proof.By, _other_paillier->n, _ctx.get()) != 1)
    {
        LOG_ERROR("proof By is not a valid ciphertext");
        throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
    }

    //============ 1st MTA verification ============
    if (!BN_mod_exp_mont(tmp1, request, proof.z1, _my_paillier->pub.n2, _ctx.get(), _my_mont.get()))
    {
        LOG_ERROR("Failed to calc C^z1, error %lu", ERR_get_error());
        throw cosigner_exception(cosigner_exception::INTERNAL_ERROR);
    }

    long paillier_status = paillier_encrypt_openssl_internal(&_my_paillier->pub, tmp2, proof.w, proof.z2, _ctx.get());
    if (paillier_status != PAILLIER_SUCCESS)
    {
        LOG_ERROR("Failed to encrypt z2 with my key during verify, error %ld", paillier_status);
        throw cosigner_exception(cosigner_exception::INTERNAL_ERROR);
    }
    
    //tmp1 holds the result
    if (!BN_mod_mul(tmp1, tmp1, tmp2, _my_paillier->pub.n2, _ctx.get()))
    {
        LOG_ERROR("Failed to calc C^z1 * enc(z2, w), error %lu", ERR_get_error());
        throw cosigner_exception(cosigner_exception::INTERNAL_ERROR);
    }
   
    //tmp2 = D^e
    if (!BN_mod_exp_mont(tmp2, response, e, _my_paillier->pub.n2, _ctx.get(), _my_mont.get()))
    {
        LOG_ERROR("Failed to calc D^e, error %lu", ERR_get_error());
        throw cosigner_exception(cosigner_exception::INTERNAL_ERROR);
    }

    //tmp2 = tmp2 * A = A * D^e
    if (!BN_mod_mul(tmp2, tmp2, proof.A, _my_paillier->pub.n2, _ctx.get()))
    {
        LOG_ERROR("Failed to calc (A * D^e), error %lu", ERR_get_error());
        throw cosigner_exception(cosigner_exception::INTERNAL_ERROR);
    }
    
    //compare tmp1 and tmp2
    if (0 != BN_cmp(tmp1, tmp2))
    {
        LOG_ERROR("Failed check C^z1 * enc(z2, w) == A * D^e");
        throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
    }

    //============ 2nd MTA verification ============ 
    paillier_status = paillier_encrypt_openssl_internal(_other_paillier.get(), tmp1, proof.wy, proof.z2, _ctx.get());
    if (paillier_status != PAILLIER_SUCCESS)
    {
        LOG_ERROR("Failed to encrypt z2 with my peer's key during verify, error %ld", paillier_status);
        throw cosigner_exception(cosigner_exception::INTERNAL_ERROR);
    }

    //tmp2 = Y^e
    if (!BN_mod_exp_mont(tmp2, commitment, e, _other_paillier->n2, _ctx.get(), _other_mont.get()))
    {
        LOG_ERROR("Failed to calc Y^e, error %lu", ERR_get_error());
        throw cosigner_exception(cosigner_exception::INTERNAL_ERROR);
    }

    //tmp2 = tmp2 * By = By * Y^e
    if (!BN_mod_mul(tmp2, proof.By, tmp2, _other_paillier->n2, _ctx.get()))
    {
        LOG_ERROR("Failed to calc (A * D^e), error %lu", ERR_get_error());
        throw cosigner_exception(cosigner_exception::INTERNAL_ERROR);
    }
    
    //compare tmp1 and tmp2
    if (0 != BN_cmp(tmp1, tmp2))
    {
        LOG_ERROR("Failed check enc(z2, w) == By * Y^e");
        throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
    }
}

void single_response_verifier::process(const byte_vector_t& request, cmp_mta_message& response, const elliptic_curve_point& public_point)
{
    bn_ctx_frame ctx_guard(_ctx.get());
    
    BIGNUM* mta_request = BN_CTX_get(_ctx.get());

    if (!mta_request  || !BN_bin2bn(request.data(), request.size(), mta_request))
    {
        throw cosigner_exception(cosigner_exception::NO_MEM);
    }  


    BIGNUM* mta_response = BN_CTX_get(_ctx.get()); //paillier encrypted minus my beta with my key
    BIGNUM* commitment = BN_CTX_get(_ctx.get()); //paillier encrypted my parties beta with his key
    if (!mta_response || !commitment ||
        !BN_bin2bn(response.message.data(), response.message.size(), mta_response) || 
        !BN_bin2bn(response.commitment.data(), response.commitment.size(), commitment))
    {
        throw cosigner_exception(cosigner_exception::NO_MEM);
    }
    
    BIGNUM* e = BN_CTX_get(_ctx.get());
    
    if (!e)
        throw cosigner_exception(cosigner_exception::NO_MEM);
    
    mta_range_zkp proof(_ctx.get());
    
    deserialize_mta_range_zkp(response.proof, &_my_ring_pedersen->pub, _my_paillier.get(), _other_paillier.get(), proof);

    // start with range check
    if ((size_t)BN_num_bytes(proof.z1) > sizeof(elliptic_curve256_scalar_t) + MTA_ZKP_EPSILON_SIZE)
    {
        LOG_ERROR("player %lu z1 (%d bits) is out of range", _other_id, BN_num_bits(proof.z1));
        throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
    }

    if ((size_t)BN_num_bytes(proof.z2) > sizeof(elliptic_curve256_scalar_t) * BETA_HIDING_FACTOR + MTA_ZKP_EPSILON_SIZE)
    {
        LOG_ERROR("player %lu z2 (%d bits) is out of range", _other_id, BN_num_bits(proof.z2));
        throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
    }

    // sample e
    uint8_t seed[SHA256_DIGEST_LENGTH];
    genarate_mta_range_zkp_seed(response, proof, _aad, seed);
    
    response.commitment.clear();
    response.proof.clear();

    drng_t* rng = NULL;
    if (drng_new(seed, SHA256_DIGEST_LENGTH, &rng) != DRNG_SUCCESS)
    {
        LOG_ERROR("Failed to create drng");
        throw cosigner_exception(cosigner_exception::NO_MEM);
    }
    std::unique_ptr<drng_t, void (*)(drng_t*)> drng_guard(rng, drng_free);

    const BIGNUM* q = _algebra->order_internal(_algebra);
    elliptic_curve256_scalar_t val;
    do
    {
        drng_read_deterministic_rand(rng, val, sizeof(elliptic_curve256_scalar_t));
        if (!BN_bin2bn(val, sizeof(elliptic_curve256_scalar_t), e))
        {
            LOG_ERROR("Failed to load e, error %lu", ERR_get_error());
            throw cosigner_exception(cosigner_exception::NO_MEM);
        }
    } while (BN_cmp(e, q) >= 0);
    drng_guard.reset();

    elliptic_curve256_point_t p1, p2;
    
    //scope for bin variable and calculate p1=q^z1
    {
        std::vector<uint8_t> bin(BN_num_bytes(proof.z1));
        BN_bn2bin(proof.z1, bin.data());
        auto status = _algebra->generator_mul_data(_algebra, bin.data(), bin.size(), &p1);
        if (status != ELLIPTIC_CURVE_ALGEBRA_SUCCESS)
        {
            LOG_ERROR("Failed to calc g^z1, error %d", status);
            throw cosigner_exception(cosigner_exception::INTERNAL_ERROR);
        }
    }

    auto status = _algebra->point_mul(_algebra, &p2, &public_point.data, &val);
    if (status != ELLIPTIC_CURVE_ALGEBRA_SUCCESS)
    {
        LOG_ERROR("Failed to calc X^e, error %d", status);
        throw cosigner_exception(cosigner_exception::INTERNAL_ERROR);
    }
    status = _algebra->add_points(_algebra, &p2, &proof.Bx, &p2);
    if (status != ELLIPTIC_CURVE_ALGEBRA_SUCCESS)
    {
        LOG_ERROR("Failed to calc Bx*X^e, error %d", status);
        throw cosigner_exception(cosigner_exception::INTERNAL_ERROR);
    }

    // verify g^z1 == Bx*X^e
    if (memcmp(p1, p2, sizeof(elliptic_curve256_point_t)) != 0)
    {
        LOG_ERROR("Failed to verify Bx*X^e == g^z1 for player %lu", _other_id);
        throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
    }

    process_paillier(e, 
                     mta_request, 
                     mta_response, 
                     commitment, 
                     proof);
    process_ring_pedersen(e, proof);
}

}
}
}
}
