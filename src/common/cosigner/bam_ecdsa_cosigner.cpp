#include "cosigner/bam_ecdsa_cosigner.h"
#include "cosigner/cosigner_exception.h"
#include <openssl/sha.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include "logging/logging_t.h"
#include <cinttypes>
#include "crypto/common/byteswap.h"
#include "blockchain/mpc/hd_derive.h"
#include "crypto/GFp_curve_algebra/GFp_curve_algebra.h"
#include "cosigner/platform_service.h"
#include "cosigner/bam_key_persistency_structures.h"
#include "cosigner/bam_tx_persistency_structures.h"
#include "cosigner_bn.h"

namespace fireblocks::common::cosigner
{


static constexpr const char SETUP_AAD_PREFIX[] = "BAM_ECDSA_COSIGNER_SETUP_AAD_";
static const std::string BAM_ECDSA_SALT_KEY_GEN("BAM ECDSA Key Generation AAD");
static const std::string BAM_ECDSA_SALT_SIGNATURE("BAM ECDSA Signature AAD");

bam_ecdsa_cosigner::bam_ecdsa_cosigner(platform_service& platform_service) : 
        _platform_service(platform_service),
        _secp256k1(elliptic_curve256_new_secp256k1_algebra(), elliptic_curve256_algebra_ctx_free),
        _secp256r1(elliptic_curve256_new_secp256r1_algebra(), elliptic_curve256_algebra_ctx_free),
        _stark(elliptic_curve256_new_stark_algebra(), elliptic_curve256_algebra_ctx_free)
{
    if (!_secp256k1 || !_secp256r1 || !_stark)
    {
        throw cosigner_exception(cosigner_exception::NO_MEM);
    }
}

std::vector<bam_signing_properties> bam_ecdsa_cosigner::fill_bam_signing_info_from_metadata(const std::string& metadata, const uint32_t blocks_num)
{
    std::vector<bam_signing_properties> signature_request_data(blocks_num);
    _platform_service.fill_bam_signing_info_from_metadata(signature_request_data, metadata);
    return signature_request_data;
}

byte_vector_t bam_ecdsa_cosigner::generate_setup_aad_bytes(const std::string& setup_id, const cosigner_sign_algorithm algorithm) const
{
    byte_vector_t setup_aad;
    setup_aad.reserve(sizeof(SETUP_AAD_PREFIX) - 1 + setup_id.size() + sizeof(algorithm) + sizeof(elliptic_curve256_point_t));
    
    // Add prefix
    setup_aad.insert(setup_aad.end(), SETUP_AAD_PREFIX, SETUP_AAD_PREFIX + sizeof(SETUP_AAD_PREFIX) - 1);
    
    // Add setup ID
    setup_aad.insert(setup_aad.end(), setup_id.begin(), setup_id.end());
    
    // Add algorithm
    const char* algo_ptr = reinterpret_cast<const char*>(&algorithm);
    setup_aad.insert(setup_aad.end(), algo_ptr, algo_ptr + sizeof(algorithm));
    
    return setup_aad;
}

void bam_ecdsa_cosigner::generate_aad_for_key_gen(const std::string& key_id, const uint64_t client_id, const uint64_t server_id, commitments_sha256_t& key_aad)
{
    SHA256_CTX hash_ctx;
    SHA256_Init(&hash_ctx);
    SHA256_Update(&hash_ctx, BAM_ECDSA_SALT_KEY_GEN.c_str(), BAM_ECDSA_SALT_KEY_GEN.size());
    SHA256_Update(&hash_ctx, key_id.c_str(), key_id.size());
    SHA256_Update(&hash_ctx, &client_id, sizeof(client_id));
    SHA256_Update(&hash_ctx, &server_id, sizeof(server_id));
    SHA256_Final(key_aad, &hash_ctx);
}

void bam_ecdsa_cosigner::generate_aad_for_signature(const std::string& key_id, const uint64_t server_id, const uint64_t client_id, const std::string& tx_id, commitments_sha256_t& signature_add)
{
    SHA256_CTX hash_ctx;
    SHA256_Init(&hash_ctx);
    // seed contains key_id, server_id, client_id and tx_id
    SHA256_Update(&hash_ctx, BAM_ECDSA_SALT_SIGNATURE.c_str(), BAM_ECDSA_SALT_SIGNATURE.size());
    SHA256_Update(&hash_ctx, key_id.c_str(), key_id.size());
    SHA256_Update(&hash_ctx, tx_id.c_str(), tx_id.size());
    SHA256_Update(&hash_ctx, &server_id, sizeof(server_id));
    SHA256_Update(&hash_ctx, &client_id, sizeof(client_id));
    SHA256_Final(signature_add, &hash_ctx);
}

void bam_ecdsa_cosigner::generate_key_commitment(const commitments_sha256_t& seed,  
                                                 const elliptic_curve256_point_t& public_key, 
                                                 commitments_sha256_t& B)
{
    SHA256_CTX hash_ctx;
    SHA256_Init(&hash_ctx);
    // seed contains key_id, server_id and client id
    SHA256_Update(&hash_ctx, seed, sizeof(commitments_sha256_t));
    SHA256_Update(&hash_ctx, public_key, sizeof(elliptic_curve256_point_t));
    SHA256_Final(B, &hash_ctx);
}

void bam_ecdsa_cosigner::check_non_null_message(const elliptic_curve256_scalar_t& message, const elliptic_curve256_algebra_ctx_t* algebra)
{
    static const elliptic_curve256_scalar_t zero = {0};
    elliptic_curve256_scalar_t tmp;
    // reduce in the scalar field, to check whether it's zero or not.
    throw_cosigner_exception(algebra->add_scalars(algebra, &tmp, message, sizeof(elliptic_curve256_scalar_t), zero, 1));

    if (memcmp(tmp, zero, sizeof(elliptic_curve256_scalar_t)) == 0) 
    {
        throw cosigner_exception(cosigner_exception::INVALID_TRANSACTION);
    }
}

void bam_ecdsa_cosigner::check_a_valid_point(const elliptic_curve256_point_t& point, const elliptic_curve256_algebra_ctx_t* algebra)
{
    const elliptic_curve_algebra_status st = algebra->validate_non_infinity_point(algebra, &point);
    if (st != ELLIPTIC_CURVE_ALGEBRA_SUCCESS)
    {
        LOG_ERROR("Unexpected invalid point received");
        throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
    }
}

void bam_ecdsa_cosigner::compute_hash_shift(const std::string& tx_id, 
                                            const elliptic_curve256_scalar_t& hash_to_sign, 
                                            const elliptic_curve256_point_t& ephemeral_common_key, 
                                            const elliptic_curve256_point_t& client_ephemeral_key, 
                                            const elliptic_curve256_point_t& public_key,
                                            elliptic_curve256_scalar_t& hash_shift)
{
    SHA256_CTX sha;
    SHA256_Init(&sha);
    SHA256_Update(&sha, tx_id.data(), tx_id.size());
    SHA256_Update(&sha, public_key, sizeof(elliptic_curve256_point_t));
    SHA256_Update(&sha, client_ephemeral_key, sizeof(elliptic_curve256_point_t));
    SHA256_Update(&sha, ephemeral_common_key, sizeof(elliptic_curve256_point_t));
    SHA256_Update(&sha, hash_to_sign, sizeof(elliptic_curve256_scalar_t));
    SHA256_Final(&hash_shift[0], &sha);
}

void bam_ecdsa_cosigner::bignum_clear_deleter::operator()(struct bignum_st* bn)
{ 
    BN_clear_free(bn); 
}

void bam_ecdsa_cosigner::bignum_clear::operator()(struct bignum_st* bn)
{
    BN_clear(bn); 
}



void bam_ecdsa_cosigner::validate_current_tenant_id(const std::string& tenant_id) const
{
    if (tenant_id != _platform_service.get_current_tenantid())
    {
        LOG_ERROR("Tenant id mismatch. Request for tenant %s while current tenant is %s", tenant_id.c_str(), _platform_service.get_current_tenantid().c_str());
        throw cosigner_exception(cosigner_exception::INTERNAL_ERROR);
    }
}


void bam_ecdsa_cosigner::validate_tenant_id_setup(bam_key_persistency_common& persistency, const std::string& setup_id) const
{   
    std::string setup_tenant_id;
    persistency.load_tenant_id_for_setup(setup_id, setup_tenant_id);
    validate_current_tenant_id(setup_tenant_id);
}


void bam_ecdsa_cosigner::make_sig_s_positive(const cosigner_sign_algorithm algorithm, const elliptic_curve256_algebra_ctx_t* algebra, recoverable_signature& sig)
{
    // calling is_positive as optimization for not calling GFp_curve_algebra_abs unless needed
    if (!is_positive(algorithm, sig.s))
    {
        uint8_t parity = sig.s[31] & 1;
        throw_cosigner_exception(GFp_curve_algebra_abs((GFp_curve_algebra_ctx_t*)algebra->ctx, &sig.s, &sig.s));
        sig.v ^= (parity ^ (sig.s[31] & 1));
    }
}


bool bam_ecdsa_cosigner::is_positive(const cosigner_sign_algorithm algorithm, const elliptic_curve256_scalar_t& n)
{
    switch (algorithm)
    {
        case ECDSA_SECP256K1:  return (n[0] & 0x80) == 0;
        
        case ECDSA_SECP256R1:
        {
            static constexpr const uint64_t half_n_first_8_bytes_le = 0x7FFFFFFF80000000ULL;
            const uint64_t n_val = bswap_64(*reinterpret_cast<const uint64_t*>(&n)); //convert highest 64 bits big endian to little endian 
            return n_val < half_n_first_8_bytes_le;
        }
        
        case ECDSA_STARK: return n[0] < 4; // stark curve is 252bit

        case EDDSA_ED25519: //fallthrough to default
        default:
            throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
    }
}

void bam_ecdsa_cosigner::derivation_key_delta(const elliptic_curve256_algebra_ctx_t* algebra, 
                                              const elliptic_curve256_point_t& public_key, 
                                              const HDChaincode& chaincode, 
                                              const std::vector<uint32_t>& path,
                                              elliptic_curve256_scalar_t& delta)
{
    static const elliptic_curve256_scalar_t ZERO = {0};
    
    if (path.size()) 
    {
        assert(path.size() == BIP44_PATH_LENGTH);
        hd_derive_status retval = derive_private_key_generic(algebra, delta, public_key, ZERO, chaincode, path.data(), path.size()); //derive 0 to get the derivation delta
        if (HD_DERIVE_SUCCESS != retval)
        {
            LOG_ERROR("Error deriving private key: %d", retval);
            throw cosigner_exception(cosigner_exception::INTERNAL_ERROR);
        }
    }
    else
    {
        memcpy(delta, ZERO, sizeof(elliptic_curve_scalar));
    }
}

// Randomizes a BIGNUM by adding a random multiple of a given factor
// The randomizer bit length defines the range for randomness
void bam_ecdsa_cosigner::bn_randomize_with_factor(struct bignum_st* res,  const struct bignum_st* base,  const struct bignum_st* factor,  const uint32_t randomizer_bitlength)
{
    long ret = -1;
    BIGNUM* randomizer = NULL;

    if (!res || !base || !factor || !randomizer_bitlength)
    {
        throw_cosigner_exception(ELLIPTIC_CURVE_ALGEBRA_INVALID_PARAMETER);
    }
    
    BN_CTX_guard ctx_guard;
    auto ctx = ctx_guard.get();

    randomizer = BN_CTX_get(ctx);
    if (!randomizer)
    {
        goto cleanup;
    }
        
    if (!BN_rand(randomizer, randomizer_bitlength, BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ANY))
    {
        goto cleanup;
    }
        
    if (!BN_mul(randomizer, randomizer, factor, ctx))
    {
        goto cleanup;
    }
        
    if (!BN_add(res, base, randomizer))
    {
        goto cleanup;
    }
        
    ret = ELLIPTIC_CURVE_ALGEBRA_SUCCESS;

cleanup:
    // Error handling and cleanup
    if (-1 == ret)
    {
        ERR_clear_error();
        ret = ELLIPTIC_CURVE_ALGEBRA_UNKNOWN_ERROR;
    }
    
    if (randomizer)
    {
        BN_clear(randomizer);
    }
    

    if (ret != ELLIPTIC_CURVE_ALGEBRA_SUCCESS)
    {
        LOG_ERROR("bn_randomize_with_factor() failed with error %ld", ret);
        throw_cosigner_exception((elliptic_curve_algebra_status)ret);
    }
}

void bam_ecdsa_cosigner::generate_private_share(const cosigner_sign_algorithm algorithm, elliptic_curve_scalar& private_share) const
{
    const auto algebra = get_algebra(algorithm);
    throw_cosigner_exception(algebra->rand(algebra, &private_share.data));
}

void bam_ecdsa_cosigner::decrypt_and_rebuild_private_share(const uint64_t my_player_id,
                                                           const cosigner_sign_algorithm algorithm, 
                                                           const std::map<uint64_t, add_user_data>& data, 
                                                           elliptic_curve_scalar& private_share,
                                                           elliptic_curve256_point_t& expected_public_key) const
{
    const auto algebra = get_algebra(algorithm);
    OPENSSL_cleanse(private_share.data, sizeof(private_share.data));
    if (data.size() == 0)
    {
        throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
    }

    bool is_first = true;
    // perform validations
    for (const auto& src_player_data : data)
    {
        if (is_first)
        {
            is_first = false;
            memcpy(&expected_public_key[0], &src_player_data.second.public_key.data[0], sizeof(elliptic_curve256_point_t));
        }
        else if (memcmp(&expected_public_key[0], &src_player_data.second.public_key.data[0], sizeof(elliptic_curve256_point_t)) != 0)
        {
            LOG_ERROR("Public key from player %" PRIu64 " is different from the key sent by player %" PRIu64, src_player_data.first, data.begin()->first);
            throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
        }
        else if (src_player_data.second.encrypted_shares.size() != 2)
        {
            LOG_ERROR("Incorrect encrypted shares size %u from player %" PRIu64, (uint32_t) src_player_data.second.encrypted_shares.size(), src_player_data.first);
            throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
        }
        
        const auto my_encrypted_share = src_player_data.second.encrypted_shares.find(my_player_id);
        if (my_encrypted_share == src_player_data.second.encrypted_shares.end())
        {
            LOG_ERROR("Player %" PRIu64 " didn't send share to me", src_player_data.first);
            throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
        }

        auto share = _platform_service.decrypt_message(my_encrypted_share->second);
        throw_cosigner_exception(algebra->add_scalars(algebra, &private_share.data, &private_share.data[0], sizeof(elliptic_curve256_scalar_t), (const uint8_t*)share.data(), share.size()));
    }
}

 void bam_ecdsa_cosigner::derive_and_compute_corrected_R(elliptic_curve256_algebra_ctx_t* algebra, 
                                                         const std::string& tx_id,
                                                         const bam_single_signature_data_base& signature_data, 
                                                         const elliptic_curve256_point_t& public_key, 
                                                         const client_partial_signature_data& partial_signature,
                                                         elliptic_curve256_point_t& derived_public_key,
                                                         elliptic_curve256_scalar_t& hash_shift,
                                                         elliptic_curve256_point_t& corrected_R)
{
    throw_cosigner_exception(algebra->generator_mul(algebra, &derived_public_key, &signature_data.derivation_delta));
    throw_cosigner_exception(algebra->add_points(algebra, &derived_public_key, &derived_public_key, &public_key));

    // recalculate shift in the same way the client did it to fix the signature
    compute_hash_shift(tx_id, signature_data.message, partial_signature.common_R, partial_signature.client_R, derived_public_key, hash_shift);
        
    // corrected_R = G^(k_client * hash_shift)
    throw_cosigner_exception(algebra->point_mul(algebra, &corrected_R, &partial_signature.client_R, &hash_shift));
    //compute the "R" of the signature by adding G^(k_client * k_server) + G^(k_client * hash_shift) = G^(k_client(k_server+ hash_shift))
    throw_cosigner_exception(algebra->add_points(algebra, &corrected_R, &corrected_R, &partial_signature.common_R));
}

}