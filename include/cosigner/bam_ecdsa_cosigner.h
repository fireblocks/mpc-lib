#pragma once
#include "cosigner_export.h"
#include "crypto/elliptic_curve_algebra/elliptic_curve256_algebra.h"
#include "crypto/commitments/pedersen.h"
#include "cosigner/types.h"
#include "cosigner/sign_algorithm.h"
#include "cosigner/cosigner_exception.h"
#include "cosigner/bam_key_persistency_common.h"
#include "../../src/common/crypto/zero_knowledge_proof/zkp_constants_internal.h"
#include <memory>
#include <cstdint>
#include <string>
#include <algorithm>
#include <map>

struct bignum_st; // for BIGNUM
struct bignum_ctx; //for BN_CTX

namespace fireblocks::common::cosigner
{
struct bam_single_signature_data_base;
class platform_service;

struct bam_signing_properties
{
    uint32_t flags { common::cosigner::NONE };
};
          
class COSIGNER_EXPORT bam_ecdsa_cosigner
{
public:
    struct cosigner_params
    {
        static constexpr const uint32_t PAILLIER_COMMITMENT_BITSIZE = 3072U;
        static constexpr const uint32_t TEMPORARY_DAMGARD_FUJISAKI_BITSIZE = 2048U; //client temporary key
        static constexpr const uint32_t OPTIMIZED_DAMGARD_FUJISAKI_CHALLENGE_BITSIZE = 40U;
        
        static constexpr const uint32_t ZKPOK_OPTIM_KAPPA_SIZE =    ::ZKPOK_OPTIM_KAPPA_SIZE();
        static constexpr const uint32_t ZKPOK_OPTIM_L_SIZE =        ::ZKPOK_OPTIM_L_SIZE(PAILLIER_COMMITMENT_BITSIZE);
        static constexpr const uint32_t ZKPOK_OPTIM_NU_SIZE =       ::ZKPOK_OPTIM_NU_SIZE(PAILLIER_COMMITMENT_BITSIZE);
        static constexpr const uint32_t ZKPOK_OPTIM_NLAMBDA_SIZE =  ::ZKPOK_OPTIM_NLAMBDA_SIZE(PAILLIER_COMMITMENT_BITSIZE);
        static constexpr const uint32_t ZKPOK_OPTIM_EPSILON_SIZE  = ::ZKPOK_OPTIM_EPSILON_SIZE(PAILLIER_COMMITMENT_BITSIZE);
        static constexpr const uint32_t ZKPOK_OPTIM_NX_SIZE =       ::ZKPOK_OPTIM_NX_SIZE(PAILLIER_COMMITMENT_BITSIZE);

        static constexpr const uint32_t ZKPOK_OPTIM_NA_SIZE =           (2 * ZKPOK_OPTIM_KAPPA_SIZE + 2 * ZKPOK_OPTIM_L_SIZE + 4 * ZKPOK_OPTIM_NU_SIZE);
        static constexpr const uint32_t ZKPOK_OPTIM_NB_SIZE =           (1 * ZKPOK_OPTIM_KAPPA_SIZE + 1 * ZKPOK_OPTIM_L_SIZE + 1 * ZKPOK_OPTIM_NU_SIZE);
        static constexpr const uint32_t ZKPOK_OPTIM_NLAMBDA0_SIZE_1 =   (1 * ZKPOK_OPTIM_NA_SIZE    + 2 * ZKPOK_OPTIM_L_SIZE + 1 * ZKPOK_OPTIM_NU_SIZE);
        static constexpr const uint32_t ZKPOK_OPTIM_NLAMBDA0_SIZE_2 =   (1 * ZKPOK_OPTIM_NB_SIZE    + 1 * ZKPOK_OPTIM_NLAMBDA_SIZE + 1 * ZKPOK_OPTIM_EPSILON_SIZE);
        static constexpr const uint32_t ZKPOK_OPTIM_NLAMBDA0_SIZE =     std::max(ZKPOK_OPTIM_NLAMBDA0_SIZE_1, ZKPOK_OPTIM_NLAMBDA0_SIZE_2) + ZKPOK_OPTIM_NU_SIZE;
    };

    struct server_setup_shared_data 
    {
        server_setup_shared_data() = default;

        template <typename T>
        server_setup_shared_data(const T& serialized) :
            paillier_commitment_pub(serialized.paillier_commitment_pub.begin(), serialized.paillier_commitment_pub.end()),
            paillier_blum_zkp(serialized.paillier_blum_zkp.begin(), serialized.paillier_blum_zkp.end()),
            small_factors_zkp(serialized.small_factors_zkp.begin(), serialized.small_factors_zkp.end()),
            damgard_fujisaki_zkp(serialized.damgard_fujisaki_zkp.begin(), serialized.damgard_fujisaki_zkp.end())
        {

        }

        //paillier commitment key and proofs
        byte_vector_t paillier_commitment_pub;
        byte_vector_t paillier_blum_zkp;
        byte_vector_t small_factors_zkp;
        byte_vector_t damgard_fujisaki_zkp;
    };

    //sent by the client to the server during key generation
    struct client_key_shared_data
    {
        client_key_shared_data() = default;

        template <typename T>
        client_key_shared_data(const T& serialized) :
            damgard_fujisaki_pub(serialized.damgard_fujisaki_pub.begin(), serialized.damgard_fujisaki_pub.end()),
            damgard_fujisaki_proof(serialized.damgard_fujisaki_proof.begin(), serialized.damgard_fujisaki_proof.end()),
            schnorr_proof(serialized.schnorr_proof.begin(), serialized.schnorr_proof.end())
        {
            if (serialized.X.size() != sizeof(elliptic_curve256_point_t))
            {
                throw cosigner_exception(cosigner_exception::INTERNAL_ERROR);    
            }
            memcpy(X, serialized.X.data(), sizeof(elliptic_curve256_point_t));
        }
            
        elliptic_curve256_point_t X;
        byte_vector_t damgard_fujisaki_pub;
        byte_vector_t damgard_fujisaki_proof;
        byte_vector_t schnorr_proof;
    };

    //sent by the server to the client during key generation
    struct server_key_shared_data
    {
        server_key_shared_data() = default;

        template <typename T>
        server_key_shared_data(const T& serialized) :
            encrypted_server_share(serialized.encrypted_server_share.begin(), serialized.encrypted_server_share.end()),
            enc_dlog_proof(serialized.enc_dlog_proof.begin(), serialized.enc_dlog_proof.end())
        {
            if (serialized.server_public_share.size() != sizeof(elliptic_curve256_point_t))
            {
                throw cosigner_exception(cosigner_exception::INTERNAL_ERROR);    
            }
            memcpy(server_public_share, serialized.server_public_share.data(), sizeof(elliptic_curve256_point_t));
        }

        elliptic_curve256_point_t server_public_share;
        byte_vector_t encrypted_server_share;
        byte_vector_t enc_dlog_proof;
    };

    //sent by the server to the client as 1st step of the signature
    struct server_signature_shared_data
    {
        server_signature_shared_data() = default;

        template <typename T>
        server_signature_shared_data(const T& serialized)
        {
            if (serialized.R.size() != sizeof(elliptic_curve256_point_t) || 
                serialized.Y.size() != sizeof(elliptic_curve256_point_t))
            {
                throw cosigner_exception(cosigner_exception::INTERNAL_ERROR);    
            }
            memcpy(R, serialized.R.data(), sizeof(elliptic_curve256_point_t));
            memcpy(Y, serialized.Y.data(), sizeof(elliptic_curve256_point_t));
        }

        elliptic_curve256_point_t R; //G^k of the server
        elliptic_curve256_point_t Y; //client's public_key^k as proof 
    };

    //sent by the client to the server as 2nd step of the signature
    struct client_partial_signature_data
    {
        client_partial_signature_data() = default;

        static constexpr size_t MAX_ENCRYPTED_PARTIAL_SIG_SIZE = 4096;
        static constexpr size_t MAX_SIG_PROOF_SIZE = 16384;

        template <typename T>
        client_partial_signature_data(const T& serialized) :
            encrypted_partial_sig(serialized.encrypted_partial_sig.begin(), serialized.encrypted_partial_sig.end()),
            sig_proof(serialized.sig_proof.begin(), serialized.sig_proof.end())
        {
           if (serialized.client_R.size() != sizeof(elliptic_curve256_point_t) ||
               serialized.common_R.size() != sizeof(elliptic_curve256_point_t))
            {
                throw cosigner_exception(cosigner_exception::INTERNAL_ERROR);
            }
            if (serialized.encrypted_partial_sig.size() > MAX_ENCRYPTED_PARTIAL_SIG_SIZE ||
                serialized.sig_proof.size() > MAX_SIG_PROOF_SIZE)
            {
                throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
            }
            memcpy(client_R, serialized.client_R.data(), sizeof(elliptic_curve256_point_t));
            memcpy(common_R, serialized.common_R.data(), sizeof(elliptic_curve256_point_t));
        }

        elliptic_curve256_point_t client_R; // this is the client's R = G^k_client - client's ephemeral key 
        elliptic_curve256_point_t common_R; // This is the common R which is G^(k_client*k_server). Proves that the client knows k_client
        byte_vector_t encrypted_partial_sig;
        byte_vector_t sig_proof;
    };
    

    struct generated_public_key
    {
        std::string pub_key;
        cosigner_sign_algorithm algorithm;
    };
    
    static  bool is_positive(const cosigner_sign_algorithm algorithm, const elliptic_curve256_scalar_t& n);
    static inline bool is_odd_point(const elliptic_curve256_point_t& p)
    {
        return (p[0] & 1) == 1;
    }

    static void make_sig_s_positive(const cosigner_sign_algorithm algorithm, const elliptic_curve256_algebra_ctx_t* algebra, recoverable_signature& sig);
    
    struct add_user_data
    {
        std::map<uint64_t, byte_vector_t> encrypted_shares;
        elliptic_curve_point public_key;
    };


protected:
    

    explicit bam_ecdsa_cosigner(platform_service& platform_service);

    virtual ~bam_ecdsa_cosigner() = default;

    std::vector<bam_signing_properties> fill_bam_signing_info_from_metadata(const std::string& metadata, const uint32_t blocks_num);
    
    
    //commitment to a specific key. 
    // Seed already contains key_id, client_id and server_id
    static void generate_key_commitment(const commitments_sha256_t& seed, 
                                        const elliptic_curve256_point_t& public_key, 
                                        commitments_sha256_t& B);

    byte_vector_t generate_setup_aad_bytes(const std::string& setup_id, const cosigner_sign_algorithm algorithm) const;
    static void generate_aad_for_key_gen(const std::string& key_id, const uint64_t client_id, const uint64_t server_id, commitments_sha256_t& key_aad);
    static void generate_aad_for_signature(const std::string& key_id, const uint64_t server_id, const uint64_t client_id, const std::string& tx_id, commitments_sha256_t& signature_add);

    static void check_non_null_message(const elliptic_curve256_scalar_t& message, const elliptic_curve256_algebra_ctx_t* algebra);
    static void check_a_valid_point(const elliptic_curve256_point_t& point, const elliptic_curve256_algebra_ctx_t* algebra);



    static void derive_and_compute_corrected_R(elliptic_curve256_algebra_ctx_t* algebra,
                                               const std::string& tx_id,
                                               const bam_single_signature_data_base& signature_data, 
                                               const elliptic_curve256_point_t& public_key, 
                                               const client_partial_signature_data& partial_signature,
                                               elliptic_curve256_point_t& derived_public_key,
                                               elliptic_curve256_scalar_t& hash_shift,
                                               elliptic_curve256_point_t& corrected_R);
                                                     
    static void bn_randomize_with_factor(struct bignum_st* res,  const struct bignum_st* base,  const struct bignum_st* factor, const uint32_t randomizer_bitlength);


    struct bignum_clear_deleter
    {
        void operator()(struct bignum_st* bn);
    };

    struct bignum_clear
    {
        void operator()(struct bignum_st* bn);
    };


    inline elliptic_curve256_algebra_ctx_t* get_algebra(cosigner_sign_algorithm algorithm) const 
    {
        return algorithm == ECDSA_SECP256K1 ? _secp256k1.get() : 
               algorithm == ECDSA_SECP256R1 ? _secp256r1.get() : 
               algorithm == ECDSA_STARK ? _stark.get() : 
               throw cosigner_exception(cosigner_exception::UNKNOWN_ALGORITHM);
    }

    void generate_private_share(const cosigner_sign_algorithm algorithm, elliptic_curve_scalar& private_share) const;
    void decrypt_and_rebuild_private_share(const uint64_t my_player_id, 
                           const cosigner_sign_algorithm algorithm, 
                           const std::map<uint64_t, add_user_data>& data, 
                           elliptic_curve_scalar& private_share,
                           elliptic_curve256_point_t& expected_public_key) const;



    static uint32_t signature_proof_size(const uint32_t paillier_commitment_n_bitsize);
    
    
    void validate_current_tenant_id(const std::string& tenant_id) const;
    void validate_tenant_id_setup(bam_key_persistency_common& persistency, const std::string& setup_id) const;

    template <class persistency_t, class key_metadata_t>
    cosigner_sign_algorithm get_public_key(const std::string& key_id, byte_vector_t& public_key, persistency_t& key_persistency)
    {
        key_metadata_t key_metadata;

        key_persistency.load_key_metadata(key_id, key_metadata);
        auto algebra = bam_ecdsa_cosigner::get_algebra(key_metadata.algorithm); // this is member function, so template cannot be statis
        public_key.assign(reinterpret_cast<const uint8_t *>(key_metadata.public_key), reinterpret_cast<const uint8_t *>(key_metadata.public_key) + algebra->point_size(algebra));
        return key_metadata.algorithm;
    }
    
    static void derivation_key_delta(const elliptic_curve256_algebra_ctx_t* algebra, 
                                     const elliptic_curve256_point_t& public_key, 
                                     const HDChaincode& chaincode, 
                                     const std::vector<uint32_t>& path,
                                     elliptic_curve256_scalar_t& delta);

    platform_service& _platform_service;
private:
    const std::unique_ptr<elliptic_curve256_algebra_ctx_t, void(*)(elliptic_curve256_algebra_ctx_t*)> _secp256k1;
    const std::unique_ptr<elliptic_curve256_algebra_ctx_t, void(*)(elliptic_curve256_algebra_ctx_t*)> _secp256r1;
    const std::unique_ptr<elliptic_curve256_algebra_ctx_t, void(*)(elliptic_curve256_algebra_ctx_t*)> _stark;

    static void compute_hash_shift(const std::string& tx_id, 
                                   const elliptic_curve256_scalar_t& hash_message, 
                                   const elliptic_curve256_point_t& ephemeral_common_key, 
                                   const elliptic_curve256_point_t& client_ephemeral_key, 
                                   const elliptic_curve256_point_t& public_key,
                                   elliptic_curve256_scalar_t &hash_shift);

};

} //namespace fireblocks::common::cosigner