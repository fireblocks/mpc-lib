#include <tests/catch.hpp>
#include "cosigner/bam_ecdsa_cosigner_client.h"
#include "cosigner/bam_ecdsa_cosigner_server.h"
#include "cosigner/bam_key_persistency_client.h"
#include "cosigner/bam_key_persistency_server.h"
#include "cosigner/bam_tx_persistency_server.h"
#include "cosigner/bam_tx_persistency_client.h"
#include "cosigner/platform_service.h"
#include "crypto/elliptic_curve_algebra/elliptic_curve256_algebra.h"
#include "crypto/GFp_curve_algebra/GFp_curve_algebra.h"
#include "blockchain/mpc/hd_derive.h"
#include "../../src/common/cosigner/utils.h"

#include <map>
#include <set>
#include <string>
#include <iostream>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/rand.h>
#include <uuid/uuid.h>
#include "crypto/paillier_commitment/paillier_commitment.h"
#include "crypto/commitments/damgard_fujisaki.h"
#ifndef UUID_STR_LEN
#define UUID_STR_LEN 37
#endif

namespace fbc = fireblocks::common::cosigner;

static const constexpr uint64_t server_id = 3213454843;
static const constexpr uint64_t client_id = 45234523;

static std::string get_tenant_id()
{
    static std::string _tenant_id;
    if (_tenant_id.size() == 0)
    {
        uuid_t uid;
        _tenant_id.resize(UUID_STR_LEN);
        uuid_generate_random(uid);
        uuid_unparse(uid, _tenant_id.data());
    }

    return _tenant_id;
}

template <class KeyMetadataType, class TempDataType>
class test_bam_key_persistency
{
public:
    bool key_exist(const std::string& key_id) const
    {
        return _keyStore.count(key_id) != 0;
    }

    void store_key(const std::string& key_id, const cosigner_sign_algorithm algorithm,  const elliptic_curve256_scalar_t& private_key)
    {
        _keyStore[key_id].first = algorithm;
        memcpy(_keyStore[key_id].second, private_key, sizeof(elliptic_curve256_scalar_t));
    }

    void load_key(const std::string& key_id, cosigner_sign_algorithm& algorithm, elliptic_curve256_scalar_t& private_key) const
    {
        const auto it = _keyStore.find(key_id);
        if (it == _keyStore.end())
        {
            throw fbc::cosigner_exception(fbc::cosigner_exception::BAD_KEY);
        }


        memcpy(private_key, it->second.second, sizeof(elliptic_curve256_scalar_t));
        algorithm = it->second.first;
    }

    void store_key_metadata(const std::string& key_id, const KeyMetadataType& metadata, const bool overwrite)
    {
        auto it = _metadata_store.find(key_id);
        if (it != _metadata_store.end())
        {
            if (!overwrite)
            {
                throw fbc::cosigner_exception(fbc::cosigner_exception::BAD_KEY);
            }
            it->second = metadata;
        }
        else
        {
            _metadata_store[key_id] = metadata;
        }
    }
    void load_key_metadata(const std::string& key_id, KeyMetadataType& metadata) const
    {
        const auto it = _metadata_store.find(key_id);
        if (it == _metadata_store.end())
        {
            throw fbc::cosigner_exception(fbc::cosigner_exception::BAD_KEY);
        }
        metadata = it->second;
    }

    void store_temp_data(const std::string& key_id, const TempDataType& data)
    {
        auto it = _temp_data.find(key_id);
        if (it != _temp_data.end())
        {
            throw fbc::cosigner_exception(fbc::cosigner_exception::BAD_KEY);
        }
        else
        {
            if constexpr (std::is_array_v<TempDataType>) // For fixed-size arrays like uint8_t[32]
            {
                memcpy(_temp_data[key_id], data, sizeof(TempDataType));
            }
            else
            {
                _temp_data[key_id] = data;  // For structs like bam_signature_metadata_server
            }
        }
    }

    void load_and_delete_temp_data(const std::string& key_id, TempDataType& data)
    {
        auto it = _temp_data.find(key_id);
        if (it == _temp_data.end())
        {
            throw fbc::cosigner_exception(fbc::cosigner_exception::BAD_KEY);
        }

        if constexpr (std::is_array_v<TempDataType>)  // If it's a fixed-size array
        {
            memcpy(data, it->second, sizeof(TempDataType));
        }
        else  // If it's a complex structure
        {
            data = it->second;
        }

        _temp_data.erase(it);
    }

    void store_tenant_id_for_setup(const std::string& setup_id, const std::string& tenant_id)
    {
        _setup_tenant[setup_id] = tenant_id;
    }
    void load_tenant_id_for_setup(const std::string& setup_id, std::string& tenant_id) const
    {
        const auto it = _setup_tenant.find(setup_id);
        if (it == _setup_tenant.end())
        {
            throw fbc::cosigner_exception(fbc::cosigner_exception::BAD_KEY);
        }
        tenant_id = it->second;
    }


private:

    std::map<std::string, std::pair<cosigner_sign_algorithm, elliptic_curve256_scalar_t>> _keyStore;
    std::map<std::string, KeyMetadataType> _metadata_store;
    std::map<std::string, TempDataType> _temp_data;
    std::map<std::string, std::string> _setup_tenant;
};

class test_bam_key_persistency_client : public fbc::bam_key_persistency_client, public fbc::bam_tx_persistency_client
{
public:

    virtual ~test_bam_key_persistency_client()  = default;

    virtual void store_tenant_id_for_setup(const std::string& setup_id, const std::string& tenant_id) override
    {
        _store.store_tenant_id_for_setup(setup_id, tenant_id);
    }
    virtual void load_tenant_id_for_setup(const std::string& setup_id, std::string& tenant_id) const override
    {
        _store.load_tenant_id_for_setup(setup_id, tenant_id);
    }

    virtual void store_key(const std::string& key_id, const cosigner_sign_algorithm algorithm,  const elliptic_curve256_scalar_t& private_key) override
    {
        _store.store_key(key_id, algorithm, private_key);
    }

    virtual void load_key(const std::string& key_id, cosigner_sign_algorithm& algorithm, elliptic_curve256_scalar_t& private_key) const override
    {
        _store.load_key(key_id, algorithm, private_key);
    }

    virtual void store_key_metadata(const std::string& key_id, const fbc::bam_key_metadata_client& metadata, const bool overwrite) override
    {
        _store.store_key_metadata(key_id, metadata, overwrite);
    }

    virtual void load_key_metadata(const std::string& key_id, fbc::bam_key_metadata_client& metadata) const override
    {
        _store.load_key_metadata(key_id, metadata);
    }

    virtual void store_key_temp_data(const std::string& key_id, const fbc::bam_temp_key_data_client& auxilary_key_client) override
    {
        _store.store_temp_data(key_id, auxilary_key_client);
    }

    virtual void load_key_temp_data_and_delete(const std::string& key_id, fbc::bam_temp_key_data_client& auxilary_key_client) override
    {
        _store.load_and_delete_temp_data(key_id, auxilary_key_client);
    }
    virtual void store_signature_data(const std::string& tx_id, const fbc::bam_client_signature_data& signature_data) override
    {
        const std::string data_key = "txid_" + tx_id;

        auto it = _sig_data.find(data_key);
        if (it != _sig_data.end())
        {
            throw fbc::cosigner_exception(fbc::cosigner_exception::BAD_KEY);
        }
        else
        {
            _sig_data[data_key] = signature_data;
        }
    }
    virtual void load_signature_data_and_delete(const std::string& tx_id, fbc::bam_client_signature_data& signature_data) override
    {
        const std::string data_key = "txid_" + tx_id;
        auto it = _sig_data.find(data_key);
        if (it == _sig_data.end())
        {
            throw fbc::cosigner_exception(fbc::cosigner_exception::BAD_KEY);
        }
        signature_data = it->second;
        _sig_data.erase(it);
    }
    virtual bool delete_temporary_tx_data(const std::string& tx_id) override { return true; }
    virtual bool delete_temporary_key_data(const std::string& key_id) override { return true; }
    virtual bool delete_key_data(const std::string& key_id) override{ return true; }
    virtual bool delete_setup_data(const std::string& setup_id) override { return true; }
    virtual bool backup_key(const std::string&) const override { return true; }

private:
    test_bam_key_persistency<fbc::bam_key_metadata_client, fbc::bam_temp_key_data_client> _store;
    std::map<std::string, fbc::bam_client_signature_data> _sig_data;
};


class test_bam_key_persistency_server : public fbc::bam_key_persistency_server, public fbc::bam_tx_persistency_server
{
public:

    virtual ~test_bam_key_persistency_server()  = default;

    virtual void store_tenant_id_for_setup(const std::string& setup_id, const std::string& tenant_id) override
    {
        _store.store_tenant_id_for_setup(setup_id, tenant_id);
    }
    virtual void load_tenant_id_for_setup(const std::string& setup_id, std::string& tenant_id) const override
    {
        _store.load_tenant_id_for_setup(setup_id, tenant_id);
    }

    virtual void store_key(const std::string& key_id, const cosigner_sign_algorithm algorithm,  const elliptic_curve256_scalar_t& private_key) override
    {
        _store.store_key(key_id, algorithm, private_key);
    }

    virtual void load_key(const std::string& key_id, cosigner_sign_algorithm& algorithm, elliptic_curve256_scalar_t& private_key) const override
    {
        _store.load_key(key_id, algorithm, private_key);
    }

    virtual void store_key_metadata(const std::string& key_id, const fbc::bam_key_metadata_server& metadata, const bool overwrite) override
    {
        _store.store_key_metadata(key_id, metadata, overwrite);
    }

    virtual void load_key_metadata(const std::string& key_id, fbc::bam_key_metadata_server& metadata) const override
    {
        _store.load_key_metadata(key_id, metadata);
    }

    void store_signature_data(const std::string& tx_id, const std::shared_ptr<fbc::bam_server_signature_data>& signature_data) override
    {
        _store.store_temp_data("txid_" + tx_id, *signature_data);
    }

    std::shared_ptr<fbc::bam_server_signature_data> load_signature_data_and_delete(const std::string& tx_id) override
    {
        auto signature_data_ptr = std::make_shared<fbc::bam_server_signature_data>();
        auto &signature_data = *signature_data_ptr;
        _store.load_and_delete_temp_data("txid_" + tx_id, signature_data);
        return signature_data_ptr;
    }
    virtual bool delete_temporary_tx_data(const std::string& tx_id) override { return true; }
    virtual bool delete_temporary_key_data(const std::string& key_id) override { return true; }
    virtual bool delete_key_data(const std::string& key_id) override { return true; }
    virtual bool delete_setup_data(const std::string& setup_id) override { return true; }

    virtual void store_setup_auxilary_key(const std::string& setup_id,  const fbc::bam_setup_auxilary_key_server& setup_aux_key) override
    {
        auto it = _setup_aux_key_map.find(setup_id);
        if (it != _setup_aux_key_map.end())
        {
            throw fbc::cosigner_exception(fbc::cosigner_exception::BAD_KEY);
        }
        else
        {
            _setup_aux_key_map[setup_id] = setup_aux_key;
        }

    }

    void load_setup_auxilary_key(const std::string& setup_id, fbc::bam_setup_auxilary_key_server& setup_aux_key) const override
    {
        const auto it = _setup_aux_key_map.find(setup_id);
        if (it == _setup_aux_key_map.end())
        {
            throw fbc::cosigner_exception(fbc::cosigner_exception::BAD_KEY);
        }
        setup_aux_key = it->second;
    }

    virtual void store_setup_metadata(const std::string& setup_id,  const fbc::bam_setup_metadata_server& setup_metadata) override
    {
        auto it = _setup_metadata.find(setup_id);
        if (it != _setup_metadata.end())
        {
            throw fbc::cosigner_exception(fbc::cosigner_exception::BAD_KEY);
        }
        else
        {
            _setup_metadata[setup_id] = setup_metadata;
        }
    }
    virtual void load_setup_metadata(const std::string& setup_id, fbc::bam_setup_metadata_server& setup_metadata) const override
    {
        const auto it = _setup_metadata.find(setup_id);
        if (it == _setup_metadata.end())
        {
            throw fbc::cosigner_exception(fbc::cosigner_exception::BAD_KEY);
        }
        setup_metadata = it->second;
    }

    virtual bool backup_key(const std::string& key_id) const override { return true; }

private:
    test_bam_key_persistency<fbc::bam_key_metadata_server, fbc::bam_server_signature_data> _store;
    std::map<std::string, fbc::bam_setup_auxilary_key_server> _setup_aux_key_map;
    std::map<std::string, fbc::bam_setup_metadata_server> _setup_metadata;
};


class test_bam_platform_service : public fbc::platform_service
{
public:
    ~test_bam_platform_service() = default;
    void gen_random(size_t len, uint8_t* random_data) const override
    {
        RAND_bytes(random_data, len);
    }
    bool backup_key(const std::string& key_id, cosigner_sign_algorithm algorithm, const elliptic_curve256_scalar_t& private_key, const fbc::cmp_key_metadata& metadata, const fbc::auxiliary_keys& aux) override {return true;}

    void derive_initial_share(const fbc::share_derivation_args& derive_from, cosigner_sign_algorithm algorithm, elliptic_curve256_scalar_t* key) const override {assert(0);}
    void on_start_signing(const std::string& key_id, const std::string& txid, const fbc::signing_data& data, const std::string& metadata_json, const std::set<std::string>& players, const signing_type signature_type) override {};
    bool is_client_id(uint64_t player_id) const override {return false;}
    virtual const std::string get_current_tenantid() const override
    {
        return get_tenant_id();
    }

    virtual uint64_t get_id_from_keyid(const std::string& key_id) const override
    {
        return 0;
    }

    virtual void fill_signing_info_from_metadata(const std::string& metadata, std::vector<uint32_t>& flags) const override
    {
        if (metadata != "")
        {
            flags[0] = fbc::POSITIVE_R;
        }
    }
    void fill_eddsa_signing_info_from_metadata(std::vector<fbc::eddsa_signature_data>& info, const std::string& metadata) const override
    {
        // Stub for tests
    }
    
    void fill_bam_signing_info_from_metadata(std::vector<fbc::bam_signing_properties>& info, const std::string& metadata) const override
    {
        if (metadata != "")
        {
            for (auto& sig : info)
                sig.flags = fbc::POSITIVE_R;
        }
    }
    virtual fbc::byte_vector_t encrypt_for_player(const uint64_t id, const fbc::byte_vector_t& data, const std::optional<std::string>& verify_modulus = std::nullopt) const override { return data; }
    virtual fbc::byte_vector_t decrypt_message(const fbc::byte_vector_t& encrypted_data) const override { return encrypted_data; }
    virtual void prepare_for_signing(const std::string& key_id, const std::string tx_id) override {};
    virtual void mark_key_setup_in_progress(const std::string& key_id) const override {};
    virtual void clear_key_setup_in_progress(const std::string& key_id) const override {};

};

void bam_key_generation(const std::string& setup_id,
                        const std::string& key_id,
                        uint64_t client_id,
                        uint64_t server_id,
                        fbc::bam_ecdsa_cosigner_server& server,
                        fbc::bam_ecdsa_cosigner_client& client,
                        const cosigner_sign_algorithm algorithm,
                        elliptic_curve256_point_t& client_share,
                        elliptic_curve256_point_t& server_share)
{
    fbc::bam_ecdsa_cosigner::client_key_shared_data client_message;
    fbc::bam_ecdsa_cosigner::server_key_shared_data server_message;
    fbc::bam_ecdsa_cosigner::generated_public_key generated_public_key;

    // Step 1.
    commitments_sha256_t B;
    fbc::bam_ecdsa_cosigner::server_setup_shared_data setup;


    REQUIRE_NOTHROW(server.generate_setup_with_proof(setup_id, get_tenant_id(), algorithm, setup));

    REQUIRE_NOTHROW(client.start_new_key_generation(setup_id, key_id, get_tenant_id(), server_id, client_id, algorithm));
    REQUIRE_NOTHROW(server.generate_share_and_commit(setup_id, key_id, server_id, client_id, algorithm, B));

    // Step 2.
    REQUIRE_NOTHROW(client.verify_setup_proof_store_key_commitment_generate_key_proof(setup_id, key_id, server_id, setup, B, client_message));

    // Step 3.
    REQUIRE_NOTHROW(server.verify_client_proofs_and_decommit_share_with_proof(key_id, client_id, client_message, server_message));

    // Step 4.
    REQUIRE_NOTHROW(client.verify_key_decommitment_and_proofs(key_id, server_id, client_id, server_message, generated_public_key));

    // return public key
    memcpy(client_share, client_message.X, sizeof(elliptic_curve256_point_t));
    memcpy(server_share, server_message.server_public_share, sizeof(elliptic_curve256_point_t));
}

void bam_key_sign(const std::string& setup_id,
                  const std::string& key_id,
                  const std::string& tx_id,
                  const uint64_t client_id,
                  const fbc::signing_data& data_to_sign,
                  const std::string& metadata,
                  fbc::bam_ecdsa_cosigner_server& server,
                  fbc::bam_ecdsa_cosigner_client& client,
                  fbc::recoverable_signature& full_signature,
                  const cosigner_sign_algorithm algorithm)
{
    std::vector<fbc::bam_ecdsa_cosigner::server_signature_shared_data> server_shares;
    std::vector<fbc::bam_ecdsa_cosigner::client_partial_signature_data> partial_signatures;
    std::vector<fbc::recoverable_signature> full_signatures;
    cosigner_sign_algorithm signature_algorithm;

    REQUIRE_NOTHROW(client.prepare_for_signature(key_id, tx_id, 0, server_id, client_id, data_to_sign, metadata, std::set<std::string>()));
    REQUIRE_NOTHROW(server.generate_signature_share(key_id, tx_id, 0, server_id, client_id, algorithm, data_to_sign, metadata, std::set<std::string>(), server_shares));
    REQUIRE_NOTHROW(client.compute_partial_signature(tx_id, server_shares, partial_signatures));
    REQUIRE_NOTHROW(server.verify_partial_signature_and_output_signature(tx_id, client_id, partial_signatures, full_signatures, signature_algorithm));
    REQUIRE(signature_algorithm == algorithm);
    memcpy(&full_signature, &full_signatures[0], sizeof(fbc::recoverable_signature));
}


void verify_ecdsa_signature(const cosigner_sign_algorithm algorithm,
                            const elliptic_curve256_point_t& X1,
                            const elliptic_curve256_point_t& X2,
                            const fbc::recoverable_signature& signature,
                            const fbc::signing_data& data_to_sign,
                            const bool isPositiveR)
{
    elliptic_curve256_algebra_ctx_t *ctx = NULL;

    // Initialize context based on the curve specified by algorithm
    switch (algorithm) {
        case ECDSA_SECP256K1:
            ctx = elliptic_curve256_new_secp256k1_algebra();
            break;
        case ECDSA_SECP256R1:
            ctx = elliptic_curve256_new_secp256r1_algebra();
            break;
        case ECDSA_STARK:
            ctx = elliptic_curve256_new_stark_algebra();
            break;
        default:
            throw std::runtime_error("unsupported algorithm");  // Unsupported algorithm
    }

    if (!ctx)
    {
        throw std::runtime_error("Failed to initialize context");
    }

    // Declare necessary variables
    elliptic_curve256_scalar_t s_inv;
    elliptic_curve256_scalar_t u1;
    elliptic_curve256_scalar_t u2;
    elliptic_curve256_point_t U1, U2;
    elliptic_curve256_point_t R;
    elliptic_curve256_scalar_t r;
    elliptic_curve256_point_t X;

    REQUIRE(ELLIPTIC_CURVE_ALGEBRA_SUCCESS == ctx->add_points(ctx, &X, &X1, &X2));


    REQUIRE(HD_DERIVE_SUCCESS == derive_public_key_generic(ctx, X, X, data_to_sign.chaincode, &data_to_sign.blocks[0].path[0], (uint32_t)data_to_sign.blocks[0].path.size()));

    // Step 1: Calculate s_inv, the modular inverse of signature.s
    REQUIRE(ELLIPTIC_CURVE_ALGEBRA_SUCCESS == ctx->inverse(ctx, &s_inv, &signature.s));

    // Step 2: Calculate u1 = (hash * s_inv) mod n
    REQUIRE(ELLIPTIC_CURVE_ALGEBRA_SUCCESS == ctx->mul_scalars(ctx, &u1, data_to_sign.blocks[0].data.data(), data_to_sign.blocks[0].data.size(), s_inv, sizeof(elliptic_curve256_scalar_t)));

    // Step 3: Calculate u2 = (signature.r * s_inv) mod n
    REQUIRE(ELLIPTIC_CURVE_ALGEBRA_SUCCESS == ctx->mul_scalars(ctx, &u2, signature.r, sizeof(elliptic_curve256_scalar_t), s_inv, sizeof(elliptic_curve256_scalar_t)));

   // Step 4: Calculate U2 = u2 * G (generator multiplication)
    REQUIRE(ELLIPTIC_CURVE_ALGEBRA_SUCCESS == ctx->generator_mul(ctx, &U1, &u1));

    // Step 5: Calculate U1 = u1 * Q (public key multiplication)
    REQUIRE(ELLIPTIC_CURVE_ALGEBRA_SUCCESS == ctx->point_mul(ctx, &U2, &X, &u2));

    // Step 6: Calculate R = U1 + U2
    REQUIRE(ELLIPTIC_CURVE_ALGEBRA_SUCCESS == ctx->add_points(ctx, &R, &U1, &U2));

    // Step 7: Extract the x-coordinate of R and compare it with signature.r
    REQUIRE(ELLIPTIC_CURVE_ALGEBRA_SUCCESS == GFp_curve_algebra_get_point_projection((const GFp_curve_algebra_ctx_t *)ctx->ctx, &r, &R, NULL));

    const uint8_t* message = data_to_sign.blocks[0].data.data();

    REQUIRE(ELLIPTIC_CURVE_ALGEBRA_SUCCESS == GFp_curve_algebra_verify_signature((const GFp_curve_algebra_ctx_t *)ctx->ctx, &X, reinterpret_cast<const elliptic_curve256_scalar_t*>(message), &signature.r, &signature.s));

    REQUIRE(memcmp(signature.r, r, sizeof(elliptic_curve256_scalar_t)) == 0);

    if (isPositiveR)
    {
        REQUIRE(fbc::bam_ecdsa_cosigner::is_positive(algorithm, signature.r));
    }

    // Clean up context
    elliptic_curve256_algebra_ctx_free(ctx);
}


std::ostream& operator<<(std::ostream& os, const fbc::bam_ecdsa_cosigner::client_key_shared_data& data)
{
    os << "client_key_shared_data {"
       << "\n  X: " << fbc::HexStr(std::begin(data.X), std::end(data.X))
       << "\n  damgard_fujisaki_pub: " << fbc::HexStr(data.damgard_fujisaki_pub.begin(), data.damgard_fujisaki_pub.end())
       << "\n  damgard_fujisaki_proof: " << fbc::HexStr(data.damgard_fujisaki_proof.begin(), data.damgard_fujisaki_proof.end())
       << "\n  schnorr_proof: " << fbc::HexStr(data.schnorr_proof.begin(), data.schnorr_proof.end())
       << "\n}";
    return os;
}


std::ostream& operator<<(std::ostream& os, const fbc::bam_ecdsa_cosigner::server_key_shared_data& data) {
    os << "server_key_shared_data {"
       << "\n  server_public_share: " << fbc::HexStr(std::begin(data.server_public_share), std::end(data.server_public_share))
       << "\n  encrypted_server_share: " << fbc::HexStr(data.encrypted_server_share.begin(), data.encrypted_server_share.end())
       << "\n  enc_dlog_proof: " << fbc::HexStr(data.enc_dlog_proof.begin(), data.enc_dlog_proof.end())
       << "\n}";
    return os;
}


struct TestSetup
{
    test_bam_key_persistency_client persistencyClient;
    test_bam_key_persistency_server persistencyServer;
    test_bam_platform_service platform;
    fbc::bam_ecdsa_cosigner_server server{ platform, persistencyServer, persistencyServer};
    fbc::bam_ecdsa_cosigner_client client{ platform, persistencyClient, persistencyClient};
};

TEST_CASE("bam_ecdsa")
{
    uuid_t ecdsa_keyid_uid ;

    SECTION("embedded cosigner secp256k1")
    {
        TestSetup testSetup;
        uuid_t uid;
        char keyid[UUID_STR_LEN] = {'\0'};
        char txid[UUID_STR_LEN] = {'\0'};
        fbc::byte_vector_t chaincode(32, '\0');
        const std::string setup_id(keyid);

        uuid_generate_random(uid);
        uuid_unparse(uid, keyid);
        uuid_generate_random(uid);
        uuid_unparse(uid, txid);

        elliptic_curve256_scalar_t hash;
        REQUIRE(RAND_bytes(hash, sizeof(hash)));

        elliptic_curve256_point_t X1, X2;

        bam_key_generation(setup_id, keyid, client_id, server_id, testSetup.server, testSetup.client, ECDSA_SECP256K1, X1, X2);
        fbc::recoverable_signature signature { 0 };

        fbc::signing_data data_to_sign = {{0}, {{ fbc::byte_vector_t(&hash[0], &hash[sizeof(hash)]), { 44, 0, 0, 0, 0} }}};
        bam_key_sign(setup_id, keyid, txid, client_id, data_to_sign, "", testSetup.server, testSetup.client, signature, ECDSA_SECP256K1);
        verify_ecdsa_signature(ECDSA_SECP256K1, X1, X2, signature, data_to_sign, false);
    }

    SECTION("attack: server sends alternative infinity R (secp256k1)") 
    {
        TestSetup testSetup;
        uuid_t uid;
        char keyid[UUID_STR_LEN] = {'\0'};
        char txid[UUID_STR_LEN] = {'\0'};
        const std::string setup_id(keyid);

        uuid_generate_random(uid);
        uuid_unparse(uid, keyid);
        uuid_generate_random(uid);
        uuid_unparse(uid, txid);

        elliptic_curve256_scalar_t hash;
        REQUIRE(RAND_bytes(hash, sizeof(hash)));

        elliptic_curve256_point_t X1, X2;
        bam_key_generation(setup_id, keyid, client_id, server_id, testSetup.server, testSetup.client, ECDSA_SECP256K1, X1, X2);

        fbc::signing_data data_to_sign = {{0}, {{ fbc::byte_vector_t(&hash[0], &hash[sizeof(hash)]), { 44, 0, 0, 0, 0} }}};

        std::vector<fbc::bam_ecdsa_cosigner::server_signature_shared_data> server_shares;
        std::vector<fbc::bam_ecdsa_cosigner::client_partial_signature_data> partial_signatures;

        REQUIRE_NOTHROW(testSetup.client.prepare_for_signature(keyid, txid, 0, server_id, client_id, data_to_sign, "", std::set<std::string>()));
        REQUIRE_NOTHROW(testSetup.server.generate_signature_share(keyid, txid, 0, server_id, client_id, ECDSA_SECP256K1, data_to_sign, "", std::set<std::string>(), server_shares));
        REQUIRE(server_shares.size() == 1);

        // Craft an "alternate infinity" encoding for GFp curves:
        // For these curves, the underlying algebra parses any encoding whose first byte is 0x00 as infinity,
        // ignoring the remaining bytes. The current BAM check compares against all-zero 33 bytes, so we set
        // the first byte to 0x00 (infinity) but poison another byte to bypass memcmp().
        memset(server_shares[0].R, 0, sizeof(elliptic_curve256_point_t));
        server_shares[0].R[0] = 0x00;    // infinity marker
        server_shares[0].R[1] = 0x01;    // poison: bypasses memcmp() against canonical infinity

        // Keep Y consistent with how the algebra will canonicalize infinity internally (all-zero encoding).
        memset(server_shares[0].Y, 0, sizeof(elliptic_curve256_point_t));

        // Security expectation: the client MUST reject infinity (in any representation).
        REQUIRE_THROWS(testSetup.client.compute_partial_signature(txid, server_shares, partial_signatures));
    }

    // Symmetric variant: malicious client sends alternative encoding of infinity in client_R.
    SECTION("attack: client sends alternative infinity client_R (secp256k1)")
    {
        TestSetup testSetup;
        uuid_t uid;
        char keyid[UUID_STR_LEN] = {'\0'};
        char txid[UUID_STR_LEN] = {'\0'};
        const std::string setup_id(keyid);

        uuid_generate_random(uid);
        uuid_unparse(uid, keyid);
        uuid_generate_random(uid);
        uuid_unparse(uid, txid);

        elliptic_curve256_scalar_t hash;
        REQUIRE(RAND_bytes(hash, sizeof(hash)));

        elliptic_curve256_point_t X1, X2;
        bam_key_generation(setup_id, keyid, client_id, server_id, testSetup.server, testSetup.client, ECDSA_SECP256K1, X1, X2);

        fbc::signing_data data_to_sign = {{0}, {{ fbc::byte_vector_t(&hash[0], &hash[sizeof(hash)]), { 44, 0, 0, 0, 0} }}};

        std::vector<fbc::bam_ecdsa_cosigner::server_signature_shared_data> server_shares;
        std::vector<fbc::bam_ecdsa_cosigner::client_partial_signature_data> partial_signatures;
        std::vector<fbc::recoverable_signature> full_signatures;
        cosigner_sign_algorithm signature_algorithm;

        REQUIRE_NOTHROW(testSetup.client.prepare_for_signature(keyid, txid, 0, server_id, client_id, data_to_sign, "", std::set<std::string>()));
        REQUIRE_NOTHROW(testSetup.server.generate_signature_share(keyid, txid, 0, server_id, client_id, ECDSA_SECP256K1, data_to_sign, "", std::set<std::string>(), server_shares));
        REQUIRE_NOTHROW(testSetup.client.compute_partial_signature(txid, server_shares, partial_signatures));
        REQUIRE(partial_signatures.size() == 1);

        // Alternate infinity encoding for GFp curves: first byte 0x00 is infinity, remaining bytes are ignored by parsing.
        // Poison a byte to bypass old memcmp()-against-canonical check.
        memset(partial_signatures[0].client_R, 0, sizeof(elliptic_curve256_point_t));
        partial_signatures[0].client_R[0] = 0x00;
        partial_signatures[0].client_R[1] = 0x01;
        memset(partial_signatures[0].common_R, 0, sizeof(elliptic_curve256_point_t));

        REQUIRE_THROWS(testSetup.server.verify_partial_signature_and_output_signature(txid, client_id, partial_signatures, full_signatures, signature_algorithm));
    }

    // Nonce-reuse regression: ensure the client does not reuse its ephemeral client_R across two signing sessions.
    SECTION("regression: client must not reuse client_R across sessions (secp256k1)")
    {
        TestSetup testSetup;
        uuid_t uid;
        char keyid[UUID_STR_LEN] = {'\0'};
        char txid1[UUID_STR_LEN] = {'\0'};
        char txid2[UUID_STR_LEN] = {'\0'};
        const std::string setup_id(keyid);

        uuid_generate_random(uid);
        uuid_unparse(uid, keyid);
        uuid_generate_random(uid);
        uuid_unparse(uid, txid1);
        uuid_generate_random(uid);
        uuid_unparse(uid, txid2);

        elliptic_curve256_scalar_t hash1, hash2;
        REQUIRE(RAND_bytes(hash1, sizeof(hash1)));
        REQUIRE(RAND_bytes(hash2, sizeof(hash2)));

        elliptic_curve256_point_t X1, X2;
        bam_key_generation(setup_id, keyid, client_id, server_id, testSetup.server, testSetup.client, ECDSA_SECP256K1, X1, X2);

        fbc::signing_data data1 = {{0}, {{ fbc::byte_vector_t(&hash1[0], &hash1[sizeof(hash1)]), { 44, 0, 0, 0, 0} }}};
        fbc::signing_data data2 = {{0}, {{ fbc::byte_vector_t(&hash2[0], &hash2[sizeof(hash2)]), { 44, 0, 0, 0, 0} }}};

        std::vector<fbc::bam_ecdsa_cosigner::server_signature_shared_data> server_shares1, server_shares2;
        std::vector<fbc::bam_ecdsa_cosigner::client_partial_signature_data> partial1, partial2;

        REQUIRE_NOTHROW(testSetup.client.prepare_for_signature(keyid, txid1, 0, server_id, client_id, data1, "", std::set<std::string>()));
        REQUIRE_NOTHROW(testSetup.server.generate_signature_share(keyid, txid1, 0, server_id, client_id, ECDSA_SECP256K1, data1, "", std::set<std::string>(), server_shares1));
        REQUIRE_NOTHROW(testSetup.client.compute_partial_signature(txid1, server_shares1, partial1));
        REQUIRE(partial1.size() == 1);

        REQUIRE_NOTHROW(testSetup.client.prepare_for_signature(keyid, txid2, 0, server_id, client_id, data2, "", std::set<std::string>()));
        REQUIRE_NOTHROW(testSetup.server.generate_signature_share(keyid, txid2, 0, server_id, client_id, ECDSA_SECP256K1, data2, "", std::set<std::string>(), server_shares2));
        REQUIRE_NOTHROW(testSetup.client.compute_partial_signature(txid2, server_shares2, partial2));
        REQUIRE(partial2.size() == 1);

        REQUIRE(memcmp(partial1[0].client_R, partial2[0].client_R, sizeof(elliptic_curve256_point_t)) != 0);
    }
    
    SECTION("embedded cosigner stark")
    {
        TestSetup testSetup;
        uuid_t uid;
        char keyid[UUID_STR_LEN] = {'\0'};
        char txid[UUID_STR_LEN] = {'\0'};
        fbc::byte_vector_t chaincode(32, '\0');
        const std::string setup_id(keyid);
        elliptic_curve256_point_t X1, X2;
        fbc::recoverable_signature signature;

        uuid_generate_random(uid);
        uuid_unparse(uid, keyid);
        uuid_generate_random(uid);
        uuid_unparse(uid, txid);

        elliptic_curve256_scalar_t hash;
        REQUIRE(RAND_bytes(hash, sizeof(hash)));

        bam_key_generation(setup_id, keyid, client_id, server_id, testSetup.server, testSetup.client, ECDSA_STARK, X1, X2);
        fbc::signing_data data_to_sign = {{0}, {{ fbc::byte_vector_t(&hash[0], &hash[sizeof(hash)]), { 44, 0, 0, 0, 0} }}};
        const std::string sign_metadata = "{ \"signInfo\":[{\"positiveR\":true}]}";
        bam_key_sign(setup_id, keyid, txid, client_id, data_to_sign, sign_metadata, testSetup.server, testSetup.client, signature, ECDSA_STARK);
        verify_ecdsa_signature(ECDSA_STARK, X1, X2, signature, data_to_sign, true);
    }

    // Attack: replay setup proof from one setup_id to a different setup_id (AAD mismatch).
    // The setup proof is bound to the setup_id via AAD, so replaying to a different setup_id must fail.
    SECTION("attack: setup proof replay to different setup_id")
    {
        TestSetup testSetup;
        uuid_t uid;
        char setup_id1_buf[UUID_STR_LEN] = {'\0'};
        char setup_id2_buf[UUID_STR_LEN] = {'\0'};
        char keyid[UUID_STR_LEN] = {'\0'};

        uuid_generate_random(uid);
        uuid_unparse(uid, setup_id1_buf);
        uuid_generate_random(uid);
        uuid_unparse(uid, setup_id2_buf);
        uuid_generate_random(uid);
        uuid_unparse(uid, keyid);

        const std::string setup_id1(setup_id1_buf);
        const std::string setup_id2(setup_id2_buf);

        // Generate setup proof for setup_id1
        fbc::bam_ecdsa_cosigner::server_setup_shared_data setup1;
        REQUIRE_NOTHROW(testSetup.server.generate_setup_with_proof(setup_id1, get_tenant_id(), ECDSA_SECP256K1, setup1));

        // Generate a second setup for setup_id2 (so it exists on server side)
        fbc::bam_ecdsa_cosigner::server_setup_shared_data setup2;
        REQUIRE_NOTHROW(testSetup.server.generate_setup_with_proof(setup_id2, get_tenant_id(), ECDSA_SECP256K1, setup2));

        // Client starts key gen with setup_id2 but receives proof from setup_id1 — should fail verification
        REQUIRE_NOTHROW(testSetup.client.start_new_key_generation(setup_id2, keyid, get_tenant_id(), server_id, client_id, ECDSA_SECP256K1));

        commitments_sha256_t B;
        REQUIRE_NOTHROW(testSetup.server.generate_share_and_commit(setup_id2, keyid, server_id, client_id, ECDSA_SECP256K1, B));

        fbc::bam_ecdsa_cosigner::client_key_shared_data client_message;
        // Client verifies setup1's proof against setup_id2's commitment — AAD mismatch must cause failure
        REQUIRE_THROWS(testSetup.client.verify_setup_proof_store_key_commitment_generate_key_proof(setup_id2, keyid, server_id, setup1, B, client_message));
    }

    // Attack: replay setup proof with wrong algorithm (secp256r1 proof used for secp256k1 key).
    SECTION("attack: setup proof replay with different algorithm")
    {
        TestSetup testSetup;
        uuid_t uid;
        char setup_id_buf[UUID_STR_LEN] = {'\0'};
        char setup_id2_buf[UUID_STR_LEN] = {'\0'};
        char keyid[UUID_STR_LEN] = {'\0'};

        uuid_generate_random(uid);
        uuid_unparse(uid, setup_id_buf);
        uuid_generate_random(uid);
        uuid_unparse(uid, setup_id2_buf);
        uuid_generate_random(uid);
        uuid_unparse(uid, keyid);

        const std::string setup_id_r1(setup_id_buf);
        const std::string setup_id_k1(setup_id2_buf);

        // Generate setup for secp256r1
        fbc::bam_ecdsa_cosigner::server_setup_shared_data setup_r1;
        REQUIRE_NOTHROW(testSetup.server.generate_setup_with_proof(setup_id_r1, get_tenant_id(), ECDSA_SECP256R1, setup_r1));

        // Generate setup for secp256k1
        fbc::bam_ecdsa_cosigner::server_setup_shared_data setup_k1;
        REQUIRE_NOTHROW(testSetup.server.generate_setup_with_proof(setup_id_k1, get_tenant_id(), ECDSA_SECP256K1, setup_k1));

        // Client starts key gen for secp256k1 but receives secp256r1 setup proof — must fail
        REQUIRE_NOTHROW(testSetup.client.start_new_key_generation(setup_id_k1, keyid, get_tenant_id(), server_id, client_id, ECDSA_SECP256K1));

        commitments_sha256_t B;
        REQUIRE_NOTHROW(testSetup.server.generate_share_and_commit(setup_id_k1, keyid, server_id, client_id, ECDSA_SECP256K1, B));

        fbc::bam_ecdsa_cosigner::client_key_shared_data client_message;
        REQUIRE_THROWS(testSetup.client.verify_setup_proof_store_key_commitment_generate_key_proof(setup_id_k1, keyid, server_id, setup_r1, B, client_message));
    }

    // Attack: encrypted_partial_sig = all zeros (Paillier coprime check).
    // Zero is not coprime to n, so Paillier decryption or well-formedness proof must reject.
    SECTION("attack: encrypted_partial_sig all zeros")
    {
        TestSetup testSetup;
        uuid_t uid;
        char keyid[UUID_STR_LEN] = {'\0'};
        char txid[UUID_STR_LEN] = {'\0'};
        const std::string setup_id(keyid);

        uuid_generate_random(uid);
        uuid_unparse(uid, keyid);
        uuid_generate_random(uid);
        uuid_unparse(uid, txid);

        elliptic_curve256_scalar_t hash;
        REQUIRE(RAND_bytes(hash, sizeof(hash)));

        elliptic_curve256_point_t X1, X2;
        bam_key_generation(setup_id, keyid, client_id, server_id, testSetup.server, testSetup.client, ECDSA_SECP256K1, X1, X2);

        fbc::signing_data data_to_sign = {{0}, {{ fbc::byte_vector_t(&hash[0], &hash[sizeof(hash)]), { 44, 0, 0, 0, 0} }}};

        std::vector<fbc::bam_ecdsa_cosigner::server_signature_shared_data> server_shares;
        std::vector<fbc::bam_ecdsa_cosigner::client_partial_signature_data> partial_signatures;
        std::vector<fbc::recoverable_signature> full_signatures;
        cosigner_sign_algorithm signature_algorithm;

        REQUIRE_NOTHROW(testSetup.client.prepare_for_signature(keyid, txid, 0, server_id, client_id, data_to_sign, "", std::set<std::string>()));
        REQUIRE_NOTHROW(testSetup.server.generate_signature_share(keyid, txid, 0, server_id, client_id, ECDSA_SECP256K1, data_to_sign, "", std::set<std::string>(), server_shares));
        REQUIRE_NOTHROW(testSetup.client.compute_partial_signature(txid, server_shares, partial_signatures));
        REQUIRE(partial_signatures.size() == 1);

        // Replace encrypted_partial_sig with all zeros
        std::fill(partial_signatures[0].encrypted_partial_sig.begin(), partial_signatures[0].encrypted_partial_sig.end(), 0x00);

        REQUIRE_THROWS(testSetup.server.verify_partial_signature_and_output_signature(txid, client_id, partial_signatures, full_signatures, signature_algorithm));
    }

    // Attack: encrypted_partial_sig = 1 (trivial ciphertext).
    // The value 1 is a trivial Paillier ciphertext — decrypts to 0, which should fail proof verification.
    SECTION("attack: encrypted_partial_sig trivial value 1")
    {
        TestSetup testSetup;
        uuid_t uid;
        char keyid[UUID_STR_LEN] = {'\0'};
        char txid[UUID_STR_LEN] = {'\0'};
        const std::string setup_id(keyid);

        uuid_generate_random(uid);
        uuid_unparse(uid, keyid);
        uuid_generate_random(uid);
        uuid_unparse(uid, txid);

        elliptic_curve256_scalar_t hash;
        REQUIRE(RAND_bytes(hash, sizeof(hash)));

        elliptic_curve256_point_t X1, X2;
        bam_key_generation(setup_id, keyid, client_id, server_id, testSetup.server, testSetup.client, ECDSA_SECP256K1, X1, X2);

        fbc::signing_data data_to_sign = {{0}, {{ fbc::byte_vector_t(&hash[0], &hash[sizeof(hash)]), { 44, 0, 0, 0, 0} }}};

        std::vector<fbc::bam_ecdsa_cosigner::server_signature_shared_data> server_shares;
        std::vector<fbc::bam_ecdsa_cosigner::client_partial_signature_data> partial_signatures;
        std::vector<fbc::recoverable_signature> full_signatures;
        cosigner_sign_algorithm signature_algorithm;

        REQUIRE_NOTHROW(testSetup.client.prepare_for_signature(keyid, txid, 0, server_id, client_id, data_to_sign, "", std::set<std::string>()));
        REQUIRE_NOTHROW(testSetup.server.generate_signature_share(keyid, txid, 0, server_id, client_id, ECDSA_SECP256K1, data_to_sign, "", std::set<std::string>(), server_shares));
        REQUIRE_NOTHROW(testSetup.client.compute_partial_signature(txid, server_shares, partial_signatures));
        REQUIRE(partial_signatures.size() == 1);

        // Replace encrypted_partial_sig with value 1 (big-endian)
        std::fill(partial_signatures[0].encrypted_partial_sig.begin(), partial_signatures[0].encrypted_partial_sig.end(), 0x00);
        partial_signatures[0].encrypted_partial_sig.back() = 0x01;

        REQUIRE_THROWS(testSetup.server.verify_partial_signature_and_output_signature(txid, client_id, partial_signatures, full_signatures, signature_algorithm));
    }

    // Attack: encrypted_partial_sig = all 0xFF (large value, coprime check).
    // A value of all 0xFF bytes is likely not coprime to n^2, so should be rejected.
    SECTION("attack: encrypted_partial_sig all 0xFF")
    {
        TestSetup testSetup;
        uuid_t uid;
        char keyid[UUID_STR_LEN] = {'\0'};
        char txid[UUID_STR_LEN] = {'\0'};
        const std::string setup_id(keyid);

        uuid_generate_random(uid);
        uuid_unparse(uid, keyid);
        uuid_generate_random(uid);
        uuid_unparse(uid, txid);

        elliptic_curve256_scalar_t hash;
        REQUIRE(RAND_bytes(hash, sizeof(hash)));

        elliptic_curve256_point_t X1, X2;
        bam_key_generation(setup_id, keyid, client_id, server_id, testSetup.server, testSetup.client, ECDSA_SECP256K1, X1, X2);

        fbc::signing_data data_to_sign = {{0}, {{ fbc::byte_vector_t(&hash[0], &hash[sizeof(hash)]), { 44, 0, 0, 0, 0} }}};

        std::vector<fbc::bam_ecdsa_cosigner::server_signature_shared_data> server_shares;
        std::vector<fbc::bam_ecdsa_cosigner::client_partial_signature_data> partial_signatures;
        std::vector<fbc::recoverable_signature> full_signatures;
        cosigner_sign_algorithm signature_algorithm;

        REQUIRE_NOTHROW(testSetup.client.prepare_for_signature(keyid, txid, 0, server_id, client_id, data_to_sign, "", std::set<std::string>()));
        REQUIRE_NOTHROW(testSetup.server.generate_signature_share(keyid, txid, 0, server_id, client_id, ECDSA_SECP256K1, data_to_sign, "", std::set<std::string>(), server_shares));
        REQUIRE_NOTHROW(testSetup.client.compute_partial_signature(txid, server_shares, partial_signatures));
        REQUIRE(partial_signatures.size() == 1);

        // Replace encrypted_partial_sig with all 0xFF
        std::fill(partial_signatures[0].encrypted_partial_sig.begin(), partial_signatures[0].encrypted_partial_sig.end(), 0xFF);

        REQUIRE_THROWS(testSetup.server.verify_partial_signature_and_output_signature(txid, client_id, partial_signatures, full_signatures, signature_algorithm));
    }

    // Attack: server R replaced with client's public key X (DH bypass attempt).
    // If the server's R = X_client, the DH consistency check should still catch tampering
    // because the client's k is random and (X_client)^k != R_client^k_server.
    SECTION("attack: server R = client public key X (DH bypass)")
    {
        TestSetup testSetup;
        uuid_t uid;
        char keyid[UUID_STR_LEN] = {'\0'};
        char txid[UUID_STR_LEN] = {'\0'};
        const std::string setup_id(keyid);

        uuid_generate_random(uid);
        uuid_unparse(uid, keyid);
        uuid_generate_random(uid);
        uuid_unparse(uid, txid);

        elliptic_curve256_scalar_t hash;
        REQUIRE(RAND_bytes(hash, sizeof(hash)));

        elliptic_curve256_point_t X1, X2;
        bam_key_generation(setup_id, keyid, client_id, server_id, testSetup.server, testSetup.client, ECDSA_SECP256K1, X1, X2);

        fbc::signing_data data_to_sign = {{0}, {{ fbc::byte_vector_t(&hash[0], &hash[sizeof(hash)]), { 44, 0, 0, 0, 0} }}};

        std::vector<fbc::bam_ecdsa_cosigner::server_signature_shared_data> server_shares;
        std::vector<fbc::bam_ecdsa_cosigner::client_partial_signature_data> partial_signatures;

        REQUIRE_NOTHROW(testSetup.client.prepare_for_signature(keyid, txid, 0, server_id, client_id, data_to_sign, "", std::set<std::string>()));
        REQUIRE_NOTHROW(testSetup.server.generate_signature_share(keyid, txid, 0, server_id, client_id, ECDSA_SECP256K1, data_to_sign, "", std::set<std::string>(), server_shares));
        REQUIRE(server_shares.size() == 1);

        // Replace server's R with client's public key share
        memcpy(server_shares[0].R, X1, sizeof(elliptic_curve256_point_t));

        // Client should detect the DH inconsistency or produce a bad partial that server rejects
        REQUIRE_THROWS(testSetup.client.compute_partial_signature(txid, server_shares, partial_signatures));
    }

    // Attack: R = Y degenerate DH pair.
    // If R == Y, this implies k_server * X_client == G^k_server, which is only true if X_client == G.
    // The client must reject this because DH consistency breaks.
    SECTION("attack: R = Y degenerate DH pair")
    {
        TestSetup testSetup;
        uuid_t uid;
        char keyid[UUID_STR_LEN] = {'\0'};
        char txid[UUID_STR_LEN] = {'\0'};
        const std::string setup_id(keyid);

        uuid_generate_random(uid);
        uuid_unparse(uid, keyid);
        uuid_generate_random(uid);
        uuid_unparse(uid, txid);

        elliptic_curve256_scalar_t hash;
        REQUIRE(RAND_bytes(hash, sizeof(hash)));

        elliptic_curve256_point_t X1, X2;
        bam_key_generation(setup_id, keyid, client_id, server_id, testSetup.server, testSetup.client, ECDSA_SECP256K1, X1, X2);

        fbc::signing_data data_to_sign = {{0}, {{ fbc::byte_vector_t(&hash[0], &hash[sizeof(hash)]), { 44, 0, 0, 0, 0} }}};

        std::vector<fbc::bam_ecdsa_cosigner::server_signature_shared_data> server_shares;
        std::vector<fbc::bam_ecdsa_cosigner::client_partial_signature_data> partial_signatures;

        REQUIRE_NOTHROW(testSetup.client.prepare_for_signature(keyid, txid, 0, server_id, client_id, data_to_sign, "", std::set<std::string>()));
        REQUIRE_NOTHROW(testSetup.server.generate_signature_share(keyid, txid, 0, server_id, client_id, ECDSA_SECP256K1, data_to_sign, "", std::set<std::string>(), server_shares));
        REQUIRE(server_shares.size() == 1);

        // Set Y = R (degenerate DH pair)
        memcpy(server_shares[0].Y, server_shares[0].R, sizeof(elliptic_curve256_point_t));

        // Client should detect the DH inconsistency
        REQUIRE_THROWS(testSetup.client.compute_partial_signature(txid, server_shares, partial_signatures));
    }

    // Attack: algorithm mismatch — request signing with wrong algorithm for key.
    SECTION("attack: algorithm mismatch on generate_signature_share")
    {
        TestSetup testSetup;
        uuid_t uid;
        char keyid[UUID_STR_LEN] = {'\0'};
        char txid[UUID_STR_LEN] = {'\0'};
        const std::string setup_id(keyid);

        uuid_generate_random(uid);
        uuid_unparse(uid, keyid);
        uuid_generate_random(uid);
        uuid_unparse(uid, txid);

        elliptic_curve256_scalar_t hash;
        REQUIRE(RAND_bytes(hash, sizeof(hash)));

        elliptic_curve256_point_t X1, X2;
        bam_key_generation(setup_id, keyid, client_id, server_id, testSetup.server, testSetup.client, ECDSA_SECP256K1, X1, X2);

        fbc::signing_data data_to_sign = {{0}, {{ fbc::byte_vector_t(&hash[0], &hash[sizeof(hash)]), { 44, 0, 0, 0, 0} }}};

        std::vector<fbc::bam_ecdsa_cosigner::server_signature_shared_data> server_shares;

        // Request signing with secp256r1 on a secp256k1 key — must be rejected
        REQUIRE_THROWS(testSetup.server.generate_signature_share(keyid, txid, 0, server_id, client_id, ECDSA_SECP256R1, data_to_sign, "", std::set<std::string>(), server_shares));
    }

    // Attack: wrong client_id on verify_partial_signature_and_output_signature.
    SECTION("attack: client_id mismatch on verify_partial_signature")
    {
        TestSetup testSetup;
        uuid_t uid;
        char keyid[UUID_STR_LEN] = {'\0'};
        char txid[UUID_STR_LEN] = {'\0'};
        const std::string setup_id(keyid);

        uuid_generate_random(uid);
        uuid_unparse(uid, keyid);
        uuid_generate_random(uid);
        uuid_unparse(uid, txid);

        elliptic_curve256_scalar_t hash;
        REQUIRE(RAND_bytes(hash, sizeof(hash)));

        elliptic_curve256_point_t X1, X2;
        bam_key_generation(setup_id, keyid, client_id, server_id, testSetup.server, testSetup.client, ECDSA_SECP256K1, X1, X2);

        fbc::signing_data data_to_sign = {{0}, {{ fbc::byte_vector_t(&hash[0], &hash[sizeof(hash)]), { 44, 0, 0, 0, 0} }}};

        std::vector<fbc::bam_ecdsa_cosigner::server_signature_shared_data> server_shares;
        std::vector<fbc::bam_ecdsa_cosigner::client_partial_signature_data> partial_signatures;
        std::vector<fbc::recoverable_signature> full_signatures;
        cosigner_sign_algorithm signature_algorithm;

        REQUIRE_NOTHROW(testSetup.client.prepare_for_signature(keyid, txid, 0, server_id, client_id, data_to_sign, "", std::set<std::string>()));
        REQUIRE_NOTHROW(testSetup.server.generate_signature_share(keyid, txid, 0, server_id, client_id, ECDSA_SECP256K1, data_to_sign, "", std::set<std::string>(), server_shares));
        REQUIRE_NOTHROW(testSetup.client.compute_partial_signature(txid, server_shares, partial_signatures));

        // Use a different client_id — must be rejected
        const uint64_t wrong_client_id = client_id + 1;
        REQUIRE_THROWS(testSetup.server.verify_partial_signature_and_output_signature(txid, wrong_client_id, partial_signatures, full_signatures, signature_algorithm));
    }

    // Batch signing: duplicate hashes must not produce duplicate nonces.
    SECTION("attack: batch signing duplicate hashes produce unique nonces")
    {
        TestSetup testSetup;
        uuid_t uid;
        char keyid[UUID_STR_LEN] = {'\0'};
        char txid[UUID_STR_LEN] = {'\0'};
        const std::string setup_id(keyid);

        uuid_generate_random(uid);
        uuid_unparse(uid, keyid);
        uuid_generate_random(uid);
        uuid_unparse(uid, txid);

        elliptic_curve256_scalar_t hash;
        REQUIRE(RAND_bytes(hash, sizeof(hash)));

        elliptic_curve256_point_t X1, X2;
        bam_key_generation(setup_id, keyid, client_id, server_id, testSetup.server, testSetup.client, ECDSA_SECP256K1, X1, X2);

        // Create batch with two identical hashes
        fbc::signing_data data_to_sign = {{0}, {
            { fbc::byte_vector_t(&hash[0], &hash[sizeof(hash)]), { 44, 0, 0, 0, 0} },
            { fbc::byte_vector_t(&hash[0], &hash[sizeof(hash)]), { 44, 0, 0, 0, 0} }
        }};
        const std::string sign_metadata = "{ \"signInfo\":[{}, {}]}";

        std::vector<fbc::bam_ecdsa_cosigner::server_signature_shared_data> server_shares;

        REQUIRE_NOTHROW(testSetup.client.prepare_for_signature(keyid, txid, 0, server_id, client_id, data_to_sign, sign_metadata, std::set<std::string>()));
        REQUIRE_NOTHROW(testSetup.server.generate_signature_share(keyid, txid, 0, server_id, client_id, ECDSA_SECP256K1, data_to_sign, sign_metadata, std::set<std::string>(), server_shares));
        REQUIRE(server_shares.size() == 2);

        // Even with identical messages, server nonces (R values) MUST differ
        REQUIRE(memcmp(server_shares[0].R, server_shares[1].R, sizeof(elliptic_curve256_point_t)) != 0);
    }
}

TEST_CASE("bam_ecdsa_attacks")
{
    // Note: no init()/term() needed — these tests use in-process TestSetup,
    // not the Thrift-based cloud-cosigner service.

    SECTION("attack: corrupted server_public_share in keygen (secp256k1)")
    {
        TestSetup testSetup;
        uuid_t uid;
        char keyid[UUID_STR_LEN] = {'\0'};
        const std::string setup_id(keyid);
        uuid_generate_random(uid);
        uuid_unparse(uid, keyid);

        fbc::bam_ecdsa_cosigner::server_setup_shared_data setup;
        commitments_sha256_t B;
        fbc::bam_ecdsa_cosigner::client_key_shared_data client_message;
        fbc::bam_ecdsa_cosigner::server_key_shared_data server_message;
        fbc::bam_ecdsa_cosigner::generated_public_key generated_public_key;

        REQUIRE_NOTHROW(testSetup.server.generate_setup_with_proof(setup_id, get_tenant_id(), ECDSA_SECP256K1, setup));
        REQUIRE_NOTHROW(testSetup.client.start_new_key_generation(setup_id, keyid, get_tenant_id(), server_id, client_id, ECDSA_SECP256K1));
        REQUIRE_NOTHROW(testSetup.server.generate_share_and_commit(setup_id, keyid, server_id, client_id, ECDSA_SECP256K1, B));
        REQUIRE_NOTHROW(testSetup.client.verify_setup_proof_store_key_commitment_generate_key_proof(setup_id, keyid, server_id, setup, B, client_message));
        REQUIRE_NOTHROW(testSetup.server.verify_client_proofs_and_decommit_share_with_proof(keyid, client_id, client_message, server_message));

        // Corrupt the server's public share
        server_message.server_public_share[1] ^= 0xFF;

        // Client should reject corrupted share (proof won't match)
        REQUIRE_THROWS(testSetup.client.verify_key_decommitment_and_proofs(keyid, server_id, client_id, server_message, generated_public_key));
    }

    SECTION("attack: corrupted enc_dlog_proof in keygen (secp256k1)")
    {
        TestSetup testSetup;
        uuid_t uid;
        char keyid[UUID_STR_LEN] = {'\0'};
        const std::string setup_id(keyid);
        uuid_generate_random(uid);
        uuid_unparse(uid, keyid);

        fbc::bam_ecdsa_cosigner::server_setup_shared_data setup;
        commitments_sha256_t B;
        fbc::bam_ecdsa_cosigner::client_key_shared_data client_message;
        fbc::bam_ecdsa_cosigner::server_key_shared_data server_message;
        fbc::bam_ecdsa_cosigner::generated_public_key generated_public_key;

        REQUIRE_NOTHROW(testSetup.server.generate_setup_with_proof(setup_id, get_tenant_id(), ECDSA_SECP256K1, setup));
        REQUIRE_NOTHROW(testSetup.client.start_new_key_generation(setup_id, keyid, get_tenant_id(), server_id, client_id, ECDSA_SECP256K1));
        REQUIRE_NOTHROW(testSetup.server.generate_share_and_commit(setup_id, keyid, server_id, client_id, ECDSA_SECP256K1, B));
        REQUIRE_NOTHROW(testSetup.client.verify_setup_proof_store_key_commitment_generate_key_proof(setup_id, keyid, server_id, setup, B, client_message));
        REQUIRE_NOTHROW(testSetup.server.verify_client_proofs_and_decommit_share_with_proof(keyid, client_id, client_message, server_message));

        // Corrupt the enc_dlog_proof
        if (!server_message.enc_dlog_proof.empty()) {
            server_message.enc_dlog_proof[0] ^= 0xFF;
        }

        REQUIRE_THROWS(testSetup.client.verify_key_decommitment_and_proofs(keyid, server_id, client_id, server_message, generated_public_key));
    }

    SECTION("attack: corrupted encrypted_server_share in keygen (secp256k1)")
    {
        TestSetup testSetup;
        uuid_t uid;
        char keyid[UUID_STR_LEN] = {'\0'};
        const std::string setup_id(keyid);
        uuid_generate_random(uid);
        uuid_unparse(uid, keyid);

        fbc::bam_ecdsa_cosigner::server_setup_shared_data setup;
        commitments_sha256_t B;
        fbc::bam_ecdsa_cosigner::client_key_shared_data client_message;
        fbc::bam_ecdsa_cosigner::server_key_shared_data server_message;
        fbc::bam_ecdsa_cosigner::generated_public_key generated_public_key;

        REQUIRE_NOTHROW(testSetup.server.generate_setup_with_proof(setup_id, get_tenant_id(), ECDSA_SECP256K1, setup));
        REQUIRE_NOTHROW(testSetup.client.start_new_key_generation(setup_id, keyid, get_tenant_id(), server_id, client_id, ECDSA_SECP256K1));
        REQUIRE_NOTHROW(testSetup.server.generate_share_and_commit(setup_id, keyid, server_id, client_id, ECDSA_SECP256K1, B));
        REQUIRE_NOTHROW(testSetup.client.verify_setup_proof_store_key_commitment_generate_key_proof(setup_id, keyid, server_id, setup, B, client_message));
        REQUIRE_NOTHROW(testSetup.server.verify_client_proofs_and_decommit_share_with_proof(keyid, client_id, client_message, server_message));

        // Corrupt the encrypted server share
        if (!server_message.encrypted_server_share.empty()) {
            server_message.encrypted_server_share[server_message.encrypted_server_share.size() / 2] ^= 0xFF;
        }

        REQUIRE_THROWS(testSetup.client.verify_key_decommitment_and_proofs(keyid, server_id, client_id, server_message, generated_public_key));
    }

    SECTION("attack: corrupted schnorr_proof in client keygen message (secp256k1)")
    {
        TestSetup testSetup;
        uuid_t uid;
        char keyid[UUID_STR_LEN] = {'\0'};
        const std::string setup_id(keyid);
        uuid_generate_random(uid);
        uuid_unparse(uid, keyid);

        fbc::bam_ecdsa_cosigner::server_setup_shared_data setup;
        commitments_sha256_t B;
        fbc::bam_ecdsa_cosigner::client_key_shared_data client_message;

        REQUIRE_NOTHROW(testSetup.server.generate_setup_with_proof(setup_id, get_tenant_id(), ECDSA_SECP256K1, setup));
        REQUIRE_NOTHROW(testSetup.client.start_new_key_generation(setup_id, keyid, get_tenant_id(), server_id, client_id, ECDSA_SECP256K1));
        REQUIRE_NOTHROW(testSetup.server.generate_share_and_commit(setup_id, keyid, server_id, client_id, ECDSA_SECP256K1, B));
        REQUIRE_NOTHROW(testSetup.client.verify_setup_proof_store_key_commitment_generate_key_proof(setup_id, keyid, server_id, setup, B, client_message));

        // Corrupt the schnorr proof (byte_vector_t — flip a byte in the middle)
        if (!client_message.schnorr_proof.empty()) {
            client_message.schnorr_proof[client_message.schnorr_proof.size() / 2] ^= 0xFF;
        }

        fbc::bam_ecdsa_cosigner::server_key_shared_data server_message;
        REQUIRE_THROWS(testSetup.server.verify_client_proofs_and_decommit_share_with_proof(keyid, client_id, client_message, server_message));
    }

    SECTION("attack: infinity X in client keygen message (secp256k1)")
    {
        TestSetup testSetup;
        uuid_t uid;
        char keyid[UUID_STR_LEN] = {'\0'};
        const std::string setup_id(keyid);
        uuid_generate_random(uid);
        uuid_unparse(uid, keyid);

        fbc::bam_ecdsa_cosigner::server_setup_shared_data setup;
        commitments_sha256_t B;
        fbc::bam_ecdsa_cosigner::client_key_shared_data client_message;

        REQUIRE_NOTHROW(testSetup.server.generate_setup_with_proof(setup_id, get_tenant_id(), ECDSA_SECP256K1, setup));
        REQUIRE_NOTHROW(testSetup.client.start_new_key_generation(setup_id, keyid, get_tenant_id(), server_id, client_id, ECDSA_SECP256K1));
        REQUIRE_NOTHROW(testSetup.server.generate_share_and_commit(setup_id, keyid, server_id, client_id, ECDSA_SECP256K1, B));
        REQUIRE_NOTHROW(testSetup.client.verify_setup_proof_store_key_commitment_generate_key_proof(setup_id, keyid, server_id, setup, B, client_message));

        // Replace X with infinity point
        memset(client_message.X, 0, sizeof(elliptic_curve256_point_t));

        fbc::bam_ecdsa_cosigner::server_key_shared_data server_message;
        REQUIRE_THROWS(testSetup.server.verify_client_proofs_and_decommit_share_with_proof(keyid, client_id, client_message, server_message));
    }

    SECTION("attack: alternative infinity X in client keygen (secp256k1)")
    {
        TestSetup testSetup;
        uuid_t uid;
        char keyid[UUID_STR_LEN] = {'\0'};
        const std::string setup_id(keyid);
        uuid_generate_random(uid);
        uuid_unparse(uid, keyid);

        fbc::bam_ecdsa_cosigner::server_setup_shared_data setup;
        commitments_sha256_t B;
        fbc::bam_ecdsa_cosigner::client_key_shared_data client_message;

        REQUIRE_NOTHROW(testSetup.server.generate_setup_with_proof(setup_id, get_tenant_id(), ECDSA_SECP256K1, setup));
        REQUIRE_NOTHROW(testSetup.client.start_new_key_generation(setup_id, keyid, get_tenant_id(), server_id, client_id, ECDSA_SECP256K1));
        REQUIRE_NOTHROW(testSetup.server.generate_share_and_commit(setup_id, keyid, server_id, client_id, ECDSA_SECP256K1, B));
        REQUIRE_NOTHROW(testSetup.client.verify_setup_proof_store_key_commitment_generate_key_proof(setup_id, keyid, server_id, setup, B, client_message));

        // Replace X with alt infinity: 0x00 prefix but non-zero trailing byte
        memset(client_message.X, 0, sizeof(elliptic_curve256_point_t));
        client_message.X[0] = 0x00;
        client_message.X[1] = 0x01;

        fbc::bam_ecdsa_cosigner::server_key_shared_data server_message;
        REQUIRE_THROWS(testSetup.server.verify_client_proofs_and_decommit_share_with_proof(keyid, client_id, client_message, server_message));
    }

    SECTION("attack: corrupted partial signature proof (secp256k1)")
    {
        TestSetup testSetup;
        uuid_t uid;
        char keyid[UUID_STR_LEN] = {'\0'};
        char txid[UUID_STR_LEN] = {'\0'};
        const std::string setup_id(keyid);
        uuid_generate_random(uid);
        uuid_unparse(uid, keyid);
        uuid_generate_random(uid);
        uuid_unparse(uid, txid);

        elliptic_curve256_scalar_t hash;
        REQUIRE(RAND_bytes(hash, sizeof(hash)));

        elliptic_curve256_point_t X1, X2;
        bam_key_generation(setup_id, keyid, client_id, server_id, testSetup.server, testSetup.client, ECDSA_SECP256K1, X1, X2);

        fbc::signing_data data_to_sign = {{0}, {{ fbc::byte_vector_t(&hash[0], &hash[sizeof(hash)]), { 44, 0, 0, 0, 0} }}};

        std::vector<fbc::bam_ecdsa_cosigner::server_signature_shared_data> server_shares;
        std::vector<fbc::bam_ecdsa_cosigner::client_partial_signature_data> partial_signatures;
        std::vector<fbc::recoverable_signature> full_signatures;
        cosigner_sign_algorithm signature_algorithm;

        REQUIRE_NOTHROW(testSetup.client.prepare_for_signature(keyid, txid, 0, server_id, client_id, data_to_sign, "", std::set<std::string>()));
        REQUIRE_NOTHROW(testSetup.server.generate_signature_share(keyid, txid, 0, server_id, client_id, ECDSA_SECP256K1, data_to_sign, "", std::set<std::string>(), server_shares));
        REQUIRE_NOTHROW(testSetup.client.compute_partial_signature(txid, server_shares, partial_signatures));
        REQUIRE(partial_signatures.size() == 1);

        // Corrupt the signature proof
        if (!partial_signatures[0].sig_proof.empty()) {
            partial_signatures[0].sig_proof[0] ^= 0xFF;
        }

        REQUIRE_THROWS(testSetup.server.verify_partial_signature_and_output_signature(txid, client_id, partial_signatures, full_signatures, signature_algorithm));
    }

    SECTION("attack: corrupted encrypted_partial_sig (secp256k1)")
    {
        TestSetup testSetup;
        uuid_t uid;
        char keyid[UUID_STR_LEN] = {'\0'};
        char txid[UUID_STR_LEN] = {'\0'};
        const std::string setup_id(keyid);
        uuid_generate_random(uid);
        uuid_unparse(uid, keyid);
        uuid_generate_random(uid);
        uuid_unparse(uid, txid);

        elliptic_curve256_scalar_t hash;
        REQUIRE(RAND_bytes(hash, sizeof(hash)));

        elliptic_curve256_point_t X1, X2;
        bam_key_generation(setup_id, keyid, client_id, server_id, testSetup.server, testSetup.client, ECDSA_SECP256K1, X1, X2);

        fbc::signing_data data_to_sign = {{0}, {{ fbc::byte_vector_t(&hash[0], &hash[sizeof(hash)]), { 44, 0, 0, 0, 0} }}};

        std::vector<fbc::bam_ecdsa_cosigner::server_signature_shared_data> server_shares;
        std::vector<fbc::bam_ecdsa_cosigner::client_partial_signature_data> partial_signatures;
        std::vector<fbc::recoverable_signature> full_signatures;
        cosigner_sign_algorithm signature_algorithm;

        REQUIRE_NOTHROW(testSetup.client.prepare_for_signature(keyid, txid, 0, server_id, client_id, data_to_sign, "", std::set<std::string>()));
        REQUIRE_NOTHROW(testSetup.server.generate_signature_share(keyid, txid, 0, server_id, client_id, ECDSA_SECP256K1, data_to_sign, "", std::set<std::string>(), server_shares));
        REQUIRE_NOTHROW(testSetup.client.compute_partial_signature(txid, server_shares, partial_signatures));
        REQUIRE(partial_signatures.size() == 1);

        // Corrupt the encrypted partial signature
        if (!partial_signatures[0].encrypted_partial_sig.empty()) {
            partial_signatures[0].encrypted_partial_sig[partial_signatures[0].encrypted_partial_sig.size() / 2] ^= 0xFF;
        }

        REQUIRE_THROWS(testSetup.server.verify_partial_signature_and_output_signature(txid, client_id, partial_signatures, full_signatures, signature_algorithm));
    }

    SECTION("attack: swapped client_R and common_R (secp256k1)")
    {
        TestSetup testSetup;
        uuid_t uid;
        char keyid[UUID_STR_LEN] = {'\0'};
        char txid[UUID_STR_LEN] = {'\0'};
        const std::string setup_id(keyid);
        uuid_generate_random(uid);
        uuid_unparse(uid, keyid);
        uuid_generate_random(uid);
        uuid_unparse(uid, txid);

        elliptic_curve256_scalar_t hash;
        REQUIRE(RAND_bytes(hash, sizeof(hash)));

        elliptic_curve256_point_t X1, X2;
        bam_key_generation(setup_id, keyid, client_id, server_id, testSetup.server, testSetup.client, ECDSA_SECP256K1, X1, X2);

        fbc::signing_data data_to_sign = {{0}, {{ fbc::byte_vector_t(&hash[0], &hash[sizeof(hash)]), { 44, 0, 0, 0, 0} }}};

        std::vector<fbc::bam_ecdsa_cosigner::server_signature_shared_data> server_shares;
        std::vector<fbc::bam_ecdsa_cosigner::client_partial_signature_data> partial_signatures;
        std::vector<fbc::recoverable_signature> full_signatures;
        cosigner_sign_algorithm signature_algorithm;

        REQUIRE_NOTHROW(testSetup.client.prepare_for_signature(keyid, txid, 0, server_id, client_id, data_to_sign, "", std::set<std::string>()));
        REQUIRE_NOTHROW(testSetup.server.generate_signature_share(keyid, txid, 0, server_id, client_id, ECDSA_SECP256K1, data_to_sign, "", std::set<std::string>(), server_shares));
        REQUIRE_NOTHROW(testSetup.client.compute_partial_signature(txid, server_shares, partial_signatures));
        REQUIRE(partial_signatures.size() == 1);

        // Swap client_R and common_R
        elliptic_curve256_point_t tmp;
        memcpy(tmp, partial_signatures[0].client_R, sizeof(elliptic_curve256_point_t));
        memcpy(partial_signatures[0].client_R, partial_signatures[0].common_R, sizeof(elliptic_curve256_point_t));
        memcpy(partial_signatures[0].common_R, tmp, sizeof(elliptic_curve256_point_t));

        REQUIRE_THROWS(testSetup.server.verify_partial_signature_and_output_signature(txid, client_id, partial_signatures, full_signatures, signature_algorithm));
    }

    SECTION("attack: generator point as server R (secp256k1)")
    {
        TestSetup testSetup;
        uuid_t uid;
        char keyid[UUID_STR_LEN] = {'\0'};
        char txid[UUID_STR_LEN] = {'\0'};
        const std::string setup_id(keyid);
        uuid_generate_random(uid);
        uuid_unparse(uid, keyid);
        uuid_generate_random(uid);
        uuid_unparse(uid, txid);

        elliptic_curve256_scalar_t hash;
        REQUIRE(RAND_bytes(hash, sizeof(hash)));

        elliptic_curve256_point_t X1, X2;
        bam_key_generation(setup_id, keyid, client_id, server_id, testSetup.server, testSetup.client, ECDSA_SECP256K1, X1, X2);

        fbc::signing_data data_to_sign = {{0}, {{ fbc::byte_vector_t(&hash[0], &hash[sizeof(hash)]), { 44, 0, 0, 0, 0} }}};

        std::vector<fbc::bam_ecdsa_cosigner::server_signature_shared_data> server_shares;
        std::vector<fbc::bam_ecdsa_cosigner::client_partial_signature_data> partial_signatures;

        REQUIRE_NOTHROW(testSetup.client.prepare_for_signature(keyid, txid, 0, server_id, client_id, data_to_sign, "", std::set<std::string>()));
        REQUIRE_NOTHROW(testSetup.server.generate_signature_share(keyid, txid, 0, server_id, client_id, ECDSA_SECP256K1, data_to_sign, "", std::set<std::string>(), server_shares));
        REQUIRE(server_shares.size() == 1);

        // Replace R with generator point G (known discrete log = 1)
        elliptic_curve256_algebra_ctx_t* algebra = elliptic_curve256_new_secp256k1_algebra();
        REQUIRE(algebra != nullptr);
        elliptic_curve256_scalar_t one;
        memset(one, 0, sizeof(one));
        one[sizeof(one) - 1] = 1;
        algebra->generator_mul(algebra, &server_shares[0].R, &one);
        elliptic_curve256_algebra_ctx_free(algebra);

        // Client should detect the known-DL point or the proof mismatch
        REQUIRE_THROWS(testSetup.client.compute_partial_signature(txid, server_shares, partial_signatures));
    }

    SECTION("attack: replay server shares from session 1 in session 2 (secp256k1)")
    {
        TestSetup testSetup;
        uuid_t uid;
        char keyid[UUID_STR_LEN] = {'\0'};
        char txid1[UUID_STR_LEN] = {'\0'};
        char txid2[UUID_STR_LEN] = {'\0'};
        const std::string setup_id(keyid);

        uuid_generate_random(uid);
        uuid_unparse(uid, keyid);
        uuid_generate_random(uid);
        uuid_unparse(uid, txid1);
        uuid_generate_random(uid);
        uuid_unparse(uid, txid2);

        elliptic_curve256_scalar_t hash1, hash2;
        REQUIRE(RAND_bytes(hash1, sizeof(hash1)));
        REQUIRE(RAND_bytes(hash2, sizeof(hash2)));

        elliptic_curve256_point_t X1, X2;
        bam_key_generation(setup_id, keyid, client_id, server_id, testSetup.server, testSetup.client, ECDSA_SECP256K1, X1, X2);

        // Session 1: get server shares
        fbc::signing_data data1 = {{0}, {{ fbc::byte_vector_t(&hash1[0], &hash1[sizeof(hash1)]), { 44, 0, 0, 0, 0} }}};
        std::vector<fbc::bam_ecdsa_cosigner::server_signature_shared_data> server_shares1;
        std::vector<fbc::bam_ecdsa_cosigner::client_partial_signature_data> partial1;

        REQUIRE_NOTHROW(testSetup.client.prepare_for_signature(keyid, txid1, 0, server_id, client_id, data1, "", std::set<std::string>()));
        REQUIRE_NOTHROW(testSetup.server.generate_signature_share(keyid, txid1, 0, server_id, client_id, ECDSA_SECP256K1, data1, "", std::set<std::string>(), server_shares1));
        REQUIRE_NOTHROW(testSetup.client.compute_partial_signature(txid1, server_shares1, partial1));

        // Session 2: prepare new session but try to use replayed server shares from session 1
        fbc::signing_data data2 = {{0}, {{ fbc::byte_vector_t(&hash2[0], &hash2[sizeof(hash2)]), { 44, 0, 0, 0, 0} }}};
        std::vector<fbc::bam_ecdsa_cosigner::server_signature_shared_data> server_shares2;
        std::vector<fbc::bam_ecdsa_cosigner::client_partial_signature_data> partial2;

        REQUIRE_NOTHROW(testSetup.client.prepare_for_signature(keyid, txid2, 0, server_id, client_id, data2, "", std::set<std::string>()));
        REQUIRE_NOTHROW(testSetup.server.generate_signature_share(keyid, txid2, 0, server_id, client_id, ECDSA_SECP256K1, data2, "", std::set<std::string>(), server_shares2));

        // Client does not validate server shares against tx_id, so this won't throw.
        // However, the resulting partial signature will be rejected by the server's
        // verify_partial_signature_and_output_signature because the R values won't match.
        // The server-side load_signature_data_and_delete prevents server-side replay.
        REQUIRE_NOTHROW(testSetup.client.compute_partial_signature(txid2, server_shares1, partial2));
    }

    SECTION("attack: empty server shares vector")
    {
        TestSetup testSetup;
        uuid_t uid;
        char keyid[UUID_STR_LEN] = {'\0'};
        char txid[UUID_STR_LEN] = {'\0'};
        const std::string setup_id(keyid);
        uuid_generate_random(uid);
        uuid_unparse(uid, keyid);
        uuid_generate_random(uid);
        uuid_unparse(uid, txid);

        elliptic_curve256_scalar_t hash;
        REQUIRE(RAND_bytes(hash, sizeof(hash)));

        elliptic_curve256_point_t X1, X2;
        bam_key_generation(setup_id, keyid, client_id, server_id, testSetup.server, testSetup.client, ECDSA_SECP256K1, X1, X2);

        fbc::signing_data data_to_sign = {{0}, {{ fbc::byte_vector_t(&hash[0], &hash[sizeof(hash)]), { 44, 0, 0, 0, 0} }}};

        REQUIRE_NOTHROW(testSetup.client.prepare_for_signature(keyid, txid, 0, server_id, client_id, data_to_sign, "", std::set<std::string>()));

        // Empty server shares
        std::vector<fbc::bam_ecdsa_cosigner::server_signature_shared_data> empty_shares;
        std::vector<fbc::bam_ecdsa_cosigner::client_partial_signature_data> partial_signatures;

        REQUIRE_THROWS(testSetup.client.compute_partial_signature(txid, empty_shares, partial_signatures));
    }

    SECTION("attack: empty partial signatures vector")
    {
        TestSetup testSetup;
        uuid_t uid;
        char keyid[UUID_STR_LEN] = {'\0'};
        char txid[UUID_STR_LEN] = {'\0'};
        const std::string setup_id(keyid);
        uuid_generate_random(uid);
        uuid_unparse(uid, keyid);
        uuid_generate_random(uid);
        uuid_unparse(uid, txid);

        elliptic_curve256_scalar_t hash;
        REQUIRE(RAND_bytes(hash, sizeof(hash)));

        elliptic_curve256_point_t X1, X2;
        bam_key_generation(setup_id, keyid, client_id, server_id, testSetup.server, testSetup.client, ECDSA_SECP256K1, X1, X2);

        fbc::signing_data data_to_sign = {{0}, {{ fbc::byte_vector_t(&hash[0], &hash[sizeof(hash)]), { 44, 0, 0, 0, 0} }}};

        std::vector<fbc::bam_ecdsa_cosigner::server_signature_shared_data> server_shares;

        REQUIRE_NOTHROW(testSetup.client.prepare_for_signature(keyid, txid, 0, server_id, client_id, data_to_sign, "", std::set<std::string>()));
        REQUIRE_NOTHROW(testSetup.server.generate_signature_share(keyid, txid, 0, server_id, client_id, ECDSA_SECP256K1, data_to_sign, "", std::set<std::string>(), server_shares));

        // Empty partial signatures
        std::vector<fbc::bam_ecdsa_cosigner::client_partial_signature_data> empty_partials;
        std::vector<fbc::recoverable_signature> full_signatures;
        cosigner_sign_algorithm signature_algorithm;

        REQUIRE_THROWS(testSetup.server.verify_partial_signature_and_output_signature(txid, client_id, empty_partials, full_signatures, signature_algorithm));
    }

    SECTION("attack: negated server_public_share in keygen (secp256k1)")
    {
        TestSetup testSetup;
        uuid_t uid;
        char keyid[UUID_STR_LEN] = {'\0'};
        const std::string setup_id(keyid);
        uuid_generate_random(uid);
        uuid_unparse(uid, keyid);

        fbc::bam_ecdsa_cosigner::server_setup_shared_data setup;
        commitments_sha256_t B;
        fbc::bam_ecdsa_cosigner::client_key_shared_data client_message;
        fbc::bam_ecdsa_cosigner::server_key_shared_data server_message;
        fbc::bam_ecdsa_cosigner::generated_public_key generated_public_key;

        REQUIRE_NOTHROW(testSetup.server.generate_setup_with_proof(setup_id, get_tenant_id(), ECDSA_SECP256K1, setup));
        REQUIRE_NOTHROW(testSetup.client.start_new_key_generation(setup_id, keyid, get_tenant_id(), server_id, client_id, ECDSA_SECP256K1));
        REQUIRE_NOTHROW(testSetup.server.generate_share_and_commit(setup_id, keyid, server_id, client_id, ECDSA_SECP256K1, B));
        REQUIRE_NOTHROW(testSetup.client.verify_setup_proof_store_key_commitment_generate_key_proof(setup_id, keyid, server_id, setup, B, client_message));
        REQUIRE_NOTHROW(testSetup.server.verify_client_proofs_and_decommit_share_with_proof(keyid, client_id, client_message, server_message));

        // Negate the server's public share (flip parity byte for compressed point)
        if (server_message.server_public_share[0] == 0x02) {
            server_message.server_public_share[0] = 0x03;
        } else if (server_message.server_public_share[0] == 0x03) {
            server_message.server_public_share[0] = 0x02;
        }

        REQUIRE_THROWS(testSetup.client.verify_key_decommitment_and_proofs(keyid, server_id, client_id, server_message, generated_public_key));
    }

    SECTION("attack: sign before keygen complete should fail")
    {
        TestSetup testSetup;
        uuid_t uid;
        char keyid[UUID_STR_LEN] = {'\0'};
        char txid[UUID_STR_LEN] = {'\0'};
        uuid_generate_random(uid);
        uuid_unparse(uid, keyid);
        uuid_generate_random(uid);
        uuid_unparse(uid, txid);

        elliptic_curve256_scalar_t hash;
        REQUIRE(RAND_bytes(hash, sizeof(hash)));

        fbc::signing_data data_to_sign = {{0}, {{ fbc::byte_vector_t(&hash[0], &hash[sizeof(hash)]), { 44, 0, 0, 0, 0} }}};
        std::vector<fbc::bam_ecdsa_cosigner::server_signature_shared_data> server_shares;

        // Try to sign without having generated a key - should throw
        REQUIRE_THROWS(testSetup.server.generate_signature_share(keyid, txid, 0, server_id, client_id, ECDSA_SECP256K1, data_to_sign, "", std::set<std::string>(), server_shares));
    }

    // ========================================================================
    // A. Malicious Client — Keygen Attacks
    // ========================================================================

    SECTION("attack: zero scalar X (G^0 = identity) in client keygen (secp256k1)")
    {
        // Different from canonical infinity: X = G^0 encoded as the identity element.
        // The generator_mul(0) returns the infinity point — test the server rejects it.
        TestSetup testSetup;
        uuid_t uid;
        char keyid[UUID_STR_LEN] = {'\0'};
        const std::string setup_id(keyid);
        uuid_generate_random(uid);
        uuid_unparse(uid, keyid);

        fbc::bam_ecdsa_cosigner::server_setup_shared_data setup;
        commitments_sha256_t B;
        fbc::bam_ecdsa_cosigner::client_key_shared_data client_message;

        REQUIRE_NOTHROW(testSetup.server.generate_setup_with_proof(setup_id, get_tenant_id(), ECDSA_SECP256K1, setup));
        REQUIRE_NOTHROW(testSetup.client.start_new_key_generation(setup_id, keyid, get_tenant_id(), server_id, client_id, ECDSA_SECP256K1));
        REQUIRE_NOTHROW(testSetup.server.generate_share_and_commit(setup_id, keyid, server_id, client_id, ECDSA_SECP256K1, B));
        REQUIRE_NOTHROW(testSetup.client.verify_setup_proof_store_key_commitment_generate_key_proof(setup_id, keyid, server_id, setup, B, client_message));

        // Compute G^0 = infinity point for secp256k1
        elliptic_curve256_algebra_ctx_t* algebra = elliptic_curve256_new_secp256k1_algebra();
        REQUIRE(algebra != nullptr);
        elliptic_curve256_scalar_t zero;
        memset(zero, 0, sizeof(zero));
        elliptic_curve256_point_t identity;
        algebra->generator_mul(algebra, &identity, &zero);
        memcpy(client_message.X, identity, sizeof(elliptic_curve256_point_t));
        elliptic_curve256_algebra_ctx_free(algebra);

        fbc::bam_ecdsa_cosigner::server_key_shared_data server_message;
        REQUIRE_THROWS(testSetup.server.verify_client_proofs_and_decommit_share_with_proof(keyid, client_id, client_message, server_message));
    }

    SECTION("attack: generator point as X (private share = 1) in client keygen (secp256k1)")
    {
        // If client sends X = G, that implies private_share = 1, which is trivially known.
        TestSetup testSetup;
        uuid_t uid;
        char keyid[UUID_STR_LEN] = {'\0'};
        const std::string setup_id(keyid);
        uuid_generate_random(uid);
        uuid_unparse(uid, keyid);

        fbc::bam_ecdsa_cosigner::server_setup_shared_data setup;
        commitments_sha256_t B;
        fbc::bam_ecdsa_cosigner::client_key_shared_data client_message;

        REQUIRE_NOTHROW(testSetup.server.generate_setup_with_proof(setup_id, get_tenant_id(), ECDSA_SECP256K1, setup));
        REQUIRE_NOTHROW(testSetup.client.start_new_key_generation(setup_id, keyid, get_tenant_id(), server_id, client_id, ECDSA_SECP256K1));
        REQUIRE_NOTHROW(testSetup.server.generate_share_and_commit(setup_id, keyid, server_id, client_id, ECDSA_SECP256K1, B));
        REQUIRE_NOTHROW(testSetup.client.verify_setup_proof_store_key_commitment_generate_key_proof(setup_id, keyid, server_id, setup, B, client_message));

        // Replace X with generator point G
        elliptic_curve256_algebra_ctx_t* algebra = elliptic_curve256_new_secp256k1_algebra();
        REQUIRE(algebra != nullptr);
        elliptic_curve256_scalar_t one;
        memset(one, 0, sizeof(one));
        one[sizeof(one) - 1] = 1;
        algebra->generator_mul(algebra, reinterpret_cast<elliptic_curve256_point_t*>(&client_message.X), &one);
        elliptic_curve256_algebra_ctx_free(algebra);

        fbc::bam_ecdsa_cosigner::server_key_shared_data server_message;
        // Server should reject because Schnorr proof won't match the new X
        REQUIRE_THROWS(testSetup.server.verify_client_proofs_and_decommit_share_with_proof(keyid, client_id, client_message, server_message));
    }

    SECTION("attack: corrupted Damgard-Fujisaki public key in client keygen (secp256k1)")
    {
        TestSetup testSetup;
        uuid_t uid;
        char keyid[UUID_STR_LEN] = {'\0'};
        const std::string setup_id(keyid);
        uuid_generate_random(uid);
        uuid_unparse(uid, keyid);

        fbc::bam_ecdsa_cosigner::server_setup_shared_data setup;
        commitments_sha256_t B;
        fbc::bam_ecdsa_cosigner::client_key_shared_data client_message;

        REQUIRE_NOTHROW(testSetup.server.generate_setup_with_proof(setup_id, get_tenant_id(), ECDSA_SECP256K1, setup));
        REQUIRE_NOTHROW(testSetup.client.start_new_key_generation(setup_id, keyid, get_tenant_id(), server_id, client_id, ECDSA_SECP256K1));
        REQUIRE_NOTHROW(testSetup.server.generate_share_and_commit(setup_id, keyid, server_id, client_id, ECDSA_SECP256K1, B));
        REQUIRE_NOTHROW(testSetup.client.verify_setup_proof_store_key_commitment_generate_key_proof(setup_id, keyid, server_id, setup, B, client_message));

        // Flip bytes in the DF public key
        for (size_t i = 0; i < client_message.damgard_fujisaki_pub.size() && i < 16; i++) {
            client_message.damgard_fujisaki_pub[i] ^= 0xFF;
        }

        fbc::bam_ecdsa_cosigner::server_key_shared_data server_message;
        REQUIRE_THROWS(testSetup.server.verify_client_proofs_and_decommit_share_with_proof(keyid, client_id, client_message, server_message));
    }


    SECTION("attack: truncated Damgard-Fujisaki public key in client keygen (secp256k1)")
    {
        TestSetup testSetup;
        uuid_t uid;
        char keyid[UUID_STR_LEN] = {'\0'};
        const std::string setup_id(keyid);
        uuid_generate_random(uid);
        uuid_unparse(uid, keyid);

        fbc::bam_ecdsa_cosigner::server_setup_shared_data setup;
        commitments_sha256_t B;
        fbc::bam_ecdsa_cosigner::client_key_shared_data client_message;

        REQUIRE_NOTHROW(testSetup.server.generate_setup_with_proof(setup_id, get_tenant_id(), ECDSA_SECP256K1, setup));
        REQUIRE_NOTHROW(testSetup.client.start_new_key_generation(setup_id, keyid, get_tenant_id(), server_id, client_id, ECDSA_SECP256K1));
        REQUIRE_NOTHROW(testSetup.server.generate_share_and_commit(setup_id, keyid, server_id, client_id, ECDSA_SECP256K1, B));
        REQUIRE_NOTHROW(testSetup.client.verify_setup_proof_store_key_commitment_generate_key_proof(setup_id, keyid, server_id, setup, B, client_message));

        // Truncate DF pub to half its length
        client_message.damgard_fujisaki_pub.resize(client_message.damgard_fujisaki_pub.size() / 2);

        fbc::bam_ecdsa_cosigner::server_key_shared_data server_message;
        REQUIRE_THROWS(testSetup.server.verify_client_proofs_and_decommit_share_with_proof(keyid, client_id, client_message, server_message));
    }

    SECTION("attack: all-zeros Schnorr proof in client keygen (secp256k1)")
    {
        TestSetup testSetup;
        uuid_t uid;
        char keyid[UUID_STR_LEN] = {'\0'};
        const std::string setup_id(keyid);
        uuid_generate_random(uid);
        uuid_unparse(uid, keyid);

        fbc::bam_ecdsa_cosigner::server_setup_shared_data setup;
        commitments_sha256_t B;
        fbc::bam_ecdsa_cosigner::client_key_shared_data client_message;

        REQUIRE_NOTHROW(testSetup.server.generate_setup_with_proof(setup_id, get_tenant_id(), ECDSA_SECP256K1, setup));
        REQUIRE_NOTHROW(testSetup.client.start_new_key_generation(setup_id, keyid, get_tenant_id(), server_id, client_id, ECDSA_SECP256K1));
        REQUIRE_NOTHROW(testSetup.server.generate_share_and_commit(setup_id, keyid, server_id, client_id, ECDSA_SECP256K1, B));
        REQUIRE_NOTHROW(testSetup.client.verify_setup_proof_store_key_commitment_generate_key_proof(setup_id, keyid, server_id, setup, B, client_message));

        // Zero out the entire Schnorr proof
        std::fill(client_message.schnorr_proof.begin(), client_message.schnorr_proof.end(), 0);

        fbc::bam_ecdsa_cosigner::server_key_shared_data server_message;
        REQUIRE_THROWS(testSetup.server.verify_client_proofs_and_decommit_share_with_proof(keyid, client_id, client_message, server_message));
    }

    SECTION("attack: swapped Schnorr proof fields (R and s) in client keygen (secp256k1)")
    {
        TestSetup testSetup;
        uuid_t uid;
        char keyid[UUID_STR_LEN] = {'\0'};
        const std::string setup_id(keyid);
        uuid_generate_random(uid);
        uuid_unparse(uid, keyid);

        fbc::bam_ecdsa_cosigner::server_setup_shared_data setup;
        commitments_sha256_t B;
        fbc::bam_ecdsa_cosigner::client_key_shared_data client_message;

        REQUIRE_NOTHROW(testSetup.server.generate_setup_with_proof(setup_id, get_tenant_id(), ECDSA_SECP256K1, setup));
        REQUIRE_NOTHROW(testSetup.client.start_new_key_generation(setup_id, keyid, get_tenant_id(), server_id, client_id, ECDSA_SECP256K1));
        REQUIRE_NOTHROW(testSetup.server.generate_share_and_commit(setup_id, keyid, server_id, client_id, ECDSA_SECP256K1, B));
        REQUIRE_NOTHROW(testSetup.client.verify_setup_proof_store_key_commitment_generate_key_proof(setup_id, keyid, server_id, setup, B, client_message));

        // Swap the first half and second half of the Schnorr proof (approximates swapping R and s)
        if (client_message.schnorr_proof.size() >= 2) {
            size_t mid = client_message.schnorr_proof.size() / 2;
            fbc::byte_vector_t swapped;
            swapped.insert(swapped.end(), client_message.schnorr_proof.begin() + mid, client_message.schnorr_proof.end());
            swapped.insert(swapped.end(), client_message.schnorr_proof.begin(), client_message.schnorr_proof.begin() + mid);
            client_message.schnorr_proof = swapped;
        }

        fbc::bam_ecdsa_cosigner::server_key_shared_data server_message;
        REQUIRE_THROWS(testSetup.server.verify_client_proofs_and_decommit_share_with_proof(keyid, client_id, client_message, server_message));
    }

    // ========================================================================
    // B. Malicious Server — Keygen Attacks
    // ========================================================================

    SECTION("attack: zero-length encrypted_server_share in keygen (secp256k1)")
    {
        TestSetup testSetup;
        uuid_t uid;
        char keyid[UUID_STR_LEN] = {'\0'};
        const std::string setup_id(keyid);
        uuid_generate_random(uid);
        uuid_unparse(uid, keyid);

        fbc::bam_ecdsa_cosigner::server_setup_shared_data setup;
        commitments_sha256_t B;
        fbc::bam_ecdsa_cosigner::client_key_shared_data client_message;
        fbc::bam_ecdsa_cosigner::server_key_shared_data server_message;
        fbc::bam_ecdsa_cosigner::generated_public_key generated_public_key;

        REQUIRE_NOTHROW(testSetup.server.generate_setup_with_proof(setup_id, get_tenant_id(), ECDSA_SECP256K1, setup));
        REQUIRE_NOTHROW(testSetup.client.start_new_key_generation(setup_id, keyid, get_tenant_id(), server_id, client_id, ECDSA_SECP256K1));
        REQUIRE_NOTHROW(testSetup.server.generate_share_and_commit(setup_id, keyid, server_id, client_id, ECDSA_SECP256K1, B));
        REQUIRE_NOTHROW(testSetup.client.verify_setup_proof_store_key_commitment_generate_key_proof(setup_id, keyid, server_id, setup, B, client_message));
        REQUIRE_NOTHROW(testSetup.server.verify_client_proofs_and_decommit_share_with_proof(keyid, client_id, client_message, server_message));

        // Empty ciphertext
        server_message.encrypted_server_share.clear();

        REQUIRE_THROWS(testSetup.client.verify_key_decommitment_and_proofs(keyid, server_id, client_id, server_message, generated_public_key));
    }

    SECTION("attack: all-zeros enc_dlog_proof in keygen (secp256k1)")
    {
        TestSetup testSetup;
        uuid_t uid;
        char keyid[UUID_STR_LEN] = {'\0'};
        const std::string setup_id(keyid);
        uuid_generate_random(uid);
        uuid_unparse(uid, keyid);

        fbc::bam_ecdsa_cosigner::server_setup_shared_data setup;
        commitments_sha256_t B;
        fbc::bam_ecdsa_cosigner::client_key_shared_data client_message;
        fbc::bam_ecdsa_cosigner::server_key_shared_data server_message;
        fbc::bam_ecdsa_cosigner::generated_public_key generated_public_key;

        REQUIRE_NOTHROW(testSetup.server.generate_setup_with_proof(setup_id, get_tenant_id(), ECDSA_SECP256K1, setup));
        REQUIRE_NOTHROW(testSetup.client.start_new_key_generation(setup_id, keyid, get_tenant_id(), server_id, client_id, ECDSA_SECP256K1));
        REQUIRE_NOTHROW(testSetup.server.generate_share_and_commit(setup_id, keyid, server_id, client_id, ECDSA_SECP256K1, B));
        REQUIRE_NOTHROW(testSetup.client.verify_setup_proof_store_key_commitment_generate_key_proof(setup_id, keyid, server_id, setup, B, client_message));
        REQUIRE_NOTHROW(testSetup.server.verify_client_proofs_and_decommit_share_with_proof(keyid, client_id, client_message, server_message));

        // Zero out the proof
        std::fill(server_message.enc_dlog_proof.begin(), server_message.enc_dlog_proof.end(), 0);

        REQUIRE_THROWS(testSetup.client.verify_key_decommitment_and_proofs(keyid, server_id, client_id, server_message, generated_public_key));
    }

    SECTION("attack: server public share = generator G in keygen (secp256k1)")
    {
        TestSetup testSetup;
        uuid_t uid;
        char keyid[UUID_STR_LEN] = {'\0'};
        const std::string setup_id(keyid);
        uuid_generate_random(uid);
        uuid_unparse(uid, keyid);

        fbc::bam_ecdsa_cosigner::server_setup_shared_data setup;
        commitments_sha256_t B;
        fbc::bam_ecdsa_cosigner::client_key_shared_data client_message;
        fbc::bam_ecdsa_cosigner::server_key_shared_data server_message;
        fbc::bam_ecdsa_cosigner::generated_public_key generated_public_key;

        REQUIRE_NOTHROW(testSetup.server.generate_setup_with_proof(setup_id, get_tenant_id(), ECDSA_SECP256K1, setup));
        REQUIRE_NOTHROW(testSetup.client.start_new_key_generation(setup_id, keyid, get_tenant_id(), server_id, client_id, ECDSA_SECP256K1));
        REQUIRE_NOTHROW(testSetup.server.generate_share_and_commit(setup_id, keyid, server_id, client_id, ECDSA_SECP256K1, B));
        REQUIRE_NOTHROW(testSetup.client.verify_setup_proof_store_key_commitment_generate_key_proof(setup_id, keyid, server_id, setup, B, client_message));
        REQUIRE_NOTHROW(testSetup.server.verify_client_proofs_and_decommit_share_with_proof(keyid, client_id, client_message, server_message));

        // Replace server_public_share with G (server private = 1)
        elliptic_curve256_algebra_ctx_t* algebra = elliptic_curve256_new_secp256k1_algebra();
        REQUIRE(algebra != nullptr);
        elliptic_curve256_scalar_t one;
        memset(one, 0, sizeof(one));
        one[sizeof(one) - 1] = 1;
        algebra->generator_mul(algebra, reinterpret_cast<elliptic_curve256_point_t*>(&server_message.server_public_share), &one);
        elliptic_curve256_algebra_ctx_free(algebra);

        // Client should reject because proof won't match the new public share
        REQUIRE_THROWS(testSetup.client.verify_key_decommitment_and_proofs(keyid, server_id, client_id, server_message, generated_public_key));
    }

    // ========================================================================
    // C. Malicious Client — Signing Attacks
    // ========================================================================

    SECTION("attack: all-zeros common_R in partial signature (secp256k1)")
    {
        TestSetup testSetup;
        uuid_t uid;
        char keyid[UUID_STR_LEN] = {'\0'};
        char txid[UUID_STR_LEN] = {'\0'};
        const std::string setup_id(keyid);
        uuid_generate_random(uid);
        uuid_unparse(uid, keyid);
        uuid_generate_random(uid);
        uuid_unparse(uid, txid);

        elliptic_curve256_scalar_t hash;
        REQUIRE(RAND_bytes(hash, sizeof(hash)));

        elliptic_curve256_point_t X1, X2;
        bam_key_generation(setup_id, keyid, client_id, server_id, testSetup.server, testSetup.client, ECDSA_SECP256K1, X1, X2);

        fbc::signing_data data_to_sign = {{0}, {{ fbc::byte_vector_t(&hash[0], &hash[sizeof(hash)]), { 44, 0, 0, 0, 0} }}};

        std::vector<fbc::bam_ecdsa_cosigner::server_signature_shared_data> server_shares;
        std::vector<fbc::bam_ecdsa_cosigner::client_partial_signature_data> partial_signatures;
        std::vector<fbc::recoverable_signature> full_signatures;
        cosigner_sign_algorithm signature_algorithm;

        REQUIRE_NOTHROW(testSetup.client.prepare_for_signature(keyid, txid, 0, server_id, client_id, data_to_sign, "", std::set<std::string>()));
        REQUIRE_NOTHROW(testSetup.server.generate_signature_share(keyid, txid, 0, server_id, client_id, ECDSA_SECP256K1, data_to_sign, "", std::set<std::string>(), server_shares));
        REQUIRE_NOTHROW(testSetup.client.compute_partial_signature(txid, server_shares, partial_signatures));
        REQUIRE(partial_signatures.size() == 1);

        // Zero out common_R (the DH product G^(k_client * k_server))
        memset(partial_signatures[0].common_R, 0, sizeof(elliptic_curve256_point_t));

        REQUIRE_THROWS(testSetup.server.verify_partial_signature_and_output_signature(txid, client_id, partial_signatures, full_signatures, signature_algorithm));
    }

    SECTION("attack: generator point as client_R (k_client = 1) in signing (secp256k1)")
    {
        TestSetup testSetup;
        uuid_t uid;
        char keyid[UUID_STR_LEN] = {'\0'};
        char txid[UUID_STR_LEN] = {'\0'};
        const std::string setup_id(keyid);
        uuid_generate_random(uid);
        uuid_unparse(uid, keyid);
        uuid_generate_random(uid);
        uuid_unparse(uid, txid);

        elliptic_curve256_scalar_t hash;
        REQUIRE(RAND_bytes(hash, sizeof(hash)));

        elliptic_curve256_point_t X1, X2;
        bam_key_generation(setup_id, keyid, client_id, server_id, testSetup.server, testSetup.client, ECDSA_SECP256K1, X1, X2);

        fbc::signing_data data_to_sign = {{0}, {{ fbc::byte_vector_t(&hash[0], &hash[sizeof(hash)]), { 44, 0, 0, 0, 0} }}};

        std::vector<fbc::bam_ecdsa_cosigner::server_signature_shared_data> server_shares;
        std::vector<fbc::bam_ecdsa_cosigner::client_partial_signature_data> partial_signatures;
        std::vector<fbc::recoverable_signature> full_signatures;
        cosigner_sign_algorithm signature_algorithm;

        REQUIRE_NOTHROW(testSetup.client.prepare_for_signature(keyid, txid, 0, server_id, client_id, data_to_sign, "", std::set<std::string>()));
        REQUIRE_NOTHROW(testSetup.server.generate_signature_share(keyid, txid, 0, server_id, client_id, ECDSA_SECP256K1, data_to_sign, "", std::set<std::string>(), server_shares));
        REQUIRE_NOTHROW(testSetup.client.compute_partial_signature(txid, server_shares, partial_signatures));
        REQUIRE(partial_signatures.size() == 1);

        // Replace client_R with G (known nonce k_client = 1)
        elliptic_curve256_algebra_ctx_t* algebra = elliptic_curve256_new_secp256k1_algebra();
        REQUIRE(algebra != nullptr);
        elliptic_curve256_scalar_t one;
        memset(one, 0, sizeof(one));
        one[sizeof(one) - 1] = 1;
        algebra->generator_mul(algebra, reinterpret_cast<elliptic_curve256_point_t*>(&partial_signatures[0].client_R), &one);
        elliptic_curve256_algebra_ctx_free(algebra);

        REQUIRE_THROWS(testSetup.server.verify_partial_signature_and_output_signature(txid, client_id, partial_signatures, full_signatures, signature_algorithm));
    }

    SECTION("attack: client_R from wrong curve (secp256r1 point in secp256k1 signing)")
    {
        TestSetup testSetup;
        uuid_t uid;
        char keyid[UUID_STR_LEN] = {'\0'};
        char txid[UUID_STR_LEN] = {'\0'};
        const std::string setup_id(keyid);
        uuid_generate_random(uid);
        uuid_unparse(uid, keyid);
        uuid_generate_random(uid);
        uuid_unparse(uid, txid);

        elliptic_curve256_scalar_t hash;
        REQUIRE(RAND_bytes(hash, sizeof(hash)));

        elliptic_curve256_point_t X1, X2;
        bam_key_generation(setup_id, keyid, client_id, server_id, testSetup.server, testSetup.client, ECDSA_SECP256K1, X1, X2);

        fbc::signing_data data_to_sign = {{0}, {{ fbc::byte_vector_t(&hash[0], &hash[sizeof(hash)]), { 44, 0, 0, 0, 0} }}};

        std::vector<fbc::bam_ecdsa_cosigner::server_signature_shared_data> server_shares;
        std::vector<fbc::bam_ecdsa_cosigner::client_partial_signature_data> partial_signatures;
        std::vector<fbc::recoverable_signature> full_signatures;
        cosigner_sign_algorithm signature_algorithm;

        REQUIRE_NOTHROW(testSetup.client.prepare_for_signature(keyid, txid, 0, server_id, client_id, data_to_sign, "", std::set<std::string>()));
        REQUIRE_NOTHROW(testSetup.server.generate_signature_share(keyid, txid, 0, server_id, client_id, ECDSA_SECP256K1, data_to_sign, "", std::set<std::string>(), server_shares));
        REQUIRE_NOTHROW(testSetup.client.compute_partial_signature(txid, server_shares, partial_signatures));
        REQUIRE(partial_signatures.size() == 1);

        // Generate a point on secp256r1 and inject it as client_R
        elliptic_curve256_algebra_ctx_t* r1 = elliptic_curve256_new_secp256r1_algebra();
        REQUIRE(r1 != nullptr);
        elliptic_curve256_scalar_t three = {0};
        three[sizeof(three) - 1] = 3;
        r1->generator_mul(r1, reinterpret_cast<elliptic_curve256_point_t*>(&partial_signatures[0].client_R), &three);
        elliptic_curve256_algebra_ctx_free(r1);

        REQUIRE_THROWS(testSetup.server.verify_partial_signature_and_output_signature(txid, client_id, partial_signatures, full_signatures, signature_algorithm));
    }

    SECTION("attack: random bytes as encrypted_partial_sig (valid length) in signing (secp256k1)")
    {
        TestSetup testSetup;
        uuid_t uid;
        char keyid[UUID_STR_LEN] = {'\0'};
        char txid[UUID_STR_LEN] = {'\0'};
        const std::string setup_id(keyid);
        uuid_generate_random(uid);
        uuid_unparse(uid, keyid);
        uuid_generate_random(uid);
        uuid_unparse(uid, txid);

        elliptic_curve256_scalar_t hash;
        REQUIRE(RAND_bytes(hash, sizeof(hash)));

        elliptic_curve256_point_t X1, X2;
        bam_key_generation(setup_id, keyid, client_id, server_id, testSetup.server, testSetup.client, ECDSA_SECP256K1, X1, X2);

        fbc::signing_data data_to_sign = {{0}, {{ fbc::byte_vector_t(&hash[0], &hash[sizeof(hash)]), { 44, 0, 0, 0, 0} }}};

        std::vector<fbc::bam_ecdsa_cosigner::server_signature_shared_data> server_shares;
        std::vector<fbc::bam_ecdsa_cosigner::client_partial_signature_data> partial_signatures;
        std::vector<fbc::recoverable_signature> full_signatures;
        cosigner_sign_algorithm signature_algorithm;

        REQUIRE_NOTHROW(testSetup.client.prepare_for_signature(keyid, txid, 0, server_id, client_id, data_to_sign, "", std::set<std::string>()));
        REQUIRE_NOTHROW(testSetup.server.generate_signature_share(keyid, txid, 0, server_id, client_id, ECDSA_SECP256K1, data_to_sign, "", std::set<std::string>(), server_shares));
        REQUIRE_NOTHROW(testSetup.client.compute_partial_signature(txid, server_shares, partial_signatures));
        REQUIRE(partial_signatures.size() == 1);

        // Replace encrypted_partial_sig with random bytes of same length
        size_t orig_len = partial_signatures[0].encrypted_partial_sig.size();
        partial_signatures[0].encrypted_partial_sig.resize(orig_len);
        RAND_bytes(partial_signatures[0].encrypted_partial_sig.data(), orig_len);

        REQUIRE_THROWS(testSetup.server.verify_partial_signature_and_output_signature(txid, client_id, partial_signatures, full_signatures, signature_algorithm));
    }

    SECTION("attack: zero-length sig_proof in signing (secp256k1)")
    {
        TestSetup testSetup;
        uuid_t uid;
        char keyid[UUID_STR_LEN] = {'\0'};
        char txid[UUID_STR_LEN] = {'\0'};
        const std::string setup_id(keyid);
        uuid_generate_random(uid);
        uuid_unparse(uid, keyid);
        uuid_generate_random(uid);
        uuid_unparse(uid, txid);

        elliptic_curve256_scalar_t hash;
        REQUIRE(RAND_bytes(hash, sizeof(hash)));

        elliptic_curve256_point_t X1, X2;
        bam_key_generation(setup_id, keyid, client_id, server_id, testSetup.server, testSetup.client, ECDSA_SECP256K1, X1, X2);

        fbc::signing_data data_to_sign = {{0}, {{ fbc::byte_vector_t(&hash[0], &hash[sizeof(hash)]), { 44, 0, 0, 0, 0} }}};

        std::vector<fbc::bam_ecdsa_cosigner::server_signature_shared_data> server_shares;
        std::vector<fbc::bam_ecdsa_cosigner::client_partial_signature_data> partial_signatures;
        std::vector<fbc::recoverable_signature> full_signatures;
        cosigner_sign_algorithm signature_algorithm;

        REQUIRE_NOTHROW(testSetup.client.prepare_for_signature(keyid, txid, 0, server_id, client_id, data_to_sign, "", std::set<std::string>()));
        REQUIRE_NOTHROW(testSetup.server.generate_signature_share(keyid, txid, 0, server_id, client_id, ECDSA_SECP256K1, data_to_sign, "", std::set<std::string>(), server_shares));
        REQUIRE_NOTHROW(testSetup.client.compute_partial_signature(txid, server_shares, partial_signatures));
        REQUIRE(partial_signatures.size() == 1);

        // Empty proof
        partial_signatures[0].sig_proof.clear();

        REQUIRE_THROWS(testSetup.server.verify_partial_signature_and_output_signature(txid, client_id, partial_signatures, full_signatures, signature_algorithm));
    }

    SECTION("attack: oversized sig_proof (10x) in signing (secp256k1)")
    {
        TestSetup testSetup;
        uuid_t uid;
        char keyid[UUID_STR_LEN] = {'\0'};
        char txid[UUID_STR_LEN] = {'\0'};
        const std::string setup_id(keyid);
        uuid_generate_random(uid);
        uuid_unparse(uid, keyid);
        uuid_generate_random(uid);
        uuid_unparse(uid, txid);

        elliptic_curve256_scalar_t hash;
        REQUIRE(RAND_bytes(hash, sizeof(hash)));

        elliptic_curve256_point_t X1, X2;
        bam_key_generation(setup_id, keyid, client_id, server_id, testSetup.server, testSetup.client, ECDSA_SECP256K1, X1, X2);

        fbc::signing_data data_to_sign = {{0}, {{ fbc::byte_vector_t(&hash[0], &hash[sizeof(hash)]), { 44, 0, 0, 0, 0} }}};

        std::vector<fbc::bam_ecdsa_cosigner::server_signature_shared_data> server_shares;
        std::vector<fbc::bam_ecdsa_cosigner::client_partial_signature_data> partial_signatures;
        std::vector<fbc::recoverable_signature> full_signatures;
        cosigner_sign_algorithm signature_algorithm;

        REQUIRE_NOTHROW(testSetup.client.prepare_for_signature(keyid, txid, 0, server_id, client_id, data_to_sign, "", std::set<std::string>()));
        REQUIRE_NOTHROW(testSetup.server.generate_signature_share(keyid, txid, 0, server_id, client_id, ECDSA_SECP256K1, data_to_sign, "", std::set<std::string>(), server_shares));
        REQUIRE_NOTHROW(testSetup.client.compute_partial_signature(txid, server_shares, partial_signatures));
        REQUIRE(partial_signatures.size() == 1);

        // 10x oversized random proof data
        size_t oversized = partial_signatures[0].sig_proof.size() * 10;
        partial_signatures[0].sig_proof.resize(oversized);
        RAND_bytes(partial_signatures[0].sig_proof.data(), oversized);

        REQUIRE_THROWS(testSetup.server.verify_partial_signature_and_output_signature(txid, client_id, partial_signatures, full_signatures, signature_algorithm));
    }

    // ========================================================================
    // D. Malicious Server — Signing Attacks
    // ========================================================================

    SECTION("attack: negated server R (-R) in signing (secp256k1)")
    {
        TestSetup testSetup;
        uuid_t uid;
        char keyid[UUID_STR_LEN] = {'\0'};
        char txid[UUID_STR_LEN] = {'\0'};
        const std::string setup_id(keyid);
        uuid_generate_random(uid);
        uuid_unparse(uid, keyid);
        uuid_generate_random(uid);
        uuid_unparse(uid, txid);

        elliptic_curve256_scalar_t hash;
        REQUIRE(RAND_bytes(hash, sizeof(hash)));

        elliptic_curve256_point_t X1, X2;
        bam_key_generation(setup_id, keyid, client_id, server_id, testSetup.server, testSetup.client, ECDSA_SECP256K1, X1, X2);

        fbc::signing_data data_to_sign = {{0}, {{ fbc::byte_vector_t(&hash[0], &hash[sizeof(hash)]), { 44, 0, 0, 0, 0} }}};

        std::vector<fbc::bam_ecdsa_cosigner::server_signature_shared_data> server_shares;
        std::vector<fbc::bam_ecdsa_cosigner::client_partial_signature_data> partial_signatures;

        REQUIRE_NOTHROW(testSetup.client.prepare_for_signature(keyid, txid, 0, server_id, client_id, data_to_sign, "", std::set<std::string>()));
        REQUIRE_NOTHROW(testSetup.server.generate_signature_share(keyid, txid, 0, server_id, client_id, ECDSA_SECP256K1, data_to_sign, "", std::set<std::string>(), server_shares));
        REQUIRE(server_shares.size() == 1);

        // Negate R by flipping parity byte
        if (server_shares[0].R[0] == 0x02) {
            server_shares[0].R[0] = 0x03;
        } else if (server_shares[0].R[0] == 0x03) {
            server_shares[0].R[0] = 0x02;
        }

        // Client should reject the inconsistent DH pair (R, Y)
        REQUIRE_THROWS(testSetup.client.compute_partial_signature(txid, server_shares, partial_signatures));
    }

    SECTION("attack: Y doesn't match R (inconsistent DH pair) in signing (secp256k1)")
    {
        TestSetup testSetup;
        uuid_t uid;
        char keyid[UUID_STR_LEN] = {'\0'};
        char txid[UUID_STR_LEN] = {'\0'};
        const std::string setup_id(keyid);
        uuid_generate_random(uid);
        uuid_unparse(uid, keyid);
        uuid_generate_random(uid);
        uuid_unparse(uid, txid);

        elliptic_curve256_scalar_t hash;
        REQUIRE(RAND_bytes(hash, sizeof(hash)));

        elliptic_curve256_point_t X1, X2;
        bam_key_generation(setup_id, keyid, client_id, server_id, testSetup.server, testSetup.client, ECDSA_SECP256K1, X1, X2);

        fbc::signing_data data_to_sign = {{0}, {{ fbc::byte_vector_t(&hash[0], &hash[sizeof(hash)]), { 44, 0, 0, 0, 0} }}};

        std::vector<fbc::bam_ecdsa_cosigner::server_signature_shared_data> server_shares;
        std::vector<fbc::bam_ecdsa_cosigner::client_partial_signature_data> partial_signatures;

        REQUIRE_NOTHROW(testSetup.client.prepare_for_signature(keyid, txid, 0, server_id, client_id, data_to_sign, "", std::set<std::string>()));
        REQUIRE_NOTHROW(testSetup.server.generate_signature_share(keyid, txid, 0, server_id, client_id, ECDSA_SECP256K1, data_to_sign, "", std::set<std::string>(), server_shares));
        REQUIRE(server_shares.size() == 1);

        // Keep R valid, replace Y with a random valid point
        elliptic_curve256_algebra_ctx_t* algebra = elliptic_curve256_new_secp256k1_algebra();
        REQUIRE(algebra != nullptr);
        elliptic_curve256_scalar_t rand_scalar = {0};
        rand_scalar[sizeof(rand_scalar) - 1] = 42;
        algebra->generator_mul(algebra, reinterpret_cast<elliptic_curve256_point_t*>(&server_shares[0].Y), &rand_scalar);
        elliptic_curve256_algebra_ctx_free(algebra);

        REQUIRE_THROWS(testSetup.client.compute_partial_signature(txid, server_shares, partial_signatures));
    }

    SECTION("attack: R and Y swapped in server signing shares (secp256k1)")
    {
        TestSetup testSetup;
        uuid_t uid;
        char keyid[UUID_STR_LEN] = {'\0'};
        char txid[UUID_STR_LEN] = {'\0'};
        const std::string setup_id(keyid);
        uuid_generate_random(uid);
        uuid_unparse(uid, keyid);
        uuid_generate_random(uid);
        uuid_unparse(uid, txid);

        elliptic_curve256_scalar_t hash;
        REQUIRE(RAND_bytes(hash, sizeof(hash)));

        elliptic_curve256_point_t X1, X2;
        bam_key_generation(setup_id, keyid, client_id, server_id, testSetup.server, testSetup.client, ECDSA_SECP256K1, X1, X2);

        fbc::signing_data data_to_sign = {{0}, {{ fbc::byte_vector_t(&hash[0], &hash[sizeof(hash)]), { 44, 0, 0, 0, 0} }}};

        std::vector<fbc::bam_ecdsa_cosigner::server_signature_shared_data> server_shares;
        std::vector<fbc::bam_ecdsa_cosigner::client_partial_signature_data> partial_signatures;

        REQUIRE_NOTHROW(testSetup.client.prepare_for_signature(keyid, txid, 0, server_id, client_id, data_to_sign, "", std::set<std::string>()));
        REQUIRE_NOTHROW(testSetup.server.generate_signature_share(keyid, txid, 0, server_id, client_id, ECDSA_SECP256K1, data_to_sign, "", std::set<std::string>(), server_shares));
        REQUIRE(server_shares.size() == 1);

        // Swap R and Y
        elliptic_curve256_point_t tmp;
        memcpy(tmp, server_shares[0].R, sizeof(elliptic_curve256_point_t));
        memcpy(server_shares[0].R, server_shares[0].Y, sizeof(elliptic_curve256_point_t));
        memcpy(server_shares[0].Y, tmp, sizeof(elliptic_curve256_point_t));

        REQUIRE_THROWS(testSetup.client.compute_partial_signature(txid, server_shares, partial_signatures));
    }

    SECTION("attack: zero-length server R and Y in signing (secp256k1)")
    {
        TestSetup testSetup;
        uuid_t uid;
        char keyid[UUID_STR_LEN] = {'\0'};
        char txid[UUID_STR_LEN] = {'\0'};
        const std::string setup_id(keyid);
        uuid_generate_random(uid);
        uuid_unparse(uid, keyid);
        uuid_generate_random(uid);
        uuid_unparse(uid, txid);

        elliptic_curve256_scalar_t hash;
        REQUIRE(RAND_bytes(hash, sizeof(hash)));

        elliptic_curve256_point_t X1, X2;
        bam_key_generation(setup_id, keyid, client_id, server_id, testSetup.server, testSetup.client, ECDSA_SECP256K1, X1, X2);

        fbc::signing_data data_to_sign = {{0}, {{ fbc::byte_vector_t(&hash[0], &hash[sizeof(hash)]), { 44, 0, 0, 0, 0} }}};

        std::vector<fbc::bam_ecdsa_cosigner::server_signature_shared_data> server_shares;
        std::vector<fbc::bam_ecdsa_cosigner::client_partial_signature_data> partial_signatures;

        REQUIRE_NOTHROW(testSetup.client.prepare_for_signature(keyid, txid, 0, server_id, client_id, data_to_sign, "", std::set<std::string>()));
        REQUIRE_NOTHROW(testSetup.server.generate_signature_share(keyid, txid, 0, server_id, client_id, ECDSA_SECP256K1, data_to_sign, "", std::set<std::string>(), server_shares));
        REQUIRE(server_shares.size() == 1);

        // Zero both R and Y
        memset(server_shares[0].R, 0, sizeof(elliptic_curve256_point_t));
        memset(server_shares[0].Y, 0, sizeof(elliptic_curve256_point_t));

        REQUIRE_THROWS(testSetup.client.compute_partial_signature(txid, server_shares, partial_signatures));
    }

    // ========================================================================
    // E. Protocol State Attacks
    // ========================================================================

    SECTION("attack: double keygen with same key_id (secp256k1)")
    {
        TestSetup testSetup;
        uuid_t uid;
        char keyid[UUID_STR_LEN] = {'\0'};
        const std::string setup_id(keyid);
        uuid_generate_random(uid);
        uuid_unparse(uid, keyid);

        elliptic_curve256_point_t X1, X2;
        // First keygen succeeds
        bam_key_generation(setup_id, keyid, client_id, server_id, testSetup.server, testSetup.client, ECDSA_SECP256K1, X1, X2);

        // Second keygen with same key_id should fail
        fbc::bam_ecdsa_cosigner::server_setup_shared_data setup2;
        commitments_sha256_t B2;
        bool threw = false;
        try {
            testSetup.server.generate_setup_with_proof(setup_id, get_tenant_id(), ECDSA_SECP256K1, setup2);
            testSetup.client.start_new_key_generation(setup_id, keyid, get_tenant_id(), server_id, client_id, ECDSA_SECP256K1);
            testSetup.server.generate_share_and_commit(setup_id, keyid, server_id, client_id, ECDSA_SECP256K1, B2);
        } catch (...) {
            threw = true;
        }
        // Either throws (expected: key already exists) or we get a duplicate key error later
        // The test verifies the system handles duplicate key IDs without undefined behavior
        REQUIRE(threw);
    }

    SECTION("attack: sign with derivation path after keygen without derivation (secp256k1)")
    {
        TestSetup testSetup;
        uuid_t uid;
        char keyid[UUID_STR_LEN] = {'\0'};
        char txid[UUID_STR_LEN] = {'\0'};
        const std::string setup_id(keyid);
        uuid_generate_random(uid);
        uuid_unparse(uid, keyid);
        uuid_generate_random(uid);
        uuid_unparse(uid, txid);

        elliptic_curve256_point_t X1, X2;
        bam_key_generation(setup_id, keyid, client_id, server_id, testSetup.server, testSetup.client, ECDSA_SECP256K1, X1, X2);

        elliptic_curve256_scalar_t hash;
        REQUIRE(RAND_bytes(hash, sizeof(hash)));

        // Use a BIP44 path (must be exactly 5 elements per BIP44_PATH_LENGTH) with
        // unusual values — high hardened indices to test edge cases in HD derivation.
        // Note: assert(path.size() == BIP44_PATH_LENGTH) in bam_ecdsa_cosigner.cpp:210
        // would crash on non-5-element paths (same assert-before-error pattern as bugs #3,#6).
        fbc::signing_data data_to_sign = {{0}, {{ fbc::byte_vector_t(&hash[0], &hash[sizeof(hash)]), { 44 | 0x80000000, 60 | 0x80000000, 0x80000000, 0, 0xFFFFFFFF} }}};

        fbc::recoverable_signature signature { 0 };
        // The signing should still work (HD derivation is applied at signing time), but
        // this tests that unusual hardened path values don't cause crashes
        REQUIRE_NOTHROW(bam_key_sign(setup_id, keyid, txid, client_id, data_to_sign, "", testSetup.server, testSetup.client, signature, ECDSA_SECP256K1));
    }

    SECTION("attack: mixed valid/invalid messages in batch signing (secp256k1)")
    {
        TestSetup testSetup;
        uuid_t uid;
        char keyid[UUID_STR_LEN] = {'\0'};
        char txid[UUID_STR_LEN] = {'\0'};
        const std::string setup_id(keyid);
        uuid_generate_random(uid);
        uuid_unparse(uid, keyid);
        uuid_generate_random(uid);
        uuid_unparse(uid, txid);

        elliptic_curve256_scalar_t hash;
        REQUIRE(RAND_bytes(hash, sizeof(hash)));

        elliptic_curve256_point_t X1, X2;
        bam_key_generation(setup_id, keyid, client_id, server_id, testSetup.server, testSetup.client, ECDSA_SECP256K1, X1, X2);

        fbc::signing_data data_to_sign = {{0}, {{ fbc::byte_vector_t(&hash[0], &hash[sizeof(hash)]), { 44, 0, 0, 0, 0} }}};

        std::vector<fbc::bam_ecdsa_cosigner::server_signature_shared_data> server_shares;
        std::vector<fbc::bam_ecdsa_cosigner::client_partial_signature_data> partial_signatures;
        std::vector<fbc::recoverable_signature> full_signatures;
        cosigner_sign_algorithm signature_algorithm;

        REQUIRE_NOTHROW(testSetup.client.prepare_for_signature(keyid, txid, 0, server_id, client_id, data_to_sign, "", std::set<std::string>()));
        REQUIRE_NOTHROW(testSetup.server.generate_signature_share(keyid, txid, 0, server_id, client_id, ECDSA_SECP256K1, data_to_sign, "", std::set<std::string>(), server_shares));
        REQUIRE_NOTHROW(testSetup.client.compute_partial_signature(txid, server_shares, partial_signatures));
        REQUIRE(partial_signatures.size() == 1);

        // Duplicate the first partial signature and corrupt the second one
        partial_signatures.push_back(partial_signatures[0]);
        memset(partial_signatures[1].client_R, 0, sizeof(elliptic_curve256_point_t));
        partial_signatures[1].client_R[0] = 0x00;
        partial_signatures[1].client_R[1] = 0x01;

        // Server should reject the batch (size mismatch or corrupted entry)
        REQUIRE_THROWS(testSetup.server.verify_partial_signature_and_output_signature(txid, client_id, partial_signatures, full_signatures, signature_algorithm));
    }

    SECTION("attack: cross-algorithm - key generated with secp256k1, signing requested with secp256r1")
    {
        TestSetup testSetup;
        uuid_t uid;
        char keyid[UUID_STR_LEN] = {'\0'};
        char txid[UUID_STR_LEN] = {'\0'};
        const std::string setup_id(keyid);

        uuid_generate_random(uid);
        uuid_unparse(uid, keyid);
        uuid_generate_random(uid);
        uuid_unparse(uid, txid);

        elliptic_curve256_scalar_t hash;
        REQUIRE(RAND_bytes(hash, sizeof(hash)));

        elliptic_curve256_point_t X1, X2;
        bam_key_generation(setup_id, keyid, client_id, server_id, testSetup.server, testSetup.client, ECDSA_SECP256K1, X1, X2);

        fbc::signing_data data_to_sign = {{0}, {{ fbc::byte_vector_t(&hash[0], &hash[sizeof(hash)]), { 44, 0, 0, 0, 0} }}};

        std::vector<fbc::bam_ecdsa_cosigner::server_signature_shared_data> server_shares;

        REQUIRE_NOTHROW(testSetup.client.prepare_for_signature(keyid, txid, 0, server_id, client_id, data_to_sign, "", std::set<std::string>()));
        // Request signing with secp256r1 on a key generated with secp256k1 — must reject
        REQUIRE_THROWS(testSetup.server.generate_signature_share(keyid, txid, 0, server_id, client_id, ECDSA_SECP256R1, data_to_sign, "", std::set<std::string>(), server_shares));
    }

    SECTION("attack: cross-algorithm - key generated with secp256r1, signing requested with secp256k1")
    {
        TestSetup testSetup;
        uuid_t uid;
        char keyid[UUID_STR_LEN] = {'\0'};
        char txid[UUID_STR_LEN] = {'\0'};
        const std::string setup_id(keyid);

        uuid_generate_random(uid);
        uuid_unparse(uid, keyid);
        uuid_generate_random(uid);
        uuid_unparse(uid, txid);

        elliptic_curve256_scalar_t hash;
        REQUIRE(RAND_bytes(hash, sizeof(hash)));

        elliptic_curve256_point_t X1, X2;
        bam_key_generation(setup_id, keyid, client_id, server_id, testSetup.server, testSetup.client, ECDSA_SECP256R1, X1, X2);

        fbc::signing_data data_to_sign = {{0}, {{ fbc::byte_vector_t(&hash[0], &hash[sizeof(hash)]), { 44, 0, 0, 0, 0} }}};

        std::vector<fbc::bam_ecdsa_cosigner::server_signature_shared_data> server_shares;

        REQUIRE_NOTHROW(testSetup.client.prepare_for_signature(keyid, txid, 0, server_id, client_id, data_to_sign, "", std::set<std::string>()));
        // Request signing with secp256k1 on a key generated with secp256r1 — must reject
        REQUIRE_THROWS(testSetup.server.generate_signature_share(keyid, txid, 0, server_id, client_id, ECDSA_SECP256K1, data_to_sign, "", std::set<std::string>(), server_shares));
    }

    // ========================================================================
    // F. Fiat-Shamir Binding / Cross-Context Replay
    //    Academic ref: ePrint 2016/771 (Fiat-Shamir cross-context attacks)
    //    The Schnorr proof hash binds to seed = SHA256(SALT || key_id || ...),
    //    so proofs from one keygen are non-transferable to another.
    // ========================================================================

    SECTION("attack: Schnorr proof cross-key replay - proof from key A used for key B (secp256k1)")
    {
        // Attack: Do 2 keygens. Replay schnorr_proof + X from key A into key B's
        // client_message. The Schnorr hash is bound to seed = SHA256(SALT || key_id || ...),
        // so different key_id => different seed => hash mismatch => server rejects.
        TestSetup testSetup;
        uuid_t uid;

        // --- Key A: complete keygen up to step 2 to get client_message_A ---
        char keyid_a[UUID_STR_LEN] = {'\0'};
        uuid_generate_random(uid);
        uuid_unparse(uid, keyid_a);
        const std::string setup_id_a(keyid_a);

        fbc::bam_ecdsa_cosigner::server_setup_shared_data setup_a;
        commitments_sha256_t B_a;
        fbc::bam_ecdsa_cosigner::client_key_shared_data client_message_a;

        REQUIRE_NOTHROW(testSetup.server.generate_setup_with_proof(setup_id_a, get_tenant_id(), ECDSA_SECP256K1, setup_a));
        REQUIRE_NOTHROW(testSetup.client.start_new_key_generation(setup_id_a, keyid_a, get_tenant_id(), server_id, client_id, ECDSA_SECP256K1));
        REQUIRE_NOTHROW(testSetup.server.generate_share_and_commit(setup_id_a, keyid_a, server_id, client_id, ECDSA_SECP256K1, B_a));
        REQUIRE_NOTHROW(testSetup.client.verify_setup_proof_store_key_commitment_generate_key_proof(setup_id_a, keyid_a, server_id, setup_a, B_a, client_message_a));

        // --- Key B: complete keygen up to step 2, then swap in A's proof + X ---
        char keyid_b[UUID_STR_LEN] = {'\0'};
        uuid_generate_random(uid);
        uuid_unparse(uid, keyid_b);
        const std::string setup_id_b(keyid_b);

        fbc::bam_ecdsa_cosigner::server_setup_shared_data setup_b;
        commitments_sha256_t B_b;
        fbc::bam_ecdsa_cosigner::client_key_shared_data client_message_b;

        REQUIRE_NOTHROW(testSetup.server.generate_setup_with_proof(setup_id_b, get_tenant_id(), ECDSA_SECP256K1, setup_b));
        REQUIRE_NOTHROW(testSetup.client.start_new_key_generation(setup_id_b, keyid_b, get_tenant_id(), server_id, client_id, ECDSA_SECP256K1));
        REQUIRE_NOTHROW(testSetup.server.generate_share_and_commit(setup_id_b, keyid_b, server_id, client_id, ECDSA_SECP256K1, B_b));
        REQUIRE_NOTHROW(testSetup.client.verify_setup_proof_store_key_commitment_generate_key_proof(setup_id_b, keyid_b, server_id, setup_b, B_b, client_message_b));

        // Replay: inject A's schnorr_proof and X into B's client_message
        client_message_b.schnorr_proof = client_message_a.schnorr_proof;
        memcpy(client_message_b.X, client_message_a.X, sizeof(elliptic_curve256_point_t));

        // Server must reject: Schnorr hash seed includes key_id, so proof doesn't verify for key B
        fbc::bam_ecdsa_cosigner::server_key_shared_data server_message_b;
        REQUIRE_THROWS(testSetup.server.verify_client_proofs_and_decommit_share_with_proof(keyid_b, client_id, client_message_b, server_message_b));
    }

    SECTION("attack: enc-dlog proof cross-key replay - server message from key A given to key B client (secp256k1)")
    {
        // Attack: Complete keygen A fully, capture server_message_A.
        // Start keygen B, feed server_message_A at step 4.
        // Commitment check (B != expected) or enc-dlog AAD mismatch rejects it.
        TestSetup testSetup;
        uuid_t uid;

        // --- Key A: full keygen ---
        char keyid_a[UUID_STR_LEN] = {'\0'};
        uuid_generate_random(uid);
        uuid_unparse(uid, keyid_a);
        const std::string setup_id_a(keyid_a);

        fbc::bam_ecdsa_cosigner::server_setup_shared_data setup_a;
        commitments_sha256_t B_a;
        fbc::bam_ecdsa_cosigner::client_key_shared_data client_message_a;
        fbc::bam_ecdsa_cosigner::server_key_shared_data server_message_a;
        fbc::bam_ecdsa_cosigner::generated_public_key gen_pubkey_a;

        REQUIRE_NOTHROW(testSetup.server.generate_setup_with_proof(setup_id_a, get_tenant_id(), ECDSA_SECP256K1, setup_a));
        REQUIRE_NOTHROW(testSetup.client.start_new_key_generation(setup_id_a, keyid_a, get_tenant_id(), server_id, client_id, ECDSA_SECP256K1));
        REQUIRE_NOTHROW(testSetup.server.generate_share_and_commit(setup_id_a, keyid_a, server_id, client_id, ECDSA_SECP256K1, B_a));
        REQUIRE_NOTHROW(testSetup.client.verify_setup_proof_store_key_commitment_generate_key_proof(setup_id_a, keyid_a, server_id, setup_a, B_a, client_message_a));
        REQUIRE_NOTHROW(testSetup.server.verify_client_proofs_and_decommit_share_with_proof(keyid_a, client_id, client_message_a, server_message_a));
        REQUIRE_NOTHROW(testSetup.client.verify_key_decommitment_and_proofs(keyid_a, server_id, client_id, server_message_a, gen_pubkey_a));

        // --- Key B: keygen up to step 3, then feed A's server_message ---
        char keyid_b[UUID_STR_LEN] = {'\0'};
        uuid_generate_random(uid);
        uuid_unparse(uid, keyid_b);
        const std::string setup_id_b(keyid_b);

        fbc::bam_ecdsa_cosigner::server_setup_shared_data setup_b;
        commitments_sha256_t B_b;
        fbc::bam_ecdsa_cosigner::client_key_shared_data client_message_b;
        fbc::bam_ecdsa_cosigner::server_key_shared_data server_message_b;
        fbc::bam_ecdsa_cosigner::generated_public_key gen_pubkey_b;

        REQUIRE_NOTHROW(testSetup.server.generate_setup_with_proof(setup_id_b, get_tenant_id(), ECDSA_SECP256K1, setup_b));
        REQUIRE_NOTHROW(testSetup.client.start_new_key_generation(setup_id_b, keyid_b, get_tenant_id(), server_id, client_id, ECDSA_SECP256K1));
        REQUIRE_NOTHROW(testSetup.server.generate_share_and_commit(setup_id_b, keyid_b, server_id, client_id, ECDSA_SECP256K1, B_b));
        REQUIRE_NOTHROW(testSetup.client.verify_setup_proof_store_key_commitment_generate_key_proof(setup_id_b, keyid_b, server_id, setup_b, B_b, client_message_b));
        REQUIRE_NOTHROW(testSetup.server.verify_client_proofs_and_decommit_share_with_proof(keyid_b, client_id, client_message_b, server_message_b));

        // Feed A's server_message to B's client — commitment mismatch or enc-dlog AAD mismatch
        REQUIRE_THROWS(testSetup.client.verify_key_decommitment_and_proofs(keyid_b, server_id, client_id, server_message_a, gen_pubkey_b));
    }

    SECTION("attack: setup proof replay to different setup_id (secp256k1)")
    {
        // Attack: Generate setup A, replay its proofs under setup_id B.
        // AAD = setup_id || algorithm differs, so Damgard-Fujisaki ZKP rejects.
        TestSetup testSetup;
        uuid_t uid;

        // --- Setup A ---
        char keyid_a[UUID_STR_LEN] = {'\0'};
        uuid_generate_random(uid);
        uuid_unparse(uid, keyid_a);
        const std::string setup_id_a(keyid_a);

        fbc::bam_ecdsa_cosigner::server_setup_shared_data setup_a;
        REQUIRE_NOTHROW(testSetup.server.generate_setup_with_proof(setup_id_a, get_tenant_id(), ECDSA_SECP256K1, setup_a));

        // --- Setup B: use A's setup data with B's identifiers ---
        char keyid_b[UUID_STR_LEN] = {'\0'};
        uuid_generate_random(uid);
        uuid_unparse(uid, keyid_b);
        const std::string setup_id_b(keyid_b);

        commitments_sha256_t B_b;
        fbc::bam_ecdsa_cosigner::client_key_shared_data client_message_b;

        // Generate B's setup (stored server-side), but we'll feed A's proofs to the client
        fbc::bam_ecdsa_cosigner::server_setup_shared_data setup_b;
        REQUIRE_NOTHROW(testSetup.server.generate_setup_with_proof(setup_id_b, get_tenant_id(), ECDSA_SECP256K1, setup_b));
        REQUIRE_NOTHROW(testSetup.client.start_new_key_generation(setup_id_b, keyid_b, get_tenant_id(), server_id, client_id, ECDSA_SECP256K1));
        REQUIRE_NOTHROW(testSetup.server.generate_share_and_commit(setup_id_b, keyid_b, server_id, client_id, ECDSA_SECP256K1, B_b));

        // Client verifies setup_a's proofs under setup_id_b — AAD mismatch should reject
        REQUIRE_THROWS(testSetup.client.verify_setup_proof_store_key_commitment_generate_key_proof(setup_id_b, keyid_b, server_id, setup_a, B_b, client_message_b));
    }

    SECTION("attack: setup proof replay with different algorithm (secp256r1 proof for secp256k1 key)")
    {
        // Attack: Generate setup with secp256r1, use it for secp256k1 key.
        // Algorithm is part of setup AAD, so proof verification fails.
        TestSetup testSetup;
        uuid_t uid;

        char keyid[UUID_STR_LEN] = {'\0'};
        uuid_generate_random(uid);
        uuid_unparse(uid, keyid);
        const std::string setup_id(keyid);

        // Generate setup with secp256r1
        fbc::bam_ecdsa_cosigner::server_setup_shared_data setup_r1;
        REQUIRE_NOTHROW(testSetup.server.generate_setup_with_proof(setup_id, get_tenant_id(), ECDSA_SECP256R1, setup_r1));

        // Try to use it for secp256k1 key generation
        char keyid_k1[UUID_STR_LEN] = {'\0'};
        uuid_generate_random(uid);
        uuid_unparse(uid, keyid_k1);

        commitments_sha256_t B;
        fbc::bam_ecdsa_cosigner::client_key_shared_data client_message;

        REQUIRE_NOTHROW(testSetup.client.start_new_key_generation(setup_id, keyid_k1, get_tenant_id(), server_id, client_id, ECDSA_SECP256K1));
        REQUIRE_NOTHROW(testSetup.server.generate_share_and_commit(setup_id, keyid_k1, server_id, client_id, ECDSA_SECP256K1, B));

        // Client verifies secp256r1 setup proofs for secp256k1 context — algorithm mismatch
        REQUIRE_THROWS(testSetup.client.verify_setup_proof_store_key_commitment_generate_key_proof(setup_id, keyid_k1, server_id, setup_r1, B, client_message));
    }

    // ========================================================================
    // G. Paillier Ciphertext Boundary Values
    //    Academic ref: Paillier malleability / chosen-ciphertext attacks
    //    Tests boundary values for encrypted_partial_sig: zero, one, max.
    // ========================================================================

    SECTION("attack: encrypted_partial_sig = all zeros (Paillier coprime check) (secp256k1)")
    {
        // Attack: Set encrypted_partial_sig to all 0x00.
        // gcd(0, N) = N != 1, so fails is_coprime_fast at bam_well_formed_proof.cpp:366
        // or fails proof verification.
        TestSetup testSetup;
        uuid_t uid;
        char keyid[UUID_STR_LEN] = {'\0'};
        char txid[UUID_STR_LEN] = {'\0'};
        const std::string setup_id(keyid);
        uuid_generate_random(uid);
        uuid_unparse(uid, keyid);
        uuid_generate_random(uid);
        uuid_unparse(uid, txid);

        elliptic_curve256_scalar_t hash;
        REQUIRE(RAND_bytes(hash, sizeof(hash)));

        elliptic_curve256_point_t X1, X2;
        bam_key_generation(setup_id, keyid, client_id, server_id, testSetup.server, testSetup.client, ECDSA_SECP256K1, X1, X2);

        fbc::signing_data data_to_sign = {{0}, {{ fbc::byte_vector_t(&hash[0], &hash[sizeof(hash)]), { 44, 0, 0, 0, 0} }}};

        std::vector<fbc::bam_ecdsa_cosigner::server_signature_shared_data> server_shares;
        std::vector<fbc::bam_ecdsa_cosigner::client_partial_signature_data> partial_signatures;
        std::vector<fbc::recoverable_signature> full_signatures;
        cosigner_sign_algorithm signature_algorithm;

        REQUIRE_NOTHROW(testSetup.client.prepare_for_signature(keyid, txid, 0, server_id, client_id, data_to_sign, "", std::set<std::string>()));
        REQUIRE_NOTHROW(testSetup.server.generate_signature_share(keyid, txid, 0, server_id, client_id, ECDSA_SECP256K1, data_to_sign, "", std::set<std::string>(), server_shares));
        REQUIRE_NOTHROW(testSetup.client.compute_partial_signature(txid, server_shares, partial_signatures));
        REQUIRE(partial_signatures.size() == 1);

        // Replace encrypted_partial_sig with all zeros (same length)
        std::fill(partial_signatures[0].encrypted_partial_sig.begin(),
                  partial_signatures[0].encrypted_partial_sig.end(), 0x00);

        REQUIRE_THROWS(testSetup.server.verify_partial_signature_and_output_signature(txid, client_id, partial_signatures, full_signatures, signature_algorithm));
    }

    SECTION("attack: encrypted_partial_sig = 1 (trivial Paillier ciphertext) (secp256k1)")
    {
        // Attack: Set encrypted_partial_sig to big-endian 1.
        // gcd(1, N) = 1 passes coprime check, but proof verification fails
        // (wrong ciphertext for the committed values).
        TestSetup testSetup;
        uuid_t uid;
        char keyid[UUID_STR_LEN] = {'\0'};
        char txid[UUID_STR_LEN] = {'\0'};
        const std::string setup_id(keyid);
        uuid_generate_random(uid);
        uuid_unparse(uid, keyid);
        uuid_generate_random(uid);
        uuid_unparse(uid, txid);

        elliptic_curve256_scalar_t hash;
        REQUIRE(RAND_bytes(hash, sizeof(hash)));

        elliptic_curve256_point_t X1, X2;
        bam_key_generation(setup_id, keyid, client_id, server_id, testSetup.server, testSetup.client, ECDSA_SECP256K1, X1, X2);

        fbc::signing_data data_to_sign = {{0}, {{ fbc::byte_vector_t(&hash[0], &hash[sizeof(hash)]), { 44, 0, 0, 0, 0} }}};

        std::vector<fbc::bam_ecdsa_cosigner::server_signature_shared_data> server_shares;
        std::vector<fbc::bam_ecdsa_cosigner::client_partial_signature_data> partial_signatures;
        std::vector<fbc::recoverable_signature> full_signatures;
        cosigner_sign_algorithm signature_algorithm;

        REQUIRE_NOTHROW(testSetup.client.prepare_for_signature(keyid, txid, 0, server_id, client_id, data_to_sign, "", std::set<std::string>()));
        REQUIRE_NOTHROW(testSetup.server.generate_signature_share(keyid, txid, 0, server_id, client_id, ECDSA_SECP256K1, data_to_sign, "", std::set<std::string>(), server_shares));
        REQUIRE_NOTHROW(testSetup.client.compute_partial_signature(txid, server_shares, partial_signatures));
        REQUIRE(partial_signatures.size() == 1);

        // Replace encrypted_partial_sig with big-endian 1 (0x00...01)
        std::fill(partial_signatures[0].encrypted_partial_sig.begin(),
                  partial_signatures[0].encrypted_partial_sig.end(), 0x00);
        partial_signatures[0].encrypted_partial_sig.back() = 0x01;

        REQUIRE_THROWS(testSetup.server.verify_partial_signature_and_output_signature(txid, client_id, partial_signatures, full_signatures, signature_algorithm));
    }

    SECTION("attack: encrypted_partial_sig = all 0xFF (large value coprime check) (secp256k1)")
    {
        // Attack: Set all bytes to 0xFF. Value = 2^(8*len)-1.
        // Either fails coprime check (if gcd(val, N) != 1) or proof mismatch.
        TestSetup testSetup;
        uuid_t uid;
        char keyid[UUID_STR_LEN] = {'\0'};
        char txid[UUID_STR_LEN] = {'\0'};
        const std::string setup_id(keyid);
        uuid_generate_random(uid);
        uuid_unparse(uid, keyid);
        uuid_generate_random(uid);
        uuid_unparse(uid, txid);

        elliptic_curve256_scalar_t hash;
        REQUIRE(RAND_bytes(hash, sizeof(hash)));

        elliptic_curve256_point_t X1, X2;
        bam_key_generation(setup_id, keyid, client_id, server_id, testSetup.server, testSetup.client, ECDSA_SECP256K1, X1, X2);

        fbc::signing_data data_to_sign = {{0}, {{ fbc::byte_vector_t(&hash[0], &hash[sizeof(hash)]), { 44, 0, 0, 0, 0} }}};

        std::vector<fbc::bam_ecdsa_cosigner::server_signature_shared_data> server_shares;
        std::vector<fbc::bam_ecdsa_cosigner::client_partial_signature_data> partial_signatures;
        std::vector<fbc::recoverable_signature> full_signatures;
        cosigner_sign_algorithm signature_algorithm;

        REQUIRE_NOTHROW(testSetup.client.prepare_for_signature(keyid, txid, 0, server_id, client_id, data_to_sign, "", std::set<std::string>()));
        REQUIRE_NOTHROW(testSetup.server.generate_signature_share(keyid, txid, 0, server_id, client_id, ECDSA_SECP256K1, data_to_sign, "", std::set<std::string>(), server_shares));
        REQUIRE_NOTHROW(testSetup.client.compute_partial_signature(txid, server_shares, partial_signatures));
        REQUIRE(partial_signatures.size() == 1);

        // Replace encrypted_partial_sig with all 0xFF
        std::fill(partial_signatures[0].encrypted_partial_sig.begin(),
                  partial_signatures[0].encrypted_partial_sig.end(), 0xFF);

        REQUIRE_THROWS(testSetup.server.verify_partial_signature_and_output_signature(txid, client_id, partial_signatures, full_signatures, signature_algorithm));
    }

    // ========================================================================
    // H. DH Consistency with Degenerate Values
    //    Tests server providing crafted R or Y values that try to bypass
    //    the DH consistency check (R^x_client == Y).
    // ========================================================================

    SECTION("attack: server R = client public key X (DH bypass attempt) (secp256k1)")
    {
        // Attack: Set server R to client's X1 from keygen.
        // For DH check to pass, Y = X1^x_client = X1 * x_client, but attacker doesn't know x_client.
        // So Y (the original one from generate_signature_share) won't match.
        TestSetup testSetup;
        uuid_t uid;
        char keyid[UUID_STR_LEN] = {'\0'};
        char txid[UUID_STR_LEN] = {'\0'};
        const std::string setup_id(keyid);
        uuid_generate_random(uid);
        uuid_unparse(uid, keyid);
        uuid_generate_random(uid);
        uuid_unparse(uid, txid);

        elliptic_curve256_scalar_t hash;
        REQUIRE(RAND_bytes(hash, sizeof(hash)));

        elliptic_curve256_point_t X1, X2;
        bam_key_generation(setup_id, keyid, client_id, server_id, testSetup.server, testSetup.client, ECDSA_SECP256K1, X1, X2);

        fbc::signing_data data_to_sign = {{0}, {{ fbc::byte_vector_t(&hash[0], &hash[sizeof(hash)]), { 44, 0, 0, 0, 0} }}};

        std::vector<fbc::bam_ecdsa_cosigner::server_signature_shared_data> server_shares;
        std::vector<fbc::bam_ecdsa_cosigner::client_partial_signature_data> partial_signatures;

        REQUIRE_NOTHROW(testSetup.client.prepare_for_signature(keyid, txid, 0, server_id, client_id, data_to_sign, "", std::set<std::string>()));
        REQUIRE_NOTHROW(testSetup.server.generate_signature_share(keyid, txid, 0, server_id, client_id, ECDSA_SECP256K1, data_to_sign, "", std::set<std::string>(), server_shares));
        REQUIRE(server_shares.size() == 1);

        // Replace R with client's public key X1 — DH pair (X1, Y_original) is inconsistent
        memcpy(server_shares[0].R, X1, sizeof(elliptic_curve256_point_t));

        REQUIRE_THROWS(testSetup.client.compute_partial_signature(txid, server_shares, partial_signatures));
    }

    SECTION("attack: R = Y (degenerate DH pair) in signing (secp256k1)")
    {
        // Attack: Set Y = R. DH check requires R^x_client == Y, i.e. R^x_client == R,
        // which means x_client == 1. Since x_client is random, this fails.
        TestSetup testSetup;
        uuid_t uid;
        char keyid[UUID_STR_LEN] = {'\0'};
        char txid[UUID_STR_LEN] = {'\0'};
        const std::string setup_id(keyid);
        uuid_generate_random(uid);
        uuid_unparse(uid, keyid);
        uuid_generate_random(uid);
        uuid_unparse(uid, txid);

        elliptic_curve256_scalar_t hash;
        REQUIRE(RAND_bytes(hash, sizeof(hash)));

        elliptic_curve256_point_t X1, X2;
        bam_key_generation(setup_id, keyid, client_id, server_id, testSetup.server, testSetup.client, ECDSA_SECP256K1, X1, X2);

        fbc::signing_data data_to_sign = {{0}, {{ fbc::byte_vector_t(&hash[0], &hash[sizeof(hash)]), { 44, 0, 0, 0, 0} }}};

        std::vector<fbc::bam_ecdsa_cosigner::server_signature_shared_data> server_shares;
        std::vector<fbc::bam_ecdsa_cosigner::client_partial_signature_data> partial_signatures;

        REQUIRE_NOTHROW(testSetup.client.prepare_for_signature(keyid, txid, 0, server_id, client_id, data_to_sign, "", std::set<std::string>()));
        REQUIRE_NOTHROW(testSetup.server.generate_signature_share(keyid, txid, 0, server_id, client_id, ECDSA_SECP256K1, data_to_sign, "", std::set<std::string>(), server_shares));
        REQUIRE(server_shares.size() == 1);

        // Set Y = R (degenerate: would only be valid if x_client == 1)
        memcpy(server_shares[0].Y, server_shares[0].R, sizeof(elliptic_curve256_point_t));

        REQUIRE_THROWS(testSetup.client.compute_partial_signature(txid, server_shares, partial_signatures));
    }

    // ========================================================================
    // J. Batch Signing Edge Case
    //    Verify that signing the same message twice in one batch produces
    //    valid signatures with DIFFERENT nonces (nonce uniqueness).
    // ========================================================================

    SECTION("attack: batch signing with duplicate hashes (same message twice) (secp256k1)")
    {
        // Sign 2 copies of the same hash in one batch. Both should succeed,
        // but they MUST use different nonces (different client_R values).
        // If nonces are reused, the private key can be extracted.
        TestSetup testSetup;
        uuid_t uid;
        char keyid[UUID_STR_LEN] = {'\0'};
        char txid[UUID_STR_LEN] = {'\0'};
        const std::string setup_id(keyid);
        uuid_generate_random(uid);
        uuid_unparse(uid, keyid);
        uuid_generate_random(uid);
        uuid_unparse(uid, txid);

        elliptic_curve256_scalar_t hash;
        REQUIRE(RAND_bytes(hash, sizeof(hash)));

        elliptic_curve256_point_t X1, X2;
        bam_key_generation(setup_id, keyid, client_id, server_id, testSetup.server, testSetup.client, ECDSA_SECP256K1, X1, X2);

        // Create signing_data with 2 identical blocks (same hash, same path)
        fbc::signing_data data_to_sign = {{0}, {
            { fbc::byte_vector_t(&hash[0], &hash[sizeof(hash)]), { 44, 0, 0, 0, 0} },
            { fbc::byte_vector_t(&hash[0], &hash[sizeof(hash)]), { 44, 0, 0, 0, 0} }
        }};

        std::vector<fbc::bam_ecdsa_cosigner::server_signature_shared_data> server_shares;
        std::vector<fbc::bam_ecdsa_cosigner::client_partial_signature_data> partial_signatures;
        std::vector<fbc::recoverable_signature> full_signatures;
        cosigner_sign_algorithm signature_algorithm;

        REQUIRE_NOTHROW(testSetup.client.prepare_for_signature(keyid, txid, 0, server_id, client_id, data_to_sign, "", std::set<std::string>()));
        REQUIRE_NOTHROW(testSetup.server.generate_signature_share(keyid, txid, 0, server_id, client_id, ECDSA_SECP256K1, data_to_sign, "", std::set<std::string>(), server_shares));
        REQUIRE(server_shares.size() == 2);
        REQUIRE_NOTHROW(testSetup.client.compute_partial_signature(txid, server_shares, partial_signatures));
        REQUIRE(partial_signatures.size() == 2);

        // Verify nonce uniqueness: client_R[0] != client_R[1]
        // If nonces were reused, attacker could extract private key via s1-s2 / (k*(h1-h2))
        REQUIRE(memcmp(partial_signatures[0].client_R, partial_signatures[1].client_R, sizeof(elliptic_curve256_point_t)) != 0);

        // Both signatures should verify successfully
        REQUIRE_NOTHROW(testSetup.server.verify_partial_signature_and_output_signature(txid, client_id, partial_signatures, full_signatures, signature_algorithm));
        REQUIRE(full_signatures.size() == 2);

        // Verify both signatures are valid
        // verify_ecdsa_signature uses blocks[0], so verify each by constructing single-block data
        fbc::signing_data data_block0 = {{0}, { data_to_sign.blocks[0] }};
        memcpy(data_block0.chaincode, data_to_sign.chaincode, sizeof(HDChaincode));
        verify_ecdsa_signature(ECDSA_SECP256K1, X1, X2, full_signatures[0], data_block0, false);

        fbc::signing_data data_block1 = {{0}, { data_to_sign.blocks[1] }};
        memcpy(data_block1.chaincode, data_to_sign.chaincode, sizeof(HDChaincode));
        verify_ecdsa_signature(ECDSA_SECP256K1, X1, X2, full_signatures[1], data_block1, false);
    }

    // ========================================================================
    // K. Key Size Validation
    //    Tests that undersized cryptographic keys are rejected during setup.
    //    Undersized Paillier key (< 3072 bits), undersized DF key (!= 2048 bits).
    // ========================================================================

    SECTION("attack: undersized Paillier key (2048-bit) in setup (secp256k1)")
    {
        // Attack: Server sends a 2048-bit Paillier key instead of the required 3072-bit.
        // Client should reject it during verify_setup_proof.
        // Ref: bam_ecdsa_cosigner_client.cpp check: paillier_public_key_size < PAILLIER_COMMITMENT_BITSIZE
        TestSetup testSetup;
        uuid_t uid;
        char keyid[UUID_STR_LEN] = {'\0'};
        const std::string setup_id(keyid);
        uuid_generate_random(uid);
        uuid_unparse(uid, keyid);

        // Generate legitimate setup with 3072-bit Paillier key
        fbc::bam_ecdsa_cosigner::server_setup_shared_data setup;
        commitments_sha256_t B;
        fbc::bam_ecdsa_cosigner::client_key_shared_data client_message;

        REQUIRE_NOTHROW(testSetup.server.generate_setup_with_proof(setup_id, get_tenant_id(), ECDSA_SECP256K1, setup));
        REQUIRE_NOTHROW(testSetup.client.start_new_key_generation(setup_id, keyid, get_tenant_id(), server_id, client_id, ECDSA_SECP256K1));
        REQUIRE_NOTHROW(testSetup.server.generate_share_and_commit(setup_id, keyid, server_id, client_id, ECDSA_SECP256K1, B));

        // Generate a smaller 2048-bit Paillier key
        paillier_commitment_private_key_t* small_paillier = nullptr;
        REQUIRE(paillier_commitment_generate_private_key(2048, &small_paillier) == PAILLIER_SUCCESS);
        const paillier_commitment_public_key_t* small_pub = paillier_commitment_private_cast_to_public(small_paillier);
        REQUIRE(small_pub != nullptr);

        // Serialize the smaller key's public portion
        uint32_t pub_size = 0;
        paillier_commitment_public_key_serialize(small_pub, 1, nullptr, 0, &pub_size);
        REQUIRE(pub_size > 0);
        setup.paillier_commitment_pub.resize(pub_size);
        REQUIRE(paillier_commitment_public_key_serialize(small_pub, 1, setup.paillier_commitment_pub.data(), pub_size, &pub_size) == PAILLIER_SUCCESS);

        paillier_commitment_free_private_key(small_paillier);

        // Client should reject the undersized Paillier key
        REQUIRE_THROWS(testSetup.client.verify_setup_proof_store_key_commitment_generate_key_proof(setup_id, keyid, server_id, setup, B, client_message));
    }

    SECTION("attack: undersized Damgard-Fujisaki key (1024-bit) in client keygen (secp256k1)")
    {
        // Attack: Client sends a 1024-bit DF key instead of the required 2048-bit.
        // Server should reject it during verify_client_proofs_and_decommit_share_with_proof.
        // Ref: bam_ecdsa_cosigner_server.cpp check: damgard_fujisaki_public_size != TEMPORARY_DAMGARD_FUJISAKI_BITSIZE
        TestSetup testSetup;
        uuid_t uid;
        char keyid[UUID_STR_LEN] = {'\0'};
        const std::string setup_id(keyid);
        uuid_generate_random(uid);
        uuid_unparse(uid, keyid);

        fbc::bam_ecdsa_cosigner::server_setup_shared_data setup;
        commitments_sha256_t B;
        fbc::bam_ecdsa_cosigner::client_key_shared_data client_message;

        REQUIRE_NOTHROW(testSetup.server.generate_setup_with_proof(setup_id, get_tenant_id(), ECDSA_SECP256K1, setup));
        REQUIRE_NOTHROW(testSetup.client.start_new_key_generation(setup_id, keyid, get_tenant_id(), server_id, client_id, ECDSA_SECP256K1));
        REQUIRE_NOTHROW(testSetup.server.generate_share_and_commit(setup_id, keyid, server_id, client_id, ECDSA_SECP256K1, B));
        REQUIRE_NOTHROW(testSetup.client.verify_setup_proof_store_key_commitment_generate_key_proof(setup_id, keyid, server_id, setup, B, client_message));

        // Generate a smaller 1024-bit DF key (dimension 2, same as BAM protocol)
        damgard_fujisaki_private_t* small_df = nullptr;
        REQUIRE(damgard_fujisaki_generate_private_key(1024, 2, &small_df) == RING_PEDERSEN_SUCCESS);
        const damgard_fujisaki_public_t* small_df_pub = damgard_fujisaki_private_key_get_public(small_df);
        REQUIRE(small_df_pub != nullptr);

        // Serialize the smaller DF public key and replace in client message
        uint32_t df_size = 0;
        damgard_fujisaki_public_serialize(small_df_pub, nullptr, 0, &df_size);
        REQUIRE(df_size > 0);
        client_message.damgard_fujisaki_pub.resize(df_size);
        REQUIRE(damgard_fujisaki_public_serialize(small_df_pub, client_message.damgard_fujisaki_pub.data(), df_size, &df_size) != nullptr);

        damgard_fujisaki_free_private(small_df);

        // Server should reject the undersized DF key (size != 2048)
        fbc::bam_ecdsa_cosigner::server_key_shared_data server_message;
        REQUIRE_THROWS(testSetup.server.verify_client_proofs_and_decommit_share_with_proof(keyid, client_id, client_message, server_message));
    }

    // ========================================================================
    // L. Invalid Keys in Well-Formed Proof (Signing Phase)
    //    Tests that invalid setup parameters are caught during signing,
    //    not just during keygen setup.
    // ========================================================================

    SECTION("attack: corrupted well-formed proof structure in signing (secp256k1)")
    {
        // Do a legitimate keygen, then corrupt the proof's internal structure
        // (not just random byte flips, but targeted corruption of the Paillier
        // commitment D component within the proof).
        TestSetup testSetup;
        uuid_t uid;
        char keyid[UUID_STR_LEN] = {'\0'};
        char txid[UUID_STR_LEN] = {'\0'};
        const std::string setup_id(keyid);
        uuid_generate_random(uid);
        uuid_unparse(uid, keyid);
        uuid_generate_random(uid);
        uuid_unparse(uid, txid);

        elliptic_curve256_scalar_t hash;
        REQUIRE(RAND_bytes(hash, sizeof(hash)));

        elliptic_curve256_point_t X1, X2;
        bam_key_generation(setup_id, keyid, client_id, server_id, testSetup.server, testSetup.client, ECDSA_SECP256K1, X1, X2);

        fbc::signing_data data_to_sign = {{0}, {{ fbc::byte_vector_t(&hash[0], &hash[sizeof(hash)]), { 44, 0, 0, 0, 0} }}};

        std::vector<fbc::bam_ecdsa_cosigner::server_signature_shared_data> server_shares;
        std::vector<fbc::bam_ecdsa_cosigner::client_partial_signature_data> partial_signatures;
        std::vector<fbc::recoverable_signature> full_signatures;
        cosigner_sign_algorithm signature_algorithm;

        REQUIRE_NOTHROW(testSetup.client.prepare_for_signature(keyid, txid, 0, server_id, client_id, data_to_sign, "", std::set<std::string>()));
        REQUIRE_NOTHROW(testSetup.server.generate_signature_share(keyid, txid, 0, server_id, client_id, ECDSA_SECP256K1, data_to_sign, "", std::set<std::string>(), server_shares));
        REQUIRE_NOTHROW(testSetup.client.compute_partial_signature(txid, server_shares, partial_signatures));
        REQUIRE(partial_signatures.size() == 1);

        // The well-formed proof structure is: [paillier_size(4) | D(2*paillier_size) | U(65) | V(65) | z1 | z2 | w0(32) | w2]
        // Corrupt the D component (Paillier commitment) — starts at offset 4, length 2*paillier_size
        size_t proof_size = partial_signatures[0].sig_proof.size();
        REQUIRE(proof_size > 100);

        // Read paillier_size from first 4 bytes, then corrupt D
        uint32_t paillier_size = 0;
        memcpy(&paillier_size, partial_signatures[0].sig_proof.data(), sizeof(uint32_t));
        size_t d_offset = sizeof(uint32_t);
        size_t d_size = 2 * paillier_size;
        if (d_offset + d_size <= proof_size)
        {
            // Flip bytes in D component
            for (size_t i = d_offset; i < d_offset + 32 && i < d_offset + d_size; i++)
            {
                partial_signatures[0].sig_proof[i] ^= 0xFF;
            }
        }

        // Server should reject: Paillier commitment verification fails
        REQUIRE_THROWS(testSetup.server.verify_partial_signature_and_output_signature(txid, client_id, partial_signatures, full_signatures, signature_algorithm));
    }

    // Corrupt stored server key metadata between keygen and signing.
    // After successful keygen, alter the server's stored public key. The server
    // recomputes the derived public key during signing and verifies the final
    // signature against it — a corrupted public key causes verification failure.
    SECTION("attack: corrupted stored public key between keygen and signing (secp256k1)")
    {
        TestSetup testSetup;
        uuid_t uid;
        char keyid[UUID_STR_LEN] = {'\0'};
        char txid[UUID_STR_LEN] = {'\0'};
        const std::string setup_id(keyid);

        uuid_generate_random(uid);
        uuid_unparse(uid, keyid);
        uuid_generate_random(uid);
        uuid_unparse(uid, txid);

        elliptic_curve256_point_t X1, X2;
        bam_key_generation(setup_id, keyid, client_id, server_id, testSetup.server, testSetup.client, ECDSA_SECP256K1, X1, X2);

        // Tamper: load server metadata, corrupt public key, store back
        fbc::bam_key_metadata_server server_meta;
        testSetup.persistencyServer.load_key_metadata(keyid, server_meta);
        server_meta.public_key[5] ^= 0xFF;
        testSetup.persistencyServer.store_key_metadata(keyid, server_meta, true);

        elliptic_curve256_scalar_t hash;
        REQUIRE(RAND_bytes(hash, sizeof(hash)));
        fbc::signing_data data_to_sign = {{0}, {{ fbc::byte_vector_t(&hash[0], &hash[sizeof(hash)]), { 44, 0, 0, 0, 0} }}};

        std::vector<fbc::bam_ecdsa_cosigner::server_signature_shared_data> server_shares;
        std::vector<fbc::bam_ecdsa_cosigner::client_partial_signature_data> partial_signatures;
        std::vector<fbc::recoverable_signature> full_signatures;
        cosigner_sign_algorithm signature_algorithm;

        // Signing flow must fail somewhere — the corrupted public key may cause
        // generate_signature_share to throw (invalid curve point) or
        // compute_partial_signature to throw (inconsistent server data).
        REQUIRE_NOTHROW(testSetup.client.prepare_for_signature(keyid, txid, 0, server_id, client_id, data_to_sign, "", std::set<std::string>()));
        bool signing_failed = false;
        try
        {
            testSetup.server.generate_signature_share(keyid, txid, 0, server_id, client_id, ECDSA_SECP256K1, data_to_sign, "", std::set<std::string>(), server_shares);
            testSetup.client.compute_partial_signature(txid, server_shares, partial_signatures);
        }
        catch (...)
        {
            signing_failed = true;
        }
        REQUIRE(signing_failed);
    }

    // Item 24 variant: Corrupt stored client private key between keygen and signing.
    // The client produces an incorrect partial signature, which the server detects
    // during final signature verification.
    SECTION("attack: corrupted stored private key between keygen and signing (secp256k1)")
    {
        TestSetup testSetup;
        uuid_t uid;
        char keyid[UUID_STR_LEN] = {'\0'};
        char txid[UUID_STR_LEN] = {'\0'};
        const std::string setup_id(keyid);

        uuid_generate_random(uid);
        uuid_unparse(uid, keyid);
        uuid_generate_random(uid);
        uuid_unparse(uid, txid);

        elliptic_curve256_point_t X1, X2;
        bam_key_generation(setup_id, keyid, client_id, server_id, testSetup.server, testSetup.client, ECDSA_SECP256K1, X1, X2);

        // Tamper: load client's private key, corrupt it, store back
        cosigner_sign_algorithm algo;
        elliptic_curve256_scalar_t priv_key;
        testSetup.persistencyClient.load_key(keyid, algo, priv_key);
        priv_key[10] ^= 0xFF;
        testSetup.persistencyClient.store_key(keyid, algo, priv_key);

        elliptic_curve256_scalar_t hash;
        REQUIRE(RAND_bytes(hash, sizeof(hash)));
        fbc::signing_data data_to_sign = {{0}, {{ fbc::byte_vector_t(&hash[0], &hash[sizeof(hash)]), { 44, 0, 0, 0, 0} }}};

        std::vector<fbc::bam_ecdsa_cosigner::server_signature_shared_data> server_shares;
        std::vector<fbc::bam_ecdsa_cosigner::client_partial_signature_data> partial_signatures;
        std::vector<fbc::recoverable_signature> full_signatures;
        cosigner_sign_algorithm signature_algorithm;

        // Client uses its private key during partial signature — corrupted key
        // causes invalid intermediate values, detected during computation.
        REQUIRE_NOTHROW(testSetup.client.prepare_for_signature(keyid, txid, 0, server_id, client_id, data_to_sign, "", std::set<std::string>()));
        REQUIRE_NOTHROW(testSetup.server.generate_signature_share(keyid, txid, 0, server_id, client_id, ECDSA_SECP256K1, data_to_sign, "", std::set<std::string>(), server_shares));
        REQUIRE_THROWS(testSetup.client.compute_partial_signature(txid, server_shares, partial_signatures));
    }

    SECTION("attack: keygen replay - each step rejects second call (secp256k1)")
    {
        TestSetup testSetup;
        uuid_t uid;
        char keyid[UUID_STR_LEN] = {'\0'};
        uuid_generate_random(uid);
        uuid_unparse(uid, keyid);
        const std::string setup_id(keyid);

        fbc::bam_ecdsa_cosigner::server_setup_shared_data setup;
        commitments_sha256_t B;
        fbc::bam_ecdsa_cosigner::client_key_shared_data client_message;
        fbc::bam_ecdsa_cosigner::server_key_shared_data server_message;
        fbc::bam_ecdsa_cosigner::generated_public_key pub_key;

        // Step 1: generate_setup_with_proof is stateless — replay is OK (idempotent)
        REQUIRE_NOTHROW(testSetup.server.generate_setup_with_proof(setup_id, get_tenant_id(), ECDSA_SECP256K1, setup));

        // Step 2: start_new_key_generation + generate_share_and_commit
        REQUIRE_NOTHROW(testSetup.client.start_new_key_generation(setup_id, keyid, get_tenant_id(), server_id, client_id, ECDSA_SECP256K1));
        REQUIRE_NOTHROW(testSetup.server.generate_share_and_commit(setup_id, keyid, server_id, client_id, ECDSA_SECP256K1, B));

        // Replay: generate_share_and_commit for same key_id should fail (share already committed)
        commitments_sha256_t B_replay;
        REQUIRE_THROWS(testSetup.server.generate_share_and_commit(setup_id, keyid, server_id, client_id, ECDSA_SECP256K1, B_replay));

        // Step 3: verify_setup_proof_store_key_commitment_generate_key_proof
        REQUIRE_NOTHROW(testSetup.client.verify_setup_proof_store_key_commitment_generate_key_proof(setup_id, keyid, server_id, setup, B, client_message));

        // Replay: second call should fail (paillier_commitment_pub already set)
        fbc::bam_ecdsa_cosigner::client_key_shared_data client_message_replay;
        REQUIRE_THROWS(testSetup.client.verify_setup_proof_store_key_commitment_generate_key_proof(setup_id, keyid, server_id, setup, B, client_message_replay));

        // Step 4: verify_client_proofs_and_decommit_share_with_proof
        REQUIRE_NOTHROW(testSetup.server.verify_client_proofs_and_decommit_share_with_proof(keyid, client_id, client_message, server_message));

        // Replay: second call should fail (encrypted_server_share already set)
        fbc::bam_ecdsa_cosigner::server_key_shared_data server_message_replay;
        REQUIRE_THROWS(testSetup.server.verify_client_proofs_and_decommit_share_with_proof(keyid, client_id, client_message, server_message_replay));

        // Step 5: verify_key_decommitment_and_proofs
        REQUIRE_NOTHROW(testSetup.client.verify_key_decommitment_and_proofs(keyid, server_id, client_id, server_message, pub_key));

        // Replay: second call should fail (client temp data was load+deleted)
        fbc::bam_ecdsa_cosigner::generated_public_key pub_key_replay;
        REQUIRE_THROWS(testSetup.client.verify_key_decommitment_and_proofs(keyid, server_id, client_id, server_message, pub_key_replay));
    }

    // ========================================================================
    // Keygen backward replay: comprehensive window test
    // ========================================================================

    SECTION("attack: keygen backward replay - after step 0 (secp256k1)")
    {
        TestSetup testSetup;
        uuid_t uid;
        char keyid[UUID_STR_LEN] = {'\0'};
        uuid_generate_random(uid);
        uuid_unparse(uid, keyid);
        const std::string setup_id(keyid);

        fbc::bam_ecdsa_cosigner::server_setup_shared_data setup;

        // Happy path: step 0
        REQUIRE_NOTHROW(testSetup.server.generate_setup_with_proof(setup_id, get_tenant_id(), ECDSA_SECP256K1, setup));

        // Window [0]: replay step 0
        fbc::bam_ecdsa_cosigner::server_setup_shared_data setup_back;
        REQUIRE_THROWS(testSetup.server.generate_setup_with_proof(setup_id, get_tenant_id(), ECDSA_SECP256K1, setup_back));
    }

    SECTION("attack: keygen backward replay - after step 1 (secp256k1)")
    {
        TestSetup testSetup;
        uuid_t uid;
        char keyid[UUID_STR_LEN] = {'\0'};
        uuid_generate_random(uid);
        uuid_unparse(uid, keyid);
        const std::string setup_id(keyid);

        fbc::bam_ecdsa_cosigner::server_setup_shared_data setup;

        // Happy path: steps 0-1
        REQUIRE_NOTHROW(testSetup.server.generate_setup_with_proof(setup_id, get_tenant_id(), ECDSA_SECP256K1, setup));
        REQUIRE_NOTHROW(testSetup.client.start_new_key_generation(setup_id, keyid, get_tenant_id(), server_id, client_id, ECDSA_SECP256K1));

        // Window [1]: replay step 1
        REQUIRE_THROWS(testSetup.client.start_new_key_generation(setup_id, keyid, get_tenant_id(), server_id, client_id, ECDSA_SECP256K1));

        // Window [0,1]: replay steps 0,1
        fbc::bam_ecdsa_cosigner::server_setup_shared_data setup_back;
        REQUIRE_THROWS(testSetup.server.generate_setup_with_proof(setup_id, get_tenant_id(), ECDSA_SECP256K1, setup_back));
        REQUIRE_THROWS(testSetup.client.start_new_key_generation(setup_id, keyid, get_tenant_id(), server_id, client_id, ECDSA_SECP256K1));
    }

    SECTION("attack: keygen backward replay - after step 2 (secp256k1)")
    {
        TestSetup testSetup;
        uuid_t uid;
        char keyid[UUID_STR_LEN] = {'\0'};
        uuid_generate_random(uid);
        uuid_unparse(uid, keyid);
        const std::string setup_id(keyid);

        fbc::bam_ecdsa_cosigner::server_setup_shared_data setup;
        commitments_sha256_t B;

        // Happy path: steps 0-2
        REQUIRE_NOTHROW(testSetup.server.generate_setup_with_proof(setup_id, get_tenant_id(), ECDSA_SECP256K1, setup));
        REQUIRE_NOTHROW(testSetup.client.start_new_key_generation(setup_id, keyid, get_tenant_id(), server_id, client_id, ECDSA_SECP256K1));
        REQUIRE_NOTHROW(testSetup.server.generate_share_and_commit(setup_id, keyid, server_id, client_id, ECDSA_SECP256K1, B));

        // Window [2]: replay step 2
        commitments_sha256_t B_back;
        REQUIRE_THROWS(testSetup.server.generate_share_and_commit(setup_id, keyid, server_id, client_id, ECDSA_SECP256K1, B_back));

        // Window [1,2]: replay steps 1,2
        REQUIRE_THROWS(testSetup.client.start_new_key_generation(setup_id, keyid, get_tenant_id(), server_id, client_id, ECDSA_SECP256K1));
        REQUIRE_THROWS(testSetup.server.generate_share_and_commit(setup_id, keyid, server_id, client_id, ECDSA_SECP256K1, B_back));

        // Window [0,1,2]: replay steps 0,1,2
        fbc::bam_ecdsa_cosigner::server_setup_shared_data setup_back;
        REQUIRE_THROWS(testSetup.server.generate_setup_with_proof(setup_id, get_tenant_id(), ECDSA_SECP256K1, setup_back));
        REQUIRE_THROWS(testSetup.client.start_new_key_generation(setup_id, keyid, get_tenant_id(), server_id, client_id, ECDSA_SECP256K1));
        REQUIRE_THROWS(testSetup.server.generate_share_and_commit(setup_id, keyid, server_id, client_id, ECDSA_SECP256K1, B_back));
    }

    SECTION("attack: keygen backward replay - after step 3 (secp256k1)")
    {
        TestSetup testSetup;
        uuid_t uid;
        char keyid[UUID_STR_LEN] = {'\0'};
        uuid_generate_random(uid);
        uuid_unparse(uid, keyid);
        const std::string setup_id(keyid);

        fbc::bam_ecdsa_cosigner::server_setup_shared_data setup;
        commitments_sha256_t B;
        fbc::bam_ecdsa_cosigner::client_key_shared_data client_message;

        // Happy path: steps 0-3
        REQUIRE_NOTHROW(testSetup.server.generate_setup_with_proof(setup_id, get_tenant_id(), ECDSA_SECP256K1, setup));
        REQUIRE_NOTHROW(testSetup.client.start_new_key_generation(setup_id, keyid, get_tenant_id(), server_id, client_id, ECDSA_SECP256K1));
        REQUIRE_NOTHROW(testSetup.server.generate_share_and_commit(setup_id, keyid, server_id, client_id, ECDSA_SECP256K1, B));
        REQUIRE_NOTHROW(testSetup.client.verify_setup_proof_store_key_commitment_generate_key_proof(setup_id, keyid, server_id, setup, B, client_message));

        // Window [3]: replay step 3
        fbc::bam_ecdsa_cosigner::client_key_shared_data client_message_back;
        REQUIRE_THROWS(testSetup.client.verify_setup_proof_store_key_commitment_generate_key_proof(setup_id, keyid, server_id, setup, B, client_message_back));

        // Window [2,3]: replay steps 2,3
        commitments_sha256_t B_back;
        REQUIRE_THROWS(testSetup.server.generate_share_and_commit(setup_id, keyid, server_id, client_id, ECDSA_SECP256K1, B_back));
        REQUIRE_THROWS(testSetup.client.verify_setup_proof_store_key_commitment_generate_key_proof(setup_id, keyid, server_id, setup, B, client_message_back));

        // Window [1,2,3]: replay steps 1,2,3
        REQUIRE_THROWS(testSetup.client.start_new_key_generation(setup_id, keyid, get_tenant_id(), server_id, client_id, ECDSA_SECP256K1));
        REQUIRE_THROWS(testSetup.server.generate_share_and_commit(setup_id, keyid, server_id, client_id, ECDSA_SECP256K1, B_back));
        REQUIRE_THROWS(testSetup.client.verify_setup_proof_store_key_commitment_generate_key_proof(setup_id, keyid, server_id, setup, B, client_message_back));

        // Window [0,1,2,3]: replay steps 0,1,2,3
        fbc::bam_ecdsa_cosigner::server_setup_shared_data setup_back;
        REQUIRE_THROWS(testSetup.server.generate_setup_with_proof(setup_id, get_tenant_id(), ECDSA_SECP256K1, setup_back));
        REQUIRE_THROWS(testSetup.client.start_new_key_generation(setup_id, keyid, get_tenant_id(), server_id, client_id, ECDSA_SECP256K1));
        REQUIRE_THROWS(testSetup.server.generate_share_and_commit(setup_id, keyid, server_id, client_id, ECDSA_SECP256K1, B_back));
        REQUIRE_THROWS(testSetup.client.verify_setup_proof_store_key_commitment_generate_key_proof(setup_id, keyid, server_id, setup, B, client_message_back));
    }

    SECTION("attack: keygen backward replay - after step 4 (secp256k1)")
    {
        TestSetup testSetup;
        uuid_t uid;
        char keyid[UUID_STR_LEN] = {'\0'};
        uuid_generate_random(uid);
        uuid_unparse(uid, keyid);
        const std::string setup_id(keyid);

        fbc::bam_ecdsa_cosigner::server_setup_shared_data setup;
        commitments_sha256_t B;
        fbc::bam_ecdsa_cosigner::client_key_shared_data client_message;
        fbc::bam_ecdsa_cosigner::server_key_shared_data server_message;

        // Happy path: steps 0-4
        REQUIRE_NOTHROW(testSetup.server.generate_setup_with_proof(setup_id, get_tenant_id(), ECDSA_SECP256K1, setup));
        REQUIRE_NOTHROW(testSetup.client.start_new_key_generation(setup_id, keyid, get_tenant_id(), server_id, client_id, ECDSA_SECP256K1));
        REQUIRE_NOTHROW(testSetup.server.generate_share_and_commit(setup_id, keyid, server_id, client_id, ECDSA_SECP256K1, B));
        REQUIRE_NOTHROW(testSetup.client.verify_setup_proof_store_key_commitment_generate_key_proof(setup_id, keyid, server_id, setup, B, client_message));
        REQUIRE_NOTHROW(testSetup.server.verify_client_proofs_and_decommit_share_with_proof(keyid, client_id, client_message, server_message));

        // Window [4]: replay step 4
        fbc::bam_ecdsa_cosigner::server_key_shared_data server_message_back;
        REQUIRE_THROWS(testSetup.server.verify_client_proofs_and_decommit_share_with_proof(keyid, client_id, client_message, server_message_back));

        // Window [3,4]: replay steps 3,4
        fbc::bam_ecdsa_cosigner::client_key_shared_data client_message_back;
        REQUIRE_THROWS(testSetup.client.verify_setup_proof_store_key_commitment_generate_key_proof(setup_id, keyid, server_id, setup, B, client_message_back));
        REQUIRE_THROWS(testSetup.server.verify_client_proofs_and_decommit_share_with_proof(keyid, client_id, client_message, server_message_back));

        // Window [2,3,4]: replay steps 2,3,4
        commitments_sha256_t B_back;
        REQUIRE_THROWS(testSetup.server.generate_share_and_commit(setup_id, keyid, server_id, client_id, ECDSA_SECP256K1, B_back));
        REQUIRE_THROWS(testSetup.client.verify_setup_proof_store_key_commitment_generate_key_proof(setup_id, keyid, server_id, setup, B, client_message_back));
        REQUIRE_THROWS(testSetup.server.verify_client_proofs_and_decommit_share_with_proof(keyid, client_id, client_message, server_message_back));

        // Window [1,2,3,4]: replay steps 1,2,3,4
        REQUIRE_THROWS(testSetup.client.start_new_key_generation(setup_id, keyid, get_tenant_id(), server_id, client_id, ECDSA_SECP256K1));
        REQUIRE_THROWS(testSetup.server.generate_share_and_commit(setup_id, keyid, server_id, client_id, ECDSA_SECP256K1, B_back));
        REQUIRE_THROWS(testSetup.client.verify_setup_proof_store_key_commitment_generate_key_proof(setup_id, keyid, server_id, setup, B, client_message_back));
        REQUIRE_THROWS(testSetup.server.verify_client_proofs_and_decommit_share_with_proof(keyid, client_id, client_message, server_message_back));

        // Window [0,1,2,3,4]: replay steps 0,1,2,3,4
        fbc::bam_ecdsa_cosigner::server_setup_shared_data setup_back;
        REQUIRE_THROWS(testSetup.server.generate_setup_with_proof(setup_id, get_tenant_id(), ECDSA_SECP256K1, setup_back));
        REQUIRE_THROWS(testSetup.client.start_new_key_generation(setup_id, keyid, get_tenant_id(), server_id, client_id, ECDSA_SECP256K1));
        REQUIRE_THROWS(testSetup.server.generate_share_and_commit(setup_id, keyid, server_id, client_id, ECDSA_SECP256K1, B_back));
        REQUIRE_THROWS(testSetup.client.verify_setup_proof_store_key_commitment_generate_key_proof(setup_id, keyid, server_id, setup, B, client_message_back));
        REQUIRE_THROWS(testSetup.server.verify_client_proofs_and_decommit_share_with_proof(keyid, client_id, client_message, server_message_back));
    }

    SECTION("attack: keygen backward replay - after step 5 (secp256k1)")
    {
        TestSetup testSetup;
        uuid_t uid;
        char keyid[UUID_STR_LEN] = {'\0'};
        uuid_generate_random(uid);
        uuid_unparse(uid, keyid);
        const std::string setup_id(keyid);

        fbc::bam_ecdsa_cosigner::server_setup_shared_data setup;
        commitments_sha256_t B;
        fbc::bam_ecdsa_cosigner::client_key_shared_data client_message;
        fbc::bam_ecdsa_cosigner::server_key_shared_data server_message;
        fbc::bam_ecdsa_cosigner::generated_public_key pub_key;

        // Happy path: steps 0-5 (full keygen)
        REQUIRE_NOTHROW(testSetup.server.generate_setup_with_proof(setup_id, get_tenant_id(), ECDSA_SECP256K1, setup));
        REQUIRE_NOTHROW(testSetup.client.start_new_key_generation(setup_id, keyid, get_tenant_id(), server_id, client_id, ECDSA_SECP256K1));
        REQUIRE_NOTHROW(testSetup.server.generate_share_and_commit(setup_id, keyid, server_id, client_id, ECDSA_SECP256K1, B));
        REQUIRE_NOTHROW(testSetup.client.verify_setup_proof_store_key_commitment_generate_key_proof(setup_id, keyid, server_id, setup, B, client_message));
        REQUIRE_NOTHROW(testSetup.server.verify_client_proofs_and_decommit_share_with_proof(keyid, client_id, client_message, server_message));
        REQUIRE_NOTHROW(testSetup.client.verify_key_decommitment_and_proofs(keyid, server_id, client_id, server_message, pub_key));

        // Window [5]: replay step 5
        fbc::bam_ecdsa_cosigner::generated_public_key pub_key_back;
        REQUIRE_THROWS(testSetup.client.verify_key_decommitment_and_proofs(keyid, server_id, client_id, server_message, pub_key_back));

        // Window [4,5]: replay steps 4,5
        fbc::bam_ecdsa_cosigner::server_key_shared_data server_message_back;
        REQUIRE_THROWS(testSetup.server.verify_client_proofs_and_decommit_share_with_proof(keyid, client_id, client_message, server_message_back));
        REQUIRE_THROWS(testSetup.client.verify_key_decommitment_and_proofs(keyid, server_id, client_id, server_message, pub_key_back));

        // Window [3,4,5]: replay steps 3,4,5
        fbc::bam_ecdsa_cosigner::client_key_shared_data client_message_back;
        REQUIRE_THROWS(testSetup.client.verify_setup_proof_store_key_commitment_generate_key_proof(setup_id, keyid, server_id, setup, B, client_message_back));
        REQUIRE_THROWS(testSetup.server.verify_client_proofs_and_decommit_share_with_proof(keyid, client_id, client_message, server_message_back));
        REQUIRE_THROWS(testSetup.client.verify_key_decommitment_and_proofs(keyid, server_id, client_id, server_message, pub_key_back));

        // Window [2,3,4,5]: replay steps 2,3,4,5
        commitments_sha256_t B_back;
        REQUIRE_THROWS(testSetup.server.generate_share_and_commit(setup_id, keyid, server_id, client_id, ECDSA_SECP256K1, B_back));
        REQUIRE_THROWS(testSetup.client.verify_setup_proof_store_key_commitment_generate_key_proof(setup_id, keyid, server_id, setup, B, client_message_back));
        REQUIRE_THROWS(testSetup.server.verify_client_proofs_and_decommit_share_with_proof(keyid, client_id, client_message, server_message_back));
        REQUIRE_THROWS(testSetup.client.verify_key_decommitment_and_proofs(keyid, server_id, client_id, server_message, pub_key_back));

        // Window [1,2,3,4,5]: replay steps 1,2,3,4,5
        REQUIRE_THROWS(testSetup.client.start_new_key_generation(setup_id, keyid, get_tenant_id(), server_id, client_id, ECDSA_SECP256K1));
        REQUIRE_THROWS(testSetup.server.generate_share_and_commit(setup_id, keyid, server_id, client_id, ECDSA_SECP256K1, B_back));
        REQUIRE_THROWS(testSetup.client.verify_setup_proof_store_key_commitment_generate_key_proof(setup_id, keyid, server_id, setup, B, client_message_back));
        REQUIRE_THROWS(testSetup.server.verify_client_proofs_and_decommit_share_with_proof(keyid, client_id, client_message, server_message_back));
        REQUIRE_THROWS(testSetup.client.verify_key_decommitment_and_proofs(keyid, server_id, client_id, server_message, pub_key_back));

        // Window [0,1,2,3,4,5]: replay steps 0,1,2,3,4,5
        fbc::bam_ecdsa_cosigner::server_setup_shared_data setup_back;
        REQUIRE_THROWS(testSetup.server.generate_setup_with_proof(setup_id, get_tenant_id(), ECDSA_SECP256K1, setup_back));
        REQUIRE_THROWS(testSetup.client.start_new_key_generation(setup_id, keyid, get_tenant_id(), server_id, client_id, ECDSA_SECP256K1));
        REQUIRE_THROWS(testSetup.server.generate_share_and_commit(setup_id, keyid, server_id, client_id, ECDSA_SECP256K1, B_back));
        REQUIRE_THROWS(testSetup.client.verify_setup_proof_store_key_commitment_generate_key_proof(setup_id, keyid, server_id, setup, B, client_message_back));
        REQUIRE_THROWS(testSetup.server.verify_client_proofs_and_decommit_share_with_proof(keyid, client_id, client_message, server_message_back));
        REQUIRE_THROWS(testSetup.client.verify_key_decommitment_and_proofs(keyid, server_id, client_id, server_message, pub_key_back));
    }

    // ========================================================================
    // Signing backward replay: comprehensive window test
    // ========================================================================

    SECTION("attack: signing replay - after steps 1,2 (secp256k1)")
    {
        TestSetup testSetup;
        uuid_t uid;
        char keyid[UUID_STR_LEN] = {'\0'};
        char txid[UUID_STR_LEN] = {'\0'};
        uuid_generate_random(uid);
        uuid_unparse(uid, keyid);
        uuid_generate_random(uid);
        uuid_unparse(uid, txid);
        const std::string setup_id(keyid);

        elliptic_curve256_point_t X1, X2;
        bam_key_generation(setup_id, keyid, client_id, server_id, testSetup.server, testSetup.client, ECDSA_SECP256K1, X1, X2);

        elliptic_curve256_scalar_t hash;
        REQUIRE(RAND_bytes(hash, sizeof(hash)));
        fbc::signing_data data_to_sign = {{0}, {{ fbc::byte_vector_t(&hash[0], &hash[sizeof(hash)]), { 44, 0, 0, 0, 0} }}};

        std::vector<fbc::bam_ecdsa_cosigner::server_signature_shared_data> server_shares;

        // Happy path: steps 1,2 (parallel — either order works)
        REQUIRE_NOTHROW(testSetup.client.prepare_for_signature(keyid, txid, 0, server_id, client_id, data_to_sign, "", std::set<std::string>()));
        REQUIRE_NOTHROW(testSetup.server.generate_signature_share(keyid, txid, 0, server_id, client_id, ECDSA_SECP256K1, data_to_sign, "", std::set<std::string>(), server_shares));

        // Window [1]: replay step 1
        REQUIRE_THROWS(testSetup.client.prepare_for_signature(keyid, txid, 0, server_id, client_id, data_to_sign, "", std::set<std::string>()));

        // Window [2]: replay step 2
        std::vector<fbc::bam_ecdsa_cosigner::server_signature_shared_data> server_shares_back;
        REQUIRE_THROWS(testSetup.server.generate_signature_share(keyid, txid, 0, server_id, client_id, ECDSA_SECP256K1, data_to_sign, "", std::set<std::string>(), server_shares_back));

        // Window [1,2]: replay steps 1,2
        REQUIRE_THROWS(testSetup.client.prepare_for_signature(keyid, txid, 0, server_id, client_id, data_to_sign, "", std::set<std::string>()));
        REQUIRE_THROWS(testSetup.server.generate_signature_share(keyid, txid, 0, server_id, client_id, ECDSA_SECP256K1, data_to_sign, "", std::set<std::string>(), server_shares_back));
    }

    SECTION("attack: signing replay - after step 3 (secp256k1)")
    {
        TestSetup testSetup;
        uuid_t uid;
        char keyid[UUID_STR_LEN] = {'\0'};
        char txid[UUID_STR_LEN] = {'\0'};
        uuid_generate_random(uid);
        uuid_unparse(uid, keyid);
        uuid_generate_random(uid);
        uuid_unparse(uid, txid);
        const std::string setup_id(keyid);

        elliptic_curve256_point_t X1, X2;
        bam_key_generation(setup_id, keyid, client_id, server_id, testSetup.server, testSetup.client, ECDSA_SECP256K1, X1, X2);

        elliptic_curve256_scalar_t hash;
        REQUIRE(RAND_bytes(hash, sizeof(hash)));
        fbc::signing_data data_to_sign = {{0}, {{ fbc::byte_vector_t(&hash[0], &hash[sizeof(hash)]), { 44, 0, 0, 0, 0} }}};

        std::vector<fbc::bam_ecdsa_cosigner::server_signature_shared_data> server_shares;
        std::vector<fbc::bam_ecdsa_cosigner::client_partial_signature_data> partial_signatures;

        // Happy path: steps 1,2,3
        REQUIRE_NOTHROW(testSetup.client.prepare_for_signature(keyid, txid, 0, server_id, client_id, data_to_sign, "", std::set<std::string>()));
        REQUIRE_NOTHROW(testSetup.server.generate_signature_share(keyid, txid, 0, server_id, client_id, ECDSA_SECP256K1, data_to_sign, "", std::set<std::string>(), server_shares));
        REQUIRE_NOTHROW(testSetup.client.compute_partial_signature(txid, server_shares, partial_signatures));

        // Window [3]: replay step 3
        std::vector<fbc::bam_ecdsa_cosigner::client_partial_signature_data> partial_signatures_back;
        REQUIRE_THROWS(testSetup.client.compute_partial_signature(txid, server_shares, partial_signatures_back));

        // Window [2,3]: replay steps 2,3
        std::vector<fbc::bam_ecdsa_cosigner::server_signature_shared_data> server_shares_back;
        REQUIRE_THROWS(testSetup.server.generate_signature_share(keyid, txid, 0, server_id, client_id, ECDSA_SECP256K1, data_to_sign, "", std::set<std::string>(), server_shares_back));
        REQUIRE_THROWS(testSetup.client.compute_partial_signature(txid, server_shares, partial_signatures_back));

        // Window [1,2,3]
        REQUIRE_NOTHROW(testSetup.client.prepare_for_signature(keyid, txid, 0, server_id, client_id, data_to_sign, "", std::set<std::string>()));
        REQUIRE_THROWS(testSetup.server.generate_signature_share(keyid, txid, 0, server_id, client_id, ECDSA_SECP256K1, data_to_sign, "", std::set<std::string>(), server_shares_back));
        REQUIRE_NOTHROW(testSetup.client.compute_partial_signature(txid, server_shares, partial_signatures_back));
    }

    SECTION("attack: signing replay - after step 4 (secp256k1)")
    {
        TestSetup testSetup;
        uuid_t uid;
        char keyid[UUID_STR_LEN] = {'\0'};
        char txid[UUID_STR_LEN] = {'\0'};
        uuid_generate_random(uid);
        uuid_unparse(uid, keyid);
        uuid_generate_random(uid);
        uuid_unparse(uid, txid);
        const std::string setup_id(keyid);

        elliptic_curve256_point_t X1, X2;
        bam_key_generation(setup_id, keyid, client_id, server_id, testSetup.server, testSetup.client, ECDSA_SECP256K1, X1, X2);

        elliptic_curve256_scalar_t hash;
        REQUIRE(RAND_bytes(hash, sizeof(hash)));
        fbc::signing_data data_to_sign = {{0}, {{ fbc::byte_vector_t(&hash[0], &hash[sizeof(hash)]), { 44, 0, 0, 0, 0} }}};

        std::vector<fbc::bam_ecdsa_cosigner::server_signature_shared_data> server_shares;
        std::vector<fbc::bam_ecdsa_cosigner::client_partial_signature_data> partial_signatures;
        std::vector<fbc::recoverable_signature> full_signatures;
        cosigner_sign_algorithm signature_algorithm;

        // Happy path: steps 1,2,3,4 (full signing)
        REQUIRE_NOTHROW(testSetup.client.prepare_for_signature(keyid, txid, 0, server_id, client_id, data_to_sign, "", std::set<std::string>()));
        REQUIRE_NOTHROW(testSetup.server.generate_signature_share(keyid, txid, 0, server_id, client_id, ECDSA_SECP256K1, data_to_sign, "", std::set<std::string>(), server_shares));
        REQUIRE_NOTHROW(testSetup.client.compute_partial_signature(txid, server_shares, partial_signatures));
        REQUIRE_NOTHROW(testSetup.server.verify_partial_signature_and_output_signature(txid, client_id, partial_signatures, full_signatures, signature_algorithm));

        // Verify the original signature is valid
        REQUIRE(signature_algorithm == ECDSA_SECP256K1);
        verify_ecdsa_signature(ECDSA_SECP256K1, X1, X2, full_signatures[0], data_to_sign, false);

        // Window [1,2,3,4]: full re-signing
        std::vector<fbc::bam_ecdsa_cosigner::server_signature_shared_data> server_shares_new;
        std::vector<fbc::bam_ecdsa_cosigner::client_partial_signature_data> partial_signatures_new;
        std::vector<fbc::recoverable_signature> full_signatures_new;
        cosigner_sign_algorithm algo_new;
        REQUIRE_NOTHROW(testSetup.client.prepare_for_signature(keyid, txid, 0, server_id, client_id, data_to_sign, "", std::set<std::string>()));
        REQUIRE_NOTHROW(testSetup.server.generate_signature_share(keyid, txid, 0, server_id, client_id, ECDSA_SECP256K1, data_to_sign, "", std::set<std::string>(), server_shares_new));
        REQUIRE_NOTHROW(testSetup.client.compute_partial_signature(txid, server_shares_new, partial_signatures_new));
        REQUIRE_NOTHROW(testSetup.server.verify_partial_signature_and_output_signature(txid, client_id, partial_signatures_new, full_signatures_new, algo_new));
        REQUIRE(algo_new == ECDSA_SECP256K1);
        verify_ecdsa_signature(ECDSA_SECP256K1, X1, X2, full_signatures_new[0], data_to_sign, false);

        // After re-signing, all data is consumed again. Now test partial replays.

        // Window [4]: replay step 4
        std::vector<fbc::recoverable_signature> full_signatures_back;
        cosigner_sign_algorithm algo_back;
        REQUIRE_THROWS(testSetup.server.verify_partial_signature_and_output_signature(txid, client_id, partial_signatures, full_signatures_back, algo_back));

        // Window [3,4]: replay steps 3,4
        std::vector<fbc::bam_ecdsa_cosigner::client_partial_signature_data> partial_signatures_back;
        REQUIRE_THROWS(testSetup.client.compute_partial_signature(txid, server_shares, partial_signatures_back));
        REQUIRE_THROWS(testSetup.server.verify_partial_signature_and_output_signature(txid, client_id, partial_signatures, full_signatures_back, algo_back));

        // Window [2,3,4]
        std::vector<fbc::bam_ecdsa_cosigner::server_signature_shared_data> server_shares_back;
        REQUIRE_NOTHROW(testSetup.server.generate_signature_share(keyid, txid, 0, server_id, client_id, ECDSA_SECP256K1, data_to_sign, "", std::set<std::string>(), server_shares_back));
        REQUIRE_THROWS(testSetup.client.compute_partial_signature(txid, server_shares, partial_signatures_back));
    }
}

// ============================================================================
// BAM Nonce Uniqueness Test (Item 5)
// Statistical test: 1000+ signatures must have unique R-parts.
// R-reuse = private key leak (nonce-reuse attack).
// ============================================================================

TEST_CASE("bam_ecdsa_nonce_uniqueness")
{
    // Note: uses in-process TestSetup, no Thrift service needed.
    // Generate 20 keys, sign 50 messages each = 1000 signatures.
    // Collect all R-part x-coordinates and verify uniqueness.

    const int NUM_KEYS = 20;
    const int SIGS_PER_KEY = 50;

    std::set<std::string> all_r_values;
    int total_sigs = 0;

    for (int key_idx = 0; key_idx < NUM_KEYS; key_idx++)
    {
        TestSetup testSetup;
        uuid_t uid;
        char keyid[UUID_STR_LEN] = {'\0'};
        const std::string setup_id(keyid);

        uuid_generate_random(uid);
        uuid_unparse(uid, keyid);

        elliptic_curve256_point_t X1, X2;
        bam_key_generation(setup_id, keyid, client_id, server_id, testSetup.server, testSetup.client, ECDSA_SECP256K1, X1, X2);

        for (int sig_idx = 0; sig_idx < SIGS_PER_KEY; sig_idx++)
        {
            uuid_t txuid;
            char txid[UUID_STR_LEN] = {'\0'};
            uuid_generate_random(txuid);
            uuid_unparse(txuid, txid);

            elliptic_curve256_scalar_t hash;
            REQUIRE(RAND_bytes(hash, sizeof(hash)));

            fbc::signing_data data_to_sign = {{0}, {{ fbc::byte_vector_t(&hash[0], &hash[sizeof(hash)]), { 44, 0, 0, 0, 0} }}};

            fbc::recoverable_signature signature = { 0 };
            REQUIRE_NOTHROW(bam_key_sign(setup_id, keyid, txid, client_id, data_to_sign, "", testSetup.server, testSetup.client, signature, ECDSA_SECP256K1));

            // Collect the R-part (r component of ECDSA signature = x-coordinate of nonce point)
            std::string r_hex = fbc::HexStr(std::begin(signature.r), std::end(signature.r));
            all_r_values.insert(r_hex);
            total_sigs++;
        }
    }

    INFO("Total signatures: " << total_sigs << ", unique R values: " << all_r_values.size());
    REQUIRE(total_sigs == NUM_KEYS * SIGS_PER_KEY);
    // Every R must be unique — R-reuse would allow private key extraction
    REQUIRE(all_r_values.size() == static_cast<size_t>(total_sigs));
}

// ============================================================================
// BAM Correctness Tests (Items 17, 18)
// Structural/algebraic correctness checks that aren't attack scenarios.
// ============================================================================

TEST_CASE("bam_ecdsa_correctness")
{
    // After keygen, explicitly verify X_client + X_server == stored joint public key.
    // Currently this is only verified implicitly via signature verification.
    SECTION("keygen shares recombine to stored public key (secp256k1)")
    {
        TestSetup testSetup;
        uuid_t uid;
        char keyid[UUID_STR_LEN] = {'\0'};
        const std::string setup_id(keyid);

        uuid_generate_random(uid);
        uuid_unparse(uid, keyid);

        elliptic_curve256_point_t X1, X2;
        bam_key_generation(setup_id, keyid, client_id, server_id, testSetup.server, testSetup.client, ECDSA_SECP256K1, X1, X2);

        // Compute X1 + X2 using EC algebra
        elliptic_curve256_algebra_ctx_t* ctx = elliptic_curve256_new_secp256k1_algebra();
        REQUIRE(ctx != nullptr);
        elliptic_curve256_point_t computed_pubkey;
        REQUIRE(ELLIPTIC_CURVE_ALGEBRA_SUCCESS == ctx->add_points(ctx, &computed_pubkey, &X1, &X2));

        // Retrieve stored public key from server
        fbc::bam_ecdsa_cosigner::generated_public_key pub_key_data;
        testSetup.server.get_public_key(keyid, pub_key_data);
        REQUIRE(pub_key_data.algorithm == ECDSA_SECP256K1);
        REQUIRE(pub_key_data.pub_key.size() == sizeof(elliptic_curve256_point_t));

        // X_client + X_server must equal the stored joint public key
        REQUIRE(memcmp(computed_pubkey, pub_key_data.pub_key.data(), sizeof(elliptic_curve256_point_t)) == 0);

        elliptic_curve256_algebra_ctx_free(ctx);
    }

    SECTION("keygen shares recombine to stored public key (secp256r1)")
    {
        TestSetup testSetup;
        uuid_t uid;
        char keyid[UUID_STR_LEN] = {'\0'};
        const std::string setup_id(keyid);

        uuid_generate_random(uid);
        uuid_unparse(uid, keyid);

        elliptic_curve256_point_t X1, X2;
        bam_key_generation(setup_id, keyid, client_id, server_id, testSetup.server, testSetup.client, ECDSA_SECP256R1, X1, X2);

        elliptic_curve256_algebra_ctx_t* ctx = elliptic_curve256_new_secp256r1_algebra();
        REQUIRE(ctx != nullptr);
        elliptic_curve256_point_t computed_pubkey;
        REQUIRE(ELLIPTIC_CURVE_ALGEBRA_SUCCESS == ctx->add_points(ctx, &computed_pubkey, &X1, &X2));

        fbc::bam_ecdsa_cosigner::generated_public_key pub_key_data;
        testSetup.server.get_public_key(keyid, pub_key_data);
        REQUIRE(pub_key_data.algorithm == ECDSA_SECP256R1);
        REQUIRE(pub_key_data.pub_key.size() == sizeof(elliptic_curve256_point_t));
        REQUIRE(memcmp(computed_pubkey, pub_key_data.pub_key.data(), sizeof(elliptic_curve256_point_t)) == 0);

        elliptic_curve256_algebra_ctx_free(ctx);
    }

    // s-part is always normalized to s <= q/2 (low-S convention).
    // This normalization is applied unconditionally by make_sig_s_positive().
    // Verify using both the internal is_positive() check and an independent
    // OpenSSL BigNum comparison against q/2.
    SECTION("s-part always positive without positiveR flag (secp256k1)")
    {
        TestSetup testSetup;
        uuid_t uid;
        char keyid[UUID_STR_LEN] = {'\0'};
        const std::string setup_id(keyid);

        uuid_generate_random(uid);
        uuid_unparse(uid, keyid);

        elliptic_curve256_point_t X1, X2;
        bam_key_generation(setup_id, keyid, client_id, server_id, testSetup.server, testSetup.client, ECDSA_SECP256K1, X1, X2);

        // Get secp256k1 group order for external check
        EC_GROUP* group = EC_GROUP_new_by_curve_name(NID_secp256k1);
        REQUIRE(group != nullptr);
        BIGNUM* order = BN_new();
        REQUIRE(EC_GROUP_get_order(group, order, nullptr));
        BIGNUM* half_order = BN_new();
        BN_rshift1(half_order, order);  // half_order = order / 2

        // Sign 10 messages without positiveR, verify s is always positive
        for (int i = 0; i < 10; i++)
        {
            uuid_t txuid;
            char txid[UUID_STR_LEN] = {'\0'};
            uuid_generate_random(txuid);
            uuid_unparse(txuid, txid);

            elliptic_curve256_scalar_t hash;
            REQUIRE(RAND_bytes(hash, sizeof(hash)));
            fbc::signing_data data_to_sign = {{0}, {{ fbc::byte_vector_t(&hash[0], &hash[sizeof(hash)]), { 44, 0, 0, 0, 0} }}};

            fbc::recoverable_signature signature = { 0 };
            bam_key_sign(setup_id, keyid, txid, client_id, data_to_sign, "", testSetup.server, testSetup.client, signature, ECDSA_SECP256K1);

            // Internal check
            REQUIRE(fbc::bam_ecdsa_cosigner::is_positive(ECDSA_SECP256K1, signature.s));

            // External check: s <= q/2
            BIGNUM* s_bn = BN_bin2bn(signature.s, sizeof(elliptic_curve256_scalar_t), nullptr);
            REQUIRE(s_bn != nullptr);
            INFO("sig " << i << ": s = " << fbc::HexStr(std::begin(signature.s), std::end(signature.s)));
            REQUIRE(BN_cmp(s_bn, half_order) <= 0);
            BN_free(s_bn);
        }

        BN_free(half_order);
        BN_free(order);
        EC_GROUP_free(group);
    }

    // When positiveR metadata is set on secp256k1, both r and s must be positive.
    // Currently positiveR is only tested on STARK — this extends coverage to secp256k1.
    SECTION("positiveR flag normalizes both r and s (secp256k1)")
    {
        TestSetup testSetup;
        uuid_t uid;
        char keyid[UUID_STR_LEN] = {'\0'};
        const std::string setup_id(keyid);

        uuid_generate_random(uid);
        uuid_unparse(uid, keyid);

        elliptic_curve256_point_t X1, X2;
        bam_key_generation(setup_id, keyid, client_id, server_id, testSetup.server, testSetup.client, ECDSA_SECP256K1, X1, X2);

        EC_GROUP* group = EC_GROUP_new_by_curve_name(NID_secp256k1);
        REQUIRE(group != nullptr);
        BIGNUM* order = BN_new();
        REQUIRE(EC_GROUP_get_order(group, order, nullptr));
        BIGNUM* half_order = BN_new();
        BN_rshift1(half_order, order);

        const std::string sign_metadata = "{ \"signInfo\":[{\"positiveR\":true}]}";

        // Sign 10 messages with positiveR, verify both r and s are positive
        for (int i = 0; i < 10; i++)
        {
            uuid_t txuid;
            char txid[UUID_STR_LEN] = {'\0'};
            uuid_generate_random(txuid);
            uuid_unparse(txuid, txid);

            elliptic_curve256_scalar_t hash;
            REQUIRE(RAND_bytes(hash, sizeof(hash)));
            fbc::signing_data data_to_sign = {{0}, {{ fbc::byte_vector_t(&hash[0], &hash[sizeof(hash)]), { 44, 0, 0, 0, 0} }}};

            fbc::recoverable_signature signature = { 0 };
            bam_key_sign(setup_id, keyid, txid, client_id, data_to_sign, sign_metadata, testSetup.server, testSetup.client, signature, ECDSA_SECP256K1);

            // Verify full signature correctness
            verify_ecdsa_signature(ECDSA_SECP256K1, X1, X2, signature, data_to_sign, true);

            // Internal checks
            REQUIRE(fbc::bam_ecdsa_cosigner::is_positive(ECDSA_SECP256K1, signature.r));
            REQUIRE(fbc::bam_ecdsa_cosigner::is_positive(ECDSA_SECP256K1, signature.s));

            // External BN checks: both r and s <= q/2
            BIGNUM* r_bn = BN_bin2bn(signature.r, sizeof(elliptic_curve256_scalar_t), nullptr);
            BIGNUM* s_bn = BN_bin2bn(signature.s, sizeof(elliptic_curve256_scalar_t), nullptr);
            REQUIRE(r_bn != nullptr);
            REQUIRE(s_bn != nullptr);
            REQUIRE(BN_cmp(r_bn, half_order) <= 0);
            REQUIRE(BN_cmp(s_bn, half_order) <= 0);
            BN_free(r_bn);
            BN_free(s_bn);
        }

        BN_free(half_order);
        BN_free(order);
        EC_GROUP_free(group);
    }
}

// ============================================================================
// BAM Extended Nonce Uniqueness Test (Item 25)
// Long-running statistical test: 10,000+ signatures (for CI; full 1M for monthly).
// Tagged [long] — excluded from normal test runs.
// Run with: ./test "[long]"
// ============================================================================

TEST_CASE("bam_ecdsa_nonce_uniqueness_extended", "[.][long]")
{
    // 200 keys x 50 sigs = 10,000 signatures (CI-friendly subset of 1M target).
    // For monthly runs, increase NUM_KEYS to 20,000 for 1M total.
    const int NUM_KEYS = 200;
    const int SIGS_PER_KEY = 50;

    std::set<std::string> all_r_values;
    int total_sigs = 0;

    for (int key_idx = 0; key_idx < NUM_KEYS; key_idx++)
    {
        TestSetup testSetup;
        uuid_t uid;
        char keyid[UUID_STR_LEN] = {'\0'};
        const std::string setup_id(keyid);

        uuid_generate_random(uid);
        uuid_unparse(uid, keyid);

        elliptic_curve256_point_t X1, X2;
        bam_key_generation(setup_id, keyid, client_id, server_id, testSetup.server, testSetup.client, ECDSA_SECP256K1, X1, X2);

        for (int sig_idx = 0; sig_idx < SIGS_PER_KEY; sig_idx++)
        {
            uuid_t txuid;
            char txid[UUID_STR_LEN] = {'\0'};
            uuid_generate_random(txuid);
            uuid_unparse(txuid, txid);

            elliptic_curve256_scalar_t hash;
            REQUIRE(RAND_bytes(hash, sizeof(hash)));

            fbc::signing_data data_to_sign = {{0}, {{ fbc::byte_vector_t(&hash[0], &hash[sizeof(hash)]), { 44, 0, 0, 0, 0} }}};

            fbc::recoverable_signature signature = { 0 };
            REQUIRE_NOTHROW(bam_key_sign(setup_id, keyid, txid, client_id, data_to_sign, "", testSetup.server, testSetup.client, signature, ECDSA_SECP256K1));

            std::string r_hex = fbc::HexStr(std::begin(signature.r), std::end(signature.r));
            all_r_values.insert(r_hex);
            total_sigs++;
        }
    }

    INFO("Total signatures: " << total_sigs << ", unique R values: " << all_r_values.size());
    REQUIRE(total_sigs == NUM_KEYS * SIGS_PER_KEY);
    REQUIRE(all_r_values.size() == static_cast<size_t>(total_sigs));
}
