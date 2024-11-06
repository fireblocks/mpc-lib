#pragma once

#include "cosigner_export.h"

#include "cosigner/types.h"

#include <functional>
#include <map>
#include <memory>

namespace fireblocks
{
namespace common
{
namespace cosigner
{

class cmp_key_persistency;
class platform_service;
struct cmp_signature_preprocessed_data;

class COSIGNER_EXPORT cmp_offline_refresh_service final
{
public:
    typedef std::function<void(uint64_t index, cmp_signature_preprocessed_data& data)> preprocessed_data_handler;

    class offline_refresh_key_persistency
    {
    public:
        virtual ~offline_refresh_key_persistency();

        virtual void load_refresh_key_seeds(const std::string& request_id, std::map<uint64_t, byte_vector_t>& player_id_to_seed) const = 0;
        virtual void store_refresh_key_seeds(const std::string& request_id, const std::map<uint64_t, byte_vector_t>& player_id_to_seed) = 0;
        virtual void transform_preprocessed_data_and_store_temporary(const std::string& key_id, const std::string& request_id, const preprocessed_data_handler &fn) = 0;
        virtual void commit(const std::string& key_id, const std::string& request_id) = 0;
        virtual void delete_refresh_key_seeds(const std::string& request_id) = 0;
        virtual void delete_temporary_key(const std::string& key_id) = 0;

        virtual void store_temporary_key(const std::string& key_id, cosigner_sign_algorithm algorithm, const elliptic_curve_scalar& private_key) = 0;
    };

    cmp_offline_refresh_service(platform_service& service, cmp_key_persistency& key_persistency, offline_refresh_key_persistency& refresh_key_persistency) : _service(service), _key_persistency(key_persistency), _refresh_key_persistency(refresh_key_persistency) {}

    void refresh_key_request(const std::string& tenant_id, const std::string& key_id, const std::string& request_id, const std::set<uint64_t>& players_ids, std::map<uint64_t, byte_vector_t>& encrypted_seeds);
    void refresh_key(const std::string& key_id, const std::string& request_id, const std::map<uint64_t, std::map<uint64_t, byte_vector_t>>& encrypted_seeds, std::string& public_key);
    void refresh_key_fast_ack(const std::string& tenant_id, const std::string& key_id, const std::string& request_id);
    void cancel_refresh_key(const std::string& request_id);

private:
    static inline elliptic_curve256_algebra_ctx_t* get_algebra(cosigner_sign_algorithm algorithm);

    platform_service& _service;
    cmp_key_persistency& _key_persistency;
    offline_refresh_key_persistency& _refresh_key_persistency;

    static const std::unique_ptr<elliptic_curve256_algebra_ctx_t, void(*)(elliptic_curve256_algebra_ctx_t*)> _secp256k1;
    static const std::unique_ptr<elliptic_curve256_algebra_ctx_t, void(*)(elliptic_curve256_algebra_ctx_t*)> _secp256r1;
    static const std::unique_ptr<elliptic_curve256_algebra_ctx_t, void(*)(elliptic_curve256_algebra_ctx_t*)> _ed25519;
    static const std::unique_ptr<elliptic_curve256_algebra_ctx_t, void(*)(elliptic_curve256_algebra_ctx_t*)> _stark;
};

}
}
}
