#ifndef __SIGNING_TEST_H__
#define __SIGNING_TEST_H__

#include <string>
#include <mutex>
#include <shared_mutex>
#include <iostream>
#include "cosigner/cmp_setup_service.h"
#include "cosigner/cmp_ecdsa_offline_signing_service.h"
#include "cosigner/cmp_signature_preprocessed_data.h"
#include "cosigner/cmp_offline_refresh_service.h"

#include <test_info.h>

class sign_platform : public fireblocks::common::cosigner::platform_service
{
public:
    sign_platform(uint64_t id) : _id(id), _positive_r(false) {}
    void set_positive_r(bool positive_r) {_positive_r = positive_r;}
private:
    void gen_random(size_t len, uint8_t* random_data) const
    {
        RAND_bytes(random_data, len);
    }

    const std::string get_current_tenantid() const {return TENANT_ID;}
    uint64_t get_id_from_keyid(const std::string& key_id) const {return _id;}
    void derive_initial_share(const fireblocks::common::cosigner::share_derivation_args& derive_from, cosigner_sign_algorithm algorithm, elliptic_curve256_scalar_t* key) const {assert(0);}
    fireblocks::common::cosigner::byte_vector_t encrypt_for_player(uint64_t id, const fireblocks::common::cosigner::byte_vector_t& data) const {return data;}
    fireblocks::common::cosigner::byte_vector_t decrypt_message(const fireblocks::common::cosigner::byte_vector_t& encrypted_data) const {return encrypted_data;}
    bool backup_key(const std::string& key_id, cosigner_sign_algorithm algorithm, const elliptic_curve256_scalar_t& private_key, const fireblocks::common::cosigner::cmp_key_metadata& metadata, const fireblocks::common::cosigner::auxiliary_keys& aux) {return true;}
    void start_signing(const std::string& key_id, const std::string& txid, const fireblocks::common::cosigner::signing_data& data, const std::string& metadata_json, const std::set<std::string>& players) { std::cout << "HERE IN SIGNING - DOING FUCK ALL" << std::endl;}
    void fill_signing_info_from_metadata(const std::string& metadata, std::vector<uint32_t>& flags) const
    {
        for (auto i = flags.begin(); i != flags.end(); ++i)
            *i = _positive_r ? fireblocks::common::cosigner::POSITIVE_R : 0;
    }
    bool is_client_id(uint64_t player_id) const override {return false;}

    const uint64_t _id;
    bool _positive_r;
};

static inline bool is_positive(const elliptic_curve256_scalar_t& n)
{
    return (n[0] & 0x80) == 0;
}

static uint8_t ZERO[sizeof(fireblocks::common::cosigner::cmp_signature_preprocessed_data)] = {0};

class key_refresh_persistency;

class preprocessing_persistency : public fireblocks::common::cosigner::cmp_ecdsa_offline_signing_service::preprocessing_persistency
{
    void store_preprocessing_metadata(const std::string& request_id, const fireblocks::common::cosigner::preprocessing_metadata& data, bool override) override
    {
        std::unique_lock lock(_mutex);
        if (!override && _metadata.find(request_id) != _metadata.end())
            throw fireblocks::common::cosigner::cosigner_exception(fireblocks::common::cosigner::cosigner_exception::INVALID_TRANSACTION);
        _metadata[request_id] = data;
    }

    void load_preprocessing_metadata(const std::string& request_id, fireblocks::common::cosigner::preprocessing_metadata& data) const override
    {
        std::shared_lock lock(_mutex);
        auto it = _metadata.find(request_id);
        if (it == _metadata.end())
            throw fireblocks::common::cosigner::cosigner_exception(fireblocks::common::cosigner::cosigner_exception::INVALID_TRANSACTION);
        data = it->second;
    }

    void store_preprocessing_data(const std::string& request_id, uint64_t index, const fireblocks::common::cosigner::ecdsa_signing_data& data) override
    {
        std::unique_lock lock(_mutex);
        _signing_data[request_id][index] = data;
    }

    void load_preprocessing_data(const std::string& request_id, uint64_t index, fireblocks::common::cosigner::ecdsa_signing_data& data) const override
    {
        std::shared_lock lock(_mutex);
        auto it = _signing_data.find(request_id);
        if (it == _signing_data.end())
            throw fireblocks::common::cosigner::cosigner_exception(fireblocks::common::cosigner::cosigner_exception::INVALID_TRANSACTION);
        auto index_it = it->second.find(index);
        if (index_it == it->second.end())
            throw fireblocks::common::cosigner::cosigner_exception(fireblocks::common::cosigner::cosigner_exception::INVALID_TRANSACTION);
        data = index_it->second;
    }

    void delete_preprocessing_data(const std::string& request_id) override
    {
        std::unique_lock lock(_mutex);
        _metadata.erase(request_id);
        _signing_data.erase(request_id);
    }

    void create_preprocessed_data(const std::string& key_id, uint64_t size) override
    {
        std::unique_lock lock(_mutex);
        auto it = _preprocessed_data.find(key_id);
        if (it != _preprocessed_data.end())
        {
            if (it->second.size() != size)
                throw fireblocks::common::cosigner::cosigner_exception(fireblocks::common::cosigner::cosigner_exception::INVALID_TRANSACTION);
        }
        else
            _preprocessed_data.emplace(key_id, std::move(std::vector<fireblocks::common::cosigner::cmp_signature_preprocessed_data>(size)));
    }

    void store_preprocessed_data(const std::string& key_id, uint64_t index, const fireblocks::common::cosigner::cmp_signature_preprocessed_data& data) override
    {
        std::unique_lock lock(_mutex);
        auto it = _preprocessed_data.find(key_id);
        if (it == _preprocessed_data.end())
            throw fireblocks::common::cosigner::cosigner_exception(fireblocks::common::cosigner::cosigner_exception::INVALID_TRANSACTION);
        if (index >= it->second.size())
            throw fireblocks::common::cosigner::cosigner_exception(fireblocks::common::cosigner::cosigner_exception::INVALID_PRESIGNING_INDEX);
        it->second[index] = data;
    }

    void load_preprocessed_data(const std::string& key_id, uint64_t index, fireblocks::common::cosigner::cmp_signature_preprocessed_data& data) override
    {
        std::unique_lock lock(_mutex);
        auto it = _preprocessed_data.find(key_id);
        if (it == _preprocessed_data.end())
            throw fireblocks::common::cosigner::cosigner_exception(fireblocks::common::cosigner::cosigner_exception::INVALID_TRANSACTION);
        if (index >= it->second.size() || memcmp(it->second[index].k.data, ZERO, sizeof(fireblocks::common::cosigner::cmp_signature_preprocessed_data)) == 0)
            throw fireblocks::common::cosigner::cosigner_exception(fireblocks::common::cosigner::cosigner_exception::INVALID_PRESIGNING_INDEX);
        data = it->second[index];
        memset(it->second[index].k.data, 0, sizeof(fireblocks::common::cosigner::cmp_signature_preprocessed_data));
    }

    void delete_preprocessed_data(const std::string& key_id) override
    {
        std::unique_lock lock(_mutex);
        _preprocessed_data.erase(key_id);
    }

    mutable std::shared_mutex _mutex;
    std::map<std::string, fireblocks::common::cosigner::preprocessing_metadata> _metadata;
    std::map<std::string, std::map<uint64_t, fireblocks::common::cosigner::ecdsa_signing_data>> _signing_data;
    std::map<std::string, std::vector<fireblocks::common::cosigner::cmp_signature_preprocessed_data>> _preprocessed_data;
    friend class key_refresh_persistency;
};

class key_refresh_persistency : public fireblocks::common::cosigner::cmp_offline_refresh_service::offline_refresh_key_persistency
{
public:
    key_refresh_persistency(preprocessing_persistency& preproc_persistency, fireblocks::common::cosigner::cmp_setup_service::setup_key_persistency& setup_persistency) : 
        _preprocessing_persistency(preproc_persistency), _setup_persistency(setup_persistency) {}
private:
    void load_refresh_key_seeds(const std::string& request_id, std::map<uint64_t, fireblocks::common::cosigner::byte_vector_t>& player_id_to_seed) const override
    {
        std::lock_guard<std::mutex> lock(_mutex);
        auto it = _seeds.find(request_id);
        if (it == _seeds.end())
            throw fireblocks::common::cosigner::cosigner_exception(fireblocks::common::cosigner::cosigner_exception::INVALID_TRANSACTION);
        player_id_to_seed = it->second;
    }

    void store_refresh_key_seeds(const std::string& request_id, const std::map<uint64_t, fireblocks::common::cosigner::byte_vector_t>& player_id_to_seed) override
    {
        std::lock_guard<std::mutex> lock(_mutex);
        if (_seeds.find(request_id) != _seeds.end())
            throw fireblocks::common::cosigner::cosigner_exception(fireblocks::common::cosigner::cosigner_exception::INVALID_TRANSACTION);
        _seeds[request_id] = player_id_to_seed;
    }

    void transform_preprocessed_data_and_store_temporary(const std::string& key_id, const std::string& request_id, const fireblocks::common::cosigner::cmp_offline_refresh_service::preprocessed_data_handler &fn) override
    {
        std::unique_lock lock(_preprocessing_persistency._mutex);
        auto it = _preprocessing_persistency._preprocessed_data.find(key_id);
        if (it == _preprocessing_persistency._preprocessed_data.end())
            throw fireblocks::common::cosigner::cosigner_exception(fireblocks::common::cosigner::cosigner_exception::INVALID_TRANSACTION);
        const auto& preprocessed_data = it->second;
        it = _temp_preprocessed_data.find(key_id);
        if (it != _temp_preprocessed_data.end())
            throw fireblocks::common::cosigner::cosigner_exception(fireblocks::common::cosigner::cosigner_exception::INVALID_TRANSACTION);

        std::vector<fireblocks::common::cosigner::cmp_signature_preprocessed_data> temp(preprocessed_data);
        for (size_t i = 0; i < temp.size(); i++)
        {
            if (memcmp(temp[i].k.data, ZERO, sizeof(fireblocks::common::cosigner::cmp_signature_preprocessed_data)) != 0)
            {
                fn(i, temp[i]);
            }
        }
        std::lock_guard<std::mutex> lg(_mutex);
        _temp_preprocessed_data[key_id] = temp;
    }

    void commit(const std::string& key_id, const std::string& request_id) override
    {
        std::unique_lock lock(_preprocessing_persistency._mutex);
        std::lock_guard<std::mutex> lg(_mutex);
        auto it = _temp_keys.find(request_id);
        if (it == _temp_keys.end())
            throw fireblocks::common::cosigner::cosigner_exception(fireblocks::common::cosigner::cosigner_exception::BAD_KEY);
        _preprocessing_persistency._preprocessed_data[key_id] = _temp_preprocessed_data[key_id];
        _temp_preprocessed_data.erase(key_id);
        _setup_persistency.store_key(key_id, it->second.second, it->second.first);
        _temp_keys.erase(request_id);
    }

    void delete_refresh_key_seeds(const std::string& request_id) override
    {
        std::lock_guard<std::mutex> lock(_mutex);
        _temp_preprocessed_data.erase(request_id);
    }

    void delete_temporary_key(const std::string& key_id) override
    {
        std::lock_guard<std::mutex> lock(_mutex);
        _temp_keys.erase(key_id);
    }

    void store_temporary_key(const std::string& key_id, cosigner_sign_algorithm algorithm, const fireblocks::common::cosigner::elliptic_curve_scalar& private_key) override
    {
        std::lock_guard<std::mutex> lock(_mutex);
        if (_temp_keys.find(key_id) != _temp_keys.end())
            throw fireblocks::common::cosigner::cosigner_exception(fireblocks::common::cosigner::cosigner_exception::BAD_KEY);
        auto& val = _temp_keys[key_id];
        memcpy(val.first, private_key.data, sizeof(elliptic_curve256_scalar_t));
        val.second = algorithm;
    }

    mutable std::mutex _mutex;
    preprocessing_persistency& _preprocessing_persistency;
    fireblocks::common::cosigner::cmp_setup_service::setup_key_persistency& _setup_persistency;
    std::map<std::string, std::map<uint64_t, fireblocks::common::cosigner::byte_vector_t>> _seeds;
    std::map<std::string, std::vector<fireblocks::common::cosigner::cmp_signature_preprocessed_data>> _temp_preprocessed_data;
    std::map<std::string, std::pair<elliptic_curve256_scalar_t, cosigner_sign_algorithm>> _temp_keys;
};

struct offline_siging_info
{
    offline_siging_info(uint64_t id, const fireblocks::common::cosigner::cmp_key_persistency& key_persistency) : platform_service(id), signing_service(platform_service, key_persistency, persistency) {}
    sign_platform platform_service;
    preprocessing_persistency persistency;
    fireblocks::common::cosigner::cmp_ecdsa_offline_signing_service signing_service;
};

void ecdsa_preprocess(std::map<uint64_t, std::unique_ptr<offline_siging_info>>& services, const std::string& keyid, uint32_t start, uint32_t count, uint32_t total);


void ecdsa_sign(std::map<uint64_t, std::unique_ptr<offline_siging_info>>& services, cosigner_sign_algorithm type, const std::string& keyid, 
                        uint32_t start_index, uint32_t count, const elliptic_curve256_point_t& pubkey, 
                        const fireblocks::common::cosigner::byte_vector_t& chaincode, const std::vector<std::vector<uint32_t>>& paths, bool positive_r = false);

#endif //#ifndef __SIGNING_TEST_H__
