#ifndef __TEST_INFO_H__
#define __TEST_INFO_H__

#include <uuid/uuid.h>
#include <string>
#include <memory>

#include "cosigner/cmp_setup_service.h"
#include "crypto/elliptic_curve_algebra/elliptic_curve256_algebra.h"
#include <openssl/rand.h>


static std::string TENANT_ID("test tenant");


class setup_persistency : public fireblocks::common::cosigner::cmp_setup_service::setup_key_persistency
{
public:
    // debug only
    std::string dump_key(const std::string& key_id) const;
private:
    bool key_exist(const std::string& key_id) const override;
    void load_key(const std::string& key_id, cosigner_sign_algorithm& algorithm, elliptic_curve256_scalar_t& private_key) const override;
    const std::string get_tenantid_from_keyid(const std::string& key_id) const override;
    void load_key_metadata(const std::string& key_id, fireblocks::common::cosigner::cmp_key_metadata& metadata, bool full_load) const override;
    void load_auxiliary_keys(const std::string& key_id, fireblocks::common::cosigner::auxiliary_keys& aux) const override;
    void store_key(const std::string& key_id, cosigner_sign_algorithm algorithm, const elliptic_curve256_scalar_t& private_key, uint64_t ttl = 0) override;
    void store_key_metadata(const std::string& key_id, const fireblocks::common::cosigner::cmp_key_metadata& metadata) override;
    void store_auxiliary_keys(const std::string& key_id, const fireblocks::common::cosigner::auxiliary_keys& aux) override;
    void store_keyid_tenant_id(const std::string& key_id, const std::string& tenant_id) override;
    void store_setup_data(const std::string& key_id, const fireblocks::common::cosigner::setup_data& metadata) override;
    void load_setup_data(const std::string& key_id, fireblocks::common::cosigner::setup_data& metadata) override;
    void store_setup_commitments(const std::string& key_id, const std::map<uint64_t, fireblocks::common::cosigner::commitment>& commitments) override;
    void load_setup_commitments(const std::string& key_id, std::map<uint64_t, fireblocks::common::cosigner::commitment>& commitments) override;
    void delete_temporary_key_data(const std::string& key_id, bool delete_key = false) override;

    struct key_info
    {
        cosigner_sign_algorithm algorithm;
        elliptic_curve256_scalar_t private_key;
        fireblocks::common::cosigner::cmp_key_metadata metadata;
        fireblocks::common::cosigner::auxiliary_keys aux_keys;
    };
    
    std::map<std::string, key_info> _keys;
    std::map<std::string, fireblocks::common::cosigner::setup_data> _setup_data;
    std::map<std::string, std::map<uint64_t, fireblocks::common::cosigner::commitment>> _commitments;
};

typedef std::map<uint64_t, setup_persistency> players_setup_info;

template<typename T>
std::string HexStr(const T itbegin, const T itend)
{
    std::string rv;
    static const char hexmap[16] = { '0', '1', '2', '3', '4', '5', '6', '7',
                                     '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };
    rv.reserve((itend-itbegin)*3);
    for(T it = itbegin; it < itend; ++it)
    {
        unsigned char val = (unsigned char)(*it);
        rv.push_back(hexmap[val>>4]);
        rv.push_back(hexmap[val&15]);
    }

    return rv;
}

template<typename T>
inline std::string HexStr(const T& vch)
{
    return HexStr(vch.begin(), vch.end());
}

class platform : public fireblocks::common::cosigner::platform_service
{
public:
    platform(uint64_t id) : _id(id) {}
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
    void start_signing(const std::string& key_id, const std::string& txid, const fireblocks::common::cosigner::signing_data& data, const std::string& metadata_json, const std::set<std::string>& players) {}
    void fill_signing_info_from_metadata(const std::string& metadata, std::vector<uint32_t>& flags) const {assert(0);}
    bool is_client_id(uint64_t player_id) const override {return false;}

    uint64_t _id;
};

struct setup_info
{
    setup_info(uint64_t id, setup_persistency& persistency) : platform_service(id), setup_service(platform_service, persistency){
        return; 
    }

    platform platform_service;
    fireblocks::common::cosigner::cmp_setup_service setup_service;
};


void create_secret(players_setup_info& players, const std::string& keyid, elliptic_curve256_point_t& pubkey);
#endif //#ifndef __TEST_INFO_H__
