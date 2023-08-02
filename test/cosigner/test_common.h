#pragma once

#include <uuid/uuid.h>
#include <string>
#include <memory>

#include "cosigner/cmp_setup_service.h"
#include "crypto/elliptic_curve_algebra/elliptic_curve256_algebra.h"

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

static const std::string TENANT_ID("test tenant");

int my_ed25519_verify(const struct ed25519_algebra_ctx* ed25519, const uint8_t *message, size_t message_len, const uint8_t signature[64], const uint8_t public_key[32], bool use_sha3);

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

void create_secret(players_setup_info& players, cosigner_sign_algorithm type, const std::string& keyid, elliptic_curve256_point_t& pubkey);
void add_user(players_setup_info& old_players, players_setup_info& new_players, cosigner_sign_algorithm type, const std::string& old_keyid, const std::string& new_keyid, const elliptic_curve256_point_t& pubkey);
