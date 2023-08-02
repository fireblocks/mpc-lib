#pragma once

#include <map>
#include <set>
#include <string>
#include <vector>
#include "cosigner/types.h"

namespace fireblocks
{
namespace common
{
namespace cosigner
{

struct cmp_key_metadata;
struct auxiliary_keys;
struct signing_data;

class platform_service
{
public:
    virtual ~platform_service() {}

    // generate true randomness
    virtual void gen_random(size_t len, uint8_t* random_data) const = 0;

    // returns the current context tenant id, used to prevent cross tenant attacks
    virtual const std::string get_current_tenantid() const = 0;
    // returns the player id based on the key used
    virtual uint64_t get_id_from_keyid(const std::string& key_id) const = 0;
    // derive a key share from a master seed defined by derive_from
    virtual void derive_initial_share(const share_derivation_args& derive_from, cosigner_sign_algorithm algorithm, elliptic_curve256_scalar_t* key) const = 0;
    // encrypts a message for spesific player, used to send unicast messages in the add user and key refresh flows
    virtual byte_vector_t encrypt_for_player(uint64_t id, const byte_vector_t& data) const = 0;
    // decrypts a message sent to the signer in the add user flow
    virtual byte_vector_t decrypt_message(const byte_vector_t& encrypted_data) const = 0;
    // called upon new key creation, if this function returns false the key will not be created
    virtual bool backup_key(const std::string& key_id, cosigner_sign_algorithm algorithm, const elliptic_curve256_scalar_t& private_key, const cmp_key_metadata& metadata, const auxiliary_keys& aux) = 0;

    // this is a callback to notify about a new signing request, this is a good point to verify the request data, this function should thow exception if the signing request is not authorized
    virtual void start_signing(const std::string& key_id, const std::string& txid, const signing_data& data, const std::string& metadata_json, const std::set<std::string>& players) = 0;
    // set the siging flags (as bitset of SIGNING_FLAGS) based on the metadata
    virtual void fill_signing_info_from_metadata(const std::string& metadata, std::vector<uint32_t>& flags) const = 0;
    // returns if the player id is a client device, used in asymmetric protocols
    virtual bool is_client_id(uint64_t player_id) const = 0;
};

}
}
}