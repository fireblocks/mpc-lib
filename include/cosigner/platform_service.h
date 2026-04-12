#pragma once

#include "cosigner_export.h"

#include <map>
#include <set>
#include <string>
#include <vector>
#include <optional>
#include "cosigner/types.h"

namespace fireblocks::common::cosigner
{

struct cmp_key_metadata;
struct auxiliary_keys;
struct signing_data;
struct eddsa_signature_data;
struct bam_signing_properties;

class COSIGNER_EXPORT platform_service
{
public:
    virtual ~platform_service();

    // generate true randomness
    virtual void gen_random(size_t len, uint8_t* random_data) const = 0;

    // returns the current context tenant id, used to prevent cross tenant attacks
    virtual const std::string get_current_tenantid() const = 0;
    // returns the player id based on the key used
    virtual uint64_t get_id_from_keyid(const std::string& key_id) const = 0;

    // this is a callback to notify about a new signing request, this is a good point to verify the request data, this function should throw exception if the signing request is not authorized
    enum signing_type
    {
        MULTI_ROUND_SIGNATURE,  // All signatures beside BAM
        SINGLE_ROUND_SIGNATURE  // For now only BAM client
    };

    virtual void on_start_signing(const std::string& key_id,
                                  const std::string& txid,
                                  const signing_data& data,
                                  const std::string& metadata_json,
                                  const std::set<std::string>& players,
                                  const signing_type signature_type) = 0;

    // function called to prepare key for the signature. Might be used to preload all key data into memory or to restore the key
    virtual void prepare_for_signing(const std::string& key_id, const std::string tx_id) = 0;

    // set the signing flags (as bitset of SIGNING_FLAGS) based on the metadata
    virtual void fill_signing_info_from_metadata(const std::string& metadata, std::vector<uint32_t>& flags) const = 0;
    virtual void fill_eddsa_signing_info_from_metadata(std::vector<eddsa_signature_data>& info, const std::string& metadata) const = 0;
    virtual void fill_bam_signing_info_from_metadata(std::vector<bam_signing_properties>& info, const std::string& metadata) const = 0;
    // derive a key share from a master seed defined by derive_from
    virtual void derive_initial_share(const share_derivation_args& derive_from, cosigner_sign_algorithm algorithm, elliptic_curve256_scalar_t* key) const = 0;

    virtual void report_signing_time(const std::string& /*algorithm*/, uint64_t /*sign_time*/, uint32_t /*num_blocks*/) const {}
    // encrypts a message for specific player, used to send unicast messages in the add user and key refresh flows
    // verify_modulus if set will contain expected modulus of the players key
    // and will be verified before encryption
    virtual byte_vector_t encrypt_for_player(const uint64_t id, const byte_vector_t& data, const std::optional<std::string>& verify_modulus = std::nullopt) const = 0;
    // decrypts a message sent to the signer in the add user flow
    virtual byte_vector_t decrypt_message(const byte_vector_t& encrypted_data) const = 0;
    // called upon new key creation, if this function returns false the key will not be created
    virtual bool backup_key(const std::string& key_id, cosigner_sign_algorithm algorithm, const elliptic_curve256_scalar_t& private_key, const cmp_key_metadata& metadata, const auxiliary_keys& aux) = 0;
    // inform platform about key generation
    virtual void mark_key_setup_in_progress(const std::string& key_id) const = 0;
    virtual void clear_key_setup_in_progress(const std::string& key_id) const = 0;

    // returns if the player id is a client device, used in asymmetric protocols
    virtual bool is_client_id(uint64_t player_id) const = 0;

    // get the current time in milliseconds since the Unix Epoch
    virtual uint64_t now_msec() const { return 0; }
};

}
