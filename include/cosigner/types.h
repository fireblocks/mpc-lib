#pragma once

#include "crypto/elliptic_curve_algebra/elliptic_curve256_algebra.h"
#include "crypto/ed25519_algebra/ed25519_algebra.h"
#include "crypto/commitments/commitments.h"
#include "cosigner/sign_algorithm.h"
#include "blockchain/mpc/hd_derive.h"
#include <openssl/crypto.h>

#include <string.h>
#include <streambuf>
#include <ostream>
#include <set>
#include <string>
#include <type_traits>
#include <vector>
#include <map>

namespace fireblocks
{
namespace common
{
namespace cosigner
{

typedef std::vector<uint8_t> byte_vector_t;

class byte_vector_ostreambuf : public std::streambuf
{
public:
    explicit byte_vector_ostreambuf(byte_vector_t& vec) : vec_(vec) {}

protected:
    std::streamsize xsputn(const char_type* s, std::streamsize count) override
    {
        vec_.insert(vec_.end(), reinterpret_cast<const uint8_t*>(s), reinterpret_cast<const uint8_t*>(s + count));
        return count;
    }

    int_type overflow(int_type ch) override
    {
        if (ch != traits_type::eof())
        {
            vec_.push_back(static_cast<uint8_t>(ch));
        }
        return ch;
    }

private:
    byte_vector_t& vec_;
};

struct elliptic_curve_point
{
    elliptic_curve256_point_t data;
    elliptic_curve_point() {OPENSSL_cleanse(&data, sizeof(elliptic_curve256_point_t));}
};

struct elliptic_curve_scalar
{
    elliptic_curve256_scalar_t data;
    elliptic_curve_scalar() {OPENSSL_cleanse(&data, sizeof(elliptic_curve_scalar));}
    ~elliptic_curve_scalar() {OPENSSL_cleanse(&data, sizeof(elliptic_curve_scalar));}
};

template <typename T>
class scalar_cleaner
{
    static_assert(std::is_trivially_destructible<T>::value, "scalar_cleaner requires a trivially destructible type (plain array or POD)");
public:
    explicit scalar_cleaner(T& secret) : _secret(secret) {}
    ~scalar_cleaner() {OPENSSL_cleanse(_secret, sizeof(_secret));}
    scalar_cleaner(const scalar_cleaner&) = delete;
    scalar_cleaner& operator=(const scalar_cleaner&) = delete;
private:
    T& _secret;
};

struct commitment
{
    commitment() {OPENSSL_cleanse(&data, sizeof(commitments_commitment_t));}
    commitment(const commitments_commitment_t* hash) {memcpy(&data, hash, sizeof(commitments_commitment_t));}
    commitments_commitment_t data;
};
using commitments_map = std::map<uint64_t, std::vector<commitment>>;
struct share_derivation_args
{
    std::string master_key_id;
    byte_vector_t chaincode;
};

struct preprocessing_metadata
{
    std::string key_id;
    cosigner_sign_algorithm algorithm;
    std::set<uint64_t> players_ids;
    uint32_t start_index;
    uint32_t count;
    commitments_sha256_t ack;
    uint32_t version;
};

enum SIGNING_FLAGS
{
    NONE            = 0x00,
    POSITIVE_R      = 0x01,
    EDDSA_KECCAK    = 0x02
};

struct signing_block_data
{
    byte_vector_t data;
    std::vector<uint32_t> path;
};

struct signing_data
{
    HDChaincode chaincode;
    std::vector<signing_block_data> blocks;
};

struct recoverable_signature
{
    elliptic_curve256_scalar_t r;
    elliptic_curve256_scalar_t s;
    uint8_t v;
};

struct eddsa_signature
{
    ed25519_point_t R;
    ed25519_scalar_t s;
};

struct player
{
    std::string id;
    std::string type;
};

}
}
}
