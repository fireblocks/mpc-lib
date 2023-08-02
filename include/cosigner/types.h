#pragma once

#include "crypto/elliptic_curve_algebra/elliptic_curve256_algebra.h"
#include "crypto/ed25519_algebra/ed25519_algebra.h"
#include "crypto/commitments/commitments.h"
#include "cosigner/sign_algorithm.h"
#include "blockchain/mpc/hd_derive.h"

#include <string.h>

#include <set>
#include <string>
#include <vector>

#ifndef ENCLAVE
#define memset_s(dest, destsz, ch, count) memset(dest, ch, count)
#endif

namespace fireblocks
{
namespace common
{
namespace cosigner
{

typedef std::vector<uint8_t> byte_vector_t;

struct elliptic_curve_point
{
    elliptic_curve256_point_t data;
    elliptic_curve_point() {memset_s(&data, sizeof(elliptic_curve256_point_t), 0, sizeof(elliptic_curve256_point_t));}
};

struct elliptic_curve_scalar
{
    elliptic_curve256_scalar_t data;
    elliptic_curve_scalar() {memset_s(&data, sizeof(elliptic_curve_scalar), 0, sizeof(elliptic_curve_scalar));}
    ~elliptic_curve_scalar() {memset_s(&data, sizeof(elliptic_curve_scalar), 0, sizeof(elliptic_curve_scalar));}
};

struct commitment
{
    commitment() {memset_s(&data, sizeof(commitments_commitment_t), 0, sizeof(commitments_commitment_t));}
    commitment(const commitments_commitment_t* hash) {memcpy(&data, hash, sizeof(commitments_commitment_t));}
    commitments_commitment_t data;
};

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

}
}
}
