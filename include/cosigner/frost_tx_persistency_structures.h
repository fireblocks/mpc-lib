#pragma once
#include "cosigner/types.h"
#include "crypto/elliptic_curve_algebra/elliptic_curve256_algebra.h"
#include <cstdint>
#include <vector>

namespace fireblocks::common::cosigner
{

// server generates ephemerals "e" and "d", and sends this data to client
// and it need to known it's own data when client's response is received
// this data is temporal and stored for the duration of a transaction signing
struct frost_single_signature_data
{
    frost_single_signature_data() = default;
    uint32_t flags;                                 // signature flags
    byte_vector_t message;                          // message to sign
    elliptic_curve256_scalar_t derivation_delta;    // key derivation
    elliptic_curve_scalar secret_d;
    elliptic_curve_scalar secret_e;
};

// Signing is done on a bulk of signatures. This is a container for FROST signature information
struct frost_signature_data : public two_party_signature_metadata_header
{
    using two_party_signature_metadata_header::two_party_signature_metadata_header;

    std::vector<frost_single_signature_data> sig_data;
};

}
