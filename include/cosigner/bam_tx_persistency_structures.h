#pragma once
#include "cosigner/types.h"
#include "crypto/elliptic_curve_algebra/elliptic_curve256_algebra.h"
#include <cstdint>
#include <vector>
namespace fireblocks::common::cosigner
{

struct bam_single_signature_data_base
{
    uint32_t flags;                                 // signature flags
    elliptic_curve256_scalar_t message;             // message to sign
    elliptic_curve256_scalar_t derivation_delta;    // key derivation

};

struct bam_signature_metadata_header : public two_party_signature_metadata_header
{
    bam_signature_metadata_header() = default;
    bam_signature_metadata_header(const uint32_t ver, const uint64_t server_id, const uint64_t client_id, const std::string& signature_key_id, const int64_t creation_time) :
        two_party_signature_metadata_header(ver, signature_key_id, creation_time),
        server_signer_id(server_id),
        client_signer_id(client_id)
    {
    }

    uint64_t server_signer_id { 0 }; // player id of the server
    uint64_t client_signer_id { 0 }; // player id of the client
};

// Signing is done on a bulk of signatures. This is a generic container for BAM signature information
template <typename SIGNATURE_DATA_TYPE>
struct bam_signature_metadata_base : public bam_signature_metadata_header
{
    using bam_signature_metadata_header::bam_signature_metadata_header;

    std::vector<SIGNATURE_DATA_TYPE> sig_data;


};

}