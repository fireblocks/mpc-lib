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

class platform_service;
class cmp_key_persistency;

void verify_tenant_id(const platform_service& service, const cmp_key_persistency& key_persistency, const std::string& key_id);

// Destination-side consumer of add-user / key-redistribute: each source player
// additively re-split its own share among the destination players; this player
// (my_player_id, one of the destination players) decrypts its own piece from
// every source part and sums them into its share of the same secret.
// Source-agnostic: any source key with >= 2 players (2-party/BAM or n-party CMP)
// is accepted - data holds one entry per source player. destination_n is the
// destination key's player count (2 for the 2-party BAM/FROST callers): every
// source part must contain exactly one encrypted share per destination player.
void decrypt_and_rebuild_private_share(uint64_t my_player_id,
                                       elliptic_curve256_algebra_ctx_t* algebra,
                                       const platform_service& service,
                                       const std::map<uint64_t, additive_add_user_data>& data,
                                       size_t destination_n,
                                       elliptic_curve_scalar& private_share,
                                       elliptic_curve256_point_t& expected_public_key);

// Produces the source-side counterpart of decrypt_and_rebuild_private_share:
// additively re-splits my own share among new_player_ids (each piece encrypted
// for its recipient via platform_service::encrypt_for_player, with the
// recipient's expected public key modulus verified before encryption) and
// records the existing key's public key, so the new players can rebuild a fresh
// sharing of the same secret. new_player_ids must be unique and every id must
// have a modulus in new_player_id_to_modulus (collected by the service layer's
// new-players verification). Mirrors the CMP additive source path, but takes the
// share directly (for protocols that hold their share outside the base key store,
// e.g. 2-party/BAM).
void build_additive_add_user_data(elliptic_curve256_algebra_ctx_t* algebra,
                                  const platform_service& service,
                                  const elliptic_curve_scalar& my_share,
                                  const elliptic_curve256_point_t& public_key,
                                  const std::vector<uint64_t>& new_player_ids,
                                  const std::map<uint64_t, std::string>& new_player_id_to_modulus,
                                  additive_add_user_data& data);

// Shared operation-type validation for add-user vs key-redistribute. Kept here
// in common code (as a free function rather than a service member) so every
// protocol - CMP, additive/FROST and 2-party/BAM - enforces the identical rule:
//   * redistribute -> old and new player sets must overlap in >= 1 player
//   * add-user     -> old and new player sets must be disjoint
// Only the mobile player id is stable across keys (the cloud id is key-specific),
// so the retained (redistribute) / forbidden (add-user) common player is always
// the mobile. Throws cosigner_exception(INVALID_PARAMETERS) on violation.
void same_players_validation(const std::set<uint64_t>& old_players_ids,
                             const std::vector<uint64_t>& new_players_ids,
                             bool is_redistribute_request,
                             const std::string& old_key_id,
                             const std::string& new_key_id);

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


}
}
}