#include "utils.h"
#include <cinttypes>
#include <openssl/crypto.h>
#include "cosigner/cmp_key_persistency.h"
#include "cosigner/cosigner_exception.h"
#include "cosigner/platform_service.h"
#include "logging/logging_t.h"

namespace fireblocks
{
namespace common
{
namespace cosigner
{

void verify_tenant_id(const platform_service& service, const cmp_key_persistency& key_persistency, const std::string& key_id)
{
    const std::string tenant_id = service.get_current_tenantid();
    if (tenant_id.compare(key_persistency.get_tenantid_from_keyid(key_id)) != 0)
    {
        LOG_ERROR("key id %s is not part of tenant %s", key_id.c_str(), tenant_id.c_str());
        throw_cosigner_exception(cosigner_exception::UNAUTHORIZED);
    }
}

void decrypt_and_rebuild_private_share(uint64_t my_player_id,
                                       elliptic_curve256_algebra_ctx_t* algebra,
                                       const platform_service& service,
                                       const std::map<uint64_t, additive_add_user_data>& data,
                                       const size_t destination_n,
                                       elliptic_curve_scalar& private_share,
                                       elliptic_curve256_point_t& expected_public_key)
{
    OPENSSL_cleanse(private_share.data, sizeof(private_share.data));

    // every MPC key has at least 2 players, on both sides of the operation
    if (data.size() < 2)
    {
        LOG_ERROR("got source parts from %u players, expected at least 2", (uint32_t)data.size());
        throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
    }
    if (destination_n < 2)
    {
        LOG_ERROR("invalid destination player count %u, expected at least 2", (uint32_t)destination_n);
        throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
    }

    bool is_first = true;
    // perform validations
    for (const auto& src_player_data : data)
    {
        if (src_player_data.second.encrypted_shares.size() != destination_n)
        {
            LOG_ERROR("Incorrect encrypted shares size %u from player %" PRIu64 ", expected %u", (uint32_t) src_player_data.second.encrypted_shares.size(), src_player_data.first, (uint32_t)destination_n);
            throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
        }

        if (is_first)
        {
            is_first = false;
            memcpy(&expected_public_key[0], &src_player_data.second.public_key.data[0], sizeof(elliptic_curve256_point_t));
        }
        else if (memcmp(&expected_public_key[0], &src_player_data.second.public_key.data[0], sizeof(elliptic_curve256_point_t)) != 0)
        {
            LOG_ERROR("Public key from player %" PRIu64 " is different from the key sent by player %" PRIu64, src_player_data.first, data.begin()->first);
            throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
        }

        const auto my_encrypted_share = src_player_data.second.encrypted_shares.find(my_player_id);
        if (my_encrypted_share == src_player_data.second.encrypted_shares.end())
        {
            LOG_ERROR("Player %" PRIu64 " didn't send share to me", src_player_data.first);
            throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
        }

        auto share = service.decrypt_message(my_encrypted_share->second);
        throw_cosigner_exception(algebra->add_scalars(algebra, &private_share.data, &private_share.data[0], sizeof(elliptic_curve256_scalar_t), (const uint8_t*)share.data(), share.size()));
    }
}

void build_additive_add_user_data(elliptic_curve256_algebra_ctx_t* algebra,
                                  const platform_service& service,
                                  const elliptic_curve_scalar& my_share,
                                  const elliptic_curve256_point_t& public_key,
                                  const std::vector<uint64_t>& new_player_ids,
                                  const std::map<uint64_t, std::string>& new_player_id_to_modulus,
                                  additive_add_user_data& data)
{
    const size_t n = new_player_ids.size();
    if (n < 2)
    {
        LOG_ERROR("build_additive_add_user_data needs at least 2 new players, got %zu", n);
        throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
    }

    const std::set<uint64_t> distinct_player_ids(new_player_ids.begin(), new_player_ids.end());
    if (distinct_player_ids.size() != n)
    {
        LOG_ERROR("got duplicated new player ids, %zu ids but only %zu unique ones", n, distinct_player_ids.size());
        throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
    }

    // Additively re-split my_share into n pieces: n-1 random + remainder, so they
    // sum back to my_share. (elliptic_curve_scalar zeroes itself on destruction.)
    std::vector<elliptic_curve_scalar> shares(n);
    elliptic_curve_scalar running_sum; // zero-initialized
    for (size_t i = 0; i + 1 < n; ++i)
    {
        throw_cosigner_exception(algebra->rand(algebra, &shares[i].data));
        throw_cosigner_exception(algebra->add_scalars(algebra, &running_sum.data,
                                                      running_sum.data, sizeof(running_sum.data),
                                                      shares[i].data, sizeof(shares[i].data)));
    }
    throw_cosigner_exception(algebra->sub_scalars(algebra, &shares[n - 1].data,
                                                  my_share.data, sizeof(my_share.data),
                                                  running_sum.data, sizeof(running_sum.data)));

    for (size_t i = 0; i < n; ++i)
    {
        const uint64_t id = new_player_ids[i];
        const auto modulus_it = new_player_id_to_modulus.find(id);
        if (modulus_it == new_player_id_to_modulus.end())
        {
            LOG_ERROR("missing public key modulus for new player %" PRIu64, id);
            throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
        }
        const byte_vector_t share_bytes(shares[i].data, shares[i].data + sizeof(elliptic_curve256_scalar_t));
        data.encrypted_shares[id] = service.encrypt_for_player(id, share_bytes, modulus_it->second);
    }

    // The existing key's public key must be preserved unchanged.
    memcpy(data.public_key.data, public_key, sizeof(elliptic_curve256_point_t));
}

void same_players_validation(const std::set<uint64_t>& old_players_ids, const std::vector<uint64_t>& new_players_ids, const bool is_redistribute_request, const std::string& old_key_id, const std::string& new_key_id)
{
    std::vector<uint64_t> same_players;
    same_players.reserve(1); // at most there will be one user
    for (const auto& new_player : new_players_ids)
    {
        if (old_players_ids.find(new_player) != old_players_ids.end())
        {
            same_players.emplace_back(new_player);
        }
    }

    // mobile player id remains the same for all keys, while cloud player id changes with key
    // this ensures that the cloud players will be different for each key even if both keys are on the same cloud cosigner

    // in redistribute request at least one player should remain the same
    if (is_redistribute_request && same_players.empty())
    {
        LOG_ERROR("Found no common players during an attempt to redistribute key shares of key %s to key %s", old_key_id.c_str(), new_key_id.c_str());
        throw_cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
    }

    // in the regular add user we expect all players to change, including mobile
    if (!is_redistribute_request && !same_players.empty())
    {
        LOG_ERROR("Found common playerid %" PRIu64 " which is already part of key %s while preparing shares for key %s", same_players[0], old_key_id.c_str(), new_key_id.c_str());
        throw_cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
    }
}

}
}
}