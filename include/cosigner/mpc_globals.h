#pragma once

namespace fireblocks
{
namespace common
{
namespace cosigner
{

constexpr unsigned int MAX_BLOCKS_TO_SIGN = 1000;

constexpr int MPC_PROTOCOL_VERSION = 7;

constexpr int MPC_MIN_SUPPORTED_PROTOCOL_VERSION = 2;
constexpr int MPC_DONT_ENCRYPT_MTA_RESPONSE_PROTOCOL_VERSION = 3;
constexpr int MPC_EDDSA_VERSION = 4;
constexpr int MPC_CMP_VERSION = 5;
constexpr int MPC_CMP_ONLINE_VERSION = 6;
constexpr int MPC_STARK_VERSION = 7;
}
}
}
