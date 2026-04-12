#pragma once

namespace fireblocks
{
namespace common
{
namespace cosigner
{

constexpr unsigned int MAX_BLOCKS_TO_SIGN = 1000;

constexpr int MPC_MIN_SUPPORTED_PROTOCOL_VERSION                = 2;
constexpr int MPC_DONT_ENCRYPT_MTA_RESPONSE_PROTOCOL_VERSION    = 3;
constexpr int MPC_EDDSA_VERSION                                 = 4;
constexpr int MPC_CMP_VERSION                                   = 5;
constexpr int MPC_CMP_ONLINE_VERSION                            = 6;
constexpr int MPC_STARK_VERSION                                 = 7;
constexpr int MPC_RAND_R_VERSION                                = 8;
constexpr int MPC_ASYMMETRIC_EDDSA                              = 9;
constexpr int MPC_REDISTRIBUTE_KEY                              = 10;
constexpr int MPC_EXTENDED_MTA                                  = 11;
constexpr int MPC_BAM_ECDSA_BETA                                = 12;
constexpr int MPC_BAM_ECDSA                                     = 13;

constexpr int MPC_PROTOCOL_VERSION                              = MPC_BAM_ECDSA;

}
}
}
