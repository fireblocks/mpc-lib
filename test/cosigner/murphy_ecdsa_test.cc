#include <iostream>
#include <iomanip>
#include <memory>
#include <uuid/uuid.h>

#include "cosigner/cmp_ecdsa_offline_signing_service.h"
#include "cosigner/cosigner_exception.h"
#include "cosigner/cmp_signature_preprocessed_data.h"
#include "cosigner/cmp_offline_refresh_service.h"
#include "cosigner/types.h"
#include "test_info.h"
#include "signing_test.h"
#include "crypto/elliptic_curve_algebra/elliptic_curve256_algebra.h"
#include "crypto/GFp_curve_algebra/GFp_curve_algebra.h"
#include "cosigner/cmp_key_persistency.h"
#include "cosigner/mpc_globals.h"



using Clock = std::conditional<std::chrono::high_resolution_clock::is_steady, std::chrono::high_resolution_clock,
        std::chrono::steady_clock>::type;

const uint32_t BLOCK_SIZE = 10;

constexpr char hexmap[] = {'0', '1', '2', '3', '4', '5', '6', '7','8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};


std::string binTohexStr(const std::unique_ptr<unsigned char[]>& data, int len)
{
  std::string s(len * 2, ' ');
  for (int i = 0; i < len; ++i) {
    s[2 * i]     = hexmap[(data.get()[i] & 0xF0) >> 4];
    s[2 * i + 1] = hexmap[data.get()[i] & 0x0F];
  }
  return s;
}

std::string UintToHex(const std::vector<uint8_t>& UintRep){
  std::unique_ptr<unsigned char[]> uncharRep (new unsigned char[UintRep.size()]);
  int index(0);
  for(std::vector<uint8_t>::const_iterator iter = UintRep.begin(); iter != UintRep.end(); ++iter){
    uncharRep[index++] = *iter; 
  }
  return (binTohexStr(uncharRep, UintRep.size()));
}

std::string ecpoint_TohexStr(const elliptic_curve256_point_t& data, int len)
{
  std::string s(len * 2, ' ');
  for (int i = 0; i < len; ++i) {
    s[2 * i]     = hexmap[(data[i] & 0xF0) >> 4];
    s[2 * i + 1] = hexmap[data[i] & 0x0F];
  }
  return s;
}

int main(int argc, char* argv[]){
    std::cout << "hello" << std::endl;
    fireblocks::common::cosigner::byte_vector_t chaincode(32, '\0');
    std::vector<uint32_t> path = {44, 0, 0, 0, 0};
    char keyid[37] = {0};
    elliptic_curve256_point_t pubkey;

    // typedef std::map<uint64_t, setup_persistency> players_setup_info;
    // setup_persistency has an internal structure with the private keys
    players_setup_info players;

    uuid_t uid;
    uuid_generate_random(uid);
#if 0
    std::cout << std::hex << std::setfill('0'); ;

    for (int i = 0; i < sizeof(uid); i++) {
        std::cout << std::setw(2) << static_cast<unsigned>(uid[i]);
        if (i == 3 || i == 5 || i == 7 || i == 9) {
            printf("-");
        }
    }
#endif
    std::cout << std::endl; 
    uuid_unparse(uid, keyid);
    std::cout << keyid << std::endl; 
    players.clear();
    players[1];
    players[2];
    players[3]; 
    create_secret(players, keyid, pubkey);
    for(auto i = players.begin(); i != players.end(); ++ i){
        std::cout << i->first << "\t" << i->second.dump_key(keyid) << std::endl; 
        std::cout << "Public Key -> " << ecpoint_TohexStr(pubkey, 33) << std::endl; 
    }

    std::map<uint64_t, std::unique_ptr<offline_siging_info>> services;
    for (auto i = players.begin(); i != players.end(); ++i)
    {
        auto info = std::make_unique<offline_siging_info>(i->first, i->second);
        services.emplace(i->first, move(info));
    }

    auto before = Clock::now();
    ecdsa_preprocess(services, keyid, 0, BLOCK_SIZE, BLOCK_SIZE);
    auto after = Clock::now();
    std::cout << "ECDSA preprocessing took: " << std::chrono::duration_cast<std::chrono::milliseconds>(after - before).count() << " ms" << std::endl;

    ecdsa_sign(services, ECDSA_SECP256K1, keyid, 0, 1, pubkey, chaincode, {path});

    return 0;
}