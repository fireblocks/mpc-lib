#include <iostream>
#include "signing_test.h"
#include "crypto/GFp_curve_algebra/GFp_curve_algebra.h"
 #include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>

void ecdsa_preprocess(std::map<uint64_t, std::unique_ptr<offline_siging_info>>& services, const std::string& keyid, uint32_t start, uint32_t count, uint32_t total){
    uuid_t uid;
    char request[37] = {0};
    uuid_generate_random(uid);
    uuid_unparse(uid, request);
    std::cout << "request id = " << request << std::endl;

    std::set<uint64_t> players_ids;
    for (auto i = services.begin(); i != services.end(); ++i)
        players_ids.insert(i->first);

    std::map<uint64_t, std::vector<fireblocks::common::cosigner::cmp_mta_request>> mta_requests;
    for (auto i = services.begin(); i != services.end(); ++i){
        auto& mta_request = mta_requests[i->first];
        //REQUIRE_NOTHROW(i->second->signing_service.start_ecdsa_signature_preprocessing(TENANT_ID, keyid, request, start, count, total, players_ids, mta_request));
        i->second->signing_service.start_ecdsa_signature_preprocessing(TENANT_ID, keyid, request, start, count, total, players_ids, mta_request);
    }

    std::map<uint64_t, fireblocks::common::cosigner::cmp_mta_responses> mta_responses;
    for (auto i = services.begin(); i != services.end(); ++i)
    {
        auto& response = mta_responses[i->first];
        i->second->signing_service.offline_mta_response(request, mta_requests, response);
    }
    mta_requests.clear();

    std::map<uint64_t, std::vector<fireblocks::common::cosigner::cmp_mta_deltas>> deltas;
    for (auto i = services.begin(); i != services.end(); ++i){
        auto& delta = deltas[i->first];
        //REQUIRE_NOTHROW(i->second->signing_service.offline_mta_verify(request, mta_responses, delta));
        i->second->signing_service.offline_mta_verify(request, mta_responses, delta);
    }
    mta_responses.clear();

    std::map<uint64_t, std::vector<fireblocks::common::cosigner::elliptic_curve_scalar>> sis;
    for (auto i = services.begin(); i != services.end(); ++i){
        auto& si = sis[i->first];
        std::string key_id;
        //REQUIRE_NOTHROW(i->second->signing_service.store_presigning_data(request, deltas, key_id));
        i->second->signing_service.store_presigning_data(request, deltas, key_id);
        assert(key_id == keyid);
    }
}

void ecdsa_sign(std::map<uint64_t, std::unique_ptr<offline_siging_info>>& services, cosigner_sign_algorithm type, 
                        const std::string& keyid, uint32_t start_index, uint32_t count, const elliptic_curve256_point_t& pubkey, 
                        const fireblocks::common::cosigner::byte_vector_t& chaincode, const std::vector<std::vector<uint32_t>>& paths, bool positive_r){
    uuid_t uid;
    char txid[37] = {0};
    uuid_generate_random(uid);
    uuid_unparse(uid, txid);
    std::cout << "txid id = " << txid << std::endl;

    std::set<uint64_t> players_ids;
    std::set<std::string> players_str;
    for (auto i = services.begin(); i != services.end(); ++i){
        players_ids.insert(i->first);
        players_str.insert(std::to_string(i->first));
        i->second->platform_service.set_positive_r(positive_r);
    }

    assert(chaincode.size() == sizeof(HDChaincode));
    fireblocks::common::cosigner::signing_data data;
    memcpy(data.chaincode, chaincode.data(), sizeof(HDChaincode));
    for (size_t i = 0; i < count; i++)
    {
        fireblocks::common::cosigner::signing_block_data block;
        block.data.insert(block.data.begin(), 32, '0');
        block.path = paths[i];
        data.blocks.push_back(block);
    }

    std::map<uint64_t, std::vector<fireblocks::common::cosigner::recoverable_signature>> partial_sigs;
    for (auto i = services.begin(); i != services.end(); ++i){
        auto& sigs = partial_sigs[i->first];
        std::string key_id;
        //REQUIRE_NOTHROW(i->second->signing_service.ecdsa_sign(keyid, txid, data, "", players_str, players_ids, start_index, sigs));
        i->second->signing_service.ecdsa_sign(keyid, txid, data, "", players_str, players_ids, start_index, sigs);
    }

    std::vector<fireblocks::common::cosigner::recoverable_signature> sigs;
    for (auto i = services.begin(); i != services.end(); ++i){
        //REQUIRE_NOTHROW(i->second->signing_service.ecdsa_offline_signature(keyid, txid, type, partial_sigs, sigs));
        i->second->signing_service.ecdsa_offline_signature(keyid, txid, type, partial_sigs, sigs);
    }

    //std::unique_ptr<elliptic_curve256_algebra_ctx_t, void(*)(elliptic_curve256_algebra_ctx_t*)> algebra(create_algebra(type), elliptic_curve256_algebra_ctx_free);
    std::unique_ptr<elliptic_curve256_algebra_ctx_t, void(*)(elliptic_curve256_algebra_ctx_t*)> algebra(elliptic_curve256_new_secp256k1_algebra(), elliptic_curve256_algebra_ctx_free);

    std::cout << "Value of count -> " << count << std::endl;
    for (size_t i = 0; i < count; i++)
    {
        elliptic_curve256_scalar_t msg;
        assert(data.blocks[i].data.size() == sizeof(elliptic_curve256_scalar_t));
        memcpy(msg, data.blocks[i].data.data(), sizeof(elliptic_curve256_scalar_t));
        std::cout << "sig r: " << HexStr(sigs[i].r, &sigs[i].r[sizeof(elliptic_curve256_scalar_t)]) << std::endl;
        std::cout << "sig s: " << HexStr(sigs[i].s, &sigs[i].s[sizeof(elliptic_curve256_scalar_t)]) << std::endl;
        
        PubKey derived_key;
        assert(derive_public_key_generic(algebra.get(), derived_key, pubkey, data.chaincode, paths[i].data(), paths[i].size()) == HD_DERIVE_SUCCESS);
        std::cout << "derived public_key: " << HexStr(derived_key, &derived_key[sizeof(PubKey)]) << std::endl;

        assert(GFp_curve_algebra_verify_signature((GFp_curve_algebra_ctx_t*)algebra->ctx, &derived_key, &msg, &sigs[i].r, &sigs[i].s) == ELLIPTIC_CURVE_ALGEBRA_SUCCESS); 
  
        std::cout << "Signature verified" << std::endl; 
        if (positive_r){
            assert(is_positive(sigs[i].r));
        }

    std::cout << "Verifying with openssl" << std::endl; 
#if 0
    int            ECDSA_verify(int type, const unsigned char *dgst,
                        int dgstlen, const unsigned char *sig,
                        int siglen, EC_KEY *eckey);
#endif
    {
        // Allocate for CTX
        std::unique_ptr<BN_CTX, decltype(&BN_CTX_free)> ctxptr (BN_CTX_new(), &BN_CTX_free );
        if (ctxptr == nullptr) {
            std::cout << "Failed to create BN context " << std::endl; 
            return; 
        }

        EC_GROUP * gp = EC_GROUP_new_by_curve_name(NID_secp256k1);
        std::string pubkey_hex = HexStr(derived_key, &derived_key[sizeof(PubKey)]); 
        std::cout << "PUBKEY_HERE -> " << pubkey_hex << std::endl; 
        EC_POINT * ec = EC_POINT_hex2point(gp, pubkey_hex.c_str(), NULL, ctxptr.get());
        EC_KEY* ec_key = EC_KEY_new_by_curve_name(NID_secp256k1);

        if (EC_KEY_set_public_key(ec_key, ec) == 0){
            std::cout << "Failed to convert public key" << std::endl; 
        }
        uint8_t raw_sig[sizeof(elliptic_curve256_scalar_t) * 2];
        memcpy(raw_sig, sigs[i].r, sizeof(elliptic_curve256_scalar_t));
        memcpy(&raw_sig[sizeof(elliptic_curve256_scalar_t)], sigs[i].s, sizeof(elliptic_curve256_scalar_t));
        elliptic_curve256_scalar_t digest;
        memcpy(msg, data.blocks[0].data.data(), sizeof(elliptic_curve256_scalar_t));
        // create an EC_Point from a hex string
        int ret = ECDSA_verify(0, digest, sizeof(elliptic_curve256_scalar_t), raw_sig, sizeof(elliptic_curve256_scalar_t) * 2, ec_key);
        std::cout << "result of verify -> " << ret << std::endl; 
        EC_KEY_free(ec_key); 
        EC_POINT_free(ec); 
        EC_GROUP_free(gp); 
    }
#ifdef USE_SECP256K1

     
        std::unique_ptr<secp256k1_context, void(*)(secp256k1_context*)> secp_ctx(secp256k1_context_create(SECP256K1_CONTEXT_VERIFY), secp256k1_context_destroy);
        if (type == ECDSA_SECP256K1)
        {
            uint8_t raw_sig[sizeof(elliptic_curve256_scalar_t) * 2];
            secp256k1_ecdsa_signature sig;
            secp256k1_pubkey public_key;
            memcpy(raw_sig, sigs[i].r, sizeof(elliptic_curve256_scalar_t));
            memcpy(&raw_sig[sizeof(elliptic_curve256_scalar_t)], sigs[i].s, sizeof(elliptic_curve256_scalar_t));
            REQUIRE(secp256k1_ec_pubkey_parse(secp_ctx.get(), &public_key, derived_key, sizeof(PubKey)));
            REQUIRE(secp256k1_ecdsa_signature_parse_compact(secp_ctx.get(), &sig, raw_sig));
            REQUIRE(secp256k1_ecdsa_verify(secp_ctx.get(), &sig, msg, &public_key));
            secp256k1_ecdsa_recoverable_signature recoverable_sig;
            secp256k1_pubkey recoveredPubKey = {0};
            int retVal = secp256k1_ecdsa_recoverable_signature_parse_compact(secp_ctx.get(), &recoverable_sig, raw_sig, sigs[i].v);
            REQUIRE(secp256k1_ecdsa_recover(secp_ctx.get(), &recoveredPubKey, &recoverable_sig, msg));
            REQUIRE(memcmp(recoveredPubKey.data, public_key.data, sizeof(secp256k1_pubkey)) == 0);

        }
#endif        
    }
}
