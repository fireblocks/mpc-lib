set(COSIGNER_FILES
    blockchain/mpc/hd_derive.cpp
    crypto/commitments/commitments.c
    crypto/commitments/ring_pedersen.c
    crypto/drng/drng.c
    crypto/ed25519_algebra/ed25519_algebra.c
    crypto/GFp_curve_algebra/GFp_curve_algebra.c
    crypto/keccak1600/keccak1600.c
    crypto/paillier/paillier_zkp.c
    crypto/paillier/paillier.c
    crypto/shamir_secret_sharing/verifiable_secret_sharing.c
    crypto/zero_knowledge_proof/diffie_hellman_log.c
    crypto/zero_knowledge_proof/range_proofs.c
    crypto/zero_knowledge_proof/schnorr.c
    cosigner/asymmetric_eddsa_cosigner_client.cpp
    cosigner/asymmetric_eddsa_cosigner_server.cpp
    cosigner/asymmetric_eddsa_cosigner.cpp
    cosigner/cmp_ecdsa_offline_signing_service.cpp
    cosigner/cmp_ecdsa_online_signing_service.cpp
    cosigner/cmp_ecdsa_signing_service.cpp
    cosigner/cmp_key_persistency.cpp
    cosigner/cmp_offline_refresh_service.cpp
    cosigner/cmp_setup_service.cpp
    cosigner/cosigner_exception.cpp
    cosigner/eddsa_online_signing_service.cpp
    cosigner/mta.cpp
    cosigner/platform_service.cpp
    cosigner/timing_map.cpp
    cosigner/utils.cpp
    logging/logging_t.c
)

add_library(cosigner SHARED ${COSIGNER_FILES})

set_target_properties(cosigner PROPERTIES
    CXX_VISIBILITY_PRESET "hidden"
    C_VISIBILITY_PRESET "hidden"
)

include(GenerateExportHeader)
generate_export_header(cosigner)

target_compile_options(cosigner PRIVATE
    -Wall -Wextra -Wvla -Wswitch-enum -Wno-missing-field-initializers -Wno-unknown-pragmas -fdiagnostics-color=always
    $<$<COMPILE_LANGUAGE:CXX>:
        -Wno-overloaded-virtual
    >
    $<$<CONFIG:Debug>:
        -Wformat -Wformat-security
    >
    $<$<NOT:$<CONFIG:Debug>>:
        -DNDEBUG -UEDEBUG -UDEBUG
    >
)

if(NOT EMSCRIPTEN)
    target_compile_options(cosigner PRIVATE -fstack-protector-strong)
endif()

target_include_directories(cosigner PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}>)
target_include_directories(cosigner PUBLIC ${PROJECT_SOURCE_DIR}/include)

target_link_libraries(cosigner PUBLIC OpenSSL::Crypto)
