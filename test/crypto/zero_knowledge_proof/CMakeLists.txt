add_executable(zero_knowledge_proof_test
    ${PROJECT_SOURCE_DIR}/src/common/crypto/commitments/ring_pedersen.c
    ${PROJECT_SOURCE_DIR}/src/common/crypto/drng/drng.c
    ${PROJECT_SOURCE_DIR}/src/common/crypto/ed25519_algebra/ed25519_algebra.c
    ${PROJECT_SOURCE_DIR}/src/common/crypto/GFp_curve_algebra/GFp_curve_algebra.c
    ${PROJECT_SOURCE_DIR}/src/common/crypto/keccak1600/keccak1600.c
    ${PROJECT_SOURCE_DIR}/src/common/crypto/paillier/paillier.c
    ${PROJECT_SOURCE_DIR}/src/common/crypto/zero_knowledge_proof/diffie_hellman_log.c
    ${PROJECT_SOURCE_DIR}/src/common/crypto/zero_knowledge_proof/range_proofs.c
    ${PROJECT_SOURCE_DIR}/src/common/crypto/zero_knowledge_proof/schnorr.c
    tests.cpp
)

target_include_directories(zero_knowledge_proof_test PRIVATE ${PROJECT_SOURCE_DIR}/include)
target_compile_options(zero_knowledge_proof_test PRIVATE -Wall -Wextra)
target_link_libraries(zero_knowledge_proof_test PRIVATE tests_main OpenSSL::Crypto)

add_test(NAME zero_knowledge_proof_test COMMAND zero_knowledge_proof_test)
