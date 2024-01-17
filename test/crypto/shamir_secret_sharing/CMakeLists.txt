add_executable(shamir_secret_sharing_test
    ${PROJECT_SOURCE_DIR}/src/common/crypto/commitments/commitments.c
    ${PROJECT_SOURCE_DIR}/src/common/crypto/ed25519_algebra/ed25519_algebra.c
    ${PROJECT_SOURCE_DIR}/src/common/crypto/GFp_curve_algebra/GFp_curve_algebra.c
    ${PROJECT_SOURCE_DIR}/src/common/crypto/keccak1600/keccak1600.c
    ${PROJECT_SOURCE_DIR}/src/common/crypto/shamir_secret_sharing/verifiable_secret_sharing.c
    tests.cpp
)

target_include_directories(shamir_secret_sharing_test PRIVATE ${PROJECT_SOURCE_DIR}/include)
target_compile_options(shamir_secret_sharing_test PRIVATE -Wall -Wextra)
target_link_libraries(shamir_secret_sharing_test PRIVATE tests_main OpenSSL::Crypto)

add_test(NAME shamir_secret_sharing_test COMMAND shamir_secret_sharing_test)
