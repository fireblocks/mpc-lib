add_executable(ed25519_algebra_test
    ${PROJECT_SOURCE_DIR}/src/common/crypto/ed25519_algebra/ed25519_algebra.c
    ${PROJECT_SOURCE_DIR}/src/common/crypto/keccak1600/keccak1600.c
    tests.cpp
)

target_include_directories(ed25519_algebra_test PRIVATE ${PROJECT_SOURCE_DIR}/include)
target_compile_options(ed25519_algebra_test PRIVATE -Wall -Wextra)
target_link_libraries(ed25519_algebra_test PRIVATE tests_main OpenSSL::Crypto)

add_test(NAME ed25519_algebra_test COMMAND ed25519_algebra_test)
