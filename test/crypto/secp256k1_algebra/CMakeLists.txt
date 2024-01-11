add_executable(secp256k1_algebra_test
    ${PROJECT_SOURCE_DIR}/src/common/crypto/GFp_curve_algebra/GFp_curve_algebra.c
    tests.cpp
)

target_include_directories(secp256k1_algebra_test PRIVATE ${PROJECT_SOURCE_DIR}/include)
target_compile_options(secp256k1_algebra_test PRIVATE -Wall -Wextra)
target_link_libraries(secp256k1_algebra_test PRIVATE tests_main OpenSSL::Crypto)

add_test(NAME secp256k1_algebra_test COMMAND secp256k1_algebra_test)
