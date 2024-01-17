add_executable(paillier_test
    ${PROJECT_SOURCE_DIR}/src/common/crypto/paillier/paillier_zkp.c
    ${PROJECT_SOURCE_DIR}/src/common/crypto/paillier/paillier.c
    tests.cpp
)

target_include_directories(paillier_test PRIVATE ${PROJECT_SOURCE_DIR}/include)
target_compile_options(paillier_test PRIVATE -Wall -Wextra)
target_link_libraries(paillier_test PRIVATE tests_main OpenSSL::Crypto)

add_test(NAME paillier_test COMMAND paillier_test)
