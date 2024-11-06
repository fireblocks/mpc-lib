add_executable(secp256k1_algebra_test
    tests.cpp
)

target_compile_options(secp256k1_algebra_test PRIVATE -Wall -Wextra)
target_link_libraries(secp256k1_algebra_test PRIVATE tests_main)

add_test(NAME secp256k1_algebra_test COMMAND secp256k1_algebra_test)
