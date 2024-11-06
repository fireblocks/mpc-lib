add_executable(ed25519_algebra_test
    tests.cpp
)

target_compile_options(ed25519_algebra_test PRIVATE -Wall -Wextra)
target_link_libraries(ed25519_algebra_test PRIVATE tests_main)

add_test(NAME ed25519_algebra_test COMMAND ed25519_algebra_test)
