add_executable(shamir_secret_sharing_test
    tests.cpp
)

target_compile_options(shamir_secret_sharing_test PRIVATE -Wall -Wextra)
target_link_libraries(shamir_secret_sharing_test PRIVATE tests_main)

add_test(NAME shamir_secret_sharing_test COMMAND shamir_secret_sharing_test)
