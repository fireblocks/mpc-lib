add_executable(paillier_test
    tests.cpp
)

target_compile_options(paillier_test PRIVATE -Wall -Wextra)
target_link_libraries(paillier_test PRIVATE tests_main)

add_test(NAME paillier_test COMMAND paillier_test)
