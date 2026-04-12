add_executable(entropy_test
    tests.cpp
    entropy_test_framework.cpp
)

target_compile_options(entropy_test PRIVATE -Wall -Wextra)
target_link_libraries(entropy_test PRIVATE tests_main)

add_test(NAME entropy_test COMMAND entropy_test)
