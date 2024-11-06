add_executable(drng_test
    tests.cpp
)

target_compile_options(drng_test PRIVATE -Wall -Wextra)
target_link_libraries(drng_test PRIVATE tests_main)

add_test(NAME drng_test COMMAND drng_test)
