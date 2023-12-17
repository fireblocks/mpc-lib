add_executable(drng_test
    ${PROJECT_SOURCE_DIR}/src/common/crypto/drng/drng.c
    main.cpp
)

target_include_directories(drng_test PRIVATE ${PROJECT_SOURCE_DIR}/include)
target_compile_options(drng_test PRIVATE -Wall -Wextra)
target_link_libraries(drng_test PRIVATE OpenSSL::Crypto)

add_test(NAME drng_test COMMAND drng_test)
