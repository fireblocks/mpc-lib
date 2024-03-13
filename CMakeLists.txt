cmake_minimum_required(VERSION 3.13)
project(mpc-lib LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT TARGET OpenSSL::Crypto)
    set(OPENSSL_USE_STATIC_LIBS TRUE)
    add_compile_definitions(OPENSSL_API_COMPAT=0x10101000L)
    find_package(OpenSSL 1.1.1 REQUIRED)
endif()

add_subdirectory(src/common)

if(${CMAKE_SOURCE_DIR} STREQUAL ${PROJECT_SOURCE_DIR} AND NOT MPC_LIB_SKIP_TESTS)
    enable_testing()
    add_subdirectory(test)
endif()
