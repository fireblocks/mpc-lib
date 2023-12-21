cmake_minimum_required(VERSION 3.13)
project(mpc-lib LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT TARGET OpenSSL::Crypto)
    set(OPENSSL_USE_STATIC_LIBS TRUE)
    find_package(OpenSSL 1.1.1 EXACT REQUIRED)
endif()

add_subdirectory(src/common)

if(NOT MPC_LIB_SKIP_TESTS)
    enable_testing()
    add_subdirectory(test)
endif()
