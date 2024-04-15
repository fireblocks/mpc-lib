cmake_minimum_required(VERSION 3.27)

# Fix for check_source_compiles: C: needs to be enabled before use.
# set(CMAKE_USER_MAKE_RULES_OVERRIDE "cmake_cpp_rules.cmake")

project(mpc-lib LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)
set(CMAKE_VERBOSE_MAKEFILE ON)

set(CMAKE_INCLUDE_CURRENT_DIR ON)## Always include the current directory

set(OPENSSL_USE_STATIC_LIBS TRUE)
find_package(OpenSSL REQUIRED)

set(CMAKE_VERBOSE_MAKEFILE ON)

if(WIN32)
   message("https://cmake.org/cmake/help/latest/variable/WIN32.html?highlight=win32")
elseif(APPLE)
   message("https://cmake.org/cmake/help/latest/variable/APPLE.html?highlight=apple")
elseif(UNIX)
    message("https://cmake.org/cmake/help/latest/variable/UNIX.html?highlight=unix")
    check_library_exists(snappy snappy_compress "" HAVE_SNAPPY)
endif()


# set fpic
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

add_subdirectory(src/common)
enable_testing()
add_subdirectory(test)

