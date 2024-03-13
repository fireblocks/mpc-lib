list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

find_package(UUID REQUIRED)
find_package(Threads REQUIRED)


add_executable(cosigner_test
    ecdsa_offline_test.cpp
    ecdsa_online_test.cpp
    eddsa_offline_test.cpp
    eddsa_online_test.cpp
    setup_test.cpp
)

target_link_libraries(cosigner_test PRIVATE tests_main cosigner Threads::Threads UUID::UUID)

add_test(NAME cosigner_test COMMAND cosigner_test)
