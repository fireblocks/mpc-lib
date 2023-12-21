add_executable(cosigner_test
    ecdsa_offline_test.cpp
    ecdsa_online_test.cpp
    eddsa_offline_test.cpp
    eddsa_online_test.cpp
    main.cpp
    setup_test.cpp
)

find_package(Threads REQUIRED)

include(FindPkgConfig)
pkg_check_modules(UUID REQUIRED IMPORTED_TARGET uuid)

target_link_libraries(cosigner_test PRIVATE cosigner Threads::Threads PkgConfig::UUID)

add_test(NAME cosigner_test COMMAND cosigner_test)
