add_executable(zero_knowledge_proof_test
    tests.cpp
)

target_compile_options(zero_knowledge_proof_test PRIVATE -Wall -Wextra)
target_link_libraries(zero_knowledge_proof_test PRIVATE tests_main)

add_test(NAME zero_knowledge_proof_test COMMAND zero_knowledge_proof_test)
