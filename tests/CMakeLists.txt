set(COMMON_LIBS mylib parse pcap event pthread)

function(add_test_executable TEST_NAME SOURCE_FILE)
    add_executable(${TEST_NAME} ${SOURCE_FILE})
    target_link_libraries(${TEST_NAME} PRIVATE ${COMMON_LIBS})
    add_test(NAME ${TEST_NAME} COMMAND ${TEST_NAME})
endfunction()

add_test_executable(test_hash_table test_hash_table.c)
add_test_executable(test_parse_tls test_parse_tls.c)