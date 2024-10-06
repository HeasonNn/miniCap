set(COMMON_LIBS event pthread pcap hiredis)

set(MYPROJECT_SOURCES ${CMAKE_SOURCE_DIR}/src/lib/hash_table.c
                      ${CMAKE_SOURCE_DIR}/src/lib/redis.c
                      ${CMAKE_SOURCE_DIR}/src/lib/parse/parse_tls.c
                      ${CMAKE_SOURCE_DIR}/src/lib/parse/parse_tcp.c
                      ${CMAKE_SOURCE_DIR}/src/lib/format_utils.c
                      ${CMAKE_SOURCE_DIR}/src/lib/write.c)

function(add_test_executable TEST_NAME SOURCE_FILE)
    add_executable(${TEST_NAME} ${SOURCE_FILE} ${MYPROJECT_SOURCES})
    target_link_libraries(${TEST_NAME} PRIVATE ${COMMON_LIBS})
    add_test(NAME ${TEST_NAME} COMMAND ${TEST_NAME})
endfunction()

add_test_executable(test_hash_table test_hash_table.c)
add_test_executable(test_parse_tls test_parse_tls.c)
add_test_executable(test_redis test_redis.c)