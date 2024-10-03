# 定义通用的外部库
set(COMMON_LIBS event pthread pcap hiredis)

# 引入主项目的源文件
set(MYPROJECT_SOURCES ${CMAKE_SOURCE_DIR}/src/lib/hash_table.c
                      ${CMAKE_SOURCE_DIR}/src/lib/redis.c
                      ${CMAKE_SOURCE_DIR}/src/lib/parse/parse_tls.c
                      ${CMAKE_SOURCE_DIR}/src/lib/parse/parse_tcp.c
                      ${CMAKE_SOURCE_DIR}/src/lib/format_utils.c
                      ${CMAKE_SOURCE_DIR}/src/lib/write.c)

# 定义一个函数用于添加测试
function(add_test_executable TEST_NAME SOURCE_FILE)
    add_executable(${TEST_NAME} ${SOURCE_FILE} ${MYPROJECT_SOURCES})
    target_link_libraries(${TEST_NAME} PRIVATE ${COMMON_LIBS})
    add_test(NAME ${TEST_NAME} COMMAND ${TEST_NAME})
endfunction()

# 添加测试可执行文件
add_test_executable(test_hash_table test_hash_table.c)
add_test_executable(test_parse_tls test_parse_tls.c)
add_test_executable(test_redis test_redis.c)