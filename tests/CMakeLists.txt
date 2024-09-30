add_executable(test_hash_table test_hash_table.c)

target_link_libraries(test_hash_table PRIVATE mylib parse pcap event pthread)

add_test(NAME HashTableTest COMMAND test_hash_table)