# 创建库
add_library(parse STATIC
    parse_dns.c
    parse_arp.c
    parse_icmp_icmp6.c
    parse_ip_ip6.c
    parse_tcp.c
    parse_udp.c
)

# 设置包含目录
target_include_directories(parse PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(parse PRIVATE mylib)