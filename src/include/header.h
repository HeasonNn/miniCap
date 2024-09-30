#pragma once
#include <arpa/inet.h>

typedef struct {
    struct in6_addr src_ip;
    struct in6_addr dst_ip;
    int src_port;
    int dst_port;
    int protocol;
    int is_ipv6;
} FiveTuple;

