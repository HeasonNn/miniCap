#pragma once

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <netinet/ether.h>

#include "../lib/write.h"

struct dns_header {
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
};

void parse_dns(const unsigned char *packet, int ip_header_len,
               int udp_header_len, struct tcp_udp_data_t *dns_data);