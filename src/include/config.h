#pragma once

#include <stdio.h>

struct config_t
{
    int verbose;
    int parse_tcp;
    int parse_udp;
    int parse_icmp;
    int parse_arp;
    int parse_ip;
    int parse_ipv6;
    int parse_dns;
    int parse_unknow;
    int parse_tls;
};

static struct config_t config = {
    .verbose = 1,
    .parse_arp = 1,
    .parse_icmp = 1,
    .parse_ipv6 = 1,
    .parse_tcp = 1,
    .parse_udp = 1,
    .parse_dns = 1,
    .parse_unknow = 1,
    .parse_ip = 1,
    .parse_tls = 1,
};

void read_config(struct config_t *config);