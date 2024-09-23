#pragma once

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <net/ethernet.h>
#include <netinet/ip.h>
#include <pcap.h>
#include <stdio.h>

#include "../lib/format_utils.h"
#include "../lib/write.h"

#include "parse_tcp.h"
#include "parse_udp.h"
#include "parse_icmp_icmp6.h"

void parse_ip(const char *device_name, const struct pcap_pkthdr *pkthdr,
              const unsigned char *packet);

void parse_ipv6(const char *device_name, const struct pcap_pkthdr *pkthdr,
                const unsigned char *packet,
                const struct ether_header *ether_header);