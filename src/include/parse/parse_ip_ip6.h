#pragma once

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <net/ethernet.h>
#include <netinet/ip.h>
#include <pcap.h>
#include <stdio.h>

#include "../format_utils.h"
#include "../write.h"
#include "parse_icmp_icmp6.h"
#include "parse_tcp.h"
#include "parse_udp.h"

int parse_ip(const char *device_name, const struct pcap_pkthdr *pkthdr,
             const unsigned char *packet);

int parse_ipv6(const char *device_name, const struct pcap_pkthdr *pkthdr,
               const unsigned char *packet,
               const struct ether_header *ether_header);