#pragma once

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <pcap.h>
#include <stdio.h>

#include "../lib/format_utils.h"
#include "../lib/write.h"
#include "parse_dns.h"

#ifndef DNS_PORT
#define DNS_PORT 53
#endif

void parse_udp(const char *device_name, const struct pcap_pkthdr *pkthdr,
               const unsigned char *packet, const struct ip *ip_header,
               char *src_ip, char *dst_ip);