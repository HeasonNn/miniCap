#pragma once

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <pcap.h>
#include <stdio.h>

#include "../format_utils.h"
#include "../write.h"

int parse_icmp(const char *device_name, const struct pcap_pkthdr *pkthdr,
               const unsigned char *packet, char *src_ip, char *dst_ip);