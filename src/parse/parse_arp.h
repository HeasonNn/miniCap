#pragma once

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif


#include <pcap.h>
#include <stdio.h>
#include <net/ethernet.h>
#include <net/if_arp.h>

#include "../lib/write.h"
#include "../lib/format_utils.h"

#ifndef MAC_ADDR_LEN
#define MAC_ADDR_LEN 18
#endif

void parse_arp(const char *user, const struct pcap_pkthdr *pkthdr,
               const unsigned char *packet,
               const struct ether_header *eth_header);