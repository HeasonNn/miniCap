#pragma once

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <pcap.h>

#include "../config.h"
#include "../format_utils.h"
#include "../write.h"
#include "parse_arp.h"
#include "parse_ip_ip6.h"

void parse_func_handler(unsigned char *user, const struct pcap_pkthdr *pkthdr,
                        const unsigned char *packet);

int parse_func(unsigned char *user, const struct pcap_pkthdr *pkthdr,
               const unsigned char *packet);