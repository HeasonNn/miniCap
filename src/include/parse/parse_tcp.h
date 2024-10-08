#pragma once

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <pcap.h>
#include <stdio.h>

#include "../format_utils.h"
#include "../header.h"
#include "../write.h"
#include "parse_tls.h"

#ifndef TLS_PORT
#define TLS_PORT 443
#endif

#ifndef SSL_PORT
#define SSL_PORT TLS_PORT
#endif

int parse_tcp(const char *device_name, const struct pcap_pkthdr *pkthdr,
              const unsigned char *packet, const struct ip *ip_header,
              char *src_ip, char *dst_ip);