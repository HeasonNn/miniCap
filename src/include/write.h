#pragma once

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include "config.h"
#include "format_utils.h"

#define MAX_INTERFACES 10

#ifndef MAC_ADDR_LEN
#define MAC_ADDR_LEN 18
#endif

typedef void (*write_func_t)(FILE *, const void *);

struct tcp_udp_data_t {
    const char *dev_name;
    const char *src_ip;
    const char *dst_ip;
    int src_port;
    int dst_port;
    const char *protocol;
    int packet_size;
};

struct icmp_data_t {
    const char *dev_name;
    const char *src_ip;
    const char *dst_ip;
    const char *protocol;
    int packet_size;
};

struct dns_data_t {
    struct tcp_udp_data_t *udp_data;
    const char *dns_query;
};

struct arp_data_t {
    const char *dev_name;
    const char *src_mac;
    const char *dst_mac;
    const char *protocol;
    int packet_size;
};

struct file_cache_t {
    const char *dev_name;
    FILE *file_ptr;
};

FILE *get_file(const char *device_name);

void write_to_file(const char *device_name, const char *src_ip,
                   const char *dst_ip, int src_port, int dst_port,
                   const char *protocol, int packet_size,
                   const char *dns_query);

void write_tcp_to_file(FILE *file, const void *data);
void write_udp_to_file(FILE *file, const void *data);
void write_dns_to_file(FILE *file, const void *data);
void write_icmp_to_file(FILE *file, const void *data);
void write_arp_to_file(FILE *file, const void *data);

void write_to_file_2(write_func_t write_func, const void *data,
                     const char *device_name);