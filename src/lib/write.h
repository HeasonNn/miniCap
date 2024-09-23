#pragma once

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include "format_utils.h"

#define MAX_INTERFACES 10

#ifndef MAC_ADDR_LEN
#define MAC_ADDR_LEN 18
#endif

struct file_cache_t {
    const char *dev_name;
    FILE *file_ptr;
};

FILE *get_file(const char *device_name);

void write_to_file(const char *device_name, const char *src_ip,
                   const char *dst_ip, int src_port, int dst_port,
                   const char *protocol, int packet_size,
                   const char *dns_query);
