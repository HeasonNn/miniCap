#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>

#ifndef MAC_ADDR_LEN
#define MAC_ADDR_LEN 18
#endif

void get_timestamp(char *buffer, size_t len);
void mac_to_string(const u_char *mac_addr, char *mac_str);