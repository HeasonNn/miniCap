#include "format_utils.h"

void get_timestamp(char *buffer, size_t len) {
    struct timeval tv;
    gettimeofday(&tv, NULL);

    struct tm time_info;
    localtime_r(&tv.tv_sec, &time_info);

    size_t time_len = strftime(buffer, len, "%Y-%m-%d %H:%M:%S", &time_info);
    if (time_len > 0 && time_len < len) {
        snprintf(buffer + time_len, len - time_len, ".%06ld", tv.tv_usec);
    }
}

void mac_to_string(const u_char *mac_addr, char *mac_str) {
    snprintf(mac_str, MAC_ADDR_LEN, "%02x:%02x:%02x:%02x:%02x:%02x",
             mac_addr[0], mac_addr[1], mac_addr[2], mac_addr[3], mac_addr[4],
             mac_addr[5]);
}

void bytes_to_hex_str(const uint8_t *data, int length, char *output) {
    for (int i = 0; i < length; ++i) {
        sprintf(output + i * 2, "%02x", data[i]);
    }
    output[length * 2] = '\0';
}
