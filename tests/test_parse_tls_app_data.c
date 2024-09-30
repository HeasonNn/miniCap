#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../src/include/header.h"
#include "../src/lib/format_utils.h"
#include "../src/lib/hash_table.h"
#include "../src/parse/parse_tls/parse_tls.h"

void test_parse_tls_app_data() {
    FiveTuple *five_tuple = (FiveTuple *)malloc(sizeof(FiveTuple));
    inet_pton(AF_INET, "192.168.1.1", &five_tuple->src_ip);
    inet_pton(AF_INET, "192.168.1.2", &five_tuple->dst_ip);
    five_tuple->src_port = 12345;
    five_tuple->dst_port = 80;
    five_tuple->protocol = 6;
    five_tuple->is_ipv6 = 0;

    unsigned char full_payload[] = {0x17, 0x03, 0x03, 0x00, 0x05,
                                    0x01, 0x02, 0x03, 0x04, 0x05};

    parse_tls_app_data(five_tuple, full_payload, sizeof(full_payload));
    unsigned char fragment1[] = {0x17, 0x03, 0x03, 0x00, 0x08,
                                 0x01, 0x02, 0x03, 0x04};  // 片段 1
    unsigned char fragment2[] = {0x17, 0x03, 0x03, 0x00, 0x08,
                                 0x05, 0x06, 0x07, 0x08};  // 片段 2

    parse_tls_app_data(five_tuple, fragment1, sizeof(fragment1));
    parse_tls_app_data(five_tuple, fragment2, sizeof(fragment2));
}

int main() {
    test_parse_tls_app_data();

    printf("All tests passed!\n");
    return 0;
}