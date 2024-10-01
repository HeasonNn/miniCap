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

void test_parse_tls_client_hello() {
    FiveTuple *five_tuple = (FiveTuple *)malloc(sizeof(FiveTuple));
    inet_pton(AF_INET, "192.168.1.1", &five_tuple->src_ip);
    inet_pton(AF_INET, "192.168.1.2", &five_tuple->dst_ip);
    five_tuple->src_port = 12345;
    five_tuple->dst_port = 80;
    five_tuple->protocol = 6;
    five_tuple->is_ipv6 = 0;

    const unsigned char payload[] = {
        0x16, 0x03, 0x03, 0x00, 0x4C,  // TLS Record Header (Type: Handshake,
                                       // Version: TLS 1.2, Length: 76 bytes)
        0x01, 0x00, 0x00,
        0x48,        // Handshake Type: ClientHello, Length: 72 bytes
        0x03, 0x03,  // Protocol Version: TLS 1.2 (0x0303)

        // Corrected Random (32 bytes total)
        0x5B, 0x8E, 0xE7, 0xC6,  // Random (4 bytes)
        0x73, 0x84, 0x27, 0xAD,  // Random (4 bytes)
        0x2A, 0x49, 0x7D, 0x9A,  // Random (4 bytes)
        0xB7, 0x12, 0xF9, 0x45,  // Random (4 bytes)
        0x6A, 0x11, 0x53, 0xBA,  // Random (4 bytes)
        0xC2, 0x91, 0x56, 0x31,  // Random (4 bytes)
        0x99, 0x85, 0x6D, 0xA1,  // Random (4 bytes)
        0xFA, 0xDF, 0x1A, 0xB4,  // Random (4 bytes)

        0x00,        // Session ID Length: 0
        0x00, 0x04,  // Cipher Suites Length: 4 bytes
        0xC0,
        0x2F,  // Cipher Suite: TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (0xC02F)
        0xC0,
        0x2B,  // Cipher Suite: TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 (0xC02B)
        0x01,
        0x00,  // Compression Methods Length: 1 byte, No compression (0x00)

        // Extensions
        0x00, 0x17,  // Extensions Length: 23 bytes

        // SNI Extension
        0x00, 0x00,              // Extension Type: Server Name (SNI) (0x0000)
        0x00, 0x0E,              // Extension Length: 14 bytes
        0x00, 0x0C,              // Server Name List Length: 12 bytes
        0x00,                    // Name Type: Host Name (0x00)
        0x00, 0x09,              // Host Name Length: 9 bytes
        0x65, 0x78, 0x61, 0x6D,  // 'e', 'x', 'a', 'm'
        0x70, 0x6C, 0x65, 0x2E,  // 'p', 'l', 'e', '.'
        0x63, 0x6F, 0x6D         // 'c', 'o', 'm'
    };

    printf("Size of total payload: %ld\n", sizeof(payload));

    parse_tls(five_tuple, payload, sizeof(payload));
}

int main() {
    // test_parse_tls_app_data();
    test_parse_tls_client_hello();

    printf("All tests passed!\n");
    return 0;
}