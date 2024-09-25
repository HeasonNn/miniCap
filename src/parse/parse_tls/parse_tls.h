#pragma once

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <pcap.h>
#include <stdint.h>
#include <stdio.h>

#include "../../lib/format_utils.h"
#include "../../lib/write.h"

#define MAX_PAYLOAD_SIZE 16384

/*
    (1) parse ClientHello
    (2) parse ServerHello
    (3) parse Server certificate
*/

/*
TLS Record:
    +-----------------------------------------------------------+
    | Content Type (1 byte) | Version (2 bytes) | Length (2 bytes)|
    +-----------------------------------------------------------+
    |                         Payload                            |
    +-----------------------------------------------------------+

Content Type:
    0x14: ChangeCipherSpec
    0x15: Alert
    0x16: Handshake
    0x17: Application Data

Version:
    0x0301: TLS 1.0
    0x0302: TLS 1.1
    0x0303: TLS 1.2
    0x0304: TLS 1.3

ClientHello:
    +-----------------------------------------------------------+
    | Handshake Type (1 byte) | Length (3 bytes)                 |
    +-----------------------------------------------------------+
    | Protocol Version (2 bytes)                                |
    +-----------------------------------------------------------+
    | Random (32 bytes)                                         |
    +-----------------------------------------------------------+
    | Session ID Length (1 byte) | Session ID (variable length) |
    +-----------------------------------------------------------+
    | Cipher Suites Length (2 bytes) | Cipher Suites (variable) |
    +-----------------------------------------------------------+
    | Compression Methods Length (1 byte) | Compression Methods |
    +-----------------------------------------------------------+
    | Extensions Length (2 bytes) | Extensions (variable)       |
    +-----------------------------------------------------------+
    Handshake Type : 0x01 -> client


ServerHello:
    +-----------------------------------------------------------+
    | Handshake Type (1 byte) | Length (3 bytes)                 |
    +-----------------------------------------------------------+
    | Protocol Version (2 bytes)                                |
    +-----------------------------------------------------------+
    | Random (32 bytes)                                         |
    +-----------------------------------------------------------+
    | Session ID Length (1 byte) | Session ID (variable length) |
    +-----------------------------------------------------------+
    | Cipher Suite (2 bytes)                                    |
    +-----------------------------------------------------------+
    | Compression Method (1 byte)                               |
    +-----------------------------------------------------------+
    | Extensions Length (2 bytes) | Extensions (variable)       |
    +-----------------------------------------------------------+
    Handshake Type : 0x02 -> server


TLS Application Data
    +-----------------------------------------------------------+
    | Content Type (1 byte) | Version (2 bytes) | Length (2 bytes)|
    +-----------------------------------------------------------+
    | Encrypted Data (variable length)                           |
    +-----------------------------------------------------------+
 */

struct tls_record_t {
    uint8_t content_type;  // Content Type (1 byte)
    uint16_t version;      // Version (2 bytes)
    uint16_t length;       // Length (2 bytes)
    uint8_t payload[MAX_PAYLOAD_SIZE];
};

struct tls_handshake_t {
    uint8_t handshake_type;     // Handshake Type (1 byte)
    uint8_t length[3];          // Length (3 bytes)
    uint16_t protocol_version;  // Protocol Version (2 bytes)
    uint8_t random[32];         // Random (32 bytes)
    uint8_t session_id_length;  // Session ID Length (1 byte)
};

struct client_hello_t {
    struct tls_handshake_t tls_handshake;  // 通用的握手部分
    // ClientHello 特有部分
    uint8_t session_id[32];  // Session ID (固定长度，可以根据需求调整)
    uint16_t
        cipher_suites[16];  // Cipher Suites (固定长度，可以根据实际情况调整)
    uint8_t compression_methods[16];  // Compression Methods
                                      // (固定长度，可以根据实际情况调整)
    uint16_t extensions_length;  // Extensions Length (2 bytes)
    uint8_t extensions[256];  // Extensions (固定长度，可以根据实际情况调整)
};

struct server_hello_t {
    struct tls_handshake_t tls_handshake;  // 通用的握手部分
    // ServerHello 特有部分
    uint8_t session_id[32];  // Session ID (固定长度，可以根据需求调整)
    uint16_t cipher_suite;       // Cipher Suite (2 bytes)
    uint8_t compression_method;  // Compression Method (1 byte)
    uint16_t extensions_length;  // Extensions Length (2 bytes)
    uint8_t extensions[256];  // Extensions (固定长度，可以根据实际情况调整)
};

#define TLS_RECORD_TYPE_CHANGE_CIPHER_SPEC 0x14
#define TLS_RECORD_TYPE_ALERT              0x15
#define TLS_RECORD_TYPE_HANDSHAKE          0x16
#define TLS_RECORD_TYPE_APPLICATION_DATA   0x17

void parse_tls(const unsigned char *payload, int payload_len);

void parse_tls_hello(const unsigned char *payload, int payload_len);