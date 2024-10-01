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

#include "../../include/header.h"
#include "../../lib/format_utils.h"
#include "../../lib/hash_table.h"
#include "../../lib/write.h"

#define MAX_PAYLOAD_SIZE 16384

/*
    Function:
    (1) parse ClientHello
    (2) parse ServerHello
    (3) parse Server certificate
    (4) parse Application Data
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

struct tls_record_header_t {
    uint8_t content_type;  // Content Type (1 byte)
    uint16_t version;      // Version (2 bytes)
    uint16_t length;       // Length (2 bytes)
};

#define TLS_RECORD_TYPE_CHANGE_CIPHER_SPEC 0x14
#define TLS_RECORD_TYPE_ALERT              0x15
#define TLS_RECORD_TYPE_HANDSHAKE          0x16
#define TLS_RECORD_TYPE_APPLICATION_DATA   0x17

struct tls_handshake_t {
    uint8_t handshake_type;     // Handshake Type (1 byte)
    uint8_t length[3];          // Length (3 bytes)
    uint16_t protocol_version;  // Protocol Version (2 bytes)
    uint8_t random[32];         // Random (32 bytes)
} __attribute__((packed));

#define TLS_PROTOCOL_SSL3   0x0300  // SSL 3.0 (Deprecated)
#define TLS_PROTOCOL_TLS1_0 0x0301  // TLS 1.0
#define TLS_PROTOCOL_TLS1_1 0x0302  // TLS 1.1
#define TLS_PROTOCOL_TLS1_2 0x0303  // TLS 1.2
#define TLS_PROTOCOL_TLS1_3 0x0304  // TLS 1.3

struct tls_client_hello_t {
    struct tls_handshake_t tls_handshake;
    uint8_t session_id_length;      // Session ID Length (1 byte)
    uint8_t *session_id;            // Variable length: Session ID (variable)
    uint16_t cipher_suites_length;  // 2 bytes: Length of cipher suites
    uint16_t *cipher_suites;        // Variable length: Cipher suites
    uint8_t compression_methods_length;  // 1 byte: Compression methods length
    uint8_t *compression_methods;        // Variable length: Compression methods
    uint16_t extensions_length;          // 2 bytes: Length of extensions
    uint8_t *extensions;                 // Variable length: Extensions
} __attribute__((packed));

struct tls_server_hello_t {
    struct tls_handshake_t tls_handshake;
    uint8_t session_id_length;  
    uint8_t session_id[32];
    uint16_t cipher_suite;
    uint8_t compression_method;
    uint16_t extensions_length;
    uint8_t extensions[256];
};

#define TLS_CLIENT_HELLO 0x01
#define TLS_SERVER_HELLO 0x02

struct tls_app_data_header_t {
    uint8_t content_type;  // Content Type (1 byte)
    uint16_t version;      // Protocol Version (2 bytes)
    uint16_t length;       // Length of encrypted data (2 bytes)
} __attribute__((packed));

struct tls_fragment_cache {
    unsigned char *data;
    int total_length;
    int current_offset;
};

void parse_tls(FiveTuple *five_tuple, const unsigned char *payload,
               int payload_len);
void parse_tls_hello(const unsigned char *payload, int payload_len);
void parse_tls_app_data(FiveTuple *five_tuple, const unsigned char *payload,
                        int payload_len);

void parse_tls_sni_extension(const uint8_t *extensions, int extensions_length);