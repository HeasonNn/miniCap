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

/*
    Function:
    (1) parse ClientHello
    (2) parse ServerHello
    (3) parse Application Data
    (4) parse Server certificate
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

#define MAX_PAYLOAD_SIZE 16384

#define TLS_RECORD_TYPE_CHANGE_CIPHER_SPEC 0x14
#define TLS_RECORD_TYPE_ALERT              0x15
#define TLS_RECORD_TYPE_HANDSHAKE          0x16
#define TLS_RECORD_TYPE_APPLICATION_DATA   0x17

#define TLS_PROTOCOL_SSL3   0x0300  // SSL 3.0 (Deprecated)
#define TLS_PROTOCOL_TLS1_0 0x0301  // TLS 1.0
#define TLS_PROTOCOL_TLS1_1 0x0302  // TLS 1.1
#define TLS_PROTOCOL_TLS1_2 0x0303  // TLS 1.2
#define TLS_PROTOCOL_TLS1_3 0x0304  // TLS 1.3

#define TLS_CLIENT_HELLO 0x01
#define TLS_SERVER_HELLO 0x02

// Cipher Suites for TLS 1.2 and below
#define TLS_RSA_WITH_AES_128_GCM_SHA256               0x009C
#define TLS_RSA_WITH_AES_256_GCM_SHA384               0x009D
#define TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256         0xC02F
#define TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384         0xC030
#define TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256       0xC02B
#define TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384       0xC02C
#define TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256   0xCCA8
#define TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 0xCCA9
#define TLS_DHE_RSA_WITH_AES_128_GCM_SHA256           0x009E
#define TLS_DHE_RSA_WITH_AES_256_GCM_SHA384           0x009F
#define TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256     0xCCAA

// Cipher Suites for TLS 1.3
#define TLS_AES_128_GCM_SHA256       0x1301
#define TLS_AES_256_GCM_SHA384       0x1302
#define TLS_CHACHA20_POLY1305_SHA256 0x1303
#define TLS_AES_128_CCM_SHA256       0x1304
#define TLS_AES_128_CCM_8_SHA256     0x1305

#define TLS_PROTOCOL_NAME(protocol_id)                \
    (protocol_id == TLS_PROTOCOL_SSL3     ? "SSL 3.0" \
     : protocol_id == TLS_PROTOCOL_TLS1_0 ? "TLS 1.0" \
     : protocol_id == TLS_PROTOCOL_TLS1_1 ? "TLS 1.1" \
     : protocol_id == TLS_PROTOCOL_TLS1_2 ? "TLS 1.2" \
     : protocol_id == TLS_PROTOCOL_TLS1_3 ? "TLS 1.3" \
                                          : "TLS/SSL")

#define TLS_CIPHER_SUITE_NAME(cipher_id)                                  \
    (cipher_id == TLS_RSA_WITH_AES_128_GCM_SHA256                         \
         ? "TLS_RSA_WITH_AES_128_GCM_SHA256"                              \
     : cipher_id == TLS_RSA_WITH_AES_256_GCM_SHA384                       \
         ? "TLS_RSA_WITH_AES_256_GCM_SHA384"                              \
     : cipher_id == TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256                 \
         ? "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"                        \
     : cipher_id == TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384                 \
         ? "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"                        \
     : cipher_id == TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256               \
         ? "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"                      \
     : cipher_id == TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384               \
         ? "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"                      \
     : cipher_id == TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256           \
         ? "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"                  \
     : cipher_id == TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256         \
         ? "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256"                \
     : cipher_id == TLS_DHE_RSA_WITH_AES_128_GCM_SHA256                   \
         ? "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256"                          \
     : cipher_id == TLS_DHE_RSA_WITH_AES_256_GCM_SHA384                   \
         ? "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384"                          \
     : cipher_id == TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256             \
         ? "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256"                    \
     : cipher_id == TLS_AES_128_GCM_SHA256 ? "TLS_AES_128_GCM_SHA256"     \
     : cipher_id == TLS_AES_256_GCM_SHA384 ? "TLS_AES_256_GCM_SHA384"     \
     : cipher_id == TLS_CHACHA20_POLY1305_SHA256                          \
         ? "TLS_CHACHA20_POLY1305_SHA256"                                 \
     : cipher_id == TLS_AES_128_CCM_SHA256   ? "TLS_AES_128_CCM_SHA256"   \
     : cipher_id == TLS_AES_128_CCM_8_SHA256 ? "TLS_AES_128_CCM_8_SHA256" \
                                             : "Unknown Cipher Suite")

struct tls_record_header_t {
    uint8_t content_type;  // Content Type (1 byte)
    uint16_t version;      // Version (2 bytes)
    uint16_t length;       // Length (2 bytes)
};

struct tls_handshake_t {
    uint8_t handshake_type;     // Handshake Type (1 byte)
    uint8_t length[3];          // Length (3 bytes)
    uint16_t protocol_version;  // Protocol Version (2 bytes)
    uint8_t random[32];         // Random (32 bytes)
} __attribute__((packed));

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
    uint8_t *session_id;
    uint16_t cipher_suite;
    uint8_t compression_method;
    uint16_t extensions_length;
    uint8_t *extensions;
};

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

int parse_tls(FiveTuple *five_tuple, const unsigned char *payload,
               int payload_len);
void parse_tls_hello(const unsigned char *payload, int payload_len);
void parse_tls_app_data(FiveTuple *five_tuple, const unsigned char *payload,
                        int payload_len);

void parse_tls_sni_extension(const uint8_t *extensions, int extensions_length);