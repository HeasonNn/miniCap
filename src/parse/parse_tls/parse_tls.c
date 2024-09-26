#include "parse_tls.h"

void parse_tls(const unsigned char *payload, int payload_len) {
    if (!config.parse_tls) return;

    struct tls_record_t *tls_record = (struct tls_record_t *)payload;

    switch (tls_record->content_type) {
        case TLS_RECORD_TYPE_CHANGE_CIPHER_SPEC:
            printf("TLS_RECORD_TYPE_CHANGE_CIPHER_SPEC\n");
            break;
        case TLS_RECORD_TYPE_ALERT:
            printf("TLS_RECORD_TYPE_ALERT\n");
            break;
        case TLS_RECORD_TYPE_HANDSHAKE:
            printf("TLS_RECORD_TYPE_HANDSHAKE\n");
            parse_tls_hello((const unsigned char *)tls_record, payload_len);
            break;
        case TLS_RECORD_TYPE_APPLICATION_DATA:
            printf("TLS_RECORD_TYPE_APPLICATION_DATA\n");
            break;
        default:
            break;
    }
}

void parse_tls_hello(const unsigned char *payload, int payload_len) {
    const unsigned char *handshake_message = payload + 5;

    if (handshake_message[0] == TLS_SERVER_HELLO) {
        struct tls_server_hello_t *tls_server_hello =
            (struct tls_server_hello_t *)handshake_message;

        char random_str[65];
        char session_id_str[65];

        bytes_to_hex_str(tls_server_hello->tls_handshake.random, 32,
                         random_str);
        bytes_to_hex_str(tls_server_hello->session_id,
                         tls_server_hello->tls_handshake.session_id_length,
                         session_id_str);

        uint16_t protocol_version =
            ntohs(tls_server_hello->tls_handshake.protocol_version);
        uint16_t cipher_suite = ntohs(tls_server_hello->cipher_suite);
        uint16_t extensions_length = ntohs(tls_server_hello->extensions_length);

        printf(
            "ServerHello detected: "
            "Protocol Version: 0x%04x, "
            "Random: %s, "
            "Session ID Length: %u, "
            "Session ID: %s, "
            "Cipher Suite: 0x%04x, "
            "Compression Method: %u, "
            "Extensions Length: %u\n",
            protocol_version, random_str,
            tls_server_hello->tls_handshake.session_id_length, session_id_str,
            cipher_suite, tls_server_hello->compression_method,
            extensions_length);

    } else if (handshake_message[0] == TLS_CLIENT_HELLO) {
        struct tls_client_hello_t *tls_client_hello =
            (struct tls_client_hello_t *)handshake_message;

        char random_str[65];
        char session_id_str[65];
        bytes_to_hex_str(tls_client_hello->tls_handshake.random, 32,
                         random_str);
        bytes_to_hex_str(tls_client_hello->session_id,
                         tls_client_hello->tls_handshake.session_id_length,
                         session_id_str);

        uint16_t protocol_version =
            ntohs(tls_client_hello->tls_handshake.protocol_version);
        uint16_t cipher_suites_length =
            ntohs(tls_client_hello->cipher_suites_length);
        uint16_t extensions_length = ntohs(tls_client_hello->extensions_length);

        printf(
            "ClientHello detected: "
            "Protocol Version: 0x%04x, "
            "Random: %s, "
            "Session ID Length: %u, "
            "Session ID: %s, "
            "Cipher Suites Length: %u, "
            "Cipher Suites: ",
            protocol_version, random_str,
            tls_client_hello->tls_handshake.session_id_length, session_id_str,
            cipher_suites_length);

        for (int i = 0; i < cipher_suites_length / 2; ++i) {
            printf("0x%04x ", ntohs(tls_client_hello->cipher_suites[i]));
        }

        printf(", Compression Methods Length: %u, Compression Methods: ",
               tls_client_hello->compression_methods_length);

        for (int i = 0; i < tls_client_hello->compression_methods_length; ++i) {
            printf("0x%02x ", tls_client_hello->compression_methods[i]);
        }

        printf(", Extensions Length: %u\n", extensions_length);
    }
}