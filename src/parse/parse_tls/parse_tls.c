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
            parse_tls_app_data((const unsigned char *)tls_record->payload,
                               payload_len);
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

        const char *protocol = "TLS/SSL";

        uint16_t cipher_suite = ntohs(tls_server_hello->cipher_suite);
        uint16_t extensions_length = ntohs(tls_server_hello->extensions_length);

        switch (ntohs(tls_server_hello->tls_handshake.protocol_version)) {
            case TLS_PROTOCOL_SSL3:
                protocol = "SSL 3.0";
                break;
            case TLS_PROTOCOL_TLS1_0:
                protocol = "TLS 1.0";
                break;
            case TLS_PROTOCOL_TLS1_1:
                protocol = "TLS 1.1";
                break;
            case TLS_PROTOCOL_TLS1_2:
                protocol = "TLS 1.2";
                break;
            case TLS_PROTOCOL_TLS1_3:
                protocol = "TLS 1.3";
                break;
        }

        printf("ServerHello detected: Protocol Version: %s\n", protocol);

        printf("Random (Hex + ASCII):\n");
        print_binary_data(tls_server_hello->tls_handshake.random, 32);

        printf("Session ID (Hex + ASCII):\n");
        print_binary_data(tls_server_hello->session_id,
                          tls_server_hello->tls_handshake.session_id_length);

        printf(
            "Cipher Suite: 0x%04x, Compression Method: %u, Extensions Length: "
            "%u\n",
            cipher_suite, tls_server_hello->compression_method,
            extensions_length);

    } else if (handshake_message[0] == TLS_CLIENT_HELLO) {
        struct tls_client_hello_t *tls_client_hello =
            (struct tls_client_hello_t *)handshake_message;

        const char *protocol = "TLS/SSL";

        uint16_t cipher_suites_length =
            ntohs(tls_client_hello->cipher_suites_length);
        uint16_t extensions_length = ntohs(tls_client_hello->extensions_length);

        switch (ntohs(tls_client_hello->tls_handshake.protocol_version)) {
            case TLS_PROTOCOL_SSL3:
                protocol = "SSL 3.0";
                break;
            case TLS_PROTOCOL_TLS1_0:
                protocol = "TLS 1.0";
                break;
            case TLS_PROTOCOL_TLS1_1:
                protocol = "TLS 1.1";
                break;
            case TLS_PROTOCOL_TLS1_2:
                protocol = "TLS 1.2";
                break;
            case TLS_PROTOCOL_TLS1_3:
                protocol = "TLS 1.3";
                break;
            default:
                break;
        }

        printf("ClientHello detected: Protocol Version: %s\n", protocol);

        printf("Random (Hex + ASCII):\n");
        print_binary_data(tls_client_hello->tls_handshake.random, 32);

        printf("Session ID (Hex + ASCII):\n");
        print_binary_data(tls_client_hello->session_id,
                          tls_client_hello->tls_handshake.session_id_length);

        printf("Cipher Suites Length: %u, Cipher Suites:\n",
               cipher_suites_length);
        print_binary_data((unsigned char *)tls_client_hello->cipher_suites,
                          cipher_suites_length);

        printf("Compression Methods Length: %u, Compression Methods:\n",
               tls_client_hello->compression_methods_length);
        print_binary_data(
            (unsigned char *)tls_client_hello->compression_methods,
            tls_client_hello->compression_methods_length);

        printf("Extensions Length: %u\n", extensions_length);
    }
}

void parse_tls_app_data(const unsigned char *payload, int payload_len) {
    int header_size = sizeof(struct tls_application_data_t);

    if (payload_len < header_size) {
        printf(
            "Payload too short to be a valid TLS Application Data record.\n");
        return;
    }

    struct tls_application_data_t tls_header;
    tls_header.content_type = payload[0];
    tls_header.version = (payload[1] << 8) | payload[2];
    tls_header.length = (payload[3] << 8) | payload[4];

    if (payload_len < header_size + tls_header.length) {
        printf("Incomplete TLS Application Data.\n");
        return;
    }

    const unsigned char *encrypted_data = payload + header_size;

    printf("Encrypted Data (Hex + ASCII):\n");
    print_binary_data(encrypted_data, tls_header.length);
}