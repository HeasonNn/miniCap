#include "parse_tls.h"

void parse_tls(const unsigned char *payload, int payload_len) {
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

    if (handshake_message[0] == 0x02) {
        struct server_hello_t *server_hello =
            (struct server_hello_t *)handshake_message;

        printf("ServerHello detected\n");
    } else if (handshake_message[0] == 0x01) {
        struct client_hello_t *server_hello =
            (struct client_hello_t *)handshake_message;

        printf("ClientHello detected\n");
    }
}