#include "parse_tls.h"

static HashTable *tls_hash_table = NULL;

void parse_tls(FiveTuple *five_tuple, const unsigned char *payload,
               int payload_len) {
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
            parse_tls_app_data(five_tuple, (const unsigned char *)tls_record,
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

void init_fragment_cache(struct tls_fragment_cache *cache, int total_length) {
    if (total_length <= 0) {
        printf(
            "Error: Invalid total_length for fragment cache initialization.\n");
        return;
    }

    cache->data = (unsigned char *)malloc(total_length);
    if (cache->data == NULL) {
        printf("Error: Memory allocation failed.\n");
        return;
    }

    cache->total_length = total_length;
    cache->current_offset = 0;
}

void free_fragment_cache(struct tls_fragment_cache *cache) {
    if (cache->data != NULL) {
        free(cache->data);
        cache->data = NULL;
    }
    cache->total_length = 0;
    cache->current_offset = 0;
}

void extend_fragment_cache(struct tls_fragment_cache *cache, int new_size) {
    if (new_size <= cache->total_length) {
        return;
    }

    unsigned char *new_data = (unsigned char *)realloc(cache->data, new_size);
    if (new_data == NULL) {
        printf("Error: Memory reallocation failed.\n");
        return;
    }

    cache->data = new_data;
    cache->total_length = new_size;
}

void append_fragment_to_cache(struct tls_fragment_cache *cache,
                              const unsigned char *fragment, int fragment_len) {
    if (cache->current_offset + fragment_len > cache->total_length) {
        printf("Extending cache size to accommodate new fragment.\n");
        extend_fragment_cache(cache, cache->current_offset + fragment_len);
    }

    if (cache->current_offset + fragment_len > cache->total_length) {
        printf("Error: Fragment length exceeds cache size. Aborting.\n");
        return;
    }

    memcpy(cache->data + cache->current_offset, fragment, fragment_len);
    cache->current_offset += fragment_len;
}

void parse_tls_app_data(FiveTuple *five_tuple, const unsigned char *payload,
                        int payload_len) {
    int header_size = sizeof(struct tls_app_data_header_t);

    if (payload_len < header_size) {
        printf(
            "Payload too short to be a valid TLS Application Data record.\n");
        return;
    }

    struct tls_app_data_header_t tls_app_data_header;
    tls_app_data_header.content_type = payload[0];
    tls_app_data_header.version = (payload[1] << 8) | payload[2];
    tls_app_data_header.length = (payload[3] << 8) | payload[4];

    if (tls_app_data_header.length <= 0 ||
        tls_app_data_header.length >
            MAX_PAYLOAD_SIZE) {
        printf("Error: Invalid TLS length field: %d\n",
               tls_app_data_header.length);
        return;
    }

    if (tls_hash_table == NULL) {
        tls_hash_table =
            create_table(HASH_TABLE_SIZE, hash_five_tuple, compare_five_tuple);
        if (tls_hash_table == NULL) {
            printf("Error: Failed to create hash table.\n");
            return;
        }
    }

    int result;
    void *value = NULL;
    struct tls_fragment_cache *cache = NULL;

    result = tls_hash_table->search(tls_hash_table, five_tuple, &value);
    if (result == 0 && value != NULL) {
        cache = (struct tls_fragment_cache *)value;
    } else {
        cache = (struct tls_fragment_cache *)malloc(
            sizeof(struct tls_fragment_cache));
        if (cache == NULL) {
            printf("Error: Failed to allocate memory for fragment cache.\n");
            return;
        }
        init_fragment_cache(cache, tls_app_data_header.length);
        if (cache->data == NULL) {
            printf("Error: Failed to initialize fragment cache data.\n");
            free(cache);
            return;
        }

        tls_hash_table->insert(tls_hash_table, five_tuple, cache);
    }

    // 判断是否是 TLS 片段
    if (payload_len - header_size < tls_app_data_header.length) {
        printf("Fragmented TLS Application Data. Caching fragment...\n");

        append_fragment_to_cache(cache, payload + header_size,
                                 payload_len - header_size);
        return;
    }

    // 如果没有缓存数据，则解析当前片段
    if (cache->data == NULL || cache->current_offset == 0) {
        const unsigned char *encrypted_data = payload + header_size;
        printf("Encrypted Data (Hex + ASCII):\n");
        print_binary_data(encrypted_data, tls_app_data_header.length);
    } else {
        // 如果已经有缓存的数据，合并并输出
        printf("Reassembling TLS fragments...\n");

        // 将当前片段数据添加到缓存
        append_fragment_to_cache(cache, payload + header_size,
                                 tls_app_data_header.length);

        // 检查缓存的数据长度是否满足 TLS 片段要求
        if (cache->current_offset >= tls_app_data_header.length) {
            // 打印缓存中完整的重组数据
            printf("Reassembled Encrypted Data (Hex + ASCII):\n");
            print_binary_data(cache->data, cache->current_offset);

            free_fragment_cache(cache);
            tls_hash_table->delete (tls_hash_table, five_tuple);
        }
    }
}