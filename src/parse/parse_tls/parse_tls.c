#include "parse_tls.h"

static HashTable *tls_hash_table = NULL;

void parse_tls(FiveTuple *five_tuple, const unsigned char *payload,
               int payload_len) {
    if (!config.parse_tls) return;

    if (payload_len < 5) {
        printf("Payload too short to be a valid TLS record.\n");
        return;
    }

    struct tls_record_header_t tls_record;
    tls_record.content_type = payload[0];
    tls_record.version = (payload[1] << 8) | payload[2];
    tls_record.length = (payload[3] << 8) | payload[4];

    printf("Sizeof tls_record_t: %ld.\n", sizeof(struct tls_record_header_t));
    printf("Length of tls record payload: %d.\n", tls_record.length);

    switch (tls_record.content_type) {
        case TLS_RECORD_TYPE_CHANGE_CIPHER_SPEC:
            printf("TLS_RECORD_TYPE_CHANGE_CIPHER_SPEC\n");
            break;
        case TLS_RECORD_TYPE_ALERT:
            printf("TLS_RECORD_TYPE_ALERT\n");
            break;
        case TLS_RECORD_TYPE_HANDSHAKE:
            printf("TLS_RECORD_TYPE_HANDSHAKE\n");
            parse_tls_hello((payload + 5), tls_record.length);
            break;
        case TLS_RECORD_TYPE_APPLICATION_DATA:
            printf("TLS_RECORD_TYPE_APPLICATION_DATA\n");
            parse_tls_app_data(five_tuple, payload, payload_len);
            break;
        default:
            break;
    }
}

void parse_tls_hello(const unsigned char *payload, int payload_len) {
    if (payload[0] == TLS_SERVER_HELLO) {
        struct tls_server_hello_t *tls_server_hello =
            (struct tls_server_hello_t *)payload;

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
                          tls_server_hello->session_id_length);

        printf(
            "Cipher Suite: 0x%04x, Compression Method: %u, Extensions Length: "
            "%u\n",
            cipher_suite, tls_server_hello->compression_method,
            extensions_length);

    } else if (payload[0] == TLS_CLIENT_HELLO) {
        if (payload_len < 38) {
            printf("Invalid ClientHello: Payload too short.\n");
            return;
        }

        struct tls_client_hello_t tls_client_hello;

        // Parse Handshake
        tls_client_hello.tls_handshake.handshake_type = payload[0];
        memcpy(tls_client_hello.tls_handshake.length, &payload[1], 3);
        tls_client_hello.tls_handshake.protocol_version =
            (payload[4] << 8) | payload[5];
        memcpy(tls_client_hello.tls_handshake.random, &payload[6], 32);

        int offset = 38;
        tls_client_hello.session_id_length = payload[offset++];

        // Parse Session ID
        if (tls_client_hello.session_id_length > 0) {
            if (payload_len - offset < tls_client_hello.session_id_length) {
                printf(
                    "Invalid ClientHello: Not enough data for Session ID.\n");
                return;
            }
            tls_client_hello.session_id =
                (uint8_t *)malloc(tls_client_hello.session_id_length);
            if (!tls_client_hello.session_id) {
                printf("Memory allocation failed for Session ID.\n");
                return;
            }
            memcpy(tls_client_hello.session_id, &payload[offset],
                   tls_client_hello.session_id_length);
            offset += tls_client_hello.session_id_length;
        } else {
            tls_client_hello.session_id = NULL;
        }

        // Parse Cipher Suites
        if (payload_len - offset < 2) {
            printf(
                "Invalid ClientHello: Not enough data for Cipher Suites "
                "length.\n");
            free(tls_client_hello.session_id);
            return;
        }
        tls_client_hello.cipher_suites_length =
            (payload[offset] << 8) | payload[offset + 1];
        offset += 2;

        printf("Payload_len: %d, Offset: %d, Cipher suites length: %d\n",
               payload_len, offset, tls_client_hello.cipher_suites_length);

        if (payload_len - offset < tls_client_hello.cipher_suites_length) {
            printf("Invalid ClientHello: Not enough data for Cipher Suites.\n");
            free(tls_client_hello.session_id);
            return;
        }
        tls_client_hello.cipher_suites =
            (uint16_t *)malloc(tls_client_hello.cipher_suites_length);
        if (!tls_client_hello.cipher_suites) {
            printf("Memory allocation failed for Cipher Suites.\n");
            free(tls_client_hello.session_id);
            return;
        }
        memcpy(tls_client_hello.cipher_suites, &payload[offset],
               tls_client_hello.cipher_suites_length);
        offset += tls_client_hello.cipher_suites_length;

        // Parse Compression Methods
        if (payload_len - offset < 1) {
            printf(
                "Invalid ClientHello: Not enough data for Compression "
                "Methods.\n");
            free(tls_client_hello.session_id);
            free(tls_client_hello.cipher_suites);
            return;
        }
        tls_client_hello.compression_methods_length = payload[offset++];
        if (payload_len - offset <
            tls_client_hello.compression_methods_length) {
            printf(
                "Invalid ClientHello: Not enough data for Compression "
                "Methods.\n");
            free(tls_client_hello.session_id);
            free(tls_client_hello.cipher_suites);
            return;
        }
        tls_client_hello.compression_methods =
            (uint8_t *)malloc(tls_client_hello.compression_methods_length);
        if (!tls_client_hello.compression_methods) {
            printf("Memory allocation failed for Compression Methods.\n");
            free(tls_client_hello.session_id);
            free(tls_client_hello.cipher_suites);
            return;
        }
        memcpy(tls_client_hello.compression_methods, &payload[offset],
               tls_client_hello.compression_methods_length);
        offset += tls_client_hello.compression_methods_length;

        // Parse Extensions
        if (payload_len - offset < 2) {
            printf(
                "Invalid ClientHello: Not enough data for Extensions "
                "length.\n");
            free(tls_client_hello.session_id);
            free(tls_client_hello.cipher_suites);
            free(tls_client_hello.compression_methods);
            return;
        }
        tls_client_hello.extensions_length =
            (payload[offset] << 8) | payload[offset + 1];
        offset += 2;
        if (payload_len - offset < tls_client_hello.extensions_length) {
            printf("Invalid ClientHello: Not enough data for Extensions.\n");
            free(tls_client_hello.session_id);
            free(tls_client_hello.cipher_suites);
            free(tls_client_hello.compression_methods);
            return;
        }
        tls_client_hello.extensions =
            (uint8_t *)malloc(tls_client_hello.extensions_length);
        if (!tls_client_hello.extensions) {
            printf("Memory allocation failed for Extensions.\n");
            free(tls_client_hello.session_id);
            free(tls_client_hello.cipher_suites);
            free(tls_client_hello.compression_methods);
            return;
        }
        memcpy(tls_client_hello.extensions, &payload[offset],
               tls_client_hello.extensions_length);
        offset += tls_client_hello.extensions_length;

        // Print Results
        const char *protocol = "TLS/SSL";
        switch (ntohs(tls_client_hello.tls_handshake.protocol_version)) {
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
        print_binary_data(tls_client_hello.tls_handshake.random, 32);

        printf("Session ID Length: %u, Session ID (Hex + ASCII):\n",
               tls_client_hello.session_id_length);
        if (tls_client_hello.session_id_length > 0) {
            print_binary_data(tls_client_hello.session_id,
                              tls_client_hello.session_id_length);
        }

        printf("Cipher Suites Length: %u, Cipher Suites:\n",
               tls_client_hello.cipher_suites_length);
        print_binary_data((unsigned char *)tls_client_hello.cipher_suites,
                          tls_client_hello.cipher_suites_length);

        printf("Compression Methods Length: %u, Compression Methods:\n",
               tls_client_hello.compression_methods_length);
        print_binary_data(tls_client_hello.compression_methods,
                          tls_client_hello.compression_methods_length);

        printf("Extensions Length: %u\n", tls_client_hello.extensions_length);
        print_binary_data(tls_client_hello.extensions,
                          tls_client_hello.extensions_length);

        parse_tls_sni_extension(tls_client_hello.extensions,
                                tls_client_hello.extensions_length);

        // Free Memory
        free(tls_client_hello.session_id);
        free(tls_client_hello.cipher_suites);
        free(tls_client_hello.compression_methods);
        free(tls_client_hello.extensions);
    }
}

void init_fragment_cache(struct tls_fragment_cache *cache, int total_length) {
    if (total_length <= 0) {
        printf(
            "Error: Invalid total_length for fragment cache "
            "initialization.\n");
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
            "Payload too short to be a valid TLS Application Data "
            "record.\n");
        return;
    }

    struct tls_app_data_header_t tls_app_data_header;
    tls_app_data_header.content_type = payload[0];
    tls_app_data_header.version = (payload[1] << 8) | payload[2];
    tls_app_data_header.length = (payload[3] << 8) | payload[4];

    if (tls_app_data_header.length <= 0 ||
        tls_app_data_header.length > MAX_PAYLOAD_SIZE) {
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
    }

    if (cache->data == NULL || cache->current_offset == 0) {
        const unsigned char *encrypted_data = payload + header_size;
        printf("Encrypted Data (Hex + ASCII):\n");
        print_binary_data(encrypted_data, tls_app_data_header.length);
    } else {
        printf("Reassembling TLS fragments...\n");

        // printf("Current offset: %d\n", cache->current_offset);

        if (cache->current_offset >= tls_app_data_header.length) {
            printf("Reassembled Encrypted Data (Hex + ASCII):\n");
            print_binary_data(cache->data, cache->current_offset);

            free_fragment_cache(cache);
            tls_hash_table->delete (tls_hash_table, five_tuple);
        }
    }
}

void parse_tls_sni_extension(const uint8_t *extensions, int extensions_length) {
    int offset = 0;

    while (offset + 4 <= extensions_length) {
        // Each extension has a type (2 bytes) and length (2 bytes)
        uint16_t ext_type = (extensions[offset] << 8) | extensions[offset + 1];
        uint16_t ext_length =
            (extensions[offset + 2] << 8) | extensions[offset + 3];
        offset += 4;

        // Check if this is the SNI extension (type 0x0000)
        if (ext_type == 0x0000) {
            if (ext_length < 5) {
                printf("Invalid SNI extension length.\n");
                return;
            }

            // Skip list length (2 bytes)
            uint16_t sni_list_length =
                (extensions[offset] << 8) | extensions[offset + 1];
            offset += 2;

            if (sni_list_length + 2 > ext_length) {
                printf("SNI list length mismatch.\n");
                return;
            }

            // SNI entry type (1 byte) and name length (2 bytes)
            uint8_t sni_type = extensions[offset];
            uint16_t sni_name_length =
                (extensions[offset + 1] << 8) | extensions[offset + 2];
            offset += 3;

            if (sni_type != 0x00 || sni_name_length + 3 > sni_list_length) {
                printf("Invalid SNI entry.\n");
                return;
            }

            // Extract and print the server name
            char sni_name[sni_name_length + 1];
            memcpy(sni_name, &extensions[offset], sni_name_length);
            sni_name[sni_name_length] = '\0';
            printf("SNI (Server Name): %s\n", sni_name);
            return;  // SNI found and processed
        }

        offset += ext_length;  // Move to the next extension
    }

    printf("No SNI extension found.\n");
}