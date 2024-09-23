#include "write.h"

static struct file_cache_t *file_cache[MAX_INTERFACES] = {NULL};

FILE *get_file(const char *device_name) {
    static int file_count = 0;

    for (int i = 0; i < file_count; ++i) {
        if (strcmp(device_name, file_cache[i]->dev_name) == 0) {
            return file_cache[i]->file_ptr;
        }
    }

    if (file_count >= MAX_INTERFACES) {
        fprintf(stderr, "File cache limit reached.\n");
        return NULL;
    }

    char filename[256];
    snprintf(filename, sizeof(filename), "%s.txt", device_name);
    FILE *file = fopen(filename, "a");
    if (file == NULL) {
        perror("Error opening file");
        return NULL;
    }

    file_cache[file_count] = malloc(sizeof(struct file_cache_t));
    if (!file_cache[file_count]) {
        perror("Error allocating memory for file cache");
        fclose(file);
        return NULL;
    }

    file_cache[file_count]->file_ptr = file;
    file_cache[file_count]->dev_name = device_name;
    file_count++;
    return file;
}

void write_to_file(const char *device_name, const char *src_ip,
                   const char *dst_ip, int src_port, int dst_port,
                   const char *protocol, int packet_size,
                   const char *dns_query) {
    FILE *file = get_file(device_name);
    if (file == NULL) return;

    char time_str[64];
    get_timestamp(time_str, sizeof(time_str));

    if (dns_query != NULL) {
        fprintf(file,
                "[%s] Src IP: %s, Dst IP: %s, Src Port: %d, Dst Port: %d, "
                "Protocol: %s, Packet Size: %d bytes, DNS Query: %s\n",
                time_str, src_ip, dst_ip, src_port, dst_port, protocol,
                packet_size, dns_query);
    } else {
        fprintf(file,
                "[%s] Src IP: %s, Dst IP: %s, Src Port: %d, Dst Port: %d, "
                "Protocol: %s, Packet Size: %d bytes\n",
                time_str, src_ip, dst_ip, src_port, dst_port, protocol,
                packet_size);
    }
    fflush(file);  // 强制刷新，确保及时写入
}