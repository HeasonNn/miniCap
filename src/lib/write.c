#include "write.h"

// Define a function pointer for the print logic
typedef void (*print_func_t)(FILE *file, const void *data,
                             const void *time_str);

// Define a macro for the write function
#define DEFINE_WRITE_FUNCTION(protocol_name, data_type, print_func)    \
    void write_##protocol_name##_to_file(FILE *file, const void *data) \
    {                                                                  \
        const data_type *protocol_data = (const data_type *)data;      \
        char time_str[64];                                             \
        get_timestamp(time_str, sizeof(time_str));                     \
        print_func(file, protocol_data, time_str);                     \
    }

// Implement the print functions for each protocol
void print_tcp_udp_data(FILE *file, const struct tcp_udp_data_t *data,
                        const char *time_str)
{
    if (config.verbose)
    {
        printf(
            "[%s] Src IP: %s, Dst IP: %s, Src Port: %d, Dst Port: %d, "
            "Protocol: %s, Packet Size: %d bytes\n",
            time_str, data->src_ip, data->dst_ip, data->src_port,
            data->dst_port, "TCP/UDP", data->packet_size);
    }

    fprintf(file,
            "[%s] Src IP: %s, Dst IP: %s, Src Port: %d, Dst Port: %d, "
            "Protocol: %s, Packet Size: %d bytes\n",
            time_str, data->src_ip, data->dst_ip, data->src_port,
            data->dst_port, "TCP/UDP", data->packet_size);
}

void print_dns_data(FILE *file, const struct dns_data_t *data,
                    const char *time_str)
{
    if (config.verbose)
    {
        printf(
            "[%s] Src IP: %s, Dst IP: %s, Src Port: %d, Dst Port: %d, "
            "Protocol: %s, Packet Size: %d bytes, DNS Query: %s\n",
            time_str, data->udp_data->src_ip, data->udp_data->dst_ip,
            data->udp_data->src_port, data->udp_data->dst_port, "DNS",
            data->udp_data->packet_size, data->dns_query);
    }

    fprintf(file,
            "[%s] Src IP: %s, Dst IP: %s, Src Port: %d, Dst Port: %d, "
            "Protocol: %s, Packet Size: %d bytes, DNS Query: %s\n",
            time_str, data->udp_data->src_ip, data->udp_data->dst_ip,
            data->udp_data->src_port, data->udp_data->dst_port, "DNS",
            data->udp_data->packet_size, data->dns_query);
}

void print_arp_data(FILE *file, const struct arp_data_t *data,
                    const char *time_str)
{
    if (config.verbose)
    {
        printf(
            "[%s] Src MAC: %s, Dst MAC: %s, Protocol: %s, Packet Size: %d "
            "bytes\n",
            time_str, data->src_mac, data->dst_mac, "ARP", data->packet_size);
    }

    fprintf(
        file,
        "[%s] Src MAC: %s, Dst MAC: %s, Protocol: %s, Packet Size: %d bytes\n",
        time_str, data->src_mac, data->dst_mac, "ARP", data->packet_size);
}

void print_icmp_data(FILE *file, const struct icmp_data_t *data,
                     const char *time_str)
{
    if (config.verbose)
    {
        printf(
            "[%s] Src IP: %s, Dst IP: %s, Protocol: %s, Packet Size: %d "
            "bytes\n",
            time_str, data->src_ip, data->dst_ip, data->protocol,
            data->packet_size);
    }

    fprintf(
        file,
        "[%s] Src IP: %s, Dst IP: %s, Protocol: %s, Packet Size: %d bytes\n",
        time_str, data->src_ip, data->dst_ip, data->protocol,
        data->packet_size);
}

// Define the write functions for each protocol
DEFINE_WRITE_FUNCTION(tcp, struct tcp_udp_data_t, print_tcp_udp_data)
DEFINE_WRITE_FUNCTION(udp, struct tcp_udp_data_t, print_tcp_udp_data)
DEFINE_WRITE_FUNCTION(dns, struct dns_data_t, print_dns_data)
DEFINE_WRITE_FUNCTION(arp, struct arp_data_t, print_arp_data)
DEFINE_WRITE_FUNCTION(icmp, struct icmp_data_t, print_icmp_data)

static struct file_cache_t *file_cache[MAX_INTERFACES] = {NULL};

FILE *get_file(const char *device_name)
{
    static int file_count = 0;

    for (int i = 0; i < file_count; ++i)
    {
        if (strcmp(device_name, file_cache[i]->dev_name) == 0)
        {
            return file_cache[i]->file_ptr;
        }
    }

    if (file_count >= MAX_INTERFACES)
    {
        fprintf(stderr, "File cache limit reached.\n");
        return NULL;
    }

    char filename[256];
    snprintf(filename, sizeof(filename), "%s.txt", device_name);
    FILE *file = fopen(filename, "a");
    if (file == NULL)
    {
        perror("Error opening file");
        return NULL;
    }

    file_cache[file_count] = malloc(sizeof(struct file_cache_t));
    if (!file_cache[file_count])
    {
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
                   const char *protocol, int packet_size, const char *dns_query)
{
    FILE *file = get_file(device_name);
    if (file == NULL) return;

    char time_str[64];
    get_timestamp(time_str, sizeof(time_str));

    if (dns_query != NULL)
    {
        fprintf(file,
                "[%s] Src IP: %s, Dst IP: %s, Src Port: %d, Dst Port: %d, "
                "Protocol: %s, Packet Size: %d bytes, DNS Query: %s\n",
                time_str, src_ip, dst_ip, src_port, dst_port, protocol,
                packet_size, dns_query);
    }
    else
    {
        fprintf(file,
                "[%s] Src IP: %s, Dst IP: %s, Src Port: %d, Dst Port: %d, "
                "Protocol: %s, Packet Size: %d bytes\n",
                time_str, src_ip, dst_ip, src_port, dst_port, protocol,
                packet_size);
    }
    fflush(file);
}

void write_to_file_2(write_func_t write_func, const void *data,
                     const char *device_name)
{
    FILE *file = get_file(device_name);
    if (file == NULL) return;

    write_func(file, data);
    fflush(file);
}