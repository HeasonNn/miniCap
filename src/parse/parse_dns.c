#include "parse_dns.h"

void parse_dns(const unsigned char *packet, int ip_header_len,
               int udp_header_len, int packet_size, const char *device_name,
               const char *src_ip, const char *dst_ip, int src_port,
               int dst_port) {
    struct dns_header *dns =
        (struct dns_header *)(packet + sizeof(struct ether_header) +
                              ip_header_len + udp_header_len);
    int dns_size = packet_size - (sizeof(struct ether_header) + ip_header_len +
                                  udp_header_len);

    // Check if the DNS packet size is valid
    if (dns_size < sizeof(struct dns_header)) {
        printf("Invalid DNS packet size\n");
        return;
    }

    // Move to the DNS question section
    const unsigned char *dns_data = (const unsigned char *)(dns + 1);

    // Extract the domain name from the query
    char domain_name[256];
    int pos = 0, i = 0;
    while (dns_data[i] != 0 && pos < sizeof(domain_name) - 1) {
        if (dns_data[i] < 32) {
            domain_name[pos++] = '.';
        } else {
            domain_name[pos++] = dns_data[i];
        }
        i++;
    }
    domain_name[pos] = '\0';

    char time_str[64];
    get_timestamp(time_str, sizeof(time_str));
    write_to_file(device_name, src_ip, dst_ip, src_port, dst_port, "DNS",
                  packet_size, domain_name);
    printf("[%s] DNS Query: %s\n", time_str, domain_name);
}