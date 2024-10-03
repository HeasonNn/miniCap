#include "parse_dns.h"

int parse_dns(const unsigned char *packet, int ip_header_len,
              int udp_header_len, struct tcp_udp_data_t *udp_data) {
    if (!config.parse_dns) return 0;

    struct dns_header *dns =
        (struct dns_header *)(packet + sizeof(struct ether_header) +
                              ip_header_len + udp_header_len);
    int dns_size = udp_data->packet_size - (sizeof(struct ether_header) +
                                            ip_header_len + udp_header_len);

    // Check if the DNS packet size is valid
    if (dns_size < sizeof(struct dns_header)) {
        printf("Invalid DNS packet size\n");
        return 0;
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

    struct dns_data_t dns_data_for_write = {
        .udp_data = udp_data,
        .dns_query = domain_name,
    };

    write_to_file_2(write_dns_to_file, &dns_data_for_write, udp_data->dev_name);

    return 0;
}