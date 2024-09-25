#include "parse_icmp_icmp6.h"

void parse_icmp(const char *device_name, const struct pcap_pkthdr *pkthdr,
                const unsigned char *packet, char *src_ip, char *dst_ip) {
    struct icmphdr *icmp_header =
        (struct icmphdr *)(packet + sizeof(struct ether_header) +
                           sizeof(struct ip));
    int packet_size = pkthdr->caplen;
    char time_str[64];
    get_timestamp(time_str, sizeof(time_str));

    const char *protocol = "ICMP";
    switch (icmp_header->type) {
        case ICMP_ECHO:
            protocol = "ICMP Echo Request";
            break;

        case ICMP_ECHOREPLY:
            protocol = "ICMP Echo Reply";
            break;

        case ICMP_DEST_UNREACH:
            protocol = "ICMP Destination Unreachable";
            break;

        default:
            break;
    }

    struct icmp_data_t icmp_data_for_write = {
        .dev_name = device_name,
        .src_ip = src_ip,
        .dst_ip = dst_ip,
        .protocol = protocol,
    };

    write_to_file_2(write_icmp_to_file, &icmp_data_for_write, device_name);
}