#include "parse_udp.h"

void parse_udp(const char *device_name, const struct pcap_pkthdr *pkthdr,
               const unsigned char *packet, const struct ip *ip_header,
               char *src_ip, char *dst_ip) {
    const char *protocol = "UDP";
    int src_port = 0, dst_port = 0;
    struct udphdr *udp_header =
        (struct udphdr *)(packet + sizeof(struct ether_header) +
                          sizeof(struct ip));
    src_port = ntohs(udp_header->source);
    dst_port = ntohs(udp_header->dest);
    int packet_size = pkthdr->caplen;

    struct tcp_udp_data_t udp_data = {.dev_name = device_name,
                                      .src_ip = src_ip,
                                      .dst_ip = dst_ip,
                                      .src_port = src_port,
                                      .dst_port = dst_port,
                                      .protocol = protocol,
                                      .packet_size = packet_size};

    if (src_port == DNS_PORT || dst_port == DNS_PORT) {
        int ip_header_len = ip_header->ip_hl * 4;
        int udp_header_len = sizeof(struct udphdr);
        parse_dns(packet, ip_header_len, udp_header_len, &udp_data);
        return;
    }

    write_to_file_2(write_udp_to_file, &udp_data, device_name);
}