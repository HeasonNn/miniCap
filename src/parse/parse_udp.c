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

    if (src_port == DNS_PORT || dst_port == DNS_PORT) {
        int ip_header_len = ip_header->ip_hl * 4;
        int udp_header_len = sizeof(struct udphdr);
        parse_dns(packet, ip_header_len, udp_header_len, pkthdr->caplen,
                  device_name, src_ip, dst_ip, src_port, dst_port);
        return;
    }

    int packet_size = pkthdr->caplen;
    char time_str[64];
    get_timestamp(time_str, sizeof(time_str));

    write_to_file(device_name, src_ip, dst_ip, src_port, dst_port, protocol,
                  packet_size, NULL);
    printf(
        "[%s] Captured packet on %s: Src IP: %s, Dst IP: %s, Src Port: %d, Dst "
        "Port: %d, Protocol: %s, Packet Size: %d bytes\n",
        time_str, device_name, src_ip, dst_ip, src_port, dst_port, protocol,
        packet_size);
}