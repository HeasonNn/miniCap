#include "parse_tcp.h"

void parse_tcp(const char *device_name, const struct pcap_pkthdr *pkthdr,
               const unsigned char *packet, const struct ip *ip_header,
               char *src_ip, char *dst_ip) {
    const char *protocol = "TCP";
    int src_port = 0, dst_port = 0;

    struct tcphdr *tcp_header =
        (struct tcphdr *)(packet + sizeof(struct ether_header) +
                          sizeof(struct ip));
    src_port = ntohs(tcp_header->source);
    dst_port = ntohs(tcp_header->dest);
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

    return;
}