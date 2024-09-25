#include "parse_tcp.h"

void parse_tcp(const char *device_name, const struct pcap_pkthdr *pkthdr,
               const unsigned char *packet, const struct ip *ip_header,
               char *src_ip, char *dst_ip) {
    const char *protocol = "TCP";
    int src_port = 0, dst_port = 0;

    struct tcphdr *tcp_header =
        (struct tcphdr *)(packet + sizeof(struct ether_header) +
                          ip_header->ip_hl * 4);

    src_port = ntohs(tcp_header->source);
    dst_port = ntohs(tcp_header->dest);
    int packet_size = pkthdr->caplen;

    int tcp_header_len = tcp_header->doff * 4;
    const unsigned char *tcp_payload = packet + sizeof(struct ether_header) +
                                       ip_header->ip_hl * 4 + tcp_header_len;

    int payload_len = packet_size - (sizeof(struct ether_header) +
                                     ip_header->ip_hl * 4 + tcp_header_len);

    if (payload_len > 0) {
        if (src_port == TLS_PORT || dst_port == TLS_PORT) {
            parse_tls(tcp_payload, payload_len);
        }
    }

    char time_str[64];
    get_timestamp(time_str, sizeof(time_str));

    struct tcp_udp_data_t tcp_data = {.dev_name = device_name,
                                      .src_ip = src_ip,
                                      .dst_ip = dst_ip,
                                      .src_port = src_port,
                                      .dst_port = dst_port,
                                      .protocol = protocol,
                                      .packet_size = packet_size};

    write_to_file_2(write_tcp_to_file, &tcp_data, device_name);

    return;
}