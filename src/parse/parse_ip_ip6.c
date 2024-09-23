#include "parse_ip_ip6.h"

void parse_ip(const char *device_name, const struct pcap_pkthdr *pkthdr,
              const unsigned char *packet) {
    struct ip *ip_header = (struct ip *)(packet + sizeof(struct ether_header));
    char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];

    inet_ntop(AF_INET, &(ip_header->ip_src), src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip_header->ip_dst), dst_ip, INET_ADDRSTRLEN);

    switch (ip_header->ip_p) {
        case IPPROTO_ICMP:
            parse_icmp(device_name, pkthdr, packet, src_ip, dst_ip);
            break;
        case IPPROTO_TCP:
            parse_tcp(device_name, pkthdr, packet, ip_header, src_ip, dst_ip);
            break;
        case IPPROTO_UDP:
            parse_udp(device_name, pkthdr, packet, ip_header, src_ip, dst_ip);
            break;
        default:
            break;
    }
}

void parse_ipv6(const char *device_name, const struct pcap_pkthdr *pkthdr,
                const unsigned char *packet,
                const struct ether_header *ether_header) {
    char time_str[64];
    get_timestamp(time_str, sizeof(time_str));
    printf("[%s] captured a ipv6 packet\n", time_str);
    // struct ip6 *ipv6_header = (struct ip6 *)(packet + sizeof(struct
    // ether_header *));
}