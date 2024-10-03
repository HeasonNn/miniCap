#include "parse.h"

void parse_func_handler(unsigned char *user, const struct pcap_pkthdr *pkthdr,
                        const unsigned char *packet) {
    int err;
    err = parse_func(user, pkthdr, packet);
    if (err) {
        printf("Parse error, error code: %d", err);
    }
}

int parse_func(unsigned char *user, const struct pcap_pkthdr *pkthdr,
               const unsigned char *packet) {
    struct ether_header *eth_header = (struct ether_header *)packet;

    switch (ntohs(eth_header->ether_type)) {
        case ETHERTYPE_IP:
            parse_ip((const char *)user, pkthdr, packet);
            break;
        case ETHERTYPE_IPV6:
            parse_ipv6((const char *)user, pkthdr, packet, eth_header);
            break;
        case ETHERTYPE_ARP:
            parse_arp((const char *)user, pkthdr, packet, eth_header);
            break;
        default: {
            if (config.parse_unknow) {
                char time_str[64];
                get_timestamp(time_str, sizeof(time_str));
                printf("[%s] Unknow packet on device %s, Ether Type: 0x%04x\n",
                       time_str, (const char *)user,
                       ntohs(eth_header->ether_type));
            }
            break;
        }
    }

    return 0;
}
