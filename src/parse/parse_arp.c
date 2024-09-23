#include "parse_arp.h"

void parse_arp(const char *user, const struct pcap_pkthdr *pkthdr,
               const unsigned char *packet,
               const struct ether_header *eth_header)
{
    // struct arphdr *arphdr = (struct arphdr *)(packet + sizeof(struct
    // ether_header));
    char dst_mac[MAC_ADDR_LEN], src_mac[MAC_ADDR_LEN];

    mac_to_string(eth_header->ether_dhost, dst_mac);
    mac_to_string(eth_header->ether_shost, src_mac);

    char time_str[64];
    get_timestamp(time_str, sizeof(time_str));

    const char *protocol = "ARP";
    int packet_size = pkthdr->caplen;

    printf(
        "[%s] Captured packet on %s: Src Mac Addr: %s, Dst Mac Addr: %s, "
        "Protocol: %s, Packet Size: %d bytes\n",
        time_str, (const char *)user, src_mac, dst_mac, protocol, packet_size);
}