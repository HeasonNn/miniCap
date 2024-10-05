#include "parse_arp.h"

int parse_arp(const char *user, const struct pcap_pkthdr *pkthdr,
              const unsigned char *packet,
              const struct ether_header *eth_header)
{
    if (!config.parse_arp) return 0;

    struct arphdr *arphdr =
        (struct arphdr *)(packet + sizeof(struct ether_header));
    char dst_mac[MAC_ADDR_LEN], src_mac[MAC_ADDR_LEN];

    mac_to_string(eth_header->ether_dhost, dst_mac);
    mac_to_string(eth_header->ether_shost, src_mac);

    const char *protocol = "ARP";
    switch (ntohs(arphdr->ar_op))
    {
        case ARPOP_REQUEST:
            protocol = "ARP Request";
            break;
        case ARPOP_REPLY:
            protocol = "ARP Reply";
            break;
        case ARPOP_InREQUEST:
            protocol = "ARP InRequest";
            break;
        case ARPOP_InREPLY:
            protocol = "ARP InReply";
            break;
        default:
            break;
    }
    int packet_size = pkthdr->caplen;

    struct arp_data_t arp_data = {.src_mac = src_mac,
                                  .dst_mac = dst_mac,
                                  .protocol = protocol,
                                  .packet_size = packet_size,
                                  .dev_name = user};

    write_to_file_2(write_arp_to_file, &arp_data, user);

    return 0;
}