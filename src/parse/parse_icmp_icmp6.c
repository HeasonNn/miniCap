#include "parse_icmp_icmp6.h"

void parse_icmp(const char *device_name, const struct pcap_pkthdr *pkthdr,
                const unsigned char *packet, char *src_ip, char *dst_ip) {
    // const char* protocol = "ICMP";
    struct icmphdr *icmp_header =
        (struct icmphdr *)(packet + sizeof(struct ether_header) +
                           sizeof(struct ip));
    int packet_size = pkthdr->caplen;
    char time_str[64];
    get_timestamp(time_str, sizeof(time_str));

    switch (icmp_header->type) {
        case ICMP_ECHO:
            printf(
                "[%s] Captured packet on %s: ICMP Echo Request from %s to %s, "
                "Packet "
                "Size: %d bytes\n",
                time_str, device_name, src_ip, dst_ip, packet_size);
            break;

        case ICMP_ECHOREPLY:
            printf(
                "[%s] Captured packet on %s: ICMP Echo Reply from %s to %s, "
                "Packet "
                "Size: %d bytes\n",
                time_str, device_name, src_ip, dst_ip, packet_size);
            break;

        case ICMP_DEST_UNREACH:
            printf(
                "[%s] Captured packet on %s: ICMP Destination Unreachable from "
                "%s to "
                "%s, Packet Size: %d bytes\n",
                time_str, device_name, src_ip, dst_ip, packet_size);
            break;

        default:
            printf(
                "[%s] Captured packet on %s: Other ICMP Type: %d from %s to "
                "%s, "
                "Packet Size: %d bytes\n",
                time_str, device_name, icmp_header->type, src_ip, dst_ip,
                packet_size);
            break;
    }
}