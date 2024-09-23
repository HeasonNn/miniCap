#define _GNU_SOURCE

#include <arpa/inet.h>
#include <event2/event.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <pcap.h>
#include <pthread.h>
#include <stdlib.h>
#include <unistd.h>

#include "lib/format_utils.h"
#include "lib/write.h"
#include "parse/parse_arp.h"
#include "parse/parse_dns.h"
#include "parse/parse_icmp_icmp6.h"
#include "parse/parse_ip_ip6.h"
#include "parse/parse_tcp.h"
#include "parse/parse_udp.h"

struct pcap_thread_args {
    pcap_t *handle;
    struct event_base *base;
    const char *dev_name;
};

struct packet_handler_args_t {
    const char *dev_name;
    pcap_t *handle;
};

void packet_handler(unsigned char *user, const struct pcap_pkthdr *pkthdr,
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
        default:
            char time_str[64];
            get_timestamp(time_str, sizeof(time_str));
            printf("[%s] Non-IP packet on device %s, Ether Type: 0x%04x\n",
                   time_str, (const char *)user, ntohs(eth_header->ether_type));
            break;
    }
}

void pcap_event_handler(evutil_socket_t fd, short event, void *arg) {
    struct packet_handler_args_t *args = (struct packet_handler_args_t *)arg;
    int ret = pcap_dispatch(args->handle, -1, packet_handler,
                            (unsigned char *)args->dev_name);
    if (ret < 0) {
        fprintf(stderr, "Error in pcap_dispatch\n");
    }
}

void *pcap_thread_handler(void *arg) {
    struct pcap_thread_args *args = (struct pcap_thread_args *)arg;

    int pcap_fd = pcap_get_selectable_fd(args->handle);
    if (pcap_fd == -1) {
        fprintf(stderr, "Unable to get selectable fd for pcap\n");
        return NULL;
    }

    struct packet_handler_args_t packet_handler_args = {args->dev_name,
                                                        args->handle};
    struct event *pcap_event =
        event_new(args->base, pcap_fd, EV_READ | EV_PERSIST, pcap_event_handler,
                  &packet_handler_args);
    if (!pcap_event) {
        fprintf(stderr, "Error creating event for pcap\n");
        return NULL;
    }

    event_add(pcap_event, NULL);
    event_base_dispatch(args->base);

    event_free(pcap_event);
    return NULL;
}

int start_pcap_capture(const char *dev_name) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live(dev_name, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev_name, errbuf);
        return -1;
    }

    if (pcap_datalink(handle) != DLT_EN10MB) {
        fprintf(stderr, "%s is not an Ethernet device\n", dev_name);
        pcap_close(handle);
        return -1;
    }

    struct event_base *base = event_base_new();
    if (!base) {
        fprintf(stderr, "Could not create event base\n");
        pcap_close(handle);
        return -1;
    }

    struct pcap_thread_args args = {handle, base, dev_name};
    pthread_t pcap_thread_id;
    if (pthread_create(&pcap_thread_id, NULL, pcap_thread_handler, &args) !=
        0) {
        fprintf(stderr, "Error creating pcap thread for device %s\n", dev_name);
        event_base_free(base);
        pcap_close(handle);
        return -1;
    }

    pthread_detach(pcap_thread_id);
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <interface1> [interface2] ...\n", argv[0]);
        return EXIT_FAILURE;
    }

    for (int i = 1; i < argc; i++) {
        if (start_pcap_capture(argv[i]) != 0) {
            fprintf(stderr, "Failed to start packet capture on %s\n", argv[i]);
            return EXIT_FAILURE;
        }
    }

    while (1) {
        sleep(1);
    }

    return EXIT_SUCCESS;
}