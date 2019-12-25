#ifndef PCAP_359_H
#define PCAP_359_H

#define DST_FOUND -1
#define INTERMEDIARY -2

#include <pcap.h>

void example_libpcap();

pcap_t *setup_pcap(char *pcap_device, char *pcap_filter);
u_char *capture(pcap_t *handle);
void dump_packet(u_char *packet);

void print_address(struct in_addr address);

#endif /* PCAP_359_H */
