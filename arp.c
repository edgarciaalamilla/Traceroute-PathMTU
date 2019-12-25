#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/if_ether.h>

#include <arpa/inet.h>

#include "lnet359.h"
#include "pcap359.h"

#include "arp.h"

int got_arp_reply(u_char *packet, u_int32_t my_IP);

void arp_check_conflict(libnet_t *libnet_context) {
	u_int32_t my_IP = libnet_get_ipaddr4(libnet_context);
	struct libnet_ether_addr *my_MAC = libnet_get_hwaddr(libnet_context);

	u_int8_t mac_broadcast[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
	u_int8_t mac_zero[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

	libnet_ptag_t arp_tag = 0;
	libnet_ptag_t ether_tag = 0;

	printf("Please give me the address you want to test: ");
	u_int32_t destination_IP = scan_ipaddr4(libnet_context);

	arp_tag = make_arp(ARPOP_REQUEST, my_MAC->ether_addr_octet, (u_int8_t *) (&my_IP), mac_zero, (u_int8_t *) (&destination_IP), libnet_context, arp_tag);

	if(arp_tag == -1) {
		fprintf(stderr, "Error making ARP header: %s\n", libnet_geterror(libnet_context));
		return;
	}

	ether_tag = make_ethernet(mac_broadcast, my_MAC->ether_addr_octet, ETHERTYPE_ARP, libnet_context, ether_tag);

	if(ether_tag == -1) {
		fprintf(stderr, "Error making Ethernet header: %s\n", libnet_geterror(libnet_context));
		return;
	}

	pcap_t *handle = setup_pcap(NULL, "arp");

	if(libnet_write(libnet_context) == -1) {
		fprintf(stderr, "Error writing packet: %s\n", libnet_geterror(libnet_context));
		return;
	}

	for(int i = 0; i < 10; i++) {
		printf("capturing...");

		u_char *packet = capture(handle);

		if(packet != NULL) {
			if(got_arp_reply(packet, my_IP)) {
				return;
			}
		}

		printf("\n");
	}
}

int got_arp_reply(u_char *packet, u_int32_t my_IP) {
	if(packet == NULL) {
		return 0;
	}

	struct ether_arp *arp_header = (struct ether_arp *) (packet + sizeof(struct ether_header));

	u_int32_t source = *((u_int32_t *) arp_header->arp_spa);
	u_int32_t target = *((u_int32_t *) arp_header->arp_tpa);

	if(target == my_IP) {
		printf("found someone in the network: %s\n", libnet_addr2name4(source, LIBNET_DONT_RESOLVE));
		return 1;
	}

	return 0;
}
