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

int verify_ICMP_datagram(u_char *packet){
	struct ip *ip_header = (struct ip *) (packet + sizeof(struct ether_header));
	int ip_header_length = ip_header->ip_hl * 4;

	if(ip_header->ip_p == IPPROTO_ICMP) {
		struct icmp *icmp_header = (struct icmp *) (packet + sizeof(struct ether_header) + ip_header_length);

		u_int type = icmp_header->icmp_type;
		u_int code = icmp_header->icmp_code;

		if(type == 3 && code == 3){
			printf("Destination port unreachable. Destination found.\n");
			print_address(ip_header->ip_src);
			return DST_FOUND;
		}
		if(type == 11 && code == 0){
			printf("Time exceeded. Intermediate router found.\n");
			print_address(ip_header->ip_src);
			return INTERMEDIARY;
		}

	}
	return 0;
}

void traceroute(libnet_t *libnet_context) {
	printf("Destination hostname: ");
	u_int32_t destination_ip = scan_hostname(libnet_context);

	libnet_ptag_t udp_tag = 0;
	libnet_ptag_t ip_tag = 0;

	pcap_t *handle = setup_pcap(NULL, "icmp");

	for(int i = 0; i < 25; i++) {
		printf("Sending probe with TTL %d\n", i + 1);

		udp_tag = make_udp(33434, NULL, 0, libnet_context, udp_tag);

		if(udp_tag == -1) {
			fprintf(stderr, "Error making UDP packet: %s\n", libnet_geterror(libnet_context));
			break;
		}

		ip_tag = make_ipv4_options(destination_ip, IPPROTO_UDP, LIBNET_UDP_H, 0, i + 1, libnet_context, ip_tag);

		if(ip_tag == -1) {
			fprintf(stderr, "Error making IPv4 packet: %s\n", libnet_geterror(libnet_context));
			break;
		}

		if(libnet_write(libnet_context) == -1) {
			fprintf(stderr, "Error writing packet: %s\n", libnet_geterror(libnet_context));
			break;
		}

		u_char *packet = capture(handle);
		
		if(packet != NULL) {
			if(verify_ICMP_datagram(packet) == DST_FOUND) return;
		}

		// Obligatory per homework instructions
		// Honor-code pledged
		sleep(1);
	}
}
