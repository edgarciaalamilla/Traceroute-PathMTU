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

#define MTU_SIZE 1500

int get_next_mtu(u_char *packet, int current_mtu);

void path_mtu(libnet_t *libnet_context) {
	printf("Destination hostname: ");
	u_int32_t destination_ip = scan_hostname(libnet_context);

	libnet_ptag_t udp_tag = 0;
	libnet_ptag_t ip_tag = 0;

	int udp_header_size = LIBNET_UDP_H;
	int ip_default_header_size = LIBNET_IPV4_H;

	int payload_size = MTU_SIZE - udp_header_size - ip_default_header_size;

	pcap_t *handle = setup_pcap(NULL, "icmp");

	char payload[payload_size];
	memset(payload, 0, payload_size);

	for(int i = 0; i < 100; i++) {
		printf("Sending probe with %d bytes\n", payload_size);	

		udp_tag = make_udp(33435, payload, payload_size, libnet_context, udp_tag);

		if(udp_tag == -1) {
			fprintf(stderr, "Error making UDP packet: %s\n", libnet_geterror(libnet_context));
			break;
		}

		ip_tag = make_ipv4_options(destination_ip, IPPROTO_UDP, LIBNET_UDP_H + payload_size, 2, 64, libnet_context, ip_tag);

		if(ip_tag == -1) {
			fprintf(stderr, "Error making IPv4 packet: %s\n", libnet_geterror(libnet_context));
			break;
		}

		if(libnet_write(libnet_context) == -1) {
			fprintf(stderr, "Error writing packet: %s\n", libnet_geterror(libnet_context));
			break;
		}

		u_char *packet = capture(handle);

		payload_size = get_next_mtu(packet, payload_size);
		if(payload_size == DST_FOUND) return;

		// Obligatory per homework instructions
		// Honor-code pledged
		sleep(1);
	}
}

int get_next_mtu(u_char *packet, int current_mtu) {
	if(packet == NULL) {
		printf("returning current MTU: %d\n", current_mtu);
		return current_mtu;
	}
		struct ip *ip_header = (struct ip *) (packet + sizeof(struct ether_header));
		int ip_header_length = ip_header->ip_hl * 4;

		if(ip_header->ip_p == IPPROTO_ICMP) {
			struct icmp *icmp_header = (struct icmp *) (packet + sizeof(struct ether_header) + ip_header_length);
			
			u_int type = icmp_header->icmp_type;
			u_int code = icmp_header->icmp_code;

			if(type == 3 && code == 3){
				printf("Found final MTU: %d\n", current_mtu);
				return DST_FOUND;
			}

			if(type == 3 && code == 4) {
				printf("returning new MTU: %d\n", icmp_header->icmp_hun.ih_pmtu.ipm_nextmtu);
				return icmp_header->icmp_hun.ih_pmtu.ipm_nextmtu;
			}
		}

	return current_mtu;
}
