#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/if_ether.h>

#include <arpa/inet.h>

#include "pcap359.h"

void example_libpcap() {
	pcap_t *handle = setup_pcap(NULL, "icmp");

	while(1) {
		printf("capturing... ");
		u_char *packet = capture(handle);

		if(packet != NULL) {
			printf("captured\n");
			dump_packet(packet);
		}
		else {
			printf("not captured\n");
		}
	}
}

pcap_t *setup_pcap(char *pcap_device, char *pcap_filter) {
	char libpcap_error_buffer[PCAP_ERRBUF_SIZE];

	if(pcap_device == NULL) {
		pcap_device = pcap_lookupdev(libpcap_error_buffer);

		if (pcap_device == NULL) {
			fprintf(stderr, "pcap_lookupdef() failed: %s\n", libpcap_error_buffer);

			return NULL;
		}
	}

	pcap_t *handle = pcap_open_live(pcap_device, /* max_packet_length */ 1024, /* promiscuous */ 1, /* chunk_interval */ 1000, libpcap_error_buffer);

	if(handle == NULL) {
		fprintf(stderr, "Error opening device %s: %s\n", pcap_device, libpcap_error_buffer);

		return NULL;
	}

	bpf_u_int32 device_address, device_netmask;

	if(pcap_lookupnet(pcap_device, &device_address, &device_netmask, libpcap_error_buffer) == -1) {
		fprintf(stderr, "Error getting information on device %s: %s\n", pcap_device, pcap_geterr(handle));

		return NULL;
	}

	struct bpf_program bpf_filter;

	if(pcap_compile(handle, &bpf_filter, pcap_filter, 0, device_netmask) == -1) {
		fprintf(stderr, "Error parsing filter %s: %s\n", pcap_filter, pcap_geterr(handle));

		return NULL;
	}

	if(pcap_setfilter(handle, &bpf_filter) == -1) {
		fprintf(stderr, "Error installing filter %s: %s\n", pcap_filter, pcap_geterr(handle));

		return NULL;
	}

	return handle;
}

u_char *capture(pcap_t *handle) {
	struct pcap_pkthdr header;
	u_char *packet;

	fflush(stdout);
	packet = (u_char *) pcap_next(handle, &header);

	return packet;
}

void dump_packet(u_char *packet) {
	if(packet == NULL) {
		return;
	}

	struct ip *ip_header = (struct ip *) (packet + sizeof(struct ether_header));

	int ip_header_length = ip_header->ip_hl * 4;

	if(ip_header->ip_p == IPPROTO_ICMP) {
		struct icmp *icmp_header = (struct icmp *) (packet + sizeof(struct ether_header) + ip_header_length);

		u_int type = icmp_header->icmp_type;
		u_int code = icmp_header->icmp_code;

		printf("type %d, code %d\n", type, code);

		print_address(ip_header->ip_src);
	}
}

void print_address(struct in_addr address) {
	char address_string[INET_ADDRSTRLEN];

	inet_ntop(AF_INET, &address, address_string, INET_ADDRSTRLEN);
	printf("%s\n", address_string);
}
