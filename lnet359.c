#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "lnet359.h"

#define NUM_PACKETS 3


void example_libnet(libnet_t *libnet_context) {
	printf("Destination IPv4 address (X.Y.Z.W): ");
	u_int32_t destination_ip = scan_ipaddr4(libnet_context);

	get_own_ipaddr4(libnet_context);
	get_own_hwaddr(libnet_context);

	libnet_ptag_t udp_tag = 0;
	libnet_ptag_t ip_tag = 0;

	for(int i = 0; i < NUM_PACKETS; i++) {
		udp_tag = make_udp(50505, NULL, 0, libnet_context, udp_tag);

		if(udp_tag == -1) {
			fprintf(stderr, "Error making UDP packet: %s\n", libnet_geterror(libnet_context));
			break;
		}

		ip_tag = make_ipv4(destination_ip, IPPROTO_UDP, LIBNET_UDP_H, libnet_context, ip_tag);

		if(ip_tag == -1) {
			fprintf(stderr, "Error making IPv4 packet: %s\n", libnet_geterror(libnet_context));
			break;
		}

		if(libnet_write(libnet_context) == -1) {
			fprintf(stderr, "Error writing packet: %s\n", libnet_geterror(libnet_context));
			break;
		}

		// Obligatory per homework instructions
		// Honor-code pledged
		sleep(1);
	}
}

void get_own_ipaddr4(libnet_t *context) {
	u_int32_t my_IP = libnet_get_ipaddr4(context);

	if(my_IP != -1) {
		printf("IP address: %s\n", libnet_addr2name4(my_IP, LIBNET_DONT_RESOLVE));
	}
	else {
		fprintf(stderr, "Error getting IP address: %s\n", libnet_geterror(context));
	}
}

void get_own_hwaddr(libnet_t *context) {
	struct libnet_ether_addr *my_MAC = libnet_get_hwaddr(context);

	if(my_MAC != NULL) {
		printf("MAC address: %02x:%02x:%02x:%02x:%02x:%02x\n",\
				my_MAC->ether_addr_octet[0],\
				my_MAC->ether_addr_octet[1],\
				my_MAC->ether_addr_octet[2],\
				my_MAC->ether_addr_octet[3],\
				my_MAC->ether_addr_octet[4],\
				my_MAC->ether_addr_octet[5]);
	}
	else {
		fprintf(stderr, "Error getting MAC address: %s\n", libnet_geterror(context));
	}
}

u_int32_t scan_ipaddr4(libnet_t *context) {
	char input[16];

	scanf("%15s",input);

	u_int32_t input_IP = libnet_name2addr4(context, input, LIBNET_DONT_RESOLVE);
	// Note: use libnet_addr2name4() for the opposite direction
	//       returns -1 on conversion failure

	return input_IP;
}

u_int32_t scan_hostname(libnet_t *context) {
	char input[128];

	scanf("%127s",input);

	u_int32_t input_IP = libnet_name2addr4(context, input, LIBNET_RESOLVE);
	// Note: use libnet_addr2name4() for the opposite direction
	//       returns -1 on conversion failure

	return input_IP;
}

int make_udp(int destination_port, char *payload, int payload_size, libnet_t *context, libnet_ptag_t tag) {
	libnet_ptag_t result = libnet_build_udp(
			libnet_get_prand(LIBNET_PRu16),
			destination_port,
			LIBNET_UDP_H + payload_size,
			0,
			(u_int8_t *) payload,
			(u_int32_t) payload_size,
			context,
			tag);

	return result;
}

int make_tcp(int destination_port, u_int8_t flags, char *payload, int payload_size, libnet_t *context, libnet_ptag_t tag) {
	libnet_ptag_t result = libnet_build_tcp (
			libnet_get_prand(LIBNET_PRu16),
			destination_port,
			0,
			0,
			flags,
			1024,
			0,
			0,
			LIBNET_TCP_H,
			(u_int8_t *) payload,
			(u_int32_t) payload_size,
			context,
			tag);

	return result;
}

int make_ipv4_options(u_int32_t destination_IP, u_int8_t upper_protocol, u_int32_t upper_payload_size, u_int16_t flags, u_int8_t ttl, libnet_t *context, libnet_ptag_t tag) {
	u_int32_t my_IP  = libnet_get_ipaddr4(context);

	if(my_IP == -1) {
		return -1;
	}

	libnet_ptag_t result = libnet_build_ipv4(
			LIBNET_IPV4_H + upper_payload_size,
			0,
			libnet_get_prand(LIBNET_PR16),
			(flags << 13),
			ttl,
			upper_protocol,
			0,
			my_IP,
			destination_IP,
			NULL,
			0,
			context,
			tag);

	return result;
}

int make_ipv4(u_int32_t destination_IP, u_int8_t upper_protocol, u_int32_t upper_payload_size, libnet_t *context, libnet_ptag_t tag) {
	return make_ipv4_options(destination_IP, upper_protocol, upper_payload_size, 0, 64, context, tag);
}

int make_arp(uint16_t operation, const uint8_t *source_mac, const uint8_t *source_ip, const uint8_t *target_mac, const uint8_t *target_ip, libnet_t *context, libnet_ptag_t tag) {
	u_short hardware;

	switch(context->link_type) {
	case 1: /* DLT_EN10MB */
		hardware = ARPHRD_ETHER;
		break;
	case 6: /* DLT_IEEE802 */
		hardware = ARPHRD_IEEE802;
		break;
	default:
		snprintf(context->err_buf, LIBNET_ERRBUF_SIZE, "%s(): unsupported link type\n", __func__);

		return -1;
	}

	libnet_ptag_t result = libnet_build_arp(
			hardware,
			ETHERTYPE_IP,
			6,
			4,
			operation,
			source_mac,
			source_ip,
			target_mac,
			target_ip,
			NULL,
			0,
			context,
			tag);

	return result;
}

int make_ethernet(u_int8_t *dst_mac_address, u_int8_t *src_mac_address, uint16_t type, libnet_t *context, libnet_ptag_t tag) {
	libnet_ptag_t result = libnet_build_ethernet(
			dst_mac_address,
			src_mac_address,
			type,
			NULL,
			0,
			context,
			tag);

	return result;
}
