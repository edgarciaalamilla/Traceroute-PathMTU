#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "lnet359.h"
#include "pcap359.h"

#include "traceroute.h"
#include "path_mtu.h"
#include "arp.h"

int main(int argc, char **argv) {
	libnet_t *libnet_context;

	char libnet_error_buffer[LIBNET_ERRBUF_SIZE];

	if(argc < 3) {
		fprintf(stderr,"Usage: tool359 <mode> <device>\n");

		return EXIT_FAILURE;
	}

	char *mode = argv[1];
	char *device = argv[2];

	// libnet initialization: LINK for the arp_check_conflict, RAW4 for everything else

	if(strcmp(mode, "arp_check_conflict") == 0) {
		printf("Initializing libnet at link level: only use arp_check_conflict\n");

		libnet_context = libnet_init(LIBNET_LINK, device, libnet_error_buffer);

		if(libnet_context == NULL) {
			fprintf(stderr, "libnet_init() failed: %s\n", libnet_error_buffer);

			return EXIT_FAILURE;
		}

		// Seed the PRNG
		libnet_seed_prand(libnet_context);

		arp_check_conflict(libnet_context);
	}
	else {
		printf("Initializing libnet at IP level: you can use traceroute, path mtu and the examples\n");

		libnet_context = libnet_init(LIBNET_RAW4, device, libnet_error_buffer);
		
		if(libnet_context == NULL) {
			fprintf(stderr, "libnet_init() failed: %s\n", libnet_error_buffer);

			return EXIT_FAILURE;
		}

		// Seed the PRNG
		libnet_seed_prand(libnet_context);

		if(strcmp(mode, "traceroute") == 0) {

			traceroute(libnet_context);	

		}

		if(strcmp(mode, "path_mtu") == 0) {
			path_mtu(libnet_context);
		}

		if(strcmp(mode, "example_libnet") == 0) {
			example_libnet(libnet_context);
		}

		if(strcmp(mode, "example_libpcap") == 0) {
			example_libpcap();
		}
	}

	libnet_destroy(libnet_context);
	
	return EXIT_SUCCESS;
}
