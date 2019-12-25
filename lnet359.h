#ifndef LNET_359_H
#define LNET_359_H

#include <libnet.h>

void example_libnet(libnet_t *libnet_context);

void get_own_ipaddr4(libnet_t *context);
void get_own_hwaddr(libnet_t *context);

u_int32_t scan_ipaddr4(libnet_t *context);
u_int32_t scan_hostname(libnet_t *context);

int make_udp(int destination_port, char *payload, int payload_size, libnet_t *context, libnet_ptag_t tag);
int make_tcp(int destination_port, u_int8_t flags, char *payload, int payload_size, libnet_t *context, libnet_ptag_t tag);
int make_ipv4(u_int32_t destination_IP, u_int8_t upper_protocol, u_int32_t upper_payload_size, libnet_t *context, libnet_ptag_t tag);
int make_arp(uint16_t operation, const uint8_t *source_mac, const uint8_t *source_ip, const uint8_t *target_mac, const uint8_t *target_ip, libnet_t *context, libnet_ptag_t tag);
int make_ethernet(u_int8_t *dst_mac_address, u_int8_t *src_mac_address, uint16_t type, libnet_t *context, libnet_ptag_t tag);

int make_ipv4_options(u_int32_t destination_IP, u_int8_t upper_protocol, u_int32_t upper_payload_size, u_int16_t flags, u_int8_t ttl, libnet_t *context, libnet_ptag_t tag);

#endif /* LNET_359_H */
