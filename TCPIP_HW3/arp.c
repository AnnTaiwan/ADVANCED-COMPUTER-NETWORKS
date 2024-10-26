#include "arp.h"

#include <netinet/if_ether.h>
#include <net/ethernet.h>
#include <linux/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
//You can fill the following functions or add other functions if needed. If not, you needn't write anything in them.  
void set_hard_type(struct ether_arp *packet, unsigned short int type) // hardware type
{
    packet->arp_hrd = type;
}
void set_prot_type(struct ether_arp *packet, unsigned short int type)
{
    packet->arp_pro = type;
}
void set_hard_size(struct ether_arp *packet, unsigned char size)
{
    packet->arp_hln = size;
}
void set_prot_size(struct ether_arp *packet, unsigned char size)
{
    packet->arp_pln = size;
}
void set_op_code(struct ether_arp *packet, short int code)
{
    packet->arp_op = code; // 1 for request, 2 for reply.
}

void set_sender_hardware_addr(struct ether_arp *packet, char *address)
{
    // Use memcpy since arp_sha is a byte array, not a null-terminated string
    memcpy(packet->arp_sha, address, ETH_ALEN); // ETH_ALEN is 6 bytes for MAC addresses
}
void set_sender_protocol_addr(struct ether_arp *packet, char *address)
{
    memcpy(packet->arp_spa, address, 4); // IPv4 addresses are 4 bytes long
}
void set_target_hardware_addr(struct ether_arp *packet, char *address)
{
    memcpy(packet->arp_tha, address, ETH_ALEN);
}
void set_target_protocol_addr(struct ether_arp *packet, char *address)
{
    memcpy(packet->arp_tpa, address, 4); // IPv4 addresses are 4 bytes long
}

char* get_target_protocol_addr(struct ether_arp *packet)
{
	// if you use malloc, remember to free it.
	return (char *)packet->arp_tpa;
}
char* get_sender_protocol_addr(struct ether_arp *packet)
{
	// if you use malloc, remember to free it.
	return (char *)packet->arp_spa;
}
char* get_sender_hardware_addr(struct ether_arp *packet)
{
	// if you use malloc, remember to free it.
	return (char *)packet->arp_sha;
}
char* get_target_hardware_addr(struct ether_arp *packet)
{
	// if you use malloc, remember to free it.
	return (char *)packet->arp_tha;
}

void print_usage() {
    printf("Format :\n");
    printf("1)  ./arp -l -a\n"); // List all ARP packets
    printf("2)  ./arp -l <filter_ip_address>\n"); // Capture ARP packets for the specified IP address.
    printf("3)  ./arp -q <query_ip_address>\n"); // Query ARP table for a specific IP.
    printf("4)  ./arp <fake_mac_address> <target_ip_address>\n"); // ARP spoofing.
}

