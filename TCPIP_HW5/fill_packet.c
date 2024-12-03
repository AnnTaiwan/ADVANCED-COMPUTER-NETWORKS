#include "fill_packet.h"
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/types.h>
#include <string.h>

void fill_iphdr(struct ip *ip_hdr, const char *src_ip, const char *dst_ip) 
{
    memset(ip_hdr, 0, sizeof(struct ip));
    // Fill in the basic information of the IP header
    ip_hdr->ip_v = 4; // IPv4
    ip_hdr->ip_hl = 7; // IP header length, 5 indicates no options, 4 bytes are one unit. So, plus ip_option[8] (8 bytes which is two units. Hence, 5+2 = 7, now can see this packet on wireshark
    ip_hdr->ip_tos = 0; // Type of service, set to 0
    ip_hdr->ip_len = htons(PACKET_SIZE); // Total length, set to the size of the packet
    ip_hdr->ip_id = 0; // Set ID to 0, can be any number
    ip_hdr->ip_off = 0; // Fragment offset, no fragmentation
    ip_hdr->ip_ttl = 1; // TTL set to 1, ensures packet stays within the local subnet
    ip_hdr->ip_p = IPPROTO_ICMP; // Set protocol to ICMP
    ip_hdr->ip_sum = 0; // Checksum (set to 0 before calculation)

    // Set the source and destination IP addresses
    inet_aton(src_ip, &ip_hdr->ip_src); // Source IP
    inet_aton(dst_ip, &ip_hdr->ip_dst); // Destination IP

    // Fill in the IP options (if applicable, here it's just zeroed for simplicity)
    u8 *options = (u8 *)(ip_hdr + 1); // Pointer to options
    memset(options, 0, 8); // Set 8 bytes of options to 0

    // Calculate checksum after setting all header fields
    ip_hdr->ip_sum = ip_checksum(ip_hdr);
}


void fill_icmphdr(struct icmphdr *icmp_hdr, u8 *data, size_t data_size, int seq) 
{
    // Fill ICMP header fields
    icmp_hdr->type = ICMP_ECHO;          // Echo Request
    icmp_hdr->code = 0;                  // No specific code for Echo Request
    icmp_hdr->un.echo.id = htons(getpid());     // Use process ID as ID
    icmp_hdr->un.echo.sequence = htons(seq);    // Sequence number starts from 1
    icmp_hdr->checksum = fill_cksum(icmp_hdr, data, data_size);

    // Copy data (student ID) into the data field
    if (data_size > 0) {
        memcpy((u8 *)(icmp_hdr + 1), data, data_size);  // Copy data after the ICMP header
    }
}

u16 ip_checksum(struct ip *ip_hdr) 
{
    u32 sum = 0;
    u16 *header = (u16 *)ip_hdr;
    int len = ip_hdr->ip_hl * 4;  // Header length in bytes

    // Sum all 16-bit words in the IP header
    while (len > 1) {
        sum += *header++;
        len -= 2;
    }

    // Add remaining byte if odd length
    if (len == 1) {
        sum += *(u8 *)header;
    }

    // Add carry-over bits
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);

    return ~sum;  // Return one's complement
}


u16 fill_cksum(struct icmphdr *icmp_hdr, u8 *data, size_t data_size) 
{
    u32 sum = 0;
    u16 *header = (u16 *)icmp_hdr;
    int len = sizeof(struct icmphdr);

    // Sum all 16-bit words in ICMP header
    while (len > 1) {
        sum += *header++;
        len -= 2;
    }

    // Add the remaining byte if odd length
    if (len == 1) {
        sum += *(u8 *)header;
    }

    // Sum all 16-bit words in the data
    u16 *payload = (u16 *)data;
    while (data_size > 1) {
        sum += *payload++;
        data_size -= 2;
    }

    // Add the remaining byte if odd length
    if (data_size == 1) {
        sum += *(u8 *)payload;
    }

    // Add carry-over bits
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);

    return ~sum;  // Return one's complement
}

