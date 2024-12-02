#include "fill_packet.h"
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/types.h>
#include <string.h>

void fill_iphdr(struct ip *ip_hdr, const char *src_ip, const char *dst_ip) 
{
    // Fill in the basic information of the IP header
    ip_hdr->ip_v = 4; // IPv4
    ip_hdr->ip_hl = 5; // IP header length, 5 indicates no options
    ip_hdr->ip_tos = 0; // Type of service, set to 0
    ip_hdr->ip_len = htons(PACKET_SIZE); // Total length, set to the size of the packet
    ip_hdr->ip_id = 0; // Set ID to 0, can be any number
    ip_hdr->ip_off = 0; // Fragment offset, no fragmentation
    ip_hdr->ip_ttl = 1; // TTL set to 1, ensures packet stays within the local subnet
    ip_hdr->ip_p = IPPROTO_ICMP; // Set protocol to ICMP
    ip_hdr->ip_sum = 0; // Set checksum to 0, it will be calculated later

    // Set the source IP address (this is usually obtained from the local interface)
    struct in_addr src;
    inet_aton(src_ip, &src); // Replace with your actual local IP address
    ip_hdr->ip_src = src;

    // Set the destination IP address
    struct in_addr dst;
    inet_aton(dst_ip, &dst); // Convert destination IP string to binary format
    ip_hdr->ip_dst = dst;
}


/*void fill_icmphdr(struct icmphdr *icmp_hdr) 
{
    icmp_hdr->type = ICMP_ECHO; // ICMP type set to Echo Request (8)
    icmp_hdr->code = 0; // Set code to 0, indicating no error
    icmp_hdr->un.echo.id = getpid(); // Set the ID to the process ID
    icmp_hdr->un.echo.sequence = 1; // Set the sequence number to 1, can be incremented for subsequent packets
    icmp_hdr->checksum = 0; // Set checksum to 0, it will be calculated later
}*/

void fill_icmphdr(struct icmphdr *icmp_hdr, u8 *data, size_t data_size, int seq) 
{
    // Fill ICMP header fields
    icmp_hdr->type = ICMP_ECHO;          // Echo Request
    icmp_hdr->code = 0;                  // No specific code for Echo Request
    icmp_hdr->un.echo.id = getpid();     // Use process ID as ID
    icmp_hdr->un.echo.sequence = seq;    // Sequence number starts from 1
    icmp_hdr->checksum = 0;              // Let OS calculate checksum if needed

    // Copy data (student ID) into the data field
    if (data_size > 0) {
        memcpy((u8 *)(icmp_hdr + 1), data, data_size);  // Copy data after the ICMP header
    }
}

u16 fill_cksum(struct icmphdr *icmp_hdr) 
{
    // Variable to accumulate the checksum
    u32 sum = 0;
    u16 *data = (u16 *)icmp_hdr;
    int len = sizeof(struct icmphdr); // Length of the ICMP header

    // Sum all 16-bit words
    while (len > 1) {
        sum += *data++;
        len -= 2;
    }

    // If the length is odd, add the remaining byte to the checksum
    if (len == 1) {
        sum += *(u8 *)data;
    }

    // Add the carry-over bits to the lower 16 bits
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);

    // Return the complement of the sum (in network byte order)
    return ~sum;
}

