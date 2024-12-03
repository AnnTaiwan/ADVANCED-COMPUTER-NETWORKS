#ifndef __FILLPACKET__H_
#define __FILLPACKET__H_

#include <netinet/ip.h>
#include <netinet/ip_icmp.h>

typedef char u8;
typedef unsigned short u16;
typedef uint32_t u32; // Define u32 as uint32_t
#define PACKET_SIZE    92
#define IP_OPTION_SIZE 8
#define ICMP_PACKET_SIZE   PACKET_SIZE - (int)sizeof(struct ip) - IP_OPTION_SIZE
#define ICMP_DATA_SIZE     ICMP_PACKET_SIZE - (int)sizeof(struct icmphdr)
#define DEFAULT_SEND_COUNT 4
#define DEFAULT_TIMEOUT 1500

typedef struct
{
	struct ip ip_hdr;// 8 bytes
	u8 ip_option[8];
	struct icmphdr icmp_hdr; // 20 bytes
	u8 data[0]; // 92-8-8-20 = 56 bytes
} myicmp ;

void fill_iphdr(struct ip *ip_hdr, const char *src_ip, const char *dst_ip);
void fill_icmphdr(struct icmphdr *icmp_hdr, u8 *data, size_t data_size, int seq);
u16 ip_checksum(struct ip *ip_hdr);
u16 fill_cksum(struct icmphdr *icmp_hdr, u8 *data, size_t data_size);
#endif
 
