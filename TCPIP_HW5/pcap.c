#include "pcap.h"
#include <sys/types.h>
#include <pcap/pcap.h>
#include <netinet/in.h>
#include <string.h>


extern pid_t pid;
extern u16 icmp_req;

extern char dev[20];
//static const char* dev = "ens33";
static char* net;
static char* mask;

static char filter_string[FILTER_STRING_SIZE] = "";

static pcap_t *p;
static struct pcap_pkthdr hdr;

/*
 * This function is almost completed.
 * But you still need to edit the filter string.
 */
void my_pcap_init( const char* dst_ip ,int timeout )
{	
	int ret;
	char errbuf[PCAP_ERRBUF_SIZE];
	
	bpf_u_int32 netp;
	bpf_u_int32 maskp;
	
	struct in_addr addr;
	
	struct bpf_program fcode;
	
	ret = pcap_lookupnet(dev, &netp, &maskp, errbuf);
	if(ret == -1){
		fprintf(stderr,"%s\n",errbuf);
		exit(1);
	}
	
	addr.s_addr = netp;
	net = inet_ntoa(addr);	
	if(net == NULL){
		perror("inet_ntoa");
		exit(1);
	}
	
	addr.s_addr = maskp;
	mask = inet_ntoa(addr);
	if(mask == NULL){
		perror("inet_ntoa");
		exit(1);
	}
	
	
	p = pcap_open_live(dev, 8000, 1, timeout, errbuf);
	if(!p){
		fprintf(stderr,"%s\n",errbuf);
		exit(1);
	}
	
	/*
	 *    you should complete your filter string before pcap_compile
	 */
	//snprintf(filter_string, FILTER_STRING_SIZE, "icmp and dst host %s", dst_ip);
	//snprintf(filter_string, FILTER_STRING_SIZE, "icmp and src host %s", dst_ip);  
	snprintf(filter_string, FILTER_STRING_SIZE, "icmp");  
	if(pcap_compile(p, &fcode, filter_string, 0, maskp) == -1){
		pcap_perror(p,"pcap_compile");
		exit(1);
	}
	
	if(pcap_setfilter(p, &fcode) == -1){
		pcap_perror(p,"pcap_setfilter");
		exit(1);
	}
}


int my_pcap_get_reply( void )
{
	const u_char *ptr;
	ptr = pcap_next(p, &hdr);
	
	/*
	 * google "pcap_next" to get more information
	 * and check the packet that ptr pointed to.
	 */
    if (!ptr) {
        printf("No packets captured.\n");
        return -1;
    }
    else
    {
        printf("Packets captured.\n");
    }

    
    // analyze Ethernet Header
    struct ethhdr *eth_hdr = (struct ethhdr *)ptr;
    printf("Ethernet Header:\n");
    printf("\tDestination MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
           eth_hdr->h_dest[0], eth_hdr->h_dest[1], eth_hdr->h_dest[2],
           eth_hdr->h_dest[3], eth_hdr->h_dest[4], eth_hdr->h_dest[5]);
    printf("\tSource MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
           eth_hdr->h_source[0], eth_hdr->h_source[1], eth_hdr->h_source[2],
           eth_hdr->h_source[3], eth_hdr->h_source[4], eth_hdr->h_source[5]);
    printf("\tEtherType: 0x%04x\n", ntohs(eth_hdr->h_proto));

    // check if it is ipv4
    if (ntohs(eth_hdr->h_proto) != ETH_P_IP) {
        printf("Not an IPv4 packet.\n");
        return -1;
    }

    // analyze IP Header
    struct ip *ip_hdr = (struct ip *)(ptr + 14); // skip Ethernet header
    printf("IP Header:\n");
    printf("\tVersion: %d\n", ip_hdr->ip_v);
    printf("\tHeader Length: %d bytes\n", ip_hdr->ip_hl * 4);
    printf("\tTotal Length: %d bytes\n", ntohs(ip_hdr->ip_len));
    printf("\tIdentification: 0x%04x\n", ntohs(ip_hdr->ip_id));
    printf("\tTTL: %d\n", ip_hdr->ip_ttl);
    printf("\tProtocol: %d\n", ip_hdr->ip_p);
    printf("\tHeader Checksum: 0x%04x\n", ntohs(ip_hdr->ip_sum));
    printf("\tSource IP: %s\n", inet_ntoa(ip_hdr->ip_src));
    printf("\tDestination IP: %s\n", inet_ntoa(ip_hdr->ip_dst));

    // check if it is ICMP
    if (ip_hdr->ip_p != IPPROTO_ICMP) {
        printf("Not an ICMP packet.\n");
        return -1;
    }

    // analyze ICMP Header
    struct icmp *icmp_hdr = (struct icmp *)((u_char *)ip_hdr + (ip_hdr->ip_hl * 4));
    printf("ICMP Header:\n");
    printf("\tType: %d\n", icmp_hdr->icmp_type);
    printf("\tCode: %d\n", icmp_hdr->icmp_code);
    printf("\tChecksum: 0x%04x\n", ntohs(icmp_hdr->icmp_cksum));
    printf("\tIdentifier: 0x%04x\n", ntohs(icmp_hdr->icmp_id));
    printf("\tSequence Number: %d\n", ntohs(icmp_hdr->icmp_seq));

    // check if it is specific Echo Reply
    if (icmp_hdr->icmp_type == ICMP_ECHOREPLY) {
        printf("Received ICMP Echo Reply from %s, seq=%u\n",
               inet_ntoa(ip_hdr->ip_src), ntohs(icmp_hdr->icmp_seq));
        return icmp_hdr->icmp_seq;
    }

    printf("Packet does not match our ICMP Echo Reply.\n");
    return -1;
}
