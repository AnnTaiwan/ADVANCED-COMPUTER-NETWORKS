#include "pcap.h"
#include <sys/types.h>
#include <pcap/pcap.h>
#include <netinet/in.h>
#include <string.h>


extern pid_t pid;
extern u16 icmp_req;

static const char* dev = "ens33";
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
	snprintf(filter_string, FILTER_STRING_SIZE, "icmp and src host %s", dst_ip);  
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
    printf("No pac###################kets captured.\n");
    }

    struct ip *ip_hdr = (struct ip *)(ptr + 14); // Skip Ethernet header
    if (ip_hdr->ip_p != IPPROTO_ICMP) {
        return -1;
    }

    struct icmp *icmp_hdr = (struct icmp *)((u_char *)ip_hdr + (ip_hdr->ip_hl * 4));
    printf("icmp_hdr = %#x\n",icmp_hdr->icmp_id);
    if (icmp_hdr->icmp_type == ICMP_ECHOREPLY && icmp_hdr->icmp_id == pid) {
        printf("Received ICMP reply from %s, seq=%u\n",
               inet_ntoa(ip_hdr->ip_src), icmp_hdr->icmp_seq);
        return 0;
    }
    return -1;
}
