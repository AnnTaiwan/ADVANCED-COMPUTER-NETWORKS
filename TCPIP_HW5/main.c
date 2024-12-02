#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <string.h>
#include <sys/time.h>

#include "fill_packet.h"
#include "pcap.h"


pid_t pid;


/**
 * Retrieve the IP address associated with the given network interface name.
 * @param interface_name The name of the network interface (e.g., "eth0").
 * @param ip_buffer Buffer to store the retrieved IP address.
 * @param buffer_size Size of the buffer to avoid overflow.
 */
void get_ip_from_interface(const char *interface_name, char *ip_buffer, size_t buffer_size) {
    int fd;
    struct ifreq ifr;

    // Create a socket to perform ioctl operations
    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    // Copy the interface name into the ifreq structure
    strncpy(ifr.ifr_name, interface_name, IFNAMSIZ - 1);
    ifr.ifr_name[IFNAMSIZ - 1] = '\0';

    // Use ioctl to get the IP address of the specified network interface
    if (ioctl(fd, SIOCGIFADDR, &ifr) < 0) {
        perror("ioctl");
        close(fd);
        exit(EXIT_FAILURE);
    }

    // Extract the IP address from the ifreq structure
    struct sockaddr_in *ip_addr = (struct sockaddr_in *)&ifr.ifr_addr;
    strncpy(ip_buffer, inet_ntoa(ip_addr->sin_addr), buffer_size - 1);
    ip_buffer[buffer_size - 1] = '\0';

    close(fd);
}

void get_netmask_from_interface(const char *interface_name, char *netmask_buffer, size_t buffer_size) {
    struct ifaddrs *ifaddr, *ifa;

    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
        exit(EXIT_FAILURE);
    }

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL || ifa->ifa_addr->sa_family != AF_INET) {
            continue; // skip not IPv4 address
        }

        if (strcmp(ifa->ifa_name, interface_name) == 0) {
            struct sockaddr_in *netmask_addr = (struct sockaddr_in *)ifa->ifa_netmask;
            strncpy(netmask_buffer, inet_ntoa(netmask_addr->sin_addr), buffer_size - 1);
            netmask_buffer[buffer_size - 1] = '\0';
            break;
        }
    }

    freeifaddrs(ifaddr);
}

int main(int argc, char* argv[])
{
	if(argc == 3)
	{
	    if(strcmp(argv[1], "-i") != 0)
	    {    
	        fprintf(stderr, "AUsage error: sudo %s -i [Network Interface Name] -t [timeout(ms)]\n", argv[0]);
	        exit(EXIT_FAILURE);
	    }
	}
	else if(argc != 5)
	{
	    fprintf(stderr, "Usage error: sudo %s -i [Network Interface Name] -t [timeout(ms)]\n", argv[0]);
	    exit(EXIT_FAILURE);
	}
	// Check if the program is running with superuser privileges
    if (geteuid() != 0) {
        fprintf(stderr, "ERROR: You must be root to use this tool!\n");
        exit(EXIT_FAILURE);
    }
    
	int sockfd;
	int on = 1;
	
	
	pid = getpid();
	struct sockaddr_in dst;
	myicmp *packet = (myicmp*)malloc(PACKET_SIZE);
	int count = DEFAULT_SEND_COUNT;
	int timeout = DEFAULT_TIMEOUT;
	
	/* 
	 * in pcap.c, initialize the pcap
	 */
	// get ip from interface name
	char target_ip[INET_ADDRSTRLEN];
    const char *interface_name = argv[2]; // input interface name
    get_ip_from_interface(interface_name, target_ip, sizeof(target_ip));
    printf("-----Initial Network Info-------------------------------\n");
    printf("IP address of %s: %s\n", interface_name, target_ip);
    
    // get netmask from interface_name
    char str_netmask[INET_ADDRSTRLEN];
    get_netmask_from_interface(interface_name, str_netmask, sizeof(str_netmask));
    printf("Netmask of %s: %s\n", interface_name, str_netmask);
    // update timeout based on input
    if(argc == 5)
    {
        timeout = atoi(argv[4]);
    }
	//my_pcap_init( target_ip , timeout);

	
	
	if((sockfd = socket(AF_INET, SOCK_RAW , IPPROTO_RAW)) < 0)
	{
		perror("socket");
		exit(1);
	}

	if(setsockopt( sockfd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0)
	{
		perror("setsockopt");
		exit(1);
	}
	
	
	
	/*
	 *   Use "sendto" to send packets, and use "pcap_get_reply"(in pcap.c) 
		 or use the standard socket like the one in the ARP homework
 	 *   to get the "ICMP echo response" packets 
	 *	 You should reset the timer every time before you send a packet.
	 */
	// data in icmp packet
    const char *student_id = "B103040047";
    size_t student_id_size = strlen(student_id);  // Calculate the size of the student ID

	// Calculate the subnet range (assuming netmask 255.255.255.0)
    struct in_addr start_ip, end_ip, netmask;
    inet_aton(target_ip, &start_ip);
    inet_aton(str_netmask, &netmask);
    start_ip.s_addr = (start_ip.s_addr & netmask.s_addr) | htonl(1);  // Start of the subnet range
    end_ip.s_addr = (start_ip.s_addr & netmask.s_addr) | htonl(254);  // End of the subnet range

    // Print start and end IP addresses in human-readable form
    // Should print: 192.168.1.1 // Should print: 192.168.1.254
    printf("Search from Start IP: %s to End IP: %s\n", inet_ntoa(start_ip), inet_ntoa(end_ip));  
    printf("--------------------------------------------------------\n");
    int seq = 1;  // Sequence number starts at 1

    // Loop through all IP addresses in the subnet
    for (struct in_addr current_ip = start_ip;
         current_ip.s_addr <= end_ip.s_addr;
         current_ip.s_addr = htonl(ntohl(current_ip.s_addr) + 1)) {

        // Prepare the destination address
        memset(&dst, 0, sizeof(dst));
        dst.sin_family = AF_INET;
        dst.sin_addr = current_ip;

        // update pcap every time
        my_pcap_init(inet_ntoa(current_ip), timeout);
        // Fill the ICMP packet
        u8 *data = (u8 *)student_id;  // Use student ID as data
        fill_iphdr(&packet->ip_hdr, target_ip, inet_ntoa(dst.sin_addr));  // Fill IP header
        fill_icmphdr(&packet->icmp_hdr, data, student_id_size, seq);      // Fill ICMP header

        // Record the start time
        struct timeval start, end;
        gettimeofday(&start, NULL);

        // Send the ICMP Echo Request
        if (sendto(sockfd, packet, PACKET_SIZE, 0, (struct sockaddr *)&dst, sizeof(dst)) < 0) {
            perror("sendto");
            continue;
        }
        printf("PING %s (data size = %ld, id = %#x, seq = %d, timeout = %d ms)\n",
               inet_ntoa(current_ip), student_id_size, pid, seq, timeout);

        // Wait for a reply with timeout
        fd_set read_fds;
        FD_ZERO(&read_fds);
        FD_SET(sockfd, &read_fds);

        struct timeval tv;
        tv.tv_sec = timeout / 1000;               // Convert milliseconds to seconds
        tv.tv_usec = (timeout % 1000) * 1000;     // Convert remaining milliseconds to microseconds

        int retval = select(sockfd + 1, &read_fds, NULL, NULL, &tv);

        if (retval == -1) {
            perror("select");  // Error in select
            continue;
        } else if (retval == 0) {
            // Timeout occurred
            printf("\tDestination %s is unreachable (timeout)\n", inet_ntoa(current_ip));
        } else {
            // Reply received
            int reply = my_pcap_get_reply();  // Capture and analyze the reply
            if (reply == 0) {
                // Record the end time and calculate elapsed time
                gettimeofday(&end, NULL);
                double elapsed_time = (end.tv_sec - start.tv_sec) * 1000.0;       // Seconds to milliseconds
                elapsed_time += (end.tv_usec - start.tv_usec) / 1000.0;           // Microseconds to milliseconds
                printf("\tReply from : %s , time : %f ms\n", inet_ntoa(current_ip), elapsed_time);
            } else {
                printf("\tDestination %s is unreachable (no valid ICMP reply)\n", inet_ntoa(current_ip));
            }
        }

        seq++;  // Increment the sequence number
    }

    // Clean up resources
    free(packet);  // Free allocated memory for the packet
    close(sockfd);  // Close the raw socket
	return 0;
}

