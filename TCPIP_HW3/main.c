#include <netinet/if_ether.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include "arp.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

#include <arpa/inet.h>
#include <ctype.h>
#include <unistd.h> // for getopt()

/* 
 * Change "enp2s0f5" to your device name (e.g. "eth0"), when you test your hoework.
 * If you don't know your device name, you can use "ifconfig" command on Linux.
 * You have to use "enp2s0f5" when you ready to upload your homework.
 */
#define DEVICE_NAME "enp2s0f5"

#define printable(ch) (isprint((unsigned char) ch) ? ch : '#')

// the global variable `optind` is updated to contain the index of the next unprocessed element of argv
extern int optind, opterr, optopt; 
extern char *optarg;// get the string after flag

static void usageError(char *progName, char *msg, int opt) /* Print "usage" message and exit */
{
	if (msg != NULL)
	    fprintf(stderr, "%s (-%c)\n", msg, printable(opt));
	print_usage();
	exit(EXIT_FAILURE);
}
void get_mac_address(unsigned char *mac_address) {
    int sockfd;
    struct ifreq ifr;

    // Create a socket
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("socket error");
        exit(1);
    }

    // Retrieve the MAC address
    strncpy(ifr.ifr_name, DEVICE_NAME, IFNAMSIZ - 1);
    if (ioctl(sockfd, SIOCGIFHWADDR, &ifr) < 0) {
        perror("ioctl(SIOCGIFHWADDR) error");
        close(sockfd);
        exit(1);
    }

    // Copy the MAC address to the provided buffer
    memcpy(mac_address, ifr.ifr_hwaddr.sa_data, ETH_ALEN); // Notice: char sa_data[14] so it can copy into MAC_ADDRESS

    close(sockfd);
}
void get_ip_address(struct in_addr *ip_address) {
    int sockfd;
    struct ifreq ifr;

    // Create a socket
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("socket error");
        exit(EXIT_FAILURE);
    }

    // Copy the interface name into the ifreq structure
    strncpy(ifr.ifr_name, DEVICE_NAME, IFNAMSIZ - 1);

    // Get the IP address associated with the network interface
    if (ioctl(sockfd, SIOCGIFADDR, &ifr) < 0) {
        perror("ioctl(SIOCGIFADDR) error");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    // Copy the IP address from the ifreq structure
    memcpy(ip_address, &((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr, sizeof(struct in_addr));

    // Close the socket
    close(sockfd);
}
/*
 * You have to open two socket to handle this program.
 * One for input , the other for output.
 */

int main(int argc, char**argv)
{
    int opt = 0; // get the result returned from get_opt
    int flag_l = 0, flag_q = 0, flag_a = 0; // record the status of the flags
    // Check if the program is running with superuser privileges
    if (geteuid() != 0) {
        fprintf(stderr, "ERROR: You must be root to use this tool!\n");
        exit(EXIT_FAILURE);
    }
    printf("[ ARP sniffer and spoof program ]\n");
    if(argc <= 1)
    {
        fprintf(stderr, "ERROR: Wrong way to ues this tool.\n");
        print_usage();
        exit(EXIT_FAILURE);
    }
    
    // Check if -help is provided as an argument
    for (int i = 1; i < argc; i++) 
    {
        if (strcmp(argv[i], "-help") == 0) 
        {
            print_usage();
            exit(EXIT_SUCCESS);
        }
    }
    // Iterate over options and handle the `-q` flag, `-q` flag expect arguments
    while ((opt = getopt(argc, argv, ":laq")) != -1) // suppress the error msg by putting ':' at start of optstring, ":" after the flag means need argument
    {
	switch (opt) 
	{ 
	    case 'q':
	        flag_q = 1;
		break;
	    case 'a':
	        flag_a = 1;
		break;
	    case 'l':
	        flag_l = 1;
	        break;
	    case ':': 
		usageError(argv[0], "Missing argument", optopt);
		break;
	    case '?': 
		usageError(argv[0], "Unrecognized option", optopt);
		break;
	    default: 
		fprintf(stderr, "Unexpected case in switch: %c\n", opt);
		exit(EXIT_FAILURE); // Terminate the program with failure status
	}
    }
    char filter_ip_address[16] = {0}; // for -l <filter_ip_address>
    char query_ip_address[16] = {0}; // for -q <query_ip_address>
    char fake_mac_address[24] = {0};
    char target_ip_address[16] = {0};
    if(flag_l == 1 && flag_a == 0 && flag_q == 0) // see the argument behind flag_l
    {
        if(argc <= optind) 
        {
            usageError(argv[0], "Missing address", optopt);
        }
        else if(argc - optind > 1) 
        {
            fprintf(stderr, "ERROR: Too many arguments, You should type %s -l <filter_ip_address>\n", argv[0]);
            print_usage();
	    exit(EXIT_FAILURE);
        }
        else
        {
            strcpy(filter_ip_address, argv[optind]); // Get the filter IP address after -l
        }
    }
    else if(flag_l == 1 && flag_a == 1 && flag_q == 0) // see the argument behind flag_l
    {
        if(argc > optind)
        {
            fprintf(stderr, "ERROR: Too many arguments, You should type %s -l -a\n", argv[0]);
            print_usage();
	    exit(EXIT_FAILURE);
        }
    }
    else if(flag_l == 0 && flag_a == 0 && flag_q == 1) // see the argument behind flag_g
    {
        if(argc <= optind) 
        {
            usageError(argv[0], "Missing address", optopt);
        }
        else if(argc - optind > 1) 
        {
            fprintf(stderr, "ERROR: Too many arguments, You should type %s -q <query_ip_address>\n", argv[0]);
            print_usage();
	    exit(EXIT_FAILURE);
        }
        strcpy(query_ip_address, argv[optind]);
        
    }
    else if(flag_l == 0 && flag_a == 0 && flag_q == 0)
    {
        if(argc - optind < 2) 
        {
            fprintf(stderr, "ERROR: Too few arguments, You should type %s <fake_mac_address> <target_ip_address>\n", argv[0]);
            print_usage();
	    exit(EXIT_FAILURE);
        }
        strcpy(fake_mac_address, argv[optind]);
        strcpy(target_ip_address, argv[optind + 1]);
    }
    else
    {
        fprintf(stderr, "ERROR: No such flag combinations\n");
        print_usage();
	exit(EXIT_FAILURE);
    }
    
    //////////// Deal with send receive socket /////////////////
    int sockfd_recv = 0, sockfd_send = 0;
    struct sockaddr_ll sa; // used in send
    struct ifreq req_recv;  // For receiving
    struct ifreq req_send;  // For sending
    struct in_addr myip; 
    
    // get my MAC
    // Get the MAC address
    unsigned char my_mac[ETH_ALEN];
    get_mac_address(my_mac);

    // Print the MAC address
    /*printf("MAC Address: %02x:%02x:%02x:%02x:%02x:%02x\n",
               my_mac[0], my_mac[1], my_mac[2],
               my_mac[3], my_mac[4], my_mac[5]);*/
    // set up myip
    // Retrieve your own IP address for the sender protocol address
    get_ip_address(&myip); // Function to get your own IP address
    
    /// receive ///
    // Open a recv socket in data-link layer.
      /* PF_PACKET: This refers to the packet socket, which allows you to capture raw Ethernet frames at the link layer.
       * SOCK_RAW: Specifies that the socket should capture raw network packets, including Ethernet headers.
       * htons(ETH_P_ALL): ETH_P_ALL indicates that the socket will capture all Ethernet protocols (not limited to ARP, but including ARP, IP, etc.). htons() converts the protocol type into network byte order (big-endian format).
       */
    if((sockfd_recv = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0) 
    {
	perror("open recv socket error");
	exit(1);
    }
            
    /*
    * Use recvfrom function to get packet.
    * recvfrom( ... )
    */
    unsigned char buffer[65536]; // received data
    struct sockaddr_ll src_addr; // used for receive
    socklen_t src_addr_len = sizeof(struct sockaddr_ll);
    
    memset(&req_recv, 0, sizeof(req_recv));
    strncpy(req_recv.ifr_name, DEVICE_NAME, IFNAMSIZ);  // Set your desired interface name
    if (ioctl(sockfd_recv, SIOCGIFINDEX, &req_recv) < 0) 
    {
        perror("ioctl failed to get interface index");
        exit(1);
    }
    memset(&src_addr, 0, sizeof(src_addr));
    src_addr.sll_family = AF_PACKET;
    src_addr.sll_ifindex = req_recv.ifr_ifindex;  // Set the interface index
    src_addr.sll_protocol = htons(ETH_P_ALL); // Capture all protocols (you can also specify ETH_P_ARP if needed)
    
    // Bind the socket to the interface
    if (bind(sockfd_recv, (struct sockaddr*)&src_addr, sizeof(src_addr)) < 0) 
    {
        perror("Bind failed");
        exit(EXIT_FAILURE);
    }
    /// send ///
    // Open a send socket in data-link layer.
    if((sockfd_send = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
    {
        perror("open send socket error");
        exit(sockfd_send);
    }
    strncpy(req_send.ifr_name, DEVICE_NAME, IFNAMSIZ - 1); // Set the interface name
    if (ioctl(sockfd_send, SIOCGIFINDEX, &req_send) < 0) 
    { // Use sockfd_send to get the interface index
        perror("ioctl(SIOCGIFINDEX) error");
        exit(EXIT_FAILURE);
    }

    // Set up the sockaddr_ll structure for sending (moved outside the loop)
    memset(&sa, 0, sizeof(sa));
    sa.sll_family = AF_PACKET;              // Address family
    sa.sll_ifindex = req_send.ifr_ifindex;       // Interface index
    sa.sll_halen = ETH_ALEN;                // Ethernet address length
    memcpy(sa.sll_addr, "\xff\xff\xff\xff\xff\xff", ETH_ALEN); // Broadcast address

    
    
    // function in this porgram
    // Capture Ethernet frames in a loop
    if(flag_l == 1) // listening, just receive the packet
    {
        printf("### ARP sniffer mode ####\n");
        while (1) 
        {
            //printf("Receiving packet...\n");
            memset(buffer, 0, sizeof(buffer));
            ssize_t packet_len = recvfrom(sockfd_recv, buffer, sizeof(buffer), 0, (struct sockaddr*)&src_addr, &src_addr_len);
            if (packet_len < 0) 
            {
                perror("Error receiving packet");
                exit(1);
            }

            //printf("Received packet of length: %ld\n", packet_len);

            // Cast buffer to the arp_packet structure
            struct arp_packet *rec_pkt = (struct arp_packet *)buffer;
            
            // Check if it's an ARP packet by examining the EtherType field
            if (ntohs(rec_pkt->eth_hdr.ether_type) == ETHERTYPE_ARP) 
            {
                // Print the destination (target) IP and source IP from the ARP packet
                struct in_addr sender_ip;
                struct in_addr target_ip;
                // Convert IP address bytes to struct in_addr
                memcpy(&sender_ip, get_sender_protocol_addr(&(rec_pkt->arp)), sizeof(struct in_addr)); // Sender's IP
                memcpy(&target_ip, get_target_protocol_addr(&(rec_pkt->arp)), sizeof(struct in_addr)); // Target's IP
                // Create local buffers to store the IP strings
                char sender_ip_str[INET_ADDRSTRLEN];
                char target_ip_str[INET_ADDRSTRLEN];

                // Convert the IP addresses to strings and store them in local buffers
                strncpy(sender_ip_str, inet_ntoa(sender_ip), INET_ADDRSTRLEN);
                strncpy(target_ip_str, inet_ntoa(target_ip), INET_ADDRSTRLEN);
                if(flag_a == 1) // -l -a ; list all ARP packet
                { // Convert IP addresses to readable format and print them
                    printf("Get ARP packet - who has %s ? \t Tell %s\n", target_ip_str, sender_ip_str);
                }
                else // just list the target-ip-address matched with filter_ip_address
                {
                    // Convert query IP address from string to struct in_addr
                    struct in_addr filter_target_ip;
                    if (inet_pton(AF_INET, filter_ip_address, &filter_target_ip) <= 0) {
                        perror("Invalid IP address format");
                        exit(EXIT_FAILURE);
                    }
                    if(filter_target_ip.s_addr == target_ip.s_addr)
                    {
                        printf("Get ARP packet - who has %s ? \t Tell %s\n", target_ip_str, sender_ip_str);
                    }
                }
                
            }
        }
    }             
   
    
    if(flag_q == 1) // request, just sending the packet, $ sudo ./main -q <query_ip_address>
    {
        printf("### ARP query mode ####\n");

        // Prepare the ARP packet
        struct arp_packet pkt;
        
        // Convert query IP address from string to struct in_addr
        struct in_addr target_ip;
        if (inet_pton(AF_INET, query_ip_address, &target_ip) <= 0) {
            perror("Invalid IP address format");
            exit(EXIT_FAILURE);
        }
        
        // Fill the Ethernet header
        memcpy(pkt.eth_hdr.ether_shost, my_mac, ETH_ALEN);  // Sender MAC (your MAC)
        memset(pkt.eth_hdr.ether_dhost, 0xff, ETH_ALEN);     // Broadcast MAC for ARP request
        pkt.eth_hdr.ether_type = htons(ETHERTYPE_ARP);       // Ethernet type: ARP

        // Fill the ARP header
        set_hard_type(&pkt.arp, htons(ARPHRD_ETHER));        // Hardware type: Ethernet
        set_prot_type(&pkt.arp, htons(ETHERTYPE_IP));        // Protocol type: IPv4
        set_hard_size(&pkt.arp, ETH_ALEN);                   // Hardware address size: 6 bytes
        set_prot_size(&pkt.arp, 4);                          // Protocol address size: 4 bytes (IPv4)
        set_op_code(&pkt.arp, htons(ARPOP_REQUEST));         // ARP operation: Request

        // Set the sender hardware and protocol addresses (your MAC and IP)
        set_sender_hardware_addr(&pkt.arp, (char *)my_mac);
        set_sender_protocol_addr(&pkt.arp, (char *)&myip);
        // Set the target hardware and protocol addresses
        unsigned char target_mac[ETH_ALEN] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00}; // 6 bytes of zeros 
        set_target_hardware_addr(&pkt.arp, (char *)target_mac);  // Target MAC is unknown (ARP request)
        set_target_protocol_addr(&pkt.arp, (char *)&target_ip);  // Target IP address to query
        // Send the ARP packet
        if (sendto(sockfd_send, &pkt, sizeof(pkt), 0, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
            perror("sendto error");
            exit(1);
        }

        //printf("ARP packet sent successfully to query IP: %s\n", query_ip_address);
        
        // Now listen for ARP reply
        while (1) 
        {
            memset(buffer, 0, sizeof(buffer));
            ssize_t packet_len = recvfrom(sockfd_recv, buffer, sizeof(buffer), 0, (struct sockaddr *)&src_addr, &src_addr_len);
            if (packet_len < 0) {
                perror("Error receiving packet");
                exit(1);
            }

            // Cast buffer to the arp_packet structure
            struct arp_packet *rec_pkt = (struct arp_packet *)buffer;

            // Check if it's an ARP packet
            if (ntohs(rec_pkt->eth_hdr.ether_type) == ETHERTYPE_ARP) 
            {
                // Check if it's a reply (opcode ARP reply)
                if (ntohs(rec_pkt->arp.arp_op) == ARPOP_REPLY) 
                {
                    struct in_addr sender_ip;
                    memcpy(&sender_ip, get_sender_protocol_addr(&(rec_pkt->arp)), sizeof(struct in_addr));
                    // Compare the sender IP with the query IP to make sure it's the reply we're waiting for
                    if (sender_ip.s_addr == target_ip.s_addr) 
                    {
                        // Print the target MAC address
                        // printf("Received ARP reply from %s\n", inet_ntoa(sender_ip));
                        printf("MAC address of %s is %02x:%02x:%02x:%02x:%02x:%02x\n", inet_ntoa(target_ip),
                               rec_pkt->eth_hdr.ether_shost[0], rec_pkt->eth_hdr.ether_shost[1],
                               rec_pkt->eth_hdr.ether_shost[2], rec_pkt->eth_hdr.ether_shost[3],
                               rec_pkt->eth_hdr.ether_shost[4], rec_pkt->eth_hdr.ether_shost[5]);
                        break; // Exit the loop once we get the reply
                    }
                }
            }
        }
    
    }
    if(flag_l == 0 && flag_a == 0 && flag_q == 0) // arp spoofing
    {
        printf("### ARP spoof mode ####\n");
        // Convert query IP address from string to struct in_addr
        struct in_addr target_ip;
        if (inet_pton(AF_INET, target_ip_address, &target_ip) <= 0) {
            perror("Invalid IP address format");
            exit(EXIT_FAILURE);
        }
        struct arp_packet *rec_pkt = NULL;
        // first try to receive the packet whose ip matched with <target_ip_address>
        while (1) 
        {
            //printf("Receiving packet...\n");
            memset(buffer, 0, sizeof(buffer));
            ssize_t packet_len = recvfrom(sockfd_recv, buffer, sizeof(buffer), 0, (struct sockaddr*)&src_addr, &src_addr_len);
            if (packet_len < 0) 
            {
                perror("Error receiving packet");
                exit(1);
            }

            //printf("Received packet of length: %ld\n", packet_len);

            // Cast buffer to the arp_packet structure
            rec_pkt = (struct arp_packet *)buffer;
            
            // Check if it's an ARP packet by examining the EtherType field
            if (ntohs(rec_pkt->eth_hdr.ether_type) == ETHERTYPE_ARP) 
            {
                // Print the destination (target) IP and source IP from the ARP packet
                struct in_addr sender_ip;
                struct in_addr rec_target_ip;
                // Convert IP address bytes to struct in_addr
                memcpy(&sender_ip, get_sender_protocol_addr(&(rec_pkt->arp)), sizeof(struct in_addr)); // Sender's IP
                memcpy(&rec_target_ip, get_target_protocol_addr(&(rec_pkt->arp)), sizeof(struct in_addr)); // Target's IP
                // Create local buffers to store the IP strings
                char sender_ip_str[INET_ADDRSTRLEN];
                char rec_target_ip_str[INET_ADDRSTRLEN];

                // Convert the IP addresses to strings and store them in local buffers
                strncpy(sender_ip_str, inet_ntoa(sender_ip), INET_ADDRSTRLEN);
                strncpy(rec_target_ip_str, inet_ntoa(rec_target_ip), INET_ADDRSTRLEN);
                // Convert IP addresses to readable format and print them
                printf("Get ARP packet - who has %s ? \t Tell %s\n", rec_target_ip_str, sender_ip_str);
                if(target_ip.s_addr == rec_target_ip.s_addr)
                {
                    break;
                }
                
                
            }
        }
        // start to make spoof packet with false MAC address
        // Prepare the ARP packet
        struct arp_packet pkt;
        unsigned char target_mac[ETH_ALEN] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00}; // 6 bytes of zeros
        if (sscanf(fake_mac_address, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", 
           &target_mac[0], &target_mac[1], &target_mac[2], 
           &target_mac[3], &target_mac[4], &target_mac[5]) != 6) {
            fprintf(stderr, "Invalid MAC address format\n");
            exit(EXIT_FAILURE);
        }


        // Fill the Ethernet header
        memcpy(pkt.eth_hdr.ether_shost, target_mac, ETH_ALEN); // Use fake MAC address instead of your real MAC
        memcpy(pkt.eth_hdr.ether_dhost, (char *)rec_pkt->eth_hdr.ether_shost, ETH_ALEN); // Broadcast MAC for ARP request
        pkt.eth_hdr.ether_type = htons(ETHERTYPE_ARP); // Ethernet type: ARP

        // Fill the ARP header
        set_hard_type(&pkt.arp, htons(ARPHRD_ETHER)); // Hardware type: Ethernet
        set_prot_type(&pkt.arp, htons(ETHERTYPE_IP)); // Protocol type: IPv4
        set_hard_size(&pkt.arp, ETH_ALEN); // Hardware address size: 6 bytes
        set_prot_size(&pkt.arp, 4); // Protocol address size: 4 bytes (IPv4)
        set_op_code(&pkt.arp, htons(ARPOP_REPLY)); // Use ARP reply for spoofing

        // Set the sender hardware and protocol addresses (fake MAC and your IP)
        set_sender_hardware_addr(&pkt.arp, (char *)target_mac); // Use fake MAC address
        set_sender_protocol_addr(&pkt.arp, (char *)&target_ip); 

        // Set the target hardware and protocol addresses
        set_target_hardware_addr(&pkt.arp, (char *)rec_pkt->eth_hdr.ether_shost); // Target MAC is unknown (ARP request)
        set_target_protocol_addr(&pkt.arp, get_sender_protocol_addr(&rec_pkt->arp)); // Target IP address to query

        // Send the ARP packet
        if (sendto(sockfd_send, &pkt, sizeof(pkt), 0, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
            perror("sendto error");
            exit(1);
        }

        printf("Sent ARP Reply : %s is %02x:%02x:%02x:%02x:%02x:%02x\n", inet_ntoa(target_ip), 
                               target_mac[0], target_mac[1],
                               target_mac[2], target_mac[3],
                               target_mac[4], target_mac[5]);
        printf("Send Successful\n");
    }
    return 0;
}

