#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>

// ICMP header structure
struct icmp_header {
    u_int8_t type;
    u_int8_t code;
    u_int16_t checksum;
    u_int16_t id;
    u_int16_t sequence;
};

// Calculate checksum for ICMP packet
unsigned short calculate_checksum(void *buffer, int length) {
    unsigned short *data = buffer;
    unsigned int sum = 0;
    unsigned short checksum = 0;

    while (length > 1) {
        sum += *data++;
        length -= 2;
    }

    if (length == 1) {
        *(unsigned char *)(&checksum) = *(unsigned char *)data;
        sum += checksum;
    }

    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    return ~sum;
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <max-hop-distance> <destination>\n", argv[0]);
        exit(EXIT_FAILURE);
    }
    // Check if the program is running with superuser privileges
    if (geteuid() != 0) {
        fprintf(stderr, "ERROR: You must be root to use this tool!\n");
        exit(EXIT_FAILURE);
    }

    int max_hops = atoi(argv[1]); // Maximum hop distance
    char *destination = argv[2];

    // Create raw socket
    int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sockfd < 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    // Address setup for destination
    struct sockaddr_in dest_addr;
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;
    if (inet_pton(AF_INET, destination, &dest_addr.sin_addr) != 1) {
        perror("inet_pton");
        exit(EXIT_FAILURE);
    }

    // Create ICMP Echo Request
    char send_buffer[64];
    memset(send_buffer, 0, sizeof(send_buffer));
    struct icmp_header *icmp = (struct icmp_header *)send_buffer;
    icmp->type = ICMP_ECHO;
    icmp->code = 0;
    icmp->id = getpid();

    printf("prog.c Tracing route to %s, max hops: %d\n", destination, max_hops);

    for (int ttl = 1; ttl <= max_hops; ttl++) {
        // Set TTL for the socket
        if (setsockopt(sockfd, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl)) < 0) {
            perror("setsockopt");
            exit(EXIT_FAILURE);
        }

        // Update ICMP sequence number
        icmp->sequence = ttl;
        icmp->checksum = 0;
        icmp->checksum = calculate_checksum(icmp, sizeof(send_buffer));

        // Send ICMP Echo Request
        if (sendto(sockfd, send_buffer, sizeof(send_buffer), 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr)) < 0) {
            perror("sendto");
            exit(EXIT_FAILURE);
        }

        // Set timeout for response
        struct timeval timeout = {1, 0}; // 1 second timeout
        setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

        // Receive ICMP Response
        char recv_buffer[1024];
        struct sockaddr_in recv_addr;
        socklen_t addr_len = sizeof(recv_addr);

        int bytes_received = recvfrom(sockfd, recv_buffer, sizeof(recv_buffer), 0, (struct sockaddr *)&recv_addr, &addr_len);

        if (bytes_received < 0) {
            // Timeout or no response
            printf("%2d  * * *\n", ttl);
        } else {
            // Extract source address from response
            char ip_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &recv_addr.sin_addr, ip_str, sizeof(ip_str));

            // Print the router's IP
            printf("%2d  %s\n", ttl, ip_str);

            // Check if we've reached the destination
            if (recv_addr.sin_addr.s_addr == dest_addr.sin_addr.s_addr) {
                printf("Reached destination: %s\n", destination);
                break;
            }
        }
    }

    close(sockfd);
    return 0;
}

