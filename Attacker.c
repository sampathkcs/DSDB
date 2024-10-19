#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <sys/socket.h>
#include <netinet/in.h>  // For sockaddr_in and IPPROTO_UDP
#include <netinet/udp.h> // For struct udphdr

// UDP header size
#define UDP_HDRLEN 8
// Total packet size (IP header + UDP header + payload)
#define PACKET_SIZE 512

// Function to calculate checksum
unsigned short checksum(void *b, int len) {
    unsigned short *buf = b;
    unsigned int sum = 0;
    unsigned short result;

    for (sum = 0; len > 1; len -= 2) {
        sum += *buf++;
    }
    if (len == 1) {
        sum += *(unsigned char*)buf;
    }
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    result = ~sum;
    return result;
}

// Main function to craft the packet
int main() {
    char packet[PACKET_SIZE]; // Buffer for the packet
    struct ip *iph = (struct ip *) packet;  // IP header
    struct udphdr *udph = (struct udphdr *) (packet + sizeof(struct ip));  // UDP header
    struct sockaddr_in sin;

    // Attacker's IP (in the same subnet as ECU1)
    char *attacker_ip = "192.168.1.100";
    // IDS destination IP
    char *ids_ip = "192.168.1.200";

    // Create raw socket
    int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
    if (sockfd < 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    // Clear the packet buffer
    memset(packet, 0, PACKET_SIZE);

    // IP header configuration
    iph->ip_hl = 5;           // Header length
    iph->ip_v = 4;            // IPv4
    iph->ip_tos = 0;          // Type of service
    iph->ip_len = htons(sizeof(struct ip) + sizeof(struct udphdr) + strlen("Mapping packet to ECU1 rules"));
    iph->ip_id = htons(54321); // Identification (Use htons for 16-bit fields)
    iph->ip_off = 0;          // Fragment offset
    iph->ip_ttl = 255;        // Time to live
    iph->ip_p = IPPROTO_UDP;  // Protocol
    iph->ip_sum = 0;          // Set to 0 before calculating checksum
    iph->ip_src.s_addr = inet_addr(attacker_ip);  // Attacker's IP address
    iph->ip_dst.s_addr = inet_addr(ids_ip);       // IDS IP address

    // UDP header configuration
    udph->uh_sport = htons(12345);  // Source port (uh_sport instead of source)
    udph->uh_dport = htons(30490);  // Destination port (uh_dport instead of dest)
    udph->uh_ulen = htons(UDP_HDRLEN + strlen("Mapping packet to ECU1 rules"));  // UDP header + data length (uh_ulen instead of len)
    udph->uh_sum = 0;  // No checksum for simplicity (uh_sum instead of check)

    // Data payload
    char *data = packet + sizeof(struct ip) + sizeof(struct udphdr);
    strcpy(data, "Mapping packet to ECU1 rules");

    // Calculate IP checksum
    iph->ip_sum = checksum((unsigned short *) packet, iph->ip_len);

    // Configure destination address
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = inet_addr(ids_ip);

    // Send the crafted packet
    if (sendto(sockfd, packet, ntohs(iph->ip_len), 0, (struct sockaddr *) &sin, sizeof(sin)) < 0) {
        perror("Packet send failed");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    printf("Packet sent from real attacker IP: %s to IDS at %s\n", attacker_ip, ids_ip);
    
    close(sockfd);  // Close the socket
    return 0;
}

