#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>   // For standard integer types like uint8_t
#include <string.h>   // For string manipulation functions like strcpy
#include <sys/socket.h>  // For socket functions
#include <netinet/in.h>  // For sockaddr_in and related networking functions
#include <arpa/inet.h>   // For inet_pton and network-related functions
#include <unistd.h>  // For close() and other system calls

// Define constants
#define DST_IP "192.168.1.1"
#define DST_PORT 12345

// Define a structure for the SOME/IP packet
struct someip_packet {
    uint16_t service_id;
    uint16_t method_id;
    uint16_t length;
    uint16_t client_id;
    uint16_t session_id;
    uint8_t protocol_version;
    uint8_t interface_version;
    uint8_t message_type;
    uint8_t return_code;
    char payload[64]; // Adjust as needed
};

// Function to send SOME/IP packet
void send_packet() {
    int sockfd;
    struct sockaddr_in dest_addr;
    struct someip_packet someip_pkt;

    // Create socket
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);  // UDP socket
    if (sockfd < 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    // Destination address
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(DST_PORT);
    inet_pton(AF_INET, DST_IP, &dest_addr.sin_addr);

    // Build the SOME/IP packet
    someip_pkt.service_id = htons(0x1234);
    someip_pkt.method_id = htons(0x5678);
    someip_pkt.length = htons(12);
    someip_pkt.client_id = htons(0x0001);
    someip_pkt.session_id = htons(0x0001);
    someip_pkt.protocol_version = 1;
    someip_pkt.interface_version = 1;
    someip_pkt.message_type = 0x00;
    someip_pkt.return_code = 0x00;
    strcpy(someip_pkt.payload, "Some/IP payload from 192.168.1.1");

    // Send packet in a loop
    while (1) {
        sendto(sockfd, &someip_pkt, sizeof(someip_pkt), 0, (struct sockaddr*)&dest_addr, sizeof(dest_addr));
        printf("Sent SOME/IP packet to %s:%d\n", DST_IP, DST_PORT);
        sleep(1);  // Adjust the sleep interval as needed
    }

    // Close the socket
    close(sockfd);
}

int main() {
    send_packet();
    return 0;
}

