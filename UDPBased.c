#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>   // For inet_pton and sockaddr_in
#include <unistd.h>      // For close() and sleep()
#include <sys/socket.h>  // For socket(), AF_INET, SOCK_DGRAM, etc.
#include <netinet/in.h>  // For struct sockaddr_in and IPPROTO_UDP

// Define SomeIP packet structure based on what you provided
struct someip_packet {
    uint16_t method_id;
    uint16_t length;
    uint16_t client_id;
    uint16_t session_id;
    uint8_t protocol_version;
    uint8_t interface_version;
    uint8_t message_type;
    uint8_t return_code;
    char payload[64];  // Adjust as needed for payload
};

// Function to construct and send the Some/IP packet over UDP
void send_someip_packet() {
    int sockfd;
    struct sockaddr_in dest_addr;

    // Create a UDP socket
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);  // SOCK_DGRAM for UDP
    if (sockfd < 0) {
        perror("Socket creation failed");
        return;
    }

    // Fill the destination address
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(30490);  // Destination port
    inet_pton(AF_INET, "192.168.1.101", &dest_addr.sin_addr);  // Destination IP

    // Construct a Some/IP packet
    struct someip_packet someip_pkt;
    someip_pkt.method_id = htons(0x1234);      // Example method ID
    someip_pkt.length = htons(sizeof(someip_pkt));  // Total length including payload
    someip_pkt.client_id = htons(0x5678);      // Example client ID
    someip_pkt.session_id = htons(0x9abc);     // Example session ID
    someip_pkt.protocol_version = 1;           // Protocol version 1
    someip_pkt.interface_version = 1;          // Interface version 1
    someip_pkt.message_type = 1;               // Example message type
    someip_pkt.return_code = 0;                // Return code 0 (success)

    // Fill the Some/IP payload with a test message
    strncpy(someip_pkt.payload, "Some/IP packet payload", sizeof(someip_pkt.payload) - 1);

    // Send the Some/IP packet encapsulated in UDP in a loop
    while (1) {
        ssize_t sent_bytes = sendto(sockfd, &someip_pkt, sizeof(someip_pkt), 0, 
                                    (struct sockaddr *)&dest_addr, sizeof(dest_addr));
        if (sent_bytes < 0) {
            perror("Failed to send packet");
        } else {
            printf("Sent Some/IP packet to 192.168.1.101:30490, bytes: %zd\n", sent_bytes);
        }

        sleep(1);  // Send a packet every second
    }

    // Close the socket when done
    close(sockfd);
}

int main() {
    send_someip_packet();
    return 0;
}

