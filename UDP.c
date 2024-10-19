#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>   // For inet_pton and sockaddr_in
#include <unistd.h>      // For close() and sleep()
#include <sys/socket.h>  // For socket(), AF_INET, SOCK_RAW, etc.
#include <netinet/in.h>  // For struct sockaddr_in and IPPROTO_UDP

void send_packet() {
    int sockfd;
    struct sockaddr_in dest_addr;
    char message[] = "Some/IP packet payload";

    // Create a raw UDP socket
    sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);  // Use SOCK_RAW for raw sockets
    if (sockfd < 0) {
        perror("Socket creation failed");
        return;
    }

    // Fill destination address
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(30490);  // Destination port
    inet_pton(AF_INET, "192.168.1.101", &dest_addr.sin_addr);  // Destination IP

    // Send the packet in a loop
    while (1) {
        sendto(sockfd, message, strlen(message), 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr));
        printf("Sent packet to 192.168.1.101:30490\n");
        sleep(1);  // Send a packet every second
    }

    close(sockfd);
}

int main() {
    send_packet();
    return 0;
}

