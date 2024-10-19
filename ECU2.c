#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>

struct someip_packet {
    uint16_t method_id;
    uint16_t length;
    uint16_t client_id;
    uint16_t session_id;
    uint8_t protocol_version;
    uint8_t interface_version;
    uint8_t message_type;
    uint8_t return_code;
    char payload[64];
};

void send_someip_packet() {
    int sockfd;
    struct sockaddr_in src_addr, dest_addr;

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("Socket creation failed");
        return;
    }

    src_addr.sin_family = AF_INET;
    src_addr.sin_port = htons(12346);  // Source port
    inet_pton(AF_INET, "192.168.1.12", &src_addr.sin_addr);  // Source IP for ECU2
    bind(sockfd, (struct sockaddr *)&src_addr, sizeof(src_addr));

    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(30491);  // Destination port
    inet_pton(AF_INET, "192.168.1.102", &dest_addr.sin_addr);  // Destination IP

    struct someip_packet someip_pkt;
    someip_pkt.method_id = htons(0x2234);  // Unique method ID
    someip_pkt.length = htons(sizeof(someip_pkt));
    someip_pkt.client_id = htons(0x6678);  // Unique client ID
    someip_pkt.session_id = htons(0x8abc);  // Unique session ID
    someip_pkt.protocol_version = 1;
    someip_pkt.interface_version = 1;
    someip_pkt.message_type = 1;
    someip_pkt.return_code = 0;
    strncpy(someip_pkt.payload, "ECU2 - Payload", sizeof(someip_pkt.payload) - 1);

    while (1) {
        sendto(sockfd, &someip_pkt, sizeof(someip_pkt), 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr));
        printf("Sent ECU2 Some/IP packet from 192.168.1.12 to 192.168.1.102:30491\n");
        sleep(1);
    }

    close(sockfd);
}

int main() {
    send_someip_packet();
    return 0;
}

