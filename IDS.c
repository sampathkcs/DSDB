#include <cheri/cheri.h>
#include <cheri/cheric.h>
#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <string.h>

// Define SomeIP packet structure
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

// Define memory locations (rules) for ECUs with CHERI capabilities
struct ecu_rule {
    char *__capability ecu_ip;  // Updated: Place __capability after the pointer type
    uint16_t method_id;
    uint16_t client_id;
    uint16_t session_id;
};

// Array to store capabilities for each ECU rule
struct ecu_rule *__capability ecu_memory[5];  // Updated: Place __capability after the type

// Function to initialize ECU rules with CHERI memory safety
void initialize_ecu_memory() {
    // Allocate memory for ECU rules with CHERI capabilities
    for (int i = 0; i < 5; i++) {
        ecu_memory[i] = (struct ecu_rule *__capability)malloc(sizeof(struct ecu_rule));  // Updated: __capability after type
        if (!ecu_memory[i]) {
            perror("Failed to allocate memory for ECU rule");
            exit(EXIT_FAILURE);
        }
    }

    // Assign rules for each ECU, protecting memory with CHERI capabilities
    ecu_memory[0]->ecu_ip = (char *__capability)cheri_setbounds("192.168.1.11", sizeof("192.168.1.11"));
    ecu_memory[0]->method_id = 0x1234;
    ecu_memory[0]->client_id = 0x5678;
    ecu_memory[0]->session_id = 0x9abc;

    ecu_memory[1]->ecu_ip = (char *__capability)cheri_setbounds("192.168.1.12", sizeof("192.168.1.12"));
    ecu_memory[1]->method_id = 0x2234;
    ecu_memory[1]->client_id = 0x6678;
    ecu_memory[1]->session_id = 0x8abc;

    ecu_memory[2]->ecu_ip = (char *__capability)cheri_setbounds("192.168.1.13", sizeof("192.168.1.13"));
    ecu_memory[2]->method_id = 0x3234;
    ecu_memory[2]->client_id = 0x7678;
    ecu_memory[2]->session_id = 0x7abc;

    ecu_memory[3]->ecu_ip = (char *__capability)cheri_setbounds("192.168.1.14", sizeof("192.168.1.14"));
    ecu_memory[3]->method_id = 0x4234;
    ecu_memory[3]->client_id = 0x8678;
    ecu_memory[3]->session_id = 0x6abc;

    ecu_memory[4]->ecu_ip = (char *__capability)cheri_setbounds("192.168.1.15", sizeof("192.168.1.15"));
    ecu_memory[4]->method_id = 0x5234;
    ecu_memory[4]->client_id = 0x9678;
    ecu_memory[4]->session_id = 0x5abc;
}

// Function to check if a packet matches any ECU rules using CHERI capabilities
int check_ecu_rule(const char *src_ip, const struct someip_packet *someip_pkt) {
    for (int i = 0; i < 5; i++) {
        // Use CHERI capability to access the ECU IP rule
        const char *ecu_ip = (const char *)ecu_memory[i]->ecu_ip;

        if (strcmp(src_ip, ecu_ip) == 0 &&
            ntohs(someip_pkt->method_id) == ecu_memory[i]->method_id &&
            ntohs(someip_pkt->client_id) == ecu_memory[i]->client_id &&
            ntohs(someip_pkt->session_id) == ecu_memory[i]->session_id) {
            return i;  // Return the index of the matched rule
        }
    }
    return -1;  // No match found
}

// Function to process packets
void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    // Parse IP header
    struct ip *ip_hdr = (struct ip *)(packet + 14);  // Skip Ethernet header (14 bytes)
    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];

    // Convert source and destination IP addresses to strings
    inet_ntop(AF_INET, &(ip_hdr->ip_src), src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip_hdr->ip_dst), dst_ip, INET_ADDRSTRLEN);

    // Check if the packet is UDP
    if (ip_hdr->ip_p == IPPROTO_UDP) {
        struct udphdr *udp_hdr = (struct udphdr *)(packet + 14 + ip_hdr->ip_hl * 4);  // Skip IP header
        printf("\nSource IP: %s\n", src_ip);
        printf("Destination IP: %s\n", dst_ip);
        printf("Source Port: %d\n", ntohs(udp_hdr->uh_sport));
        printf("Destination Port: %d\n", ntohs(udp_hdr->uh_dport));

        // Extract SomeIP packet encapsulated in UDP
        const struct someip_packet *someip_pkt = (struct someip_packet *)(packet + 14 + ip_hdr->ip_hl * 4 + sizeof(struct udphdr));

        // Check if the packet matches any ECU rule
        int rule_index = check_ecu_rule(src_ip, someip_pkt);
        if (rule_index >= 0) {
            printf("Matched ECU rule for ECU%d at memory location %d\n", rule_index + 1, rule_index + 1);
        } else {
            printf("Unmatched packet! Potential anomaly from %s\n", src_ip);
        }
    } else {
        printf("Non-UDP packet, ignoring.\n");
    }
}

int main() {
    pcap_if_t *alldevs;
    pcap_if_t *device;
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "udp";  // Filter for UDP packets
    bpf_u_int32 net;
    bpf_u_int32 mask;

    // Initialize ECU memory locations with CHERI capabilities
    initialize_ecu_memory();

    // Find all available devices
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "Error finding devices: %s\n", errbuf);
        return 1;
    }

    // Select the first device from the list (for simplicity)
    device = alldevs;
    if (device == NULL) {
        fprintf(stderr, "No devices found! Exiting.\n");
        return 1;
    }

    // Get network number and mask
    if (pcap_lookupnet(device->name, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Couldn't get netmask for device %s: %s\n", device->name, errbuf);
        net = 0;
        mask = 0;
    }

    // Open the device for live capture
    handle = pcap_open_live(device->name, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", device->name, errbuf);
        return 2;
    }

    // Compile and apply the filter for UDP packets
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return 2;
    }

    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return 2;
    }

    printf("Sniffing on device: %s\n", device->name);

    // Capture packets and process them in real-time
    pcap_loop(handle, -1, process_packet, NULL);

    // Free the device list
    pcap_freealldevs(alldevs);

    // Close the session (this will only be reached if pcap_loop exits, such as via signal)
    pcap_close(handle);

    return 0;
}

