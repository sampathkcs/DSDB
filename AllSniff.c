#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <string.h>
#include <netinet/ip.h>   // Provides declarations for IP header
#include <netinet/udp.h>  // Provides declarations for UDP header
#include <netinet/tcp.h>  // Provides declarations for TCP header
#include <pthread.h>      // For threading

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
    char payload[64];  // Adjust as needed
};

// Function to print the SomeIP packet
void print_someip_packet(const struct someip_packet *pkt) {
    printf("\n------------------- SomeIP Packet -------------------\n");
    printf("Method ID: 0x%04x\n", ntohs(pkt->method_id));
    printf("Length: %u\n", ntohs(pkt->length));
    printf("Client ID: 0x%04x\n", ntohs(pkt->client_id));
    printf("Session ID: 0x%04x\n", ntohs(pkt->session_id));
    printf("Protocol Version: %u\n", pkt->protocol_version);
    printf("Interface Version: %u\n", pkt->interface_version);
    printf("Message Type: %u\n", pkt->message_type);
    printf("Return Code: %u\n", pkt->return_code);
    printf("Payload: %s\n", pkt->payload);  // Assuming the payload is a string
    printf("------------------------------------------------------\n");
}

// Callback function for packet processing
void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    // Parse IP header
    struct ip *ip_hdr = (struct ip*)(packet + 14);  // Skip Ethernet header (14 bytes)
    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];

    // Convert IP addresses to strings
    inet_ntop(AF_INET, &(ip_hdr->ip_src), src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip_hdr->ip_dst), dst_ip, INET_ADDRSTRLEN);

    // Print source and destination IPs
    printf("\nSource IP: %s\n", src_ip);
    printf("Destination IP: %s\n", dst_ip);

    // Check if the packet is UDP or TCP
    if (ip_hdr->ip_p == IPPROTO_UDP) {
        struct udphdr *udp_hdr = (struct udphdr*)(packet + 14 + ip_hdr->ip_hl * 4);  // Skip IP header
        printf("Source Port: %d\n", ntohs(udp_hdr->uh_sport));
        printf("Destination Port: %d\n", ntohs(udp_hdr->uh_dport));

        // Assuming that SomeIP is encapsulated in UDP
        const struct someip_packet *someip_pkt = (struct someip_packet *)(packet + 14 + ip_hdr->ip_hl * 4 + sizeof(struct udphdr));
        print_someip_packet(someip_pkt);
    }
    else if (ip_hdr->ip_p == IPPROTO_TCP) {
        struct tcphdr *tcp_hdr = (struct tcphdr*)(packet + 14 + ip_hdr->ip_hl * 4);  // Skip IP header
        printf("Source Port: %d\n", ntohs(tcp_hdr->th_sport));
        printf("Destination Port: %d\n", ntohs(tcp_hdr->th_dport));
    } else {
        printf("Neither TCP nor UDP\n");
    }
}

// Thread function to sniff on a specific interface
void *sniff_on_interface(void *arg) {
    pcap_t *handle = (pcap_t *)arg;
    pcap_loop(handle, -1, process_packet, NULL);
    pcap_close(handle);
    return NULL;
}

int main() {
    pcap_if_t *alldevs, *device;
    char errbuf[PCAP_ERRBUF_SIZE];
    pthread_t threads[10];  // Array to hold thread IDs (adjust if you have more interfaces)
    int thread_count = 0;

    // Find all available devices
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "Error finding devices: %s\n", errbuf);
        return 1;
    }

    // Loop through all devices and start sniffing on each one
    for (device = alldevs; device != NULL; device = device->next) {
        // Skip non-network interfaces like USB
        if (strstr(device->name, "usb") != NULL) {
            printf("Skipping non-network interface: %s\n", device->name);
            continue;
        }

        pcap_t *handle;
        struct bpf_program fp;
        char filter_exp[] = "udp or tcp";  // Filter for UDP and TCP packets
        bpf_u_int32 net;
        bpf_u_int32 mask;

        printf("Opening device: %s\n", device->name);

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
            continue;
        }

        // Compile and apply the filter for UDP and TCP packets
        if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
            fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
            pcap_close(handle);
            continue;
        }

        if (pcap_setfilter(handle, &fp) == -1) {
            fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
            pcap_close(handle);
            continue;
        }

        // Create a new thread for each interface to sniff concurrently
        if (pthread_create(&threads[thread_count], NULL, sniff_on_interface, handle) != 0) {
            fprintf(stderr, "Error creating thread for device %s\n", device->name);
            pcap_close(handle);
            continue;
        }

        thread_count++;
    }

    // Wait for all threads to finish
    for (int i = 0; i < thread_count; i++) {
        pthread_join(threads[i], NULL);
    }

    // Free the device list
    pcap_freealldevs(alldevs);

    return 0;
}

