#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <cjson/cJSON.h>
#include <stdbool.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <sys/time.h>
#include <netinet/udp.h>
#include <errno.h>

/**
 * Struct to define the pseudo header used for TCP checksum calculations.
 */
struct pseudo_header {
    u_int32_t source_address;
    u_int32_t dest_address;
    u_int8_t placeholder;
    u_int8_t protocol;
    u_int16_t tcp_length;
};

/**
 * Reads and parses configuration data from a JSON file.
 * @param configFilePath Path to the configuration file.
 * @param configContent Pointer to store the content of the configuration file.
 * @return Pointer to cJSON object containing the parsed configuration data.
 */
cJSON* getConfigFromFile(const char *configFilePath, char **configContent) {
    printf("Opening configuration file: %s\n", configFilePath);

    // Attempt to open the configuration file
    FILE *configFile = fopen(configFilePath, "r");
    if (!configFile) {
        perror("Error: Failed to open the configuration file.");
        exit(EXIT_FAILURE);
    }

    // Read the file content into a buffer
    char buffer[1024];
    int bytesRead = fread(buffer, 1, sizeof(buffer) - 1, configFile);
    buffer[bytesRead] = '\0';
    fclose(configFile);

    // Allocate memory for storing the configuration data
    *configContent = malloc(bytesRead + 1);
    if (!*configContent) {
        perror("Error: Memory allocation failed for configuration data.");
        exit(EXIT_FAILURE);
    }
    strcpy(*configContent, buffer);

    // Parse the JSON data
    cJSON *configJSON = cJSON_Parse(*configContent);
    if (!configJSON) {
        perror("Error: Parsing JSON data failed.");
        free(*configContent);
        exit(EXIT_FAILURE);
    }

    printf("Configuration data loaded and parsed successfully.\n");
    return configJSON;
}

/**
 * Computes the Internet checksum (RFC 1071) for the provided buffer.
 * This checksum is commonly used in networking for error-checking of headers.
 *
 * @param buffer Pointer to the data buffer whose checksum is to be calculated.
 * @param size The size of the buffer in bytes.
 * @return The computed checksum as an unsigned short.
 */
unsigned short checksum(const char *buffer, unsigned size) {
    uint32_t sum = 0;
    unsigned i;

    // Accumulate checksum word by word
    for (i = 0; i < size - 1; i += 2) {
        // Assemble bytes into a word: network byte order is big-endian
        uint16_t word = (unsigned char)buffer[i] << 8 | (unsigned char)buffer[i + 1];
        sum += word;
    }

    // Add the last byte if there is an odd number of bytes
    if (size & 1) {
        uint16_t word = (unsigned char)buffer[i] << 8;
        sum += word;
    }

    // Fold 32-bit sum to 16 bits: add carrier to result
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    // One's complement of the sum
    return (unsigned short)~sum;
}

/**
 * Sends a series of UDP packets with specified characteristics to a server.
 * 
 * @param client_ip The IP address of the client sending the packets.
 * @param server_ip The IP address of the server to receive the packets.
 * @param source_port The source port number for UDP packets.
 * @param dest_port The destination port number on the server.
 * @param packet_size The size of the payload in each UDP packet.
 * @param packet_count The number of packets to send.
 * @param is_random Whether the payload should contain random data.
 * @param ttl The Time To Live (TTL) for the UDP packets.
 */
void send_udp_packets(const char* client_ip, const char* server_ip, int source_port, int dest_port, int packet_size, int packet_count, bool is_random, int ttl) {
    // Create a raw socket for UDP
    int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
    if (sockfd < 0) {
        perror("Failed to create raw socket");
        exit(1);
    }

    // Enable IP header inclusion for manual crafting
    int optval = 1;
    if (setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &optval, sizeof(optval)) < 0) {
        perror("Failed to set IP_HDRINCL");
        close(sockfd);
        exit(1);
    }

    // Prepare buffer for the packet
    char packet[sizeof(struct iphdr) + sizeof(struct udphdr) + packet_size];
    memset(packet, 0, sizeof(packet));

    // Setup destination address structure
    struct sockaddr_in dest_addr = {
        .sin_family = AF_INET,
        .sin_port = htons(dest_port),
        .sin_addr.s_addr = inet_addr(server_ip)
    };

    // Open /dev/urandom for random data generation, if necessary
    FILE *urandom = is_random ? fopen("/dev/urandom", "r") : NULL;
    if (is_random && !urandom) {
        perror("Failed to open /dev/urandom");
        close(sockfd);
        exit(1);
    }

    for (int i = 0; i < packet_count; ++i) {
        // Setup IP header
        struct iphdr *iph = (struct iphdr *) packet;
        iph->ihl = 5;                                               // IP header length in 32-bit words
        iph->version = 4;                                           // IP version 4
        iph->tos = 0;                                               // Type of Service: default routine
        iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct udphdr) + packet_size); // Total packet length
        iph->id = htons(54321);                                     // Identification field
        iph->frag_off = htons(IP_DF);                               // Fragment offset field with Don't Fragment flag
        iph->ttl = ttl;                                             // Time To Live: specifies packet's lifetime
        iph->protocol = IPPROTO_UDP;                                // Protocol type: UDP
        iph->saddr = inet_addr(client_ip);                          // Source IP address
        iph->daddr = inet_addr(server_ip);                          // Destination IP address

        // Setup UDP header
        struct udphdr *udph = (struct udphdr *) (packet + sizeof(struct iphdr));
        udph->source = htons(source_port);                          // Source port number
        udph->dest = htons(dest_port);                              // Destination port number
        udph->len = htons(sizeof(struct udphdr) + packet_size);     // Length of UDP header and payload

        // Setup payload
        char *payload = packet + sizeof(struct iphdr) + sizeof(struct udphdr);
        *((unsigned short *)payload) = htons(i);  // Packet ID at the start of the payload
        
        if (is_random) {
            fread(payload + 2, 1, packet_size - 2, urandom);  // Fill with random data
        }

        // Calculate and set IP checksum
        iph->check = 0;
        iph->check = checksum((char *)iph, iph->ihl * 4);

        // Send the packet
        if (sendto(sockfd, packet, ntohs(iph->tot_len), 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr)) < 0) {
            perror("Failed to send packet");
            break;
        }
    }

    if (urandom) {
        fclose(urandom);
    }
    close(sockfd);
}

// Sends a SYN packet using raw sockets, either as a 'head' or 'tail' packet
void send_syn_packet(const char *client_ip, const char *server_ip, int dest_port, int ttl, bool is_head) {
    // Log the type of SYN packet being sent
    printf("Preparing to send %s SYN packet to %s:%d\n", is_head ? "head" : "tail", server_ip, dest_port);

    // Create a raw socket for the TCP protocol
    int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sockfd < 0) {
        perror("Failed to create raw socket");
        exit(1);
    }

    // Enable IP header inclusion for manual construction
    int val = 1;
    if (setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &val, sizeof(val)) < 0) {
        perror("Failed to set IP_HDRINCL");
        close(sockfd);
        exit(1);
    }

    // Construct the packet buffer
    char packet[sizeof(struct iphdr) + sizeof(struct tcphdr)];
    memset(packet, 0, sizeof(packet));

    // Set up the IP header fields
    struct iphdr *iph = (struct iphdr *) packet;
    iph->ihl = 5;                                               // Header length
    iph->version = 4;                                           // IPv4
    iph->tos = 0;                                               // Type of service
    iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr)); // Total length
    iph->id = htons(54321);                                     // Identification number
    iph->frag_off = 0;                                          // Fragment offset
    iph->ttl = ttl;                                             // Time to live
    iph->protocol = IPPROTO_TCP;                                // Protocol type
    iph->saddr = inet_addr(client_ip);                          // Source IP
    iph->daddr = inet_addr(server_ip);                          // Destination IP

    // Set up the TCP header fields
    struct tcphdr *tcph = (struct tcphdr *) (packet + sizeof(struct iphdr));
    tcph->source = htons(12345);                                // Source port
    tcph->dest = htons(dest_port);                              // Destination port
    tcph->seq = is_head ? htonl(1) : htonl(2);                  // Sequence number
    tcph->ack_seq = 0;                                          // Acknowledgement number
    tcph->doff = 5;                                             // Data offset
    tcph->syn = 1;                                              // SYN flag
    tcph->fin = !is_head;                                       // FIN flag, inverted based on head/tail status
    tcph->window = htons(64240);                                // Window size

    // Calculate the checksum for the IP header and set it
    iph->check = checksum((const char *)packet, iph->ihl * 4);

    // Construct pseudo header for TCP checksum calculation
    struct pseudo_header psh;
    psh.source_address = inet_addr(client_ip);
    psh.dest_address = inet_addr(server_ip);
    psh.placeholder = 0;
    psh.protocol = IPPROTO_TCP;
    psh.tcp_length = htons(sizeof(struct tcphdr));

    // Create the pseudogram by concatenating pseudo header and TCP header
    char pseudogram[sizeof(struct pseudo_header) + sizeof(struct tcphdr)];
    memcpy(pseudogram, &psh, sizeof(struct pseudo_header));
    memcpy(pseudogram + sizeof(struct pseudo_header), tcph, sizeof(struct tcphdr));

    // Calculate and set the TCP checksum
    tcph->check = checksum(pseudogram, sizeof(pseudogram));

    // Configure the destination address for the packet
    struct sockaddr_in dest_addr;
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(dest_port);
    dest_addr.sin_addr.s_addr = inet_addr(server_ip);

    // Send the packet
    if (sendto(sockfd, packet, ntohs(iph->tot_len), 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr)) < 0) {
        perror("Failed to send SYN packet");
        close(sockfd);
        exit(1);
    }

    // Close the socket and log success
    close(sockfd);
    printf("%s SYN packet sent successfully.\n", is_head ? "Head" : "Tail");
}

/**
 * Listens for RST packets sent in response to SYN packets and calculates the time difference between
 * the arrivals of the first two RST packets. This function is used to determine network characteristics
 * like compression detection by analyzing how quickly RST packets are sent back by the server.
 *
 * @return long The time difference in milliseconds between the first and second RST packets received.
 *              Returns -1 if a timeout or error occurs before receiving two RST packets.
 */
long listen_for_rst_packets() {
    char buffer[65535];  // Large buffer to capture any incoming TCP packet entirely
    struct sockaddr_in saddr;
    socklen_t saddr_size = sizeof(saddr);
    struct timeval start_time, end_time;
    int rst_count = 0;  // Counter for RST packets received

    // Create a raw socket for capturing TCP packets
    int raw_sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (raw_sock < 0) {
        perror("Failed to create raw socket for RST listening");
        exit(1);
    }

    // Set a 5-second timeout for the recvfrom call
    struct timeval timeout;
    timeout.tv_sec = 5;
    timeout.tv_usec = 0;
    if (setsockopt(raw_sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) {
        perror("setsockopt - SO_RCVTIMEO");
        close(raw_sock);
        exit(1);
    }

    // Continuously receive packets until two RST packets have been captured
    while (rst_count < 2) {
        int len = recvfrom(raw_sock, buffer, sizeof(buffer), 0, (struct sockaddr *)&saddr, &saddr_size);
        if (len < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                perror("Timeout in receiving RST packets");
            } else {
                perror("Error in receiving RST packets");
            }
            close(raw_sock);
            return -1; // Indicate a timeout or error
        }

        // Parse the IP header to find the start of the TCP header
        struct iphdr *iph = (struct iphdr*)buffer;
        struct tcphdr *tcph = (struct tcphdr*)(buffer + iph->ihl * 4);

        // Check for the RST flag in the TCP header
        if (tcph->rst) {
            struct timeval pkt_time;
            gettimeofday(&pkt_time, NULL);
            if (rst_count == 0) {
                start_time = pkt_time;
                printf("First RST received.\n");
                rst_count++;
            } else if (rst_count == 1) {
                end_time = pkt_time;
                printf("Second RST received.\n");
                rst_count++;
            }
        }
    }

    close(raw_sock);

    // Compute and return the time difference between the two RST packets
    long time_diff = (end_time.tv_sec - start_time.tv_sec) * 1000 + (end_time.tv_usec - start_time.tv_usec) / 1000;
    return time_diff;
}

/**
 * Main entry point for the compression detection application.
 * This program uses raw sockets to send and receive packets to detect network compression.
 *
 * Usage: <executable> <config_file>
 * Example: ./compDetect config.json
 * 
 * @param argc Number of command-line arguments.
 * @param argv Array of command-line arguments.
 * @return int Returns 0 on successful execution, 1 on errors.
 */
int main(int argc, char *argv[]) {
    // Check for correct usage
    if (argc != 2) {
        printf("Usage: %s <config_file>\n", argv[0]);
        return 1;
    }

    char *info = NULL;
    // Load and parse the configuration file
    cJSON *config = getConfigFromFile(argv[1], &info);
    if (!config) {
        fprintf(stderr, "Failed to load or parse configuration.\n");
        if (info) free(info);
        return 1;
    }

    // Extract configuration details
    char *client_ip_str = cJSON_GetObjectItemCaseSensitive(config, "Client_IP")->valuestring;
    char *server_ip_str = cJSON_GetObjectItemCaseSensitive(config, "Server_IP")->valuestring;
    int source_port_udp = cJSON_GetObjectItemCaseSensitive(config, "Source_Port_UDP")->valueint;
    int dest_port_udp = cJSON_GetObjectItemCaseSensitive(config, "Destination_Port_UDP")->valueint;
    int udp_payload_size = cJSON_GetObjectItemCaseSensitive(config, "UDP_Payload_Size")->valueint;
    int udp_packet_count = cJSON_GetObjectItemCaseSensitive(config, "UDP_Packet_Count")->valueint;
    int udp_packet_ttl = cJSON_GetObjectItemCaseSensitive(config, "UDP_Packet_TTL")->valueint;
    int dest_port_tcp_syn_head = cJSON_GetObjectItemCaseSensitive(config, "Destination_Port_TCP_SYN_Head")->valueint;
    int dest_port_tcp_syn_tail = cJSON_GetObjectItemCaseSensitive(config, "Destination_Port_TCP_SYN_Tail")->valueint;

    printf("Starting transmission...\n");

    // Send head SYN for the low entropy packet train
    send_syn_packet(client_ip_str, server_ip_str, dest_port_tcp_syn_head, udp_packet_ttl, true);

    // Send low entropy UDP packets
    send_udp_packets(client_ip_str, server_ip_str, source_port_udp, dest_port_udp, udp_payload_size, udp_packet_count, false, udp_packet_ttl);

    // Send tail SYN for the low entropy packet train
    send_syn_packet(client_ip_str, server_ip_str, dest_port_tcp_syn_tail, udp_packet_ttl, false);

    // Wait for a brief moment between trains
    sleep(15);  // Inter-measurement delay

    // Send head SYN for the high entropy packet train
    send_syn_packet(client_ip_str, server_ip_str, dest_port_tcp_syn_head, udp_packet_ttl, true);

    // Send high entropy UDP packets
    send_udp_packets(client_ip_str, server_ip_str, source_port_udp, dest_port_udp, udp_payload_size, udp_packet_count, true, udp_packet_ttl);

    // Send tail SYN for the high entropy packet train
    send_syn_packet(client_ip_str, server_ip_str, dest_port_tcp_syn_tail, udp_packet_ttl, false);

    // Listen for RST packets and calculate the time difference
    long rst_time_diff = listen_for_rst_packets();
    printf("RST packet time difference: %ld ms\n", rst_time_diff);

    // Evaluate the presence of compression based on the time difference
    if (rst_time_diff > 100) {
        printf("Compression detected.\n");
    } else {
        printf("No compression was detected.\n");
    }

    // Cleanup
    cJSON_Delete(config);
    free(info);

    return 0;
}
