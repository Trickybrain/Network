#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <cjson/cJSON.h>
#include <stdbool.h>

/**
 * Retrieves and parses configuration information from a specified file.
 *
 * @param configFilePath Path to the configuration file.
 * @param configContent Pointer to store the loaded file content.
 * @return A cJSON object containing the parsed configuration.
 */
cJSON* getConfig(const char *configFilePath, char **configContent) {
    // Display which configuration file is being read
    printf("Reading configuration from file: %s\n", configFilePath);

    // Attempt to open the configuration file
    FILE *file = fopen(configFilePath, "r");
    if (!file) {
        perror("Failed to open the config file");  // Log error if file opening fails
        exit(1);
    }

    // Read file into buffer
    char buffer[1024];
    int length = fread(buffer, 1, sizeof(buffer) - 1, file);
    buffer[length] = '\0';  // Null-terminate the buffer
    fclose(file);  // Close the file after reading

    // Allocate memory for configuration content
    *configContent = malloc(length + 1);
    if (!*configContent) {
        perror("Failed to allocate memory for configuration data");  // Log error if memory allocation fails
        exit(1);
    }
    strcpy(*configContent, buffer);  // Copy file content into allocated memory

    // Parse JSON content from the configuration data
    cJSON *config = cJSON_Parse(*configContent);
    if (!config) {
        perror("Error parsing JSON from configuration file");  // Log parsing errors
        free(*configContent);  // Free allocated memory on error
        exit(1);
    }
    
    printf("Configuration parsed successfully.\n");  // Confirm successful parsing
    return config;  // Return the parsed JSON object
}

/**
 * Establishes a TCP connection and transmits configuration data to a server.
 *
 * @param serverIp IP address of the server.
 * @param port Port number on the server to connect to.
 * @param info Configuration data to send.
 * @param dataLength Length of the configuration data.
 */
void sendConfigToServer(const char *serverIp, int port, const char *info, int dataLength) {
    printf("Connecting to server %s on port %d\n", serverIp, port);

    struct sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(port);
    serverAddr.sin_addr.s_addr = inet_addr(serverIp);

    int clientSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (clientSocket < 0) {
        perror("Failed to create TCP socket");
        exit(1);
    }
    
    if (connect(clientSocket, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) < 0) {
        perror("Failed to connect to server");
        close(clientSocket);
        exit(1);
    }
    
    printf("Connected to server. Sending configuration data...\n");
    if (send(clientSocket, info, dataLength, 0) < 0) {
        perror("Failed to send configuration data");
        close(clientSocket);
        exit(1);
    }

    printf("Configuration data sent successfully.\n");
    close(clientSocket);
    sleep(1);
}

/**
 * Sends UDP packets to a server with specified properties.
 *
 * @param serverIp IP address of the server to receive the packets.
 * @param sourcePort The source port number for UDP packets.
 * @param destPort The destination port number on the server.
 * @param packetSize The size of the payload in each UDP packet.
 * @param packetCount The number of packets to send.
 * @param isRandom Whether the payload should contain random data.
 */
void sendUdpPackets(const char* serverIp, int sourcePort, int destPort, int packetSize, int packetCount, bool isRandom) {
    printf("Setting up UDP socket to send packets to %s:%d\n", serverIp, destPort);

    int udpSocket = socket(AF_INET, SOCK_DGRAM, 0);
    if (udpSocket < 0) {
        perror("Error creating UDP socket");
        exit(1);
    }

    // Set up the client's address structure
    struct sockaddr_in clientAddr;
    clientAddr.sin_family = AF_INET;
    clientAddr.sin_port = htons(sourcePort);
    clientAddr.sin_addr.s_addr = INADDR_ANY;

    // Bind the socket to the client's address and port
    if (bind(udpSocket, (struct sockaddr*)&clientAddr, sizeof(clientAddr)) < 0) {
        perror("Error binding UDP socket to local address");
        close(udpSocket);
        exit(1);
    }

    struct sockaddr_in servAddr;
    servAddr.sin_family = AF_INET;
    servAddr.sin_port = htons(destPort);
    servAddr.sin_addr.s_addr = inet_addr(serverIp);

    int val = IP_PMTUDISC_DO;
    if (setsockopt(udpSocket, IPPROTO_IP, IP_MTU_DISCOVER, &val, sizeof(val)) < 0) {
        perror("Error setting IP_MTU_DISCOVER option on UDP socket");
        exit(1);
    }

    // Generate random data
    char buffer[packetSize];
    FILE *urandom = urandom = fopen("/dev/urandom", "r");
    if (!urandom) {
        perror("Error opening /dev/urandom");
        close(udpSocket);
        exit(1);
    }

    // Send number of packets
    for (int i = 0; i < packetCount; i++) {
        memset(buffer, 0, packetSize);
        
        // Setting Packet ID
        *((unsigned short *)buffer) = htons(i);
        
        // Set payload with random data
        if (isRandom) {
            fread(buffer + 2, 1, packetSize - 2, urandom);
        }

        // Send the packet to the server
        if (sendto(udpSocket, buffer, packetSize, 0, (struct sockaddr*)&servAddr, sizeof(servAddr)) < 0) {
            perror("Error sending UDP packet");
            fclose(urandom);
            close(udpSocket);
            exit(1);
        }
    }

    fclose(urandom);
    close(udpSocket);
    printf("All UDP packets successfully sent.\n");
}

/**
 * Main function of the application.
 * It loads configuration, extracts necessary details, and sends UDP packets as per specifications.
 *
 * @param argc Number of command line arguments.
 * @param argv Array of command line arguments.
 * @return Exit status of the application.
 */
int main(int argc, char *argv[]) {
    // Check command line arguments.
    if (argc != 2) {
        printf("ERROR Usage: ./client <config_file>\n");
        return 1;
    }

    // Load and parse the configuration file.
    char *configContent = NULL;
    cJSON *config = getConfig(argv[1], &configContent);

    if (!config) {
        fprintf(stderr, "Failed to load or parse configuration.\n");
        if (configContent) free(configContent);
        return 1;
    }

    // Extract necessary details from configuration for network communication.
    char *serverIp = cJSON_GetObjectItemCaseSensitive(config, "Server_IP")->valuestring;
    int TCP_pre = cJSON_GetObjectItemCaseSensitive(config, "Port_TCP_Pre_Probing")->valueint;
    int TCP_post = cJSON_GetObjectItemCaseSensitive(config, "Port_TCP_Post_Probing")->valueint;

    // Initiate a TCP connection and send configuration data to the server.
    sendConfigToServer(serverIp, TCP_pre, configContent, strlen(configContent));

    int sourcePortUdp = cJSON_GetObjectItemCaseSensitive(config, "Source_Port_UDP")->valueint;
    int destPortUdp = cJSON_GetObjectItemCaseSensitive(config, "Destination_Port_UDP")->valueint;
    int udpPayloadSize = cJSON_GetObjectItemCaseSensitive(config, "UDP_Payload_Size")->valueint;
    int udpPacketCount = cJSON_GetObjectItemCaseSensitive(config, "UDP_Packet_Count")->valueint;
    int interMeasurementTime = cJSON_GetObjectItemCaseSensitive(config, "Inter_Measurement_Time")->valueint;

    // Execute probing phase with low entropy packets.
    sendUdpPackets(serverIp, sourcePortUdp, destPortUdp, udpPayloadSize, udpPacketCount, false);

    // Wait a specified time before sending high entropy packets.
    sleep(interMeasurementTime);
    
    // Execute probing phase with high entropy packets.
    sendUdpPackets(serverIp, sourcePortUdp, destPortUdp, udpPayloadSize, udpPacketCount, true);

    // Configure TCP socket for receiving compression detection results.
    struct sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(TCP_post);
    serverAddr.sin_addr.s_addr = inet_addr(serverIp);

    // Creating TCP socket
    int clientSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (clientSocket < 0) {
        perror("Error creating socket");
        return 1;
    }

    // Connect to the server for receiving results.
    if (connect(clientSocket, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) < 0) {
        perror("Error connecting to server");
        close(clientSocket);
        return 1;
    }

    // Receive the server's response.
    char compression[256];
    int bytes = recv(clientSocket, compression, sizeof(compression) - 1, 0);
    if (bytes < 0) {
        perror("Error receiving data from server");
        close(clientSocket);
        return 1;
    }

    compression[bytes] = '\0';
    printf("%s", compression);

    // Cleanup resources.
    close(clientSocket);
    cJSON_Delete(config);
    free(configContent);

    return 0;
}
