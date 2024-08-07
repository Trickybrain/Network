#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <cjson/cJSON.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/time.h>

/**
 * Initializes a TCP server that listens on a specified port and receives configuration data from a client.
 */
void tcpServerListen(int port, char *buffer, size_t bufferSize) {
    // Creating a socket for TCP communication
    int serverSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSocket < 0) {
        perror("Failed to create socket");
        exit(1);
    }

    // Setting server address and binding the socket
    struct sockaddr_in serverAddr, clientAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(port);
    serverAddr.sin_addr.s_addr = INADDR_ANY;

    if (bind(serverSocket, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) < 0) {
        perror("Failed to bind socket");
        close(serverSocket);
        exit(1);
    }

    // Listening for client connections
    if (listen(serverSocket, 5) < 0) {
        perror("Failed to listen on socket");
        close(serverSocket);
        exit(1);
    }
    printf("Server is listening on port %d...\n", port);

    // Accepting connections
    socklen_t clientAddrSize = sizeof(clientAddr);
    int clientSocket = accept(serverSocket, (struct sockaddr*)&clientAddr, &clientAddrSize);
    if (clientSocket < 0) {
        perror("Failed to accept connection");
        close(serverSocket);
        exit(1);
    }
    printf("Connection accepted from %s\n", inet_ntoa(clientAddr.sin_addr));

    // Receiving data from client
    int bytesReceived = recv(clientSocket, buffer, bufferSize - 1, 0);
    if (bytesReceived < 0) {
        perror("Failed to receive data");
    } else {
        buffer[bytesReceived] = '\0';
        printf("Received data: %s\n", buffer);
    }

    // Cleanup
    close(clientSocket);
    close(serverSocket);
}

/**
 * Listens for UDP packets and logs the arrival times of the first, last low entropy, and last high entropy packets.
 */
void udpServerListen(struct sockaddr_in serverAddr, int totalUdpPacketCount, char *buffer, size_t bufferSize, struct timeval *firstTime, struct timeval *lastLowTime, struct timeval *lastHighTime) {
    // Creating UDP socket
    int udpSocket = socket(AF_INET, SOCK_DGRAM, 0);
    if (udpSocket < 0) {
        perror("Failed to create UDP socket");
        exit(1);
    }

    // Binding UDP socket
    if (bind(udpSocket, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) < 0) {
        perror("Failed to bind UDP socket");
        close(udpSocket);
        exit(1);
    }

    // Setting timeout for receiving packets
    struct timeval timeout = {10, 0};
    if (setsockopt(udpSocket, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) {
        perror("Failed to set socket timeout");
        close(udpSocket);
        exit(1);
    }

    printf("UDP server is ready to receive packets...\n");

    // Receiving packets and recording times
    struct timeval currentTime;
    socklen_t clientAddrSize = sizeof(struct sockaddr_in);
    int receivedPackets = 0;

    while (receivedPackets < totalUdpPacketCount) {
        int len = recvfrom(udpSocket, buffer, bufferSize - 1, 0, (struct sockaddr*)&serverAddr, &clientAddrSize);
        if (len < 0) {
            printf("Timeout reached or error receiving packets\n");
            break;
        }

        receivedPackets++;
        gettimeofday(&currentTime, NULL);

        if (receivedPackets == 1) *firstTime = currentTime;
        if (receivedPackets == totalUdpPacketCount / 2) *lastLowTime = currentTime;
        if (receivedPackets == totalUdpPacketCount) *lastHighTime = currentTime;
    }

    printf("Received all packets, total: %d\n", receivedPackets);
    close(udpSocket);
}

/**
 * Responds to the client with the result of compression detection after probing.
 */
void postProbingTcpResponse(struct sockaddr_in serverAddr, long difference) {
    // Creating TCP socket for response
    int serverSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSocket < 0) {
        perror("Failed to create socket");
        exit(1);
    }

    int opt = 1;
    if (setsockopt(serverSocket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        perror("Failed to set socket options");
        close(serverSocket);
        exit(1);
    }

    if (bind(serverSocket, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) < 0) {
        perror("Failed to bind socket");
        close(serverSocket);
        exit(1);
    }

    if (listen(serverSocket, 5) < 0) {
        perror("Failed to listen on socket");
        close(serverSocket);
        exit(1);
    }

    // Accepting client connection for response
    socklen_t clientAddrSize = sizeof(struct sockaddr_in);
    int clientSocket = accept(serverSocket, (struct sockaddr*)&serverAddr, &clientAddrSize);
    if (clientSocket < 0) {
        perror("Failed to accept connection");
        close(serverSocket);
        exit(1);
    }

    // Sending compression result
    if (difference > 100) {
        send(clientSocket, "Compression detected\n", strlen("Compression detected\n"), 0);
        printf("Compression detected, message sent.\n");
    } else {
        send(clientSocket, "No compression was detected\n", strlen("No compression was detected\n"), 0);
        printf("No compression detected, message sent.\n");
    }

    close(clientSocket);
    close(serverSocket);
}

/**
 * The main function to start the server, listen for incoming connections,
 * receive data, perform network probing, and send results back to the client.
 */
int main(int argc, char *argv[]) {
    // Check command-line arguments for proper usage
    if (argc != 2) {
        printf("ERROR USAGE: ./server <port>\n");
        exit(1);
    }

    // Convert command-line string argument to integer for the port
    int port = atoi(argv[1]);
    printf("Server starting on port %d...\n", port);

    // Buffer to hold data received over TCP
    char buffer[1024];

    // Listen on the specified TCP port and receive configuration data
    tcpServerListen(port, buffer, sizeof(buffer));

    // Parse the JSON configuration data received from client
    cJSON *configJson = cJSON_Parse(buffer);
    if (configJson == NULL) {
        perror("Failed to parse configuration");
        exit(1);
    }

    // Retrieve number of UDP packets to send from the JSON configuration
    int udpPacketCount = cJSON_GetObjectItemCaseSensitive(configJson, "UDP_Packet_Count")->valueint;
    int totalUdpPacketCount = 2 * udpPacketCount;  // Total includes both low and high entropy packets

    // Retrieve destination port for UDP from configuration
    int destPortUdp = cJSON_GetObjectItemCaseSensitive(configJson, "Destination_Port_UDP")->valueint;

    // Configure the server's address for UDP listening
    struct sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(destPortUdp);
    serverAddr.sin_addr.s_addr = INADDR_ANY;

    // Variables to store the arrival times of the first, last low, and last high entropy packets
    struct timeval firstTime, lastLowTime, lastHighTime;

    // Listen for UDP packets and track the arrival times
    udpServerListen(serverAddr, totalUdpPacketCount, buffer, sizeof(buffer), &firstTime, &lastLowTime, &lastHighTime);

    // Calculate time differences between the first and last received packets for low and high entropy data
    long deltaTL = (lastLowTime.tv_sec * 1000 + lastLowTime.tv_usec / 1000) - (firstTime.tv_sec * 1000 + firstTime.tv_usec / 1000);
    long deltaTH = (lastHighTime.tv_sec * 1000 + lastHighTime.tv_usec / 1000) - (firstTime.tv_sec * 1000 + firstTime.tv_usec / 1000);
    long difference = deltaTH - deltaTL;

    // Get TCP port for post probing phase from configuration and set it
    int portPostProbing = cJSON_GetObjectItemCaseSensitive(configJson, "Port_TCP_Post_Probing")->valueint;
    serverAddr.sin_port = htons(portPostProbing);

    // Send the results of the probing to the client
    postProbingTcpResponse(serverAddr, difference);

    // Clean up JSON object
    cJSON_Delete(configJson);
    printf("Server operation completed.\n");
    
    return 0;
}
