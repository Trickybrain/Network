# End-to-End Detection of Network Compression

## Description
This project implements two network applications designed to detect network compression on a network path. The primary goal is to identify the presence of compression and locate the compression link. There are two main applications:

1. **Client/Server Application**: Operates in a cooperative environment where both the client and server participate in the detection process.
2. **Standalone Application**: Operates in an uncooperative environment and does not require any special software to be installed on the host being tested.

## Usage Instructions
To use these applications, follow the instructions below based on the desired operation mode:

##Build Instructions
-Compile the server:
gcc -o server server.c -I/usr/include/cjson -lcjson
-Compile the client:
gcc -o client client.c -I/usr/include/cjson -lcjson
-Compile the standalone detection program:
gcc -o compDetect compDetect.c -I/usr/include/cjson -lcjson

### Client
./client config.json
- Run this command on the client system with a configuration file specifying the operation details.

### Server
./server 7777
- Execute this command on the server system. The command-line argument specifies the TCP port number for communication.

### Standalone Mode
./compdetect config.json
- This command can be run on any system to initiate the standalone detection application.

## Features
### Compression Detection Client/Server Application
- Sends two sets of `n` UDP packets, known as packet trains, back-to-back.
- The first packet train contains packets filled with zeros, while the second contains random bits.
- Compression is detected if the arrival time difference between the first and last packets of the two trains exceeds 100 ms.

### Standalone Application
- Sends a head SYN packet followed by a train of `n` UDP packets and a tail SYN packet to inactive or closed ports.
- Listens for RST packets triggered by SYN packets to closed ports.
- Reports "Compression detected" if the difference in arrival times of the RST packets indicates compression; otherwise, it reports "No compression detected."

## Contact Information
- **Developer**: Edwin Ye
- **Email**: edwinyedeveloper@gmail.com

Feel free to contact me for any questions or feedback regarding this project.