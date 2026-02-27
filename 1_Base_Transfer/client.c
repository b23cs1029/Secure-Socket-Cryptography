
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#define PORT 8080
#define BUFFER_SIZE 1024

int main() {
    int sock = 0;
    struct sockaddr_in serv_addr;
    char buffer[BUFFER_SIZE];

    // 1. Create the socket
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Socket creation error");
        return -1;
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);

    // 2. Set the Server IP Address
    // CHANGE THIS TO YOUR UBUNTU VM'S IP ADDRESS!
    if (inet_pton(AF_INET, "10.0.2.4", &serv_addr.sin_addr) <= 0) {
        perror("Invalid address or Address not supported");
        return -1;
    }

    // 3. Connect to the server
    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("Connection Failed");
        return -1;
    }
    printf("Connected to server!\n");

    // 4. Open the file to send in binary read mode
    FILE *fp = fopen("file.txt", "rb");
    if (fp == NULL) {
        perror("Error opening file. Does 'file.txt' exist?");
        return 1;
    }

    int bytes_read;

    // 5. Read the file in chunks and send over the socket
    while ((bytes_read = fread(buffer, 1, BUFFER_SIZE, fp)) > 0) {
        if (send(sock, buffer, bytes_read, 0) < 0) {
            perror("Failed to send data");
            break;
        }
    }

    printf("File sent successfully!\n");

    // 6. Clean up
    fclose(fp);

    // Closing the socket sends an EOF signal to the server, telling it to stop receiving
    close(sock);

    return 0;
}
