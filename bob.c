#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <openssl/bn.h>
#include <openssl/dh.h>
#include "settings.h"
#include "utils.h"

int setupSocketToServer()
{
    int serverSocket;

    if ((serverSocket = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        printf("ERROR: Failed to create socket! Error: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }

    struct sockaddr_in serverAddress; 
    memset(&serverAddress, '0', sizeof(serverAddress)); 

    serverAddress.sin_family = AF_INET;
    serverAddress.sin_port = htons(SERVER_PORT); 

    if (inet_pton(AF_INET, "127.0.0.1", &serverAddress.sin_addr) == -1)
    {
        printf("ERROR: Failed to convert the IP address to binary form! Error: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    } 

    if (connect(serverSocket, (struct sockaddr *)&serverAddress, sizeof(serverAddress)) < 0)
    {
        printf("ERROR: Failed to connect to server at port %d\"! Error: %s\n", SERVER_PORT, strerror(errno));
        shutdown(serverSocket, SHUT_RDWR);
        close(serverSocket);
        exit(EXIT_FAILURE);
    }

    return serverSocket;
}

int performClientSideHandshake(int serverSocket)
{
    char *buffer = NULL;

    sendString(serverSocket, HANDSHAKE_INIT);

    if (receiveString(serverSocket, &buffer) <= 0)
    {
        return -1;
    }

    if (strcmp(buffer, HANDSHAKE_ACK) != 0)
    {
        return -1;
    }

    return 0;
}

int main(int argc, char *argv[])
{
    int serverSocket = 0;
    
    // Setup connection to the server
    printf("Starting client ...\n");
    serverSocket = setupSocketToServer();
    printf("Client started and connected to the server ...\n");

    // Create buffers
    char sendBuffer[BUFFER_SIZE];
    char recvBuffer[BUFFER_SIZE];

    memset(recvBuffer, '0', sizeof(recvBuffer));
    
    // Handshake
    printf("Perform handshake ...\n");

    if (performClientSideHandshake(serverSocket) == -1)
    {
        printf("ERROR: Handshake with the server failed!");
        return EXIT_FAILURE;
    }

    // Diffie-Helmann
    unsigned char *sharedKey;

    if (performClientSideDiffieHelmann(serverSocket, &sharedKey) == -1)
    {
        printf("ERROR: Diffie-Helmann protocol failed!");
        return EXIT_FAILURE;
    }


    // Dump the shared key
    printf("Shared secret key: %s\n", sharedKey);
    
    
    free(sharedKey);

    return 0;
}
