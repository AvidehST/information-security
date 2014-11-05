#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <openssl/bn.h>
#include <openssl/dh.h>
#include <openssl/bio.h>
#include "settings.h"
#include "utils.h"

int setupServerSocket()
{
    int serverSocket = 0;

    if ((serverSocket = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        printf("ERROR: Failed to create socket! Error: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }
    
    struct sockaddr_in serverAddress;
    memset(&serverAddress, '0', sizeof(serverAddress));

    serverAddress.sin_family = AF_INET;
    serverAddress.sin_addr.s_addr = htonl(INADDR_ANY);
    serverAddress.sin_port = htons(SERVER_PORT);

    if (bind(serverSocket, (struct sockaddr*)&serverAddress, sizeof(serverAddress)) == -1) {
        printf("ERROR: Failed to bind socket! Error: %s\n", strerror(errno));
        shutdown(serverSocket, SHUT_RDWR);
        close(serverSocket);
        exit(EXIT_FAILURE);
    }
    if (listen(serverSocket, 10) == -1) {
        printf("ERROR: Failed to set socket to listen mode! Error: %s\n", strerror(errno));
        shutdown(serverSocket, SHUT_RDWR);
        close(serverSocket);
        exit(EXIT_FAILURE);
    }

    return serverSocket;
}

int performServerSideHandshake(int clientSocket)
{
    char *buffer = NULL;

    if (receiveString(clientSocket, &buffer) <= 0)
    {
        return -1;
    }

    if (strcmp(buffer, HANDSHAKE_INIT) != 0)
    {
        return -1;
    }
    
    sendString(clientSocket, HANDSHAKE_ACK);

    return 0;
}

int main(int argc, char *argv[])
{
    int serverSocket = 0, clientSocket = 0;
    
    // Setup server socket
    printf("Starting server ...\n");
    serverSocket = setupServerSocket();

    // Create buffers
    char sendBuffer[1025];
    char recvBuffer[1025];

    memset(sendBuffer, '0', sizeof(sendBuffer));


    while(1)
    {
        // Accept client connections
        printf("Waiting for client ...\n");

        if ((clientSocket = accept(serverSocket, (struct sockaddr*)NULL, NULL)) == -1) {
            printf("ERROR: Failed to accept client connection! Error: %s\n", strerror(errno));
            continue;
        }

        // Handshake
        printf("Perform handshake ...\n");

        if (performServerSideHandshake(clientSocket) == -1)
        {
            printf("ERROR: Handshake with the client failed!");
            continue;
        }

        // Diffie-Helmann
        unsigned char *sharedKey;

        if (performServerSideDiffieHelmann(clientSocket, &sharedKey) == -1)
        {
            printf("ERROR: Diffie-Helmann protocol failed!");
            return EXIT_FAILURE;
        }
        
        // Dump the shared key
        printf("Shared secret key: %s\n", sharedKey);
        
        free(sharedKey);
     }

     return 0;
}
