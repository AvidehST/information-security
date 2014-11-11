#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include "settings.h"
#include "connection.h"
#include "utils.h"

int main(int argc, char *argv[])
{
    int serverSocket = 0, clientSocket = 0;
    
    // Setup server socket
    printf("Starting server ...\n");
    serverSocket = setupServerSocket(SERVER_PORT);


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

        // Challenge Response
        printf("Perform challenge response ...\n");
        char *buffer = NULL;

        printf("Receiving ID of the client ...\n");
        if (receiveString(clientSocket, &buffer) <= 0)
        {
            return -1;
        }

        printf("Send random number (challenge string) to the client ...\n");
        char *randomString = generateRandomString(256);
        sendString(clientSocket, randomString);

        printf("Receive result of challenge and compare with own result ...\n");
        if (receiveString(clientSocket, &buffer) <= 0)
        {
            return -1;
        }

        char *challengeResult = calculateHMAC(randomString);

        if (strcmp(buffer, challengeResult) == 0)
        {
            printf("Bob send a valid result of the challenge!\n");
        }
        else
        {
            printf("Bob send an invalid result of the challenge!\n");
        }

        printf("Done ...\n");
        free(buffer);
     }

     return 0;
}
