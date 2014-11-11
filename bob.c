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
#include "settings.h"
#include "connection.h"
#include "utils.h"



int main(int argc, char *argv[])
{
    int serverSocket = 0;
    
    // Setup connection to the server
    printf("Starting client ...\n");
    serverSocket = setupSocketToServer(SERVER_PORT);
    printf("Client started and connected to the server ...\n");

    // Handshake
    printf("Perform handshake ...\n");

    if (performClientSideHandshake(serverSocket) == -1)
    {
        printf("ERROR: Handshake with the server failed!");
        return EXIT_FAILURE;
    }

    // Challenge Response
    printf("Perform challenge response ...\n");
    char *buffer = NULL;

    printf("Send ID ...\n");
    sendString(serverSocket, "BOB");

    printf("Receive a random number (challenge string) ...\n");
    if (receiveString(serverSocket, &buffer) <= 0)
    {
        return -1;
    }

    printf("Perfom challenge and send result ...\n");
    char *challengeResult = calculateHMAC(buffer);
    sendString(serverSocket, challengeResult);

    printf("Done ...\n");
    free(buffer);

    return 0;
}
