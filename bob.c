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
    serverSocket = setupSocketToServer(SERVER_PORT_FAKED);
    printf("Client started and connected to the server ...\n");

    // Handshake
    printf("Perform handshake ...\n");

    if (performClientSideHandshake(serverSocket) == -1)
    {
        printf("ERROR: Handshake with the server failed!");
        return EXIT_FAILURE;
    }

    // Diffie-Hellman
    unsigned char *sharedKey;
    int sharedKeySize;

    if ((sharedKeySize = performClientSideDiffieHellman(serverSocket, &sharedKey)) == -1)
    {
        printf("ERROR: Diffie-Hellman protocol failed!");
        return EXIT_FAILURE;
    }


    // Dump the shared key
    printf("Shared secret key: %s\n", sharedKey);
    
    
    free(sharedKey);

    return 0;
}
