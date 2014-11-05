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
    int fakedServerSocket = 0, clientSocket = 0;
    
    // Setup server socket
    printf("Starting server ...\n");
    fakedServerSocket = setupServerSocket(SERVER_PORT_FAKED);


    while(1)
    {
        // Accept client connections
        printf("Waiting for client ...\n");

        if ((clientSocket = accept(fakedServerSocket, (struct sockaddr*)NULL, NULL)) == -1) {
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

        // Diffie-Hellman
        unsigned char *sharedKeyWithClient;
        int sharedKeyWithClientSize;

        if ((sharedKeyWithClientSize = performServerSideDiffieHellman(clientSocket, &sharedKeyWithClient)) == -1)
        {
            printf("ERROR: Diffie-Hellman protocol failed!");
            return EXIT_FAILURE;
        }


        // Connect to real server
        int realServerSocket = 0;
        
        // Setup connection to the server
        printf("Connect to real server ...\n");
        realServerSocket = setupSocketToServer(SERVER_PORT);

        // Handshake
        printf("Perform handshake with real server ...\n");

        if (performClientSideHandshake(realServerSocket) == -1)
        {
            printf("ERROR: Handshake with the real server failed!");
            return EXIT_FAILURE;
        }

        // Diffie-Hellman
        unsigned char *sharedKeyWithServer;
        int sharedKeyWithServerSize;

        if ((sharedKeyWithServerSize = performClientSideDiffieHellman(realServerSocket, &sharedKeyWithServer)) == -1)
        {
            printf("ERROR: Diffie-Hellman protocol failed!");
            return EXIT_FAILURE;
        }


        // Dump the shared keys
        printf("Shared secret key with client: %s\n", sharedKeyWithClient);
        printf("Shared secret key with server: %s\n", sharedKeyWithServer);
        
        
        free(sharedKeyWithServer);
        free(sharedKeyWithClient);
     }

     return 0;
}
