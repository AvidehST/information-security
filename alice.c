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

int performServerHandshake(int clientSocket, char *recvBuffer)
{

    read(clientSocket, recvBuffer, sizeof(recvBuffer)-1);

    if(strcmp(recvBuffer, HANDSHAKE_INIT))
    {
        return -1;
    }
    
    write(clientSocket, HANDSHAKE_ACK, sizeof(HANDSHAKE_ACK));
    
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
        if(performServerHandshake(clientSocket, recvBuffer) == -1)
        {
            printf("ERROR: Handshake with the client failed!");
            continue;
        }

           
        DH *dh = DH_new();
        unsigned char *dh_secret = "";
        BIGNUM *clientPublicKey = BN_new();
        memset(&recvBuffer[0], 0, sizeof(recvBuffer));
        read(clientSocket, recvBuffer, sizeof(recvBuffer)-1);
        BN_dec2bn(&dh->p, recvBuffer);

        memset(&recvBuffer[0], 0, sizeof(recvBuffer));
        read(clientSocket, recvBuffer, sizeof(recvBuffer)-1);
        BN_dec2bn(&dh->g, recvBuffer);
        
        memset(&recvBuffer[0], 0, sizeof(recvBuffer));
        read(clientSocket, recvBuffer, sizeof(recvBuffer)-1);
        BN_dec2bn(&clientPublicKey, recvBuffer);
        
        if(!DH_generate_key(dh)){
            printf("server key generation error\n");
        }
        memset(&sendBuffer[0], 0, sizeof(sendBuffer));
        snprintf(sendBuffer, sizeof(sendBuffer), "%s", BN_bn2dec(dh->pub_key));
        write(clientSocket, sendBuffer, sizeof(sendBuffer));
        
        
        dh_secret = OPENSSL_malloc(sizeof(unsigned char) * DH_size(dh));
        DH_compute_key(dh_secret, clientPublicKey, dh);
        
        //printf("Server: shared secret key = %s\n", dh_secret);
        BIO_dump_fp(stdout, dh_secret, DH_size(dh));
        
        DH_free(dh);
        BN_free(clientPublicKey);
        free(dh_secret);
     }

     return 0;
}
