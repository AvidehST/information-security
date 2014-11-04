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

    if(inet_pton(AF_INET, "127.0.0.1", &serverAddress.sin_addr) == -1)
    {
        printf("ERROR: Failed to convert the IP address to binary form! Error: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    } 

    if(connect(serverSocket, (struct sockaddr *)&serverAddress, sizeof(serverAddress)) < 0)
    {
        printf("ERROR: Failed to connect to server at port %d\"! Error: %s\n", SERVER_PORT, strerror(errno));
        shutdown(serverSocket, SHUT_RDWR);
        close(serverSocket);
        exit(EXIT_FAILURE);
    }

    return serverSocket;
}

int performClientHandshake(int serverSocket, char *recvBuffer)
{
    write(serverSocket, HANDSHAKE_INIT, sizeof(HANDSHAKE_INIT)); 

    memset(&recvBuffer[0], 0, sizeof(recvBuffer));
    read(serverSocket, recvBuffer, sizeof(recvBuffer)-1);

    if(!strcmp(recvBuffer, HANDSHAKE_ACK))
    {
        return 0;
    }

    return -1;
}

int main(int argc, char *argv[])
{
    int serverSocket = 0, n = 0;
    
    // Setup connection to the server
    printf("Starting client ...\n");
    serverSocket = setupSocketToServer();
    printf("Client started and connected to the server ...\n");

    // Create buffers
    char sendBuffer[BUFFER_SIZE];
    char recvBuffer[BUFFER_SIZE];

    memset(recvBuffer, '0', sizeof(recvBuffer));
    
    // Handshake
    if(performClientHandshake(serverSocket, recvBuffer) == -1)
    {
        printf("ERROR: Handshake with the server failed!");
        return EXIT_FAILURE;
    }

    DH *dh; 
    unsigned char *dh_secret = "";
    BIGNUM *serverPublicKey = BN_new();
    dh = DH_generate_parameters(256, 2, NULL, NULL);
    
    memset(&sendBuffer[0], 0, sizeof(sendBuffer));
    snprintf(sendBuffer, sizeof(sendBuffer), "%s", BN_bn2dec(dh->p));
    write(serverSocket, sendBuffer, sizeof(sendBuffer));
    
    memset(&sendBuffer[0], 0, sizeof(sendBuffer));
    snprintf(sendBuffer, sizeof(sendBuffer), "%s", BN_bn2dec(dh->g));
    write(serverSocket, sendBuffer, sizeof(sendBuffer));

    if(!DH_generate_key(dh)){
            printf("client key generation error\n");
    }
    memset(&sendBuffer[0], 0, sizeof(sendBuffer));
    snprintf(sendBuffer, sizeof(sendBuffer), "%s", BN_bn2dec(dh->pub_key));
    write(serverSocket, sendBuffer, sizeof(sendBuffer));
    
    memset(&recvBuffer[0], 0, sizeof(recvBuffer));
    read(serverSocket, recvBuffer, sizeof(recvBuffer)-1);
    BN_dec2bn(&serverPublicKey, recvBuffer);
    
    
    dh_secret = OPENSSL_malloc(sizeof(unsigned char) * DH_size(dh));
    DH_compute_key(dh_secret, serverPublicKey, dh);
    
    BIO_dump_fp(stdout, dh_secret, DH_size(dh));
    //printf("Client: shared secret key = %s\n", dh_secret);
    
    DH_free(dh);
    BN_free(serverPublicKey);
    free(dh_secret);


    if(n < 0)
    {
        printf("\n Read error \n");
    } 

    return 0;
}
