#ifndef CONNECTION_H
#define CONNECTION_H

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/poll.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

/* Socket */
int setupServerSocket(int port)
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
    serverAddress.sin_port = htons(port);

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

int setupSocketToServer(int port)
{
    int serverSocket;

    if ((serverSocket = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        printf("ERROR: Failed to create socket! Error: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }

    struct sockaddr_in serverAddress; 
    memset(&serverAddress, '0', sizeof(serverAddress)); 

    serverAddress.sin_family = AF_INET;
    serverAddress.sin_port = htons(port); 

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

/* Handshake */
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

/* Read/Write */
int receiveString(int socket, char **buffer)
{
    struct pollfd pollData[] = {{socket, POLLIN, 0}};
    int i, pollRes, bytesRead = 0, availBytes = 0;
    char *newBuffer;

    *buffer = NULL;
    while (1) {
        pollData[0].revents = 0;
        pollRes = poll(pollData, 1, 3000);

        if (pollRes <= 0)
        {
            free(*buffer);
            *buffer = NULL;
            printf("ERROR: Failed to read from socket! Error: %s\n", pollRes ? strerror(errno) : strerror(ETIMEDOUT));
            return -1;
        }

        if (pollData[0].revents != POLLIN || recv(socket, &i, 1, MSG_DONTWAIT | MSG_PEEK) == 0 || ioctl(socket, FIONREAD, &availBytes) == -1)
        {
            free(*buffer);
            *buffer = NULL;
            printf("ERROR: Failed to read from socket! Error: %s\n", strerror(ECONNRESET));
            return -2;
        }

        if (availBytes == 0) 
            continue;

        if (!(newBuffer = (char*)realloc(*buffer, bytesRead + availBytes))) {
            free(*buffer);
            *buffer = NULL;
            printf("ERROR: Out of memory (%d bytes)!\n", bytesRead + availBytes);
            return -3;
        }

        *buffer = newBuffer;
        for (i = bytesRead; i < bytesRead + availBytes; ++i)
        {
            if (read(socket, &(*buffer)[i], 1) < 1)
            {
                free(*buffer);
                *buffer = NULL;
                printf("ERROR: Failed to read from socket! Error: %s\n", strerror(errno));
                return -4;
            }
            if ((*buffer)[i] == '\0') 
                return i;
        }
        bytesRead += availBytes;
    }
    return 0;
}

int sendString(const int socket, const char* const buffer)
{
    int res;

    if ((res = write(socket, buffer, strlen(buffer) + 1)) == -1)
        printf("ERROR: Failed to write to socket! Error: %s\n", strerror(errno));

    return res;
}

#endif