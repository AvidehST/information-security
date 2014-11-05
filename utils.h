#ifndef UTILS_H
#define UTILS_H

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/poll.h>
#include <sys/ioctl.h>

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

/* Diffie-Helmann */
int performServerSideDiffieHelmann(int socket, unsigned char **sharedKey)
{
    DH *dh = DH_new();
    char *buffer = NULL;

    // Exchange parameters
    printf("Waiting for client's prime number...\n");
    if (receiveString(socket, &buffer) <= 0)
    {
        return -1;
    }

    if (!BN_hex2bn(&dh->p, buffer))
    {
        printf("ERROR: Failed to convert prime number to BigNum! Error: %d\n", ERR_get_error());
        free(buffer);
        DH_free(dh);
        return -1;
    }

    free(buffer);
    buffer = NULL;

    printf("Waiting for client's generator...\n");
    if (receiveString(socket, &buffer) <= 0)
    {
        free(buffer);
        return -1;
    }

    if (!BN_hex2bn(&dh->g, buffer)) {
        printf("ERROR: Failed to convert generator to BigNum! Error: %d\n", ERR_get_error());
        free(buffer);
        DH_free(dh);
        return -1;
    }

    free(buffer);
    buffer = NULL;

    // Generate keys
    if(!DH_generate_key(dh))
    {
        printf("ERROR: Failed to generate the key!\n");
        DH_free(dh);
        return -1;
    }

    // Exchange keys
    BIGNUM *clientPublicKey = NULL;

    printf("Waiting for the clients's public key ...\n");
    if (receiveString(socket, &buffer) <= 0)
    {
        DH_free(dh);
        return -1;
    }

    if (!BN_hex2bn(&clientPublicKey, buffer))
    {
        printf("ERROR: Failed to convert public key to BigNum! Error: %d\n", ERR_get_error());
        free(buffer);
        DH_free(dh);
        return -1;
    }

    free(buffer);

    printf("Sending the public key to the client ...\n");
    if (sendString(socket, BN_bn2hex(dh->pub_key)) == -1)
    {
        BN_free(clientPublicKey);
        DH_free(dh);
        return -1;
    }

    // Generate shared key
    printf("Generate shared key ...\n");
    if (!(*sharedKey = malloc(DH_size(dh))))
    {
        printf("ERROR: Out of memory (%d bytes)!\n", DH_size(dh));
        free(buffer);
        BN_free(clientPublicKey);
        DH_free(dh);
        return -1;
    }

    int sharedKeySize = DH_compute_key(*sharedKey, clientPublicKey, dh);

    if (sharedKeySize == -1)
    {
        printf("ERROR: Failed to generate shared key! Error: %d\n", ERR_get_error());
        free(buffer);
        BN_free(clientPublicKey);
        DH_free(dh);
        free(*sharedKey);
        *sharedKey = NULL;
        return -1;
    }

    BN_free(clientPublicKey);
    DH_free(dh);

    return 0;
}

int performClientSideDiffieHelmann(int socket, unsigned char **sharedKey)
{
    DH *dh;

    // Generate parameters
    dh = DH_generate_parameters(256, 2, NULL, NULL);

    // Exchange parameters
    printf("Sending the prime number to the server ...\n");
    if (sendString(socket, BN_bn2hex(dh->p)) == -1)
    {
        return -1;
    }

    printf("Sending the generator to the server ...\n");
    if (sendString(socket, BN_bn2hex(dh->g)) == -1)
    {
        return -1;
    }

    // Generate keys
    if(!DH_generate_key(dh))
    {
        printf("ERROR: Failed to generate the key!\n");
        DH_free(dh);
        return -1;
    }

    // Exchange keys
    char *buffer = NULL;
    BIGNUM *serverPublicKey = NULL;

    printf("Sending the public key to the server ...\n");
    if (sendString(socket, BN_bn2hex(dh->pub_key)) == -1)
    {
        return -1;
    }

    printf("Waiting for the server's public key ...\n");
    if (receiveString(socket, &buffer) <= 0)
    {
        return -1;
    } 

    if (!BN_hex2bn(&serverPublicKey, buffer))
    {
        printf("ERROR: Failed to convert public key to BigNum! Error: %d\n", ERR_get_error());
        return -1;
    }

    // Generate shared key
    printf("Generate shared key ...\n");
    if (!(*sharedKey = malloc(DH_size(dh))))
    {
        printf("ERROR: Out of memory (%d bytes)!\n", DH_size(dh));
        free(buffer);
        BN_free(serverPublicKey);
        DH_free(dh);
        return -1;
    }

    int sharedKeySize = DH_compute_key(*sharedKey, serverPublicKey, dh);

    if (sharedKeySize == -1)
    {
        printf("ERROR: Failed to generate shared key! Error: %d\n", ERR_get_error());
        free(buffer);
        BN_free(serverPublicKey);
        DH_free(dh);
        free(*sharedKey);
        *sharedKey = NULL;
        return -1;
    }

    free(buffer);
    BN_free(serverPublicKey);
    DH_free(dh);

    return 0;
}





#endif