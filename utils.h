#ifndef UTILS_H
#define UTILS_H

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <openssl/bn.h>
#include <openssl/dh.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>

char *generateRandomString(size_t size)
{
    const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVW";
    
    char *string = malloc(size + 1);

    if (size)
    {
        --size;
        size_t n = 0;

        while(n < size)
        {
            int key = rand() % (int) (sizeof charset - 1);
            string[n] = charset[key];
            n++;
        }
        string[size] = '\0';
    }

    return string;
}

char* calculateHMAC(char* challenge)
{
    unsigned char key[] = "b0ff8318d2b8bdf1542850d66c83f4a921d36ce9ce47d1357eefd8007d620cf83ee4050b5715d0d13c5d85f2877eec2f63b931bd47417a81a538327af927da3e";
    unsigned char out[EVP_MAX_MD_SIZE];
    unsigned int outlen;
    char *res = malloc(outlen + 1);

    if (!HMAC(EVP_sha512(), key, sizeof(key)-1, challenge, sizeof(challenge)-1, out, &outlen))
    {
        return NULL;
    }

    return strcpy(res, out);
}

#endif