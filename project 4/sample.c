#include "oracle.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#define MAX_LENGTH 512

char *xor( char *message,  char *tag)
{
    static  char messageXored[16];
    
    int i;
    for (i = 0; i < 16; i++)
    {
        messageXored[i] = tag[i] ^ message[i];
    }
    
    return messageXored;
}

int main(int argc, char *argv[]) {
     unsigned char message[64] = {0};
     unsigned char message1[33] = {0};
     unsigned char message2[33] = {0};
     unsigned char message3[65] = {0};
    
     unsigned char tag1[16] = {0};
     unsigned char tag2[16] = {0};
    unsigned char tag3[16] = {0};
    
    int i, mlength, ret;
    FILE *fpIn;

    if (argc != 2) {
        printf("Usage: sample <filename>\n");
        return -1;
    }

    fpIn = fopen(argv[1], "r");
    for(i=0; i<MAX_LENGTH; i++) {
      if (fscanf(fpIn, "%c", &message[i]) == EOF) break;
    }
    fclose(fpIn);

    mlength = i;

    Oracle_Connect();
    
    strncpy(message1, strndup(message, 32), 32);
    Mac(message1, 32, tag1);
    
    strncat(message2, xor(strndup(message + 32, 16), tag1), 16);
    Mac(message2, 16, tag2);
    
    strncat(message3, xor(strndup(message + 48, 16), tag2), 16);
    Mac(message3, 16, tag3);
    
    ret = Vrfy(message, 64, tag3);
    
    if (ret) {
        printf("Message verified successfully!\n");
        
        for(i = 0; i < 16; i++)
        {
            printf("%02x ", tag3[i]);
        }
        printf("\n");
    } else {
        printf("Message verficiation failed.\n");
    }

    Oracle_Disconnect();
}
