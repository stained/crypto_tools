#include "oracle.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

// Read a ciphertext from a file, send it to the server, and get back a result.
// If you run this using the challenge ciphertext (which was generated correctly),
// you should get back a 1. If you modify bytes of the challenge ciphertext, you
// may get a different result...

// Note that this code assumes a 3-block ciphertext.

static int const blockSize = 16;
static int const blocks = 3;
static int const blockBytes = blockSize * blocks;

int main(int argc, char *argv[]) {
    
    // allocate space for 48 bytes, i.e., 3 blocks
    unsigned char cipherText[blockBytes];
    
    unsigned char cipherConcat[blockSize * 2] = {0};
    int intermediate = 0;
    
    // allocate space for plain text
    unsigned char plainActual[blockBytes - blockSize] = {0};
    
    int i, j, block, tmp, ret;
    int padding = 0;
    
    FILE *fpIn;
    
    if (argc != 2) {
        printf("Usage: sample <filename>\n");
        return -1;
    }
    
    fpIn = fopen(argv[1], "r");
    
    for(i=0; i< blockBytes; i++) {
        fscanf(fpIn, "%02x", &tmp);
        cipherText[i] = tmp;
    }
    
    fclose(fpIn);
    
    Oracle_Connect();
    
    for (block = blocks; block > 1; block--)
    {
        for (i = 0; i < blockSize; i++)
        {
            cipherConcat[blockSize + i] = cipherText[block * blockSize - blockSize + i];
        }

        padding = 1;
        
        for (i = blockSize - 1; i >= 0; i--)
        {
            intermediate = -1;
            
            for (j = 0; j < 256; j++)
            {
                cipherConcat[i] = j;
                
                ret = Oracle_Send(cipherConcat, 2);
                if (ret == 1)
                {
                    intermediate = cipherConcat[i];
                    break;
                }
                else if (ret == -1)
                {
                    printf("Connectin failed\n");
                    return -1;
                }
            }
            
            if (intermediate == -1)
            {
                printf("Failed to get intermediate\n");
                return -1;
            }
            
            tmp = ((block - 1) * blockSize) - (blockSize - i);
            plainActual[tmp] = padding ^ intermediate  ^ cipherText[tmp];
            
            printf("%c", plainActual[tmp]);
            
            padding++;
            
            for (j = i; j < blockSize; j++)
            {
                tmp = ((block - 1) * blockSize) - (blockSize - j);
                cipherConcat[j] = padding ^ plainActual[tmp] ^ cipherText[tmp];
            }
        }
        
    }

    Oracle_Disconnect();

    printf("\n%s", plainActual);
}
