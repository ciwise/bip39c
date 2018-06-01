/* bip39c.c
 * A BIP-39 Implementation using C.
 * 
 * Generation of mnemonic words to be used to create 
 * a seed for the creation of private keys to be used 
 * with the implementation of a deterministic (seeded)
 * bitcoin wallet.
 * 
 * written by: David L. Whitehurst
 * date: May 30, 2018
 * 
 * Algorithm:
 * 1. Create a random sequence (entropy) of 128 to 256 bits.
 * 2. Create a checksum of the random sequence by taking the
 *    first (entropy-length/32) bits of its SHA256 hash.
 * 3. Add the checksum to the end of the random sequence.
 * 4. Split the result into 11-bit length segments.
 * 5. Map each 11-bit value to a word from the predefined
 *    dictionary of 2048 words.
 * 6. The mnemonic code is the sequence of words.
 *
 * Worksheet:
 * 1. 256 entropy bits + checksum 8 bits = 264 bits and 24 mnemonic words
 *  
 */
      
    #include <stdio.h>
    #include <stdlib.h>
    #include <string.h>

    #include <ctype.h>
    #include <openssl/rand.h>
    #include <openssl/err.h>
    #include <openssl/sha.h>

    char hexToNibble(char n)
    /* convert hexidecimal character to nibble. 0-9a-f. */
    {
        /* printf("%c", n); */
        return n - ( n <= '9' ? '0' : ('a'-10) );
    }

    unsigned char hexToByte(char *hex)
    /* convert byte to hexidecimal characters. 0 <= n <= 255. */
    {
        unsigned char n = hexToNibble(*hex++);
        n <<= 4;
        n += hexToNibble(*hex++);
        return n;
    }

    int sha256(char *string, char outputBuffer[65])
    {
        unsigned char hash[SHA256_DIGEST_LENGTH];
        SHA256_CTX sha256;
        SHA256_Init(&sha256);
        SHA256_Update(&sha256, string, strlen(string));
        SHA256_Final(hash, &sha256);

        for(int i = 0; i < SHA256_DIGEST_LENGTH; i++)
        {
            sprintf(outputBuffer + (i * 2), "%02hhX ", hash[i]);
        }

        outputBuffer[64] = 0;
        return 0;
    }

    int main()
    {
        unsigned char entropy[32];
        unsigned char result[33];

        int rc = RAND_bytes(entropy, sizeof(entropy));
        unsigned long err = ERR_get_error();
        printf("Return code = %d\n\n", rc);

        /* Check for return code 1 */
        if(rc != 1) {
            printf("Error: %lu", err);
        }

        printf("256 Bit Entropy:\t\t");
        printf("0x");
        char entropyStr[sizeof(entropy)*2 + 1];
        int j;

        for(j=0;j< sizeof(entropy);j++) {
            sprintf(&entropyStr[j*2], "%02x", entropy[j]);
        }

        printf("%s\n", entropyStr);


        static char checksum[65];

        sha256(entropyStr, checksum);

        printf("SHA256 checksum:\t\t0x%s\n", checksum);

        int k=0;
        for (k=0; k< 32; k++) {
            result[k] = entropy[k];
        }
        printf("%c", checksum[0]);
        printf("%c", checksum[1]);
        printf("\n##\n");

        static char piece[2];
        piece[0] = checksum[0];
        piece[1] = checksum[1];

        /* stringToHex(firstByte, piece, 2); */
        int tmp = 0;
        printf("%02x", hexToByte(piece));

        result[32] =  hexToByte(piece);

        printf("264 bit hex string is:\t\t");
        printf("0x");
        int l = 0;
        for (l = 0; l < sizeof(result); l++) {
            printf("%02x", result[l]);
        }
        printf("\n");

        return 0;
    }

