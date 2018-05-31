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
    #include <string.h>
    #include <openssl/rand.h>
    #include <openssl/err.h>
    #include <openssl/sha.h>

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

        if(rc != 1) {
            /* RAND_bytes failed */
            /* `err` is valid    */
            printf("Error: %lu", err);
        }

        /* OK to proceed */
        printf("256 bit cryptographically secure random number: ");
        for (int i = sizeof(entropy) -1 ; i > -1; i --) {
            printf("%02hhX ", entropy[i]);
        }

        printf("\n");

        printf("Sizeof entropy: %lu\n", sizeof(entropy));

        static unsigned char checksum[65];
        int chk = sha256(*entropy, checksum);
        printf("SHA256 checksum: \n");
        for (int i = sizeof(checksum) -1; i > -1; i --) {
            printf("%02hhX ", checksum[i]);
        }

        printf("\n");
        printf("\n");

        printf("%02hhX", checksum[0]);
        printf("\n");

        return 0;
    }

