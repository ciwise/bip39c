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
    #include "bip39c.h"


    /*
     * The main method calls the generate method to output a random set of
     * mnemonics per BIP-39
     */

    int main(int argc, char* argv[])
    {
        /* Key method to generate a 128 bit entropy randomized mnemonic sentence */

        if (argc > 0) {
            bool result = generate(ENTROPY_BITS);
        } else {
            printf("Usage: bip39c\n");
        }

        return EXIT_SUCCESS;
    }

    /*
     * This method checks to see if an input exists in an array
     */

    bool isvalueinarray(int val, int *arr, int size){
        int i;
        for (i=0; i < size; i++) {
            if (arr[i] == val)
                return true;
        }
        return false;
    }

    /*
     * The method that generates the mnemonics. Only bit sizes 128, 160, 192, 224,
     * and 256 may be used for entropy per BIP-39
     */

    bool generate(int entropysize) {

        int ENTROPY_ARRAY[5] = { 128, 160, 192, 224, 256 };
        static char *string = "car boat cat random quarry radio buzz\n";

        bool result = isvalueinarray(entropysize, ENTROPY_ARRAY, 5);

        if (result != true) {
            printf("ERROR: Only the following values for entropy bit sizes may be used: 128, 160, 192, 224, and 256\n");
        } else {

            /* call generate mnemonic sentence */
            printf("%s\n", string);
            int bytesOfEntropy = entropysize/8;
            int addChecksumBytes = entropysize/32;
            bool chk = getMnemonic(bytesOfEntropy,addChecksumBytes);

        }
        return true;
    }

    /*
     * The method called by generate that implements the BIP-39 algorithm.
     * The data integer is the multiple that maintains our entropy. The mnemonic must
     * encode entropy multiple of 32 bits hence the use of 128,160,192,224,256.
     *
     * Next, each entropy bit size will require entropy-bits/8 entropy byte counts
     * hence the use of 16,20,24,28,32.
     *
     * The CS values below are the number of checksum bits that are added to the
     * entropy bytes prior to splitting the entire random series (ENT+CS) of bytes
     * into 11 bit words to be matched with the 2048 count language word files. The
     * final output or mnemonic sentence consists of (MS) words.
     *
     * CS = ENT / 32
     * MS = (ENT + CS) / 11
     *
     * |  ENT  | CS | ENT+CS |  MS  |
     * +-------+----+--------+------+
     * |  128  |  4 |   132  |  12  |
     * |  160  |  5 |   165  |  15  |
     * |  192  |  6 |   198  |  18  |
     * |  224  |  7 |   231  |  21  |
     * |  256  |  8 |   264  |  24  |
     */

    bool getMnemonic(int entBytes, int csAdd) {

        int ENTROPY_BYTES[5] = { 16, 20, 24, 28, 32 };
        int ENTROPY_BIT_SIZE = entBytes * 8;

        bool result = isvalueinarray(entBytes, ENTROPY_BYTES, 5);


        if (result != true) {
            printf("ERROR: Only the following values for the number of entropy bytes may be used: 16, 20, 24, 28, and 32\n");
        } else {

            /*
             * ENT (Entropy)
             */

            unsigned char entropy[entBytes];
            char entropyBits[ENTROPY_BIT_SIZE + 1];
            entropyBits[0] = '\0';

            char binaryByte[9];
            char segment[133] = { "" };

            int rc = RAND_bytes(entropy, sizeof(entropy));
            printf("ENTROPY:\n");

            int i;
            for (i=0; i< sizeof(entropy); i++) {
                char buffer[3];
                memcpy( buffer, &entropy[i], 2 );
                buffer[2] = '\0';
                unsigned char *byte = hexstr_to_char(buffer);
                sprintf(binaryByte, BYTE_TO_BINARY_PATTERN, BYTE_TO_BINARY(*byte));
                binaryByte[8] = '\0';
                strcat(entropyBits, binaryByte);
            }
            printf("%s", entropyBits);
            printf("\n");

            /*
             * ENT SHA256 checksum
             */

            static char checksum[65];
            char entropyStr[sizeof(entropy)*2 + 1];
            sha256(entropyStr, checksum);

            /*
             * CS to add to entropy
             */

            int b = 0;
            unsigned char *bytes;

            switch (csAdd) {

                case 4: // 128-Bit entropy
                    printf("\n");
                    char csBits[5] = { "" };
                    char hexStr[3];
                    memcpy( hexStr, &checksum[0], 2 );
                    hexStr[2] = '\0';

                    bytes = hexstr_to_char(hexStr);

                    printf("CS-ADD:\n");
                    sprintf(binaryStr, BYTE_TO_FIRST_FOUR_BINARY_PATTERN, BYTE_TO_FIRST_FOUR_BINARY(*bytes));
                    csBits[4] = '\0';
                    printf("%s", csBits);
                    printf("\n\n");

                    strcat(segment, entropyBits);
                    strcat(segment, csBits);
                    segment[132] = '\0';
                    printf("ENT + CS-ADD:\n");
                    printf("%s\n", segment);

                    break;

                case 5:

                    break;
                case 6:
                    break;
                case 7:
                    break;
                case 8:
                    b = checksum[0];
                    b += checksum[1];
                    printf("%d", b);
                    printf("\n");
                    break;
                default:
                    break;
            }
         }

        return true;
    }

    unsigned char *hexstr_to_char(const char* hexstr)
    {
        size_t len = strlen(hexstr);
        //printf("len: %zd\n", len);
        size_t final_len = len / 2;
        //printf("final_len: %zd\n", final_len);
        size_t s = sizeof(unsigned char*);
        //printf("The size of an unsigned char pointer is: %zd\n", s);
        unsigned char *chrs = (unsigned char *) malloc((final_len + 1) * sizeof(*chrs));
//        unsigned char *chrs = (unsigned char *) malloc ((final_len) * sizeof(*chrs));
        for (size_t i = 0, j = 0; j < final_len; i += 2, j++)
            chrs[j] = (hexstr[i] % 32 + 9) % 25 * 16 + (hexstr[i + 1] % 32 + 9) % 25;
        chrs[final_len] = '\0';
        return chrs;
    }


    /*
     *
     */
    void printUCharArray(unsigned char bytes[], int size) {
        printf("0x");
        char str[size*2 + 1];
        int j;

        for(j=0;j< size;j++) {
            sprintf(&str[j*2], "%02x", bytes[j]);
        }

        printf("%s\n", str);
    }

    /*
     * This method implements a SHA256 checksum from a hex
     * string and loads a string of fixed length (hex string
     * of 64 chars or 32 bytes)
     */

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



