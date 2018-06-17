/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2018 David L. Whitehurst
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 * bip39c.c
 * A BIP-39 Implementation using C.
 * 
 * Generation of varying length mnemonic words to be used
 * to create a root seed for the creation of a Hierarchical
 * Deterministic (HD) wallet (BIP-32).
 * 
 * author: David L. Whitehurst
 * date: May 30, 2018
 * 
 * Algorithm:
 *
 *  First Part
 *      1. Create a random sequence (entropy) of 128 to 256 bits.
 *      2. Create a checksum of the random sequence by taking the
 *          first (entropy-length/32) bits of its SHA256 hash.
 *      3. Add the checksum to the end of the random sequence.
 *      4. Split the result into 11-bit length segments.
 *      5. Map each 11-bit value to a word from the predefined
 *          dictionary of 2048 words.
 *      6. The mnemonic code is the sequence of words.
 *
 *  Second Part
 *      7. Use the mnemonic as the first parameter for the
 *          key-stretching PBKDF2 algorithm.
 *      8. The second parameter is a "salt" that's a string
 *          constant "mnemonic plus an optional user-supplied
 *          passphrase of any length.
 *      9. PBKDF2 stretches the mnemonic and salt parameters using
 *          OpenSSL and 2048 rounds of HMAC-SHA512 to produce a
 *          512-bit root seed or digest in hex-form.

 * Find this code useful? Please donate:
 *  Bitcoin: 1Mxt427mTF3XGf8BiJ8HjkhbiSVvJbkDFY
 *
 */

#include "bip39c.h"
#include "conversion.h"
#include "crypto.h"
#include "print_util.h"

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <limits.h>
#include <string.h>
#include <ctype.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/evp.h>

/*
 * Global variables
 */

char *words[LANG_WORD_CNT];

/* program usage statement */
static char const usage[] = "\
Usage: " PACKAGE_NAME " [OPTIONS]\n\
 Mnemonic:\n\
  e.g. " PACKAGE_NAME " -e 128 -l eng\n\
 Key:\n\
  e.g. " PACKAGE_NAME " -k \"mnemonic\" [-p passphrase]\n\
 Options:\n\
  -e, specify the entropy to use\n\
    128\n\
    160\n\
    192\n\
    224\n\
    256\n\
  -l  specify the language code for the mnemonic\n\
    eng   English\n\
    spa   Spanish\n\
    fra   French\n\
    ita   Italian\n\
    kor   Korean\n\
    jpn   Japanese\n\
    tc    Traditional Chinese\n\
    sc    Simplified Chinese\n\
";

/*
 * The main function uses the GNU-added getopt function to std=c99 to provide options
 * to 1) create a varying length mnemonic and 2) a root seed or key for the creation
 * of an HD-wallet per BIP-39.
 */

int main(int argc, char **argv) //*argv[])
{
    char *evalue, *kvalue, *lvalue, *pvalue = NULL;

    int c;

    if (argc == 1) {
        fprintf(stderr, usage);
        //fprintf(stderr, "Usage: %s -e entropy bits [-l language code] or %s -k \"mnemonic mnemonic ... \"\n", argv[0], argv[0]);
        exit(EXIT_FAILURE);
    }

    while ((c = getopt(argc, argv, "e: l: k: p:")) != -1) {

        switch (c) {

            case 'e': // entropy set
                evalue = optarg;

                /* load word file into memory */
                //get_words();

                /* convert string value to long */
                //long entropyBits = strtol(evalue, NULL, 10);

                /* actual program call */
                //get_mnemonic(entropyBits);

                break;

            case 'l': // longuage
                lvalue = optarg;
                break;

            case 'k': // root seed key derived from mnemonic
                evalue = NULL;
                lvalue = NULL;
                kvalue = optarg;
                break;

            case 'p': // optional passphrase
                pvalue = optarg;
                //printf("passphrass=%s\n", pvalue);
                break;

            case '?':
                if (optopt == 'e' || optopt == 'l' || optopt == 'k' || optopt == 'p')
                    fprintf(stderr, "Option -%c requires an argument.\n", optopt);
                else if (isprint(optopt))
                    fprintf(stderr, "Unknown option `-%c'.\n", optopt);
                else
                    fprintf(stderr,
                            "Unknown option character `\\x%x'.\n",
                            optopt);
                return 1;

            default:
                exit(EXIT_FAILURE);
        } // end switch


    } // end while

    if (evalue != NULL && lvalue != NULL) {
        /* load word file into memory */
        get_words(lvalue);

        /* convert string value to long */
        long entropyBits = strtol(evalue, NULL, 10);

        /* actual program call */
        get_mnemonic(entropyBits);

    } else if (kvalue != NULL) {

        /* set passsphrase to empty string if null */
        if (pvalue == NULL) {
            pvalue = "";
        }

        /* get truly random binary seed */
        get_root_seed(kvalue, pvalue);

    } else {
            fprintf(stderr, "Both entropy (-e) and language (-l) options are required.\n");
            exit(EXIT_FAILURE);
    }

    return EXIT_SUCCESS;
}

/*
 * This function implements the first part of the BIP-39 algorithm.
 * The randomness or entropy for the mnemonic must be a multiple of
 * 32 bits hence the use of 128,160,192,224,256.
 *
 * The CS values below represent a portion (in bits) of the first
 * byte of the checksum or SHA256 digest of the entropy that the user
 * chooses by program option. These checksum bits are added to the
 * entropy prior to splitting the entire random series (ENT+CS) of bits
 * into 11 bit words to be matched with the 2048 count language word
 * file chosen. The final output or mnemonic sentence consists of (MS) words.
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

void get_mnemonic(int entropysize) {

    if (!(entropysize >= 128 && entropysize <= 256 && entropysize % 32 == 0)) {
        fprintf(stderr,
                "ERROR: Only the following values for entropy bit sizes may be used: 128, 160, 192, 224, and 256\n");
        exit(EXIT_FAILURE);
    }


    int entBytes = entropysize / 8; // bytes instead of bits
    int csAdd = entropysize / 32; // portion in bits of a single byte

    /*
     * ENT (Entropy)
     */

    unsigned char entropy[entBytes];
    char entropyBits[entropysize + 1];
    entropyBits[0] = '\0';

    char binaryByte[9];

    /* OpenSSL */
    int rc = RAND_bytes(entropy, sizeof(entropy));

    for (size_t i = 0; i < sizeof(entropy); i++) {
        char buffer[3];
        memcpy(buffer, &entropy[i], 2);
        buffer[2] = '\0';
        unsigned char *byte = hexstr_to_char(buffer);
        sprintf(binaryByte, BYTE_TO_BINARY_PATTERN, BYTE_TO_BINARY(*byte));
        binaryByte[8] = '\0';
        strcat(entropyBits, binaryByte);
    }

    /*
     * ENT SHA256 checksum
     */

    static char checksum[65];
    char entropyStr[sizeof(entropy) * 2 + 1];

    /* me and OpenSSL */
    sha256(entropyStr, checksum);

    char hexStr[3];
    memcpy(hexStr, &checksum[0], 2);
    hexStr[2] = '\0';

    /*
     * CS (Checksum portion) to add to entropy
     */

    produce_mnemonic_sentence(csAdd * 33 + 1, csAdd + 1, hexStr, entropyBits);

}

/*
 * This function implements the second part of the BIP-39 algorithm.
 */

void get_root_seed(const char *pass, const char *passphrase) {

        /* initialize variables */
        char HexResult[128];
        memset(HexResult, 0, 64);
        unsigned char digest[64];

        /* create salt, passphrase could be empty string */
        char *salt = malloc(strlen(passphrase) + 9);
        salt = strcat(salt, "mnemonic");
        salt = strcat(salt, passphrase);

        /* openssl function */
        PKCS5_PBKDF2_HMAC(pass, strlen(pass), (const unsigned char *) salt, strlen((const char *) salt), 2048, EVP_sha512(), 64, digest);

        /* we're done with salt */
        free(salt);

        for (size_t i = 0; i < sizeof(digest); i++)
            sprintf(HexResult + (i * 2), "%02x", 255 & digest[i]);

        printf("%s\n", HexResult);

}


/*
 * This function reads the language file once and loads an array of words for
 * repeated use.
 */

void get_words(char *lang) {

    char *source = NULL;
    const char *filepath = NULL;

    if (strcmp(lang,"spa") == 0) {
        filepath = "/usr/local/data/spanish.txt";
    } else if (strcmp(lang,"eng") == 0) {
        filepath = "/usr/local/data/english.txt";
    } else if (strcmp(lang,"jpn") == 0) {
        filepath = "/usr/local/data/japanese.txt";
    } else if (strcmp(lang,"ita") == 0) {
        filepath = "/usr/local/data/italian.txt";
    } else if (strcmp(lang,"fra") == 0) {
        filepath = "/usr/local/data/french.txt";
    } else if (strcmp(lang,"kor") == 0) {
        filepath = "/usr/local/data/korean.txt";
    } else if (strcmp(lang,"sc") == 0) {
        filepath = "/usr/local/data/chinese-simplified.txt";
    } else if (strcmp(lang,"tc") == 0) {
        filepath = "/usr/local/data/chinese-traditional.txt";
    } else {
        fprintf(stderr, "Language or language file does not exist.\n");
        exit(EXIT_FAILURE);
    }

    FILE *fp = fopen(filepath, "r");

    if (fp != NULL) {

        /* Go to the end of the file. */
        if (fseek(fp, 0L, SEEK_END) == 0) {

            /* Get the size of the file. */
            long bufsize = ftell(fp);

            if (bufsize == -1) {
                fprintf(stderr,
                        "ERROR: File size?\n");
            }

            /* Allocate our buffer to that size. */
            source = malloc(sizeof(char) * (bufsize + 1));

            /* Go back to the start of the file. */
            if (fseek(fp, 0L, SEEK_SET) != 0) {
                fprintf(stderr,
                        "ERROR: File seek beginning of file.\n");
            }

            /* Read the entire file into memory. */
            size_t newLen;
            newLen = fread(source, sizeof(char), (size_t) bufsize, fp);
            if ( ferror( fp ) != 0 ) {
                fprintf(stderr,
                        "ERROR: File read.\n");
            } else {
                source[newLen++] = '\0'; /* Just to be safe. */
            }
        }
        fclose(fp);
    }

    char * word;
    word = strtok (source,"\n");
    int i = 0;
    while (word != NULL)
    {
        words[i] = malloc(strlen(word) + 1 );
        strcpy(words[i], word);
        i++;
        word = strtok (NULL, "\n");
    }

    free(source);
}

/*
 * This function prints the mnemonic sentence of size based on the segment
 * size and number of checksum bits appended to the entropy bits.
 */

void produce_mnemonic_sentence(int segSize, int checksumBits, char *firstByte, char entropy[]) {

    unsigned char *bytes;

    char segment[segSize];
    memset(segment, 0, segSize * sizeof(char));

    char csBits[checksumBits];
    memset(csBits, 0, checksumBits * sizeof(char));

    bytes = hexstr_to_char(firstByte);

    switch(checksumBits) {
        case 5:
            sprintf(csBits, BYTE_TO_FIRST_FOUR_BINARY_PATTERN, BYTE_TO_FIRST_FOUR_BINARY(*bytes));
            break;
        case 6:
            sprintf(csBits, BYTE_TO_FIRST_FIVE_BINARY_PATTERN, BYTE_TO_FIRST_FIVE_BINARY(*bytes));
            break;
        case 7:
            sprintf(csBits, BYTE_TO_FIRST_SIX_BINARY_PATTERN, BYTE_TO_FIRST_SIX_BINARY(*bytes));
            break;
        case 8:
            sprintf(csBits, BYTE_TO_FIRST_SEVEN_BINARY_PATTERN, BYTE_TO_FIRST_SEVEN_BINARY(*bytes));
            break;
        case 9:
            sprintf(csBits, BYTE_TO_BINARY_PATTERN, BYTE_TO_BINARY(*bytes));
            break;
        default:
            exit(EXIT_FAILURE);
            break;
    }

    csBits[checksumBits - 1] = '\0';

    strcat(segment, entropy);
    strcat(segment, csBits);
    segment[segSize - 1] = '\0';

    char elevenBits[12] = {""};

    int elevenBitIndex = 0;
    for (size_t i = 0; i < segSize; i++) {

        if (elevenBitIndex == 11) {
            elevenBits[11] = '\0';
            long real = strtol(elevenBits, NULL, 2);
            printf("%s", words[real]);
            printf(" ");
            elevenBitIndex = 0;
        }

        elevenBits[elevenBitIndex] = segment[i];
        elevenBitIndex++;
    }
    printf("\n");
}


