/* bip39c.h
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
 */

#ifndef BIP39C_BIP39C_H
#define BIP39C_BIP39C_H

/*
 * Includes
 */
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <limits.h>
#include <string.h>
#include <ctype.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/sha.h>


/*
 * Defines
 */

#define BYTE_TO_BINARY_PATTERN "%c%c%c%c%c%c%c%c"
#define BYTE_TO_BINARY(byte)  \
  (byte & 0x80 ? '1' : '0'), \
  (byte & 0x40 ? '1' : '0'), \
  (byte & 0x20 ? '1' : '0'), \
  (byte & 0x10 ? '1' : '0'), \
  (byte & 0x08 ? '1' : '0'), \
  (byte & 0x04 ? '1' : '0'), \
  (byte & 0x02 ? '1' : '0'), \
  (byte & 0x01 ? '1' : '0')

#define BYTE_TO_FIRST_FOUR_BINARY_PATTERN "%c%c%c%c"
#define BYTE_TO_FIRST_FOUR_BINARY(byte)  \
  (byte & 0x80 ? '1' : '0'), \
  (byte & 0x40 ? '1' : '0'), \
  (byte & 0x20 ? '1' : '0'), \
  (byte & 0x10 ? '1' : '0')

#define BYTE_TO_FIRST_FIVE_BINARY_PATTERN "%c%c%c%c%c"
#define BYTE_TO_FIRST_FIVE_BINARY(byte)  \
  (byte & 0x80 ? '1' : '0'), \
  (byte & 0x40 ? '1' : '0'), \
  (byte & 0x20 ? '1' : '0'), \
  (byte & 0x10 ? '1' : '0'), \
  (byte & 0x08 ? '1' : '0')

#define BYTE_TO_FIRST_SIX_BINARY_PATTERN "%c%c%c%c%c%c"
#define BYTE_TO_FIRST_SIX_BINARY(byte)  \
  (byte & 0x80 ? '1' : '0'), \
  (byte & 0x40 ? '1' : '0'), \
  (byte & 0x20 ? '1' : '0'), \
  (byte & 0x10 ? '1' : '0'), \
  (byte & 0x08 ? '1' : '0'), \
  (byte & 0x04 ? '1' : '0')

#define BYTE_TO_FIRST_SEVEN_BINARY_PATTERN "%c%c%c%c%c%c%c"
#define BYTE_TO_FIRST_SEVEN_BINARY(byte)  \
  (byte & 0x80 ? '1' : '0'), \
  (byte & 0x40 ? '1' : '0'), \
  (byte & 0x20 ? '1' : '0'), \
  (byte & 0x10 ? '1' : '0'), \
  (byte & 0x08 ? '1' : '0'), \
  (byte & 0x04 ? '1' : '0'), \
  (byte & 0x02 ? '1' : '0')


/* function to generate mnemonic sentence */
int generate(int entropysize);

/* function to check values in an array */
bool isvalueinarray(int val, int *arr, int size);

/* function implementing BIP-39 algorithm */
int getMnemonic(int entBytes, int csAdd);

/* function that prints byte array as hex string */
void printUCharArray(unsigned char bytes[], int size);

/* function that implements SHA-256 using openssl */
int sha256(char *string, char outputBuffer[65]);

/* function to convert hex string to series of unsigned charactees at pointer */
unsigned char* hexstr_to_char(const char* hexstr);

/* function to print word found at linenumber */
int printWord(long lineNumber);

/* function to print entire mnemonic sentence from segmeent (entropy+checksum bits) */
int produceMnemonicSentence(int segSize, int checksumBits, char *firstByte, char entropy[]);

#endif //BIP39C_BIP39C_H
