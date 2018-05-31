/* bip39c.c
 * A BIP-39 Implementation using C.
 * 
 * Generation of deterministic mnemonic words to be used as 
 * a seed for the creation of private keys to be used with
 * the implementation if a Bitcoin wallet.
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
 *  
 */
      
    #include <stdio.h>
    #define LAST 10
      
    int main()
    {
        int i, sum = 0;
       
        for ( i = 1; i <= LAST; i++ ) {
          sum += i;
        } /*-for-*/
        printf("sum = %d\n", sum);

        return 0;
    }
