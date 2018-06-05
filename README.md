# bip39c (BIP-39 C-Implementation) 

[![Build Status](https://travis-ci.org/ciwise/bip39c.svg)](https://travis-ci.org/ciwise/bip39c)

Implementation of BIP-0039: Mnemonic code for generating deterministic keys using C [BIP0039] (https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki) The BIP-39 standard consists
of two parts, the generation of the mnemonic sentence of random words and then the generation
of a truly random binary seed. This seed can be used to create deterministic wallets described
by BIP-32 or similar specification.

## Changes
v0.1.0 June 5, 2018 - This version supports the complete implementation of the generation of
the mnemonic sentence.

See the [changelog](./ChangeLog) file, or the Github releases for specific tags.

## Dependencies
 * openssl libcrypto https://www.openssl.org/

## Download
 * Git tree:   https://github.com/ciwise/bip39c
 * Clone with `git clone https://github.com/ciwise/bip39.git`
 
## Build
After cloning the repository you can build the bip39c command easily using the Automake and Autoconf tools with Linux.
Configure and make the command first and then install using sudo.

`$ autogen.sh && ./configure && make`

Now as sudo install.

`$ sudo make install`
   
## Documentation
Using the BIP-39 command is easy. The command creates a mnemonic sentence
using 5 preselected entropy bit lengths, 128, 160, 192, 224, and 256. For
example you can create a mnemonic sentence with a 256 bit entropy like so:

`$ bip39c -e 256`

The system will produce a mnemonic sentence.

`agree often tribe olive cement peanut bullet burger stay merit roof cabbage found chapter card divert talk festival rain axis misery spell fog`

An English wordlist is included currently. Support for other languages will follow in future releases. 

## Errata

There are no bugs or issues known at this time.

## Donations

Please consider a small donation for the work provided here.

bitcoin:1Mxt427mTF3XGf8BiJ8HjkhbiSVvJbkDFY

## Authors

- David L. Whitehurst <david@ciwise.com> - This implementation in C
- Marek Palatinus <marek@satoshilabs.com> - Python reference implementation
- Pavol Rusnak <stick@satoshilabs.com> - Python reference implementation

## License
MIT License. See [LICENSE](LICENSE) for details.

[license-url]: https://github.com/ciwise/bip39c/LICENSE.
