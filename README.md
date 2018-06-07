# bip39c (BIP-39 C-Implementation) 

[![Build Status](https://travis-ci.org/ciwise/bip39c.svg)](https://travis-ci.org/ciwise/bip39c)

Implementation of BIP-0039: Mnemonic code for generating deterministic keys using C [BIP0039] (https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki) The BIP-39 standard consists
of two parts, the generation of the mnemonic sentence of random words and then the generation
of a truly random binary seed. This seed can be used to create deterministic wallets described
by BIP-32 or similar specification.

## Changes
See the [changelog](./ChangeLog) file, or the Github releases for specific tags.

## Dependencies
 * openssl libcrypto https://www.openssl.org/

## Download
 * Git tree:   https://github.com/ciwise/bip39c
 * Clone with `git clone https://github.com/ciwise/bip39.git`
 
## Build
After cloning the repository you can build the bip39c command easily using the Automake and Autoconf tools with Linux.
Configure and make the command first and then install using sudo.

For Debian/Ubuntu platforms, you may need to install these things as dependencies.
```
sudo apt-get install build-essential libssl-dev libcurl4-openssl-dev
```
Simple configuration and build.
```
$ autogen.sh
$ ./configure
$ make
```

Now as sudo install.

```
$ sudo make install
```
   
## Documentation
Using the BIP-39 command is easy. The command creates a mnemonic sentence
using 5 preselected entropy bit lengths, 128, 160, 192, 224, and 256. For
example you can create a mnemonic sentence with a 256 bit entropy like so:

```
bip39c -e 256
tell great unaware human cargo frozen real cause dentist grace during blanket eagle bag bomb print laundry real adult wine rocket slow fence fly
```
An English wordlist is included currently. Support for other languages will follow in future releases. 

You can also create a 512-bit, 64 byte derived key from the mnemonic you just created. The mnemonic will always produce the same 512-bit HD wallet seed. Once the seed is used to create a wallet, you MUST hang on to the mnemonic word list (in order). The mnemonic is the only way to retrieve your wallet again in the event of tampering, loss, or theft.

Create the seed key like so:

```
$ bip39c -k "tell great unaware human cargo frozen real cause dentist grace during blanket eagle bag bomb print laundry real adult wine rocket slow fence fly"
1741c7a59e31dc81ebc284726f0211d589d15a5e3c467b4b14bb13ecfa6f0d3f22a6c040a3e6a68542d6a86d2bd7e52b7247b52af98ddc7bd64b5ab5b2d502bc
```
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
