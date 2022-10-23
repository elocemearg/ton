# ton - Transfer Over Network

ton is a zero-configuration local-network file transfer tool. It is designed
for when you have a file on computer A, and you want to copy the file to
computer B on the same network. ton does this without you having to mess about
with USB sticks, look up any IP addresses, or email the file to yourself.

## Usage example

Say you want to transfer `myfile.tar.gz` from computer A to computer B. Both
machines are on the same local network.

1. Run `ton push myfile.tar.gz` on computer A. `ton` will generate and print a
random four-word passphrase.

2. Run `ton pull` on computer B. It will prompt for a passphrase. Enter the
same passphrase as generated above.

3. The two machines find each other on the network, authenticate using the
passphrase, and the file is transferred from A to B over a channel encrypted
using the passphrase. The transfer is secure provided the passphrase is kept
secret.

## How it works

The receiving or "pulling" side sends UDP multicast packets to the whole
network announcing that it's ready to receive a file, inviting the sending
side to connect to it on a TCP port. These announcement packets are sent on
every IPv4 and IPv6 interface in the hope that at least one of them allows
two-way communication. The announcement packets are encrypted with the
passphrase.

The sending or "pushing" side listens for these announcement packets, and
tries to decrypt them with its passphrase. In the event of a successful
decryption, the pushing side makes a TCP connection to the port indicated in
the announcement packet.

Both sides authenticate with each other over the TCP connection using the
passphrase as a pre-shared key. If this succeeds, the channel is encrypted
with the key from this point on, and the file is transferred.

## Building ton for Linux on Linux

### Prerequisites

Install the following packages, if they are not already installed:
* `gcc`
* `libssl-dev`
* `libcunit1` (only if you want to run the unit tests)
* `libcunit1-dev` (only if you want to run the unit tests)

### Build

Clone the ton git repository, `cd` to that directory and build `ton`:

```
make ton
```

This produces a binary called `ton`.

### Install

```
sudo make install
```

This installs ton in `/usr/local/bin/` and the man pages in
`/usr/local/share/man/`.

### Use

For help, use `ton push -h` or `ton pull -h` as appropriate.

To transfer a file:
* On the sending machine:
 - `ton push /path/to/file/or/dir`
 - [generates and displays a passphrase]
* On the receiving machine:
 - `ton pull [destination]`
 - [enter same passphrase]

Both machines must be on the same network and the passphrases must match.

### Testing

To build `ton` with the unit tests:
```
TON_CUNIT=1 make ton
```

To run the unit tests:
```
ton test
```

## Building ton for Windows using MinGW

Building ton on Linux for Windows is possible with MinGW, but there are
additional prerequisites. First you need to install mingw64, download the
OpenSSL source (and CUnit if required) and build custom MinGW versions of them.

### Building a custom MinGW OpenSSL

To configure and build OpenSSL with MinGW:
* Download and unpack OpenSSL
* Navigate to the unpacked directory
* `./Configure --cross-compile-prefix=x86_64-w64-mingw32- mingw64`
* `make`

### Building ton for Windows

`ton`'s `Makefile` then requires the following environment variables to be set:

* `MINGW_OPENSSL_ROOT`: the path containing the `libssl.a` and `libcrypto.a` files you built with MinGW.
* `MINGW_CUNIT_ROOT`: the path to the top-level directory containing `install/lib/libcunit.a`. (This is only required if you're building `ton.exe` with the unit tests using `TON_CUNIT=1`.)

Finally, build `ton.exe`. This is a Windows console application.
```
make ton.exe
```

## Licensing

`ton` is released under the 3-Clause BSD License. Run `ton licence` for more
information.

If you build the Windows version using the instructions above, you get a
statically-compiled binary which includes the required OpenSSL libraries
inside it. Run `ton notices` for the relevant acknowledgements.
