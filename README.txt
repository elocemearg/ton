ton securely transfers files and directories over a local network.
It does this without having to enter any hostnames, IP addresses or other
configuration on either end, except for an automatically-generated passphrase.

To build ton on Linux, for Linux:

Install the following packages, if they are not already installed:
    gcc
    glibc
    libssl-dev
    libcunit1 (only if you want to run the unit tests)
    libcunit1-dev (only if you want to run the unit tests)

To build:
    make ton
This produces a binary, "ton".

To install:
    sudo make install
This installs ton in /usr/local/bin/ and the man pages in /usr/local/share/man/.

To run and get help:
    ton push -h
    ton pull -h

To transfer a file:
    On the sending machine:
        ton push /path/to/file/or/dir
        [generates and displays a passphrase]
    On the receiving machine:
        ton pull [destination]
        [enter same passphrase]

Both machines must be on the same network and the passphrase must match.


To build with unit tests:
    TON_CUNIT=1 make ton

To run the unit tests:
    ton test


Building ton on Linux for Windows is also possible with MinGW, but you need to
install mingw64, download OpenSSL (and CUnit if required) and build custom
MinGW versions of them.

To configure and build OpenSSL with MinGW:
    * Download and unpack OpenSSL
    * Navigate to the unpacked directory
    * ./Configure --cross-compile-prefix=x86_64-w64-mingw32- mingw64
    * make

ton's Makefile then requires the following environment variables to be set:
MINGW_OPENSSL_ROOT: the path containing the libssl.a and libcrypto.a files
you built with MinGW.
MINGW_CUNIT_ROOT: the path to the top-level directory containing
install/lib/libcunit.a. (This is only required if you're building ton.exe with
the unit tests using TON_CUNIT=1.)

Then run "make ton.exe".

