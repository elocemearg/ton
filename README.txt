ton securely transfers files and directories over a local network.
It does this without having to enter any hostnames, IP addresses or other
configuration on either end, except for an automatically-generated passphrase.

To build ton on Linux, for Linux:

Install the following packages, if they are not already installed:
    gcc
    glibc
    python3 (to generate passphrase word list)
    libssl-dev
    libcunit1 (only if you want to run the unit tests)
    libcunit1-dev (only if you want to run the unit tests)

To build:
    make ton

This produces a binary, "ton".

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

Both machines must be on the same network and the passphrase must be correct.


To build with unit tests:
    TON_CUNIT=1 make ton

To run the unit tests:
    ton test


Building ton on Linux for Windows is also possible with MinGW, but you need to
install mingw64, download OpenSSL (and CUnit if required) and build custom
MinGW versions of them, then edit the paths at the top of compile_win.sh, then
run that. This produces a Windows binary "ton.exe".

To configure and build OpenSSL with MinGW:

* Download and unpack OpenSSL
* Navigate to the unpacked directory
* ./Configuire --cross-compile-prefix=x86_64-w64-mingw32- mingw64
* make
