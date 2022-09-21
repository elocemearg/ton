#!/bin/bash

GCC=x86_64-w64-mingw32-gcc
OPENSSL_ROOT=/home/graeme/openssl/openssl-1.1.1q
OPENSSL_INCLUDE=$OPENSSL_ROOT/include
CUNIT_ROOT=/home/graeme/cunit/install/lib
CUNIT_INCLUDE=/home/graeme/cunit/install/include

if [ ! -e wordlist/generatedwordlist.c -o wordlist/generatedwordlist.c -ot wordlist/wordlist.txt ]; then
    ./wordlist/makewordlist.py wordlist/wordlist.txt > wordlist/generatedwordlist.c || exit 1
fi

$GCC -Wall -DWINDOWS=1 -DTON_UNIT_TESTS=1 -std=gnu99 -g -static \
    -I "$OPENSSL_INCLUDE" -I "$CUNIT_INCLUDE" \
    -o ton.exe \
    src/ton.c src/tontest.c src/tonpush.c src/tonpull.c src/discover.c \
    src/utils.c src/encryption.c src/netif.c src/session.c src/accept.c \
    src/protocol.c src/filetransfer.c src/connect.c src/localfs.c \
    wordlist/generatedwordlist.c \
    -L"$OPENSSL_ROOT" -L"$CUNIT_ROOT" \
    -lcunit -lssl -lcrypto -liphlpapi -lws2_32

exit $?
