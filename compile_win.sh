#!/bin/bash

GCC=x86_64-w64-mingw32-gcc
OPENSSL_ROOT=/home/graeme/openssl/openssl-1.1.1q
CUNIT_ROOT=/home/graeme/cunit/install/lib
OPENSSL_INCLUDE=$OPENSSL_ROOT/include
CUNIT_INCLUDE=$CUNIT_ROOT/../include

if [ ! -e wordlist/generatedwordlist.c -o wordlist/generatedwordlist.c -ot wordlist/wordlist.txt ]; then
    ./wordlist/makewordlist.py wordlist/wordlist.txt > wordlist/generatedwordlist.c || exit 1
fi

if [ "$TON_CUNIT" = 1 ]; then
    DEFINE_CUNIT="-DTON_UNIT_TESTS=1"
    LINK_CUNIT_PATH="-L$CUNIT_ROOT"
    LINK_CUNIT="-lcunit"
else
    DEFINE_CUNIT=""
    LINK_CUNIT_PATH=""
    LINK_CUNIT=""
    CUNIT_INCLUDE="./src"
fi

GIT_COMMIT_HASH=$(git rev-parse HEAD) || GIT_COMMIT_HASH=unknown

$GCC -Wall -DWINDOWS=1 $DEFINE_CUNIT \
    -DTON_GIT_COMMIT_HASH="\"$GIT_COMMIT_HASH\"" -std=gnu99 -g -static \
    -I "$OPENSSL_INCLUDE" -I "$CUNIT_INCLUDE" \
    -o ton.exe \
    src/ton.c src/tontest.c src/tonpush.c src/tonpull.c src/discover.c \
    src/utils.c src/encryption.c src/netif.c src/session.c src/accept.c \
    src/protocol.c src/filetransfer.c src/connect.c src/localfs.c \
    wordlist/generatedwordlist.c \
    -L"$OPENSSL_ROOT" $LINK_CUNIT_PATH \
    $LINK_CUNIT -lssl -lcrypto -liphlpapi -lws2_32

exit $?
