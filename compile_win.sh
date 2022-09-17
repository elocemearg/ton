#!/bin/bash

GCC=x86_64-w64-mingw32-gcc
OPENSSL_ROOT=/home/graeme/openssl/openssl-1.1.1q
OPENSSL_INCLUDE=$OPENSSL_ROOT/include
CUNIT_ROOT=/home/graeme/cunit/install/lib
CUNIT_INCLUDE=/home/graeme/cunit/install/include

$GCC -Wall -DWINDOWS=1 -DTTT_UNIT_TESTS=1 -g -static \
    -I "$OPENSSL_INCLUDE" -I "$CUNIT_INCLUDE" \
    -o ttt.exe \
    ttt.c ttttest.c tttpush.c tttpull.c discover.c utils.c encryption.c \
    netif.c session.c accept.c protocol.c filetransfer.c connect.c \
    generatedwordlist.c \
    -L"$OPENSSL_ROOT" -L"$CUNIT_ROOT" \
    -lcunit -lssl -lcrypto -liphlpapi -lws2_32

exit $?
