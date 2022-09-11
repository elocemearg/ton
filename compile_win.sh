#!/bin/bash

GCC=x86_64-w64-mingw32-gcc
OPENSSL_ROOT=/home/graeme/openssl/openssl-1.1.1q
OPENSSL_INCLUDE=$OPENSSL_ROOT/include

$GCC -Wall -DWINDOWS=1 -g -static \
    -I "$OPENSSL_INCLUDE" \
    -o ttt.exe \
    ttt.c tttpush.c tttpull.c discover.c utils.c encryption.c \
    netif.c session.c accept.c protocol.c filetransfer.c connect.c \
    generatedwordlist.c \
    -L"$OPENSSL_ROOT" \
    -lssl -lcrypto -liphlpapi -lws2_32

exit $?
