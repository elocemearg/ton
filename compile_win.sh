#!/bin/bash

GCC=x86_64-w64-mingw32-gcc

$GCC -Wall -DWINDOWS=1 -g -o ttt.exe \
    ttt.c tttpush.c tttpull.c discover.c utils.c encryption.c \
    netif.c session.c accept.c protocol.c filetransfer.c \
    generatedwordlist.c \
    -lcrypto -lssl

exit $?
