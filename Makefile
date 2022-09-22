
CUNIT=${TON_CUNIT}

CC=gcc
CFLAGS=-Wall -g -DUNIX=1 -std=gnu99 -Wpedantic
LDFLAGS=-lcrypto -lssl

ifeq ($(CUNIT),1)
	CFLAGS := $(CFLAGS) -DTON_UNIT_TESTS
	LDFLAGS := $(LDFLAGS) -lcunit
endif

TON_C_FILES:=$(wildcard src/*.c)
TON_H_FILES:=$(wildcard src/*.h)

ton: $(TON_C_FILES) $(TON_H_FILES) wordlist/generatedwordlist.c
	gcc $(CFLAGS) -o ton $(TON_C_FILES) wordlist/generatedwordlist.c $(LDFLAGS)

wordlist/generatedwordlist.c: wordlist/makewordlist.py src/wordlist.h wordlist/wordlist.txt
	python3 wordlist/makewordlist.py wordlist/wordlist.txt > wordlist/generatedwordlist.c

clean:
	rm -f ton wordlist/generatedwordlist.c src/*.o
