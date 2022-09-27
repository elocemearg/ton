
CUNIT=${TON_CUNIT}

CC=gcc
CFLAGS=-Wall -g -DUNIX=1 -std=gnu99 -Wpedantic
LDFLAGS=-lcrypto -lssl
INSTALL_DEST_DIR=/usr/local/bin
INSTALL_MAN_DEST_DIR=/usr/local/share/man/man1

ifeq ($(CUNIT),1)
	CFLAGS := $(CFLAGS) -DTON_UNIT_TESTS
	LDFLAGS := $(LDFLAGS) -lcunit
endif

TON_C_FILES:=$(wildcard src/*.c)
TON_H_FILES:=$(wildcard src/*.h)
GIT_COMMIT_HASH:=$(shell git rev-parse HEAD || echo unknown)

ton: $(TON_C_FILES) $(TON_H_FILES) wordlist/generatedwordlist.c
	gcc $(CFLAGS) -o ton $(TON_C_FILES) -DTON_GIT_COMMIT_HASH="\"$(GIT_COMMIT_HASH)\"" wordlist/generatedwordlist.c $(LDFLAGS)

wordlist/generatedwordlist.c: wordlist/makewordlist.py src/wordlist.h wordlist/wordlist.txt
	python3 wordlist/makewordlist.py wordlist/wordlist.txt > wordlist/generatedwordlist.c

man/man1/%.1.gz: man/man1/%.1
	rm -f $@; gzip -k $<

.PHONY: clean install

install: ton man/man1/ton-push.1.gz man/man1/ton-pull.1.gz man/man1/ton.1.gz
	cp ./ton $(INSTALL_DEST_DIR)/ && mkdir -p $(INSTALL_MAN_DEST_DIR) && cp man/man1/*.gz $(INSTALL_MAN_DEST_DIR)/

clean:
	rm -f ton wordlist/generatedwordlist.c src/*.o
