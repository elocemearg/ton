
CUNIT=${TON_CUNIT}

CFLAGS=-Wall -g -DUNIX=1 -std=gnu99 -Wpedantic
LDFLAGS=-lcrypto -lssl

ifeq ($(CUNIT),1)
	CFLAGS := $(CFLAGS) -DTON_UNIT_TESTS
	LDFLAGS := $(LDFLAGS) -lcunit
endif

TON_C_FILES:=$(wildcard src/*.c)
TON_H_FILES:=$(wildcard src/*.h)

TON_OBJECTS:=$(patsubst %.c,%.o,$(TON_C_FILES)) wordlist/generatedwordlist.o

ton: $(TON_OBJECTS)
	gcc -o ton $(TON_OBJECTS) $(LDFLAGS)

wordlist/generatedwordlist.c: wordlist/makewordlist.py src/wordlist.h wordlist/wordlist.txt
	wordlist/makewordlist.py wordlist/wordlist.txt > wordlist/generatedwordlist.c

clean:
	rm -f ton wordlist/generatedwordlist.c src/*.o
