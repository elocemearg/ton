
CUNIT=${TON_CUNIT}

CC=gcc
MINGW_CC=x86_64-w64-mingw32-gcc
CFLAGS=-Wall -g -std=gnu99
LDFLAGS=-lssl -lcrypto
INSTALL_DEST_DIR=/usr/local/bin
INSTALL_MAN_DEST_DIR=/usr/local/share/man/man1

# Special note for building the Windows executable...
# If we're building ton.exe, the environment variable MINGW_OPENSSL_ROOT
# must be set externally. The value must be the path to your MinGW OpenSSL
# build. Additionally, if we're building ton.exe with CUNIT=1, we need the
# environment variable MINGW_CUNIT_ROOT set to the path to the MinGW CUnit
# build.

ifeq ($(CUNIT),1)
	# If we're building the unit tests, we also need libcunit.
	CFLAGS := $(CFLAGS) -DTON_UNIT_TESTS
	LDFLAGS := $(LDFLAGS) -lcunit
	MINGW_LINK_CUNIT_PATH := "-L$(MINGW_CUNIT_ROOT)/install/lib"
	MINGW_CUNIT_INCLUDE := -I "$(MINGW_CUNIT_ROOT)/install/include"
else
	# If we're not building the unit tests, still set MINGW_CUNIT_ROOT to "."
	# because if we leave it blank the ton.exe recipe will think we need cunit
	# but don't have it.
	MINGW_CUNIT_ROOT := "."
endif

MINGW_OPENSSL_INCLUDE := -I "$(MINGW_OPENSSL_ROOT)/include"

TON_C_FILES:=$(wildcard src/*.c)
TON_H_FILES:=$(wildcard src/*.h)
GIT_COMMIT_HASH:=$(shell git rev-parse HEAD || echo unknown)

# Linux executable: build with TON_C_FILES and the word list file.
ton: $(TON_C_FILES) $(TON_H_FILES) src/wordlist.txt licence.txt
	$(CC) $(CFLAGS) -Wpedantic -DUNIX=1 \
		-DTON_GIT_COMMIT_HASH="\"$(GIT_COMMIT_HASH)\"" \
		-o ton \
		$(TON_C_FILES) \
		-Wl,--format=binary -Wl,src/wordlist.txt -Wl,licence.txt -Wl,--format=default \
		$(LDFLAGS)

# Windows executable: check that MINGW_OPENSSL_ROOT and MINGW_CUNIT_ROOT are
# set (MINGW_CUNIT_ROOT will be the dummy "." if we're not actually building
# the unit tests). If they are, build a static executable for Windows.
ton.exe: $(TON_C_FILES) $(TON_H_FILES) src/wordlist.txt licence.txt
ifndef MINGW_OPENSSL_ROOT
	$(error "ton for Windows requires a MinGW-compiled OpenSSL library. You need to build OpenSSL with MinGW, then set MINGW_OPENSSL_ROOT to the directory containing libcrypto.a and libssl.a, then rerun this make.")
else ifndef MINGW_CUNIT_ROOT
	$(error "You need to build CUnit with MinGW, then set MINGW_CUNIT_ROOT to the top-level directory containing install/lib/libcunit.a, then rerun this make.")
else
	$(MINGW_CC) $(CFLAGS) -DWINDOWS=1 -DTON_CONTAINS_OPENSSL=1 \
		-DTON_GIT_COMMIT_HASH="\"$(GIT_COMMIT_HASH)\"" \
		-static \
		$(MINGW_OPENSSL_INCLUDE) $(MINGW_CUNIT_INCLUDE) \
		-o ton.exe \
		$(TON_C_FILES) \
		-Wl,--format=binary -Wl,src/wordlist.txt -Wl,licence.txt -Wl,--format=default \
		-L$(MINGW_OPENSSL_ROOT) $(MINGW_LINK_CUNIT_PATH) \
		$(LDFLAGS) -liphlpapi -lws2_32
endif

# Man pages need to be gzipped before being copied to $(INSTALL_MAN_DEST_DIR)
man/man1/%.1.gz: man/man1/%.1
	rm -f $@; gzip -k $<

.PHONY: clean install

install: ton man/man1/ton-push.1.gz man/man1/ton-pull.1.gz man/man1/ton.1.gz
	cp ./ton $(INSTALL_DEST_DIR)/ && mkdir -p $(INSTALL_MAN_DEST_DIR) && cp man/man1/*.gz $(INSTALL_MAN_DEST_DIR)/

clean:
	rm -f ton ton.exe
