
CUNIT=1

CFLAGS=-Wall -g -DUNIX=1
LDFLAGS=-lcrypto -lssl

ifeq ($(CUNIT),1)
	CFLAGS := $(CFLAGS) -DTON_UNIT_TESTS -std=gnu99 -Wpedantic
	LDFLAGS := $(LDFLAGS) -lcunit
endif

ton: ton.c tontest.c tonpush.c tonpull.c tonpush.h tonpull.h tontest.h \
	discover.c discover.h utils.c utils.h encryption.c encryption.h \
	netif.c netif.h session.c session.h accept.c accept.h \
	protocol.c protocol.h connect.c connect.h localfs.c localfs.h \
	filetransfer.c filetransfer.h defaults.h generatedwordlist.c Makefile
	gcc $(CFLAGS) -o ton \
		ton.c tontest.c tonpush.c tonpull.c discover.c utils.c encryption.c \
		netif.c session.c accept.c protocol.c filetransfer.c connect.c \
		localfs.c generatedwordlist.c \
		$(LDFLAGS)

tondiscovertest: tondiscovertest.c discover.c discover.h \
	utils.c utils.h encryption.c encryption.h netif.c netif.h \
	session.c session.h accept.c accept.h defaults.h \
	connect.c connect.h \
	generatedwordlist.c
	gcc $(CFLAGS) -o tondiscovertest \
		tondiscovertest.c discover.c netif.c utils.c encryption.c \
		session.c accept.c connect.c generatedwordlist.c \
		$(LDFLAGS)

tonaccepttest: tonaccept.c tonsession.c tonsession.h tonutils.h tonutils.c toncrypt.h toncrypt.c
	gcc $(CFLAGS) -DTON_ACCEPT_MAIN=1 -o tonaccepttest \
		accept.c session.c utils.c encryption.c \
		$(LDFLAGS)

generatedwordlist.c: makewordlist.py wordlist.txt
	./makewordlist.py wordlist.txt > generatedwordlist.c

clean:
	rm -f ton tondiscovertest tonaccepttest generatedwordlist.c
