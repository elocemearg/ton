CFLAGS=-Wall -g -DUNIX=1

tttdiscovertest: tttdiscovertest.c discover.c discover.h \
	utils.c utils.h encryption.c encryption.h netif.c netif.h \
	session.c session.h accept.c accept.h defaults.h \
	generatedwordlist.c
	gcc $(CFLAGS) -o tttdiscovertest \
		tttdiscovertest.c discover.c netif.c utils.c encryption.c \
		session.c accept.c generatedwordlist.c \
		-lcrypto -lssl

tttaccepttest: tttaccept.c tttsession.c tttsession.h tttutils.h tttutils.c tttcrypt.h tttcrypt.c
	gcc $(CFLAGS) -DTTT_ACCEPT_MAIN=1 -o tttaccepttest \
		accept.c session.c utils.c encryption.c \
		-lcrypto -lssl

generatedwordlist.c: makewordlist.py wordlist.txt
	./makewordlist.py wordlist.txt > generatedwordlist.c

ttt: ttt.c tttpush.c tttpull.c tttpush.h tttpull.h discover.c discover.h \
	utils.c utils.h encryption.c encryption.h netif.c netif.h \
	session.c session.h accept.c accept.h protocol.c protocol.h \
	filetransfer.c filetransfer.h defaults.h generatedwordlist.c
	gcc $(CFLAGS) -o ttt \
		ttt.c tttpush.c tttpull.c discover.c utils.c encryption.c \
		netif.c session.c accept.c protocol.c filetransfer.c \
		generatedwordlist.c \
		-lcrypto -lssl

clean:
	rm ttt tttdiscovertest tttaccepttest generatedwordlist.c
