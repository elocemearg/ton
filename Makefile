tttdiscovertest: tttdiscovertest.c tttdiscover.c tttdiscover.h \
	tttutils.c tttutils.h tttcrypt.c tttcrypt.h tttnetif.c tttnetif.h \
	tttsession.c tttsession.h tttaccept.c tttaccept.h \
	generatedwordlist.c
	gcc -Wall -g -o tttdiscovertest \
		tttdiscovertest.c tttdiscover.c tttnetif.c tttutils.c tttcrypt.c \
		tttsession.c tttaccept.c generatedwordlist.c \
		-lcrypto -lssl

tttaccepttest: tttaccept.c tttsession.c tttsession.h tttutils.h tttutils.c tttcrypt.h tttcrypt.c
	gcc -Wall -DTTT_ACCEPT_MAIN=1 -g -o tttaccepttest \
		tttaccept.c tttsession.c tttutils.c tttcrypt.c \
		-lcrypto -lssl

generatedwordlist.c: makewordlist.py wordlist.txt
	./makewordlist.py wordlist.txt > generatedwordlist.c

clean:
	rm tttdiscovertest tttaccepttest generatedwordlist.c
