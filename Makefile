tttdiscovertest: tttdiscovertest.c tttdiscover.c tttdiscover.h tttutils.c tttutils.h tttcrypt.c tttcrypt.h tttnetif.c tttnetif.h
	gcc -Wall -g -o tttdiscovertest tttdiscovertest.c tttdiscover.c tttnetif.c tttutils.c tttcrypt.c -lcrypto

tttaccepttest: tttaccept.c tttsession.c tttsession.h tttutils.h tttutils.c
	gcc -Wall -g -o tttaccepttest tttaccept.c tttsession.c tttutils.c -lcrypto
