tttdiscover: tttdiscover.c tttutils.c tttutils.h tttcrypt.c tttcrypt.h
	gcc -Wall -g -o tttdiscover tttdiscover.c tttutils.c tttcrypt.c -lcrypto
