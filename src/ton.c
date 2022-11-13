#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <openssl/crypto.h>

#include "tonpush.h"
#include "tonpull.h"
#include "tontest.h"
#include "utils.h"
#include "wordlist.h"

#ifndef TON_GIT_COMMIT_HASH
#define TON_GIT_COMMIT_HASH "unknown"
#endif

#define TON_VERSION_STRING "1.0.1"

/* Resource: licence.txt */
extern const char _binary_licence_txt_start[];
extern const char _binary_licence_txt_end[];

void
print_main_help(FILE *out) {
    fprintf(out,
"Main commands:\n"
"    ton push [options] <file> ...    # send files\n"
"    ton pull [options]               # receive files\n"
"Run ton push -h or ton pull -h for help.\n"
"\n"
"Other commands:\n"
"    ton help                         # show this help\n"
#ifdef TON_UNIT_TESTS
"    ton test                         # run unit tests\n"
#endif
"    ton version                      # show version information\n"
"    ton licence                      # show licensing information\n"
#ifdef TON_CONTAINS_OPENSSL
"    ton notices                      # show notices about third-party software\n"
#endif
    );
}

void
print_version(void) {
    printf("ton %s\n", TON_VERSION_STRING);
    printf("Copyright 2022 by Graeme Cole <graeme@greem.co.uk>\n");
    printf("Released under the 3-Clause BSD License (see \"ton licence\" for details).\n");
    printf("git commit hash: %s\n", TON_GIT_COMMIT_HASH);
    printf("This binary was compiled on %s at %s\n", __DATE__, __TIME__);
#ifdef TON_CONTAINS_OPENSSL
    printf("This binary has parts of OpenSSL compiled into it (see \"ton notices\").\n");
#endif
    printf("Using OpenSSL version: %s\n", SSLeay_version(SSLEAY_VERSION));
}

void
print_licence(void) {
    /* Print the contents of licence.txt */
    size_t length = _binary_licence_txt_end - _binary_licence_txt_start;
    size_t bytes_written = 0;

    while (bytes_written < length) {
        size_t ret = fwrite(_binary_licence_txt_start + bytes_written, 1, length - bytes_written, stdout);
        if (ret == 0) {
            fprintf(stderr, "ton: %s\n", strerror(errno));
        }
        bytes_written += ret;
    }
}

void
print_notices(void) {
#ifdef TON_CONTAINS_OPENSSL
    /* If this binary was statically built then it contains OpenSSL code in
     * binary form, so we should include the required notices in accordance
     * with the OpenSSL licence. */
    printf("This binary has parts of OpenSSL statically compiled into it.\n");
    printf("The OpenSSL license can be found here:\nhttps://www.openssl.org/source/license-openssl-ssleay.txt\n");
    printf("This product includes cryptographic software written by Eric Young (eay@cryptsoft.com).\n");
    printf("This product includes software written by Tim Hudson (tjh@cryptsoft.com).\n");
#endif
}

int main(int argc, char **argv) {
    char *verb;
    int ret = 0;

#ifdef UNIX
    /* Ignore SIGPIPE */
    struct sigaction pipeact;
    memset(&pipeact, 0, sizeof(pipeact));
    pipeact.sa_handler = SIG_IGN;
    sigaction(SIGPIPE, &pipeact, NULL);
#endif

    ton_sockets_setup();

    if (argc < 2) {
        print_main_help(stderr);
        exit(1);
    }

    verb = argv[1];
    if (!strcmp(verb, "push")) {
        ret = main_push(argc - 1, argv + 1);
    }
    else if (!strcmp(verb, "pull")) {
        ret = main_pull(argc - 1, argv + 1);
    }
    else if (!strcmp(verb, "test")) {
        ret = main_test(argc - 1, argv + 1);
    }
    else if (!strcmp(verb, "version")) {
        print_version();
    }
    else if (!strcmp(verb, "license") || !strcmp(verb, "licence")) {
        print_licence();
    }
    else if (!strcmp(verb, "notices")) {
        print_notices();
    }
    else if (!strcmp(verb, "help")) {
        print_main_help(stdout);
    }
    else {
        fprintf(stderr, "Unknown command \"%s\".\nTry \"ton push\" or \"ton pull\".\n", verb);
        ret = 1;
    }

    ton_sockets_teardown();

    ton_wordlist_free();

    return ret;
}
