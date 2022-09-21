#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>

#include "tonpush.h"
#include "tonpull.h"
#include "tontest.h"
#include "utils.h"

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
        fprintf(stderr,
"Usage:\n"
"    ton push [options] <file> ...\n"
"    ton pull [options]\n"
"Run ton push -h or ton pull -h for further help.\n");
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
    else {
        fprintf(stderr, "Unknown command %s\nTry \"ton push\" or \"ton pull\".\n", verb);
        ret = 1;
    }

    ton_sockets_teardown();

    return ret;
}