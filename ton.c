#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "tonpush.h"
#include "tonpull.h"
#ifdef TON_UNIT_TESTS
#include "tontest.h"
#endif
#include "utils.h"

int main(int argc, char **argv) {
    char *verb;
    int ret = 0;

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
#ifdef TON_UNIT_TESTS
        ret = main_test(argc - 1, argv + 1);
#else
        fprintf(stderr, "ton was not compiled with CUnit support.\n");
        ret = 1;
#endif
    }
    else {
        fprintf(stderr, "Unknown command %s\nTry \"ton push\" or \"ton pull\".\n", verb);
        ret = 1;
    }

    ton_sockets_teardown();

    return ret;
}
