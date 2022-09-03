#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "tttpush.h"
#include "tttpull.h"

int main(int argc, char **argv) {
    char *verb;

    if (argc < 2) {
        fprintf(stderr,
"Usage:\n"
"    ttt push [options] <file> ...\n"
"    ttt pull [options]\n"
"Run ttt push -h or ttt pull -h for further help.\n");
        exit(1);
    }

    verb = argv[1];
    if (!strcmp(verb, "push")) {
        return main_push(argc - 1, argv + 1);
    }
    else if (!strcmp(verb, "pull")) {
        return main_pull(argc - 1, argv + 1);
    }
    else {
        fprintf(stderr, "Unknown command %s\nTry \"ttt push\" or \"ttt pull\".\n", verb);
    }
    return 1;
}
