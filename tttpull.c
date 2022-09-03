#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <getopt.h>

#include "tttcrypt.h"
#include "tttutils.h"
#include "tttsession.h"
#include "tttfiletransfer.h"
#include "tttdiscover.h"

enum main_pull_longopts {
    PULL_MAX_ANNOUNCEMENTS = 256,
    PULL_ANNOUNCEMENT_INTERVAL,
    PULL_PASSPHRASE,
    PULL_DISCOVER_PORT,
    PULL_MULTICAST_TTL,
    PULL_MULTICAST_ADDRESS,
    PULL_PASSPHRASE_WORDS,
};

static const struct option longopts[] = {
    { "max-announcements", 1, NULL, PULL_MAX_ANNOUNCEMENTS },
    { "announcement-interval", 1, NULL, PULL_ANNOUNCEMENT_INTERVAL },
    { "passphrase", 1, NULL, PULL_PASSPHRASE },
    { "discover-port", 1, NULL, PULL_DISCOVER_PORT },
    { "multicast-ttl", 1, NULL, PULL_MULTICAST_TTL },
    { "multicast-address", 1, NULL, PULL_MULTICAST_ADDRESS },
    { "output-dir", 1, NULL, 'o' },
    { "words", 1, NULL, PULL_PASSPHRASE_WORDS },

    { "help", 0, NULL, 'h' },
    { "verbose", 0, NULL, 'v' },

    { NULL, 0, NULL, 0 }
};

static void
print_help(FILE *f) {
    fprintf(f,
"ttt pull: receive a file or set of files over TTT\n"
"\n"
"Usage:\n"
"    ttt pull [-o outputfileordir] [other options...]\n"
"Options:\n"
"    --announcement-interval <ms>\n"
"                             Discovery broadcast interval (ms) (default 1000)\n"
"    --discover-port <port>   Specify discovery UDP port number (default %d,\n"
"                               pusher must use the same)\n"
"    -h, --help               Show this help\n"
"    --max-announcements <n>  Give up after <n> discovery announcements\n"
"                               (default 0, continue indefinitely)\n"
"    --multicast-address <a>  Announce to multicast address <a> (default\n"
"                               %s, pusher must use the same)\n"
"    --multicast-ttl <n>      Set multicast TTL to <n> (default 1)\n"
"    -o <dir>                 Destination directory for received file(s).\n"
"                               Default is the current directory. The directory\n"
"                               will be created if it doesn't exist.\n"
"    --passphrase <str>       Specify passphrase (default: prompt)\n"
"    -v, --verbose            Show extra diagnostic output\n"
,
        TTT_DEFAULT_DISCOVER_PORT, TTT_MULTICAST_RENDEZVOUS_ADDR);
}

int
main_pull(int argc, char **argv) {
    int c;
    int verbose = 0;
    int max_announcements = 0;
    int announcement_interval_ms = 1000;
    int discover_port = -1;
    int multicast_ttl = 1;
    char *passphrase = NULL;
    char *multicast_address = NULL;
    struct ttt_session sess;
    int sess_valid = 0;
    int exit_status = 0;
    char *output_dir = ".";

    while ((c = getopt_long(argc, argv, "ho:v", longopts, NULL)) != -1) {
        switch (c) {
            case PULL_MAX_ANNOUNCEMENTS:
                max_announcements = atoi(optarg);
                if (max_announcements < 0) {
                    max_announcements = 0;
                }
                break;

            case PULL_ANNOUNCEMENT_INTERVAL:
                announcement_interval_ms = atoi(optarg);
                if (announcement_interval_ms < 50) {
                    ttt_error(1, 0, "--announcement-interval: interval must be at least 50ms");
                }
                break;

            case PULL_PASSPHRASE:
                passphrase = strdup(optarg);
                break;

            case PULL_DISCOVER_PORT:
                discover_port = atoi(optarg);
                if (discover_port == 0 || discover_port > 65535) {
                    ttt_error(1, 0, "--discover-port: port number must be between 1 and 65535");
                }
                break;

            case PULL_MULTICAST_ADDRESS:
                multicast_address = optarg;
                break;

            case PULL_MULTICAST_TTL:
                multicast_ttl = atoi(optarg);
                if (multicast_ttl < 1)
                    multicast_ttl = 1;
                else if (multicast_ttl > 5)
                    ttt_error(1, 0, "--multicast-ttl: I'm not going higher than 5");
                break;

            case 'o':
                output_dir = optarg;
                break;

            case 'h':
                print_help(stdout);
                exit(0);
                break;

            case 'v':
                verbose = 1;
                break;

            default:
                exit(1);
        }
    }

    if (passphrase == NULL) {
        /* No passphrase supplied, so prompt for one. */
        fprintf(stderr, "Enter the passphrase generated or specified on the pushing side.\n");
        passphrase = ttt_prompt_passphrase("Passphrase? ");
        if (passphrase == NULL) {
            exit(1);
        }
    }

    if (ttt_discover_and_accept(multicast_address, discover_port,
                max_announcements, announcement_interval_ms, multicast_ttl,
                passphrase, strlen(passphrase), verbose, &sess) == 0) {
        sess_valid = 1;
    }
    else {
        ttt_error(0, 0, "failed to establish incoming connection");
        exit_status = 1;
    }

    if (sess_valid) {
        exit_status = (ttt_file_transfer_session(&sess, 0, output_dir, NULL, 0) != 0);
        ttt_session_destroy(&sess);
    }

    free(passphrase);

    return exit_status;
}
