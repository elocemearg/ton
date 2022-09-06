#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <getopt.h>
#include <unistd.h>
#include <errno.h>

#ifdef WINDOWS
#include <winsock2.h>
#include <winsock.h>
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#endif

#include "encryption.h"
#include "utils.h"
#include "session.h"
#include "filetransfer.h"
#include "discover.h"

enum main_push_longopts {
    PUSH_PASSPHRASE = 256,
    PUSH_DISCOVER_PORT,
    PUSH_MULTICAST_ADDRESS,
    PUSH_SEND_FULL_METADATA
};

static const struct option longopts[] = {
    { "passphrase", 1, NULL, PUSH_PASSPHRASE },
    { "discover-port", 1, NULL, PUSH_DISCOVER_PORT },
    { "multicast-address", 1, NULL, PUSH_MULTICAST_ADDRESS },
    { "send-full-metadata", 0, NULL, PUSH_SEND_FULL_METADATA },
    { "words", 1, NULL, 'w' },
    { "help", 0, NULL, 'h' },
    { "verbose", 0, NULL, 'v' },

    { NULL, 0, NULL, 0 }
};

static void
print_help(FILE *f) {
    fprintf(f,
"ttt push: send a file or set of files over TTT\n"
"\n"
"Usage:\n"
"    ttt push [options] files...\n"
"Options:\n"
"    --discover-port <port>   Specify discovery UDP port number (default %d,\n"
"                               puller must use the same)\n"
"    --help                   Show this help\n"
"    --multicast-address <a>  Specify discovery multicast address (default\n"
"                               %s, puller must use the same)\n"
"    --passphrase <str>       Specify passphrase (default: auto-generate)\n"
"    --send-full-metadata     Send full metadata to receiver before transfer\n"
"    -w, --words <count>      Generate passphrase of <count> words (default 4)\n"
"    -v, --verbose            Show extra diagnostic output\n"
,
        TTT_DEFAULT_DISCOVER_PORT, TTT_MULTICAST_RENDEZVOUS_ADDR);
}

static void
listening_callback(void *cookie) {
    if (cookie != NULL) {
        /* Tell the user what passphrase we generated, now that everything
         * else is set up. If we generated the passphrase rather than having
         * it specified by the user, then we asked ttt_discover_and_connect to
         * pass our passphrase as the cookie. */
        fprintf(stderr, "On the destination host, run:\n    ttt pull\nand enter this passphrase:\n");
        fprintf(stderr, "    %s\n", (char *) cookie);
    }
    fprintf(stderr, "\nWaiting for announcement from the destination...\n");
}

static void
received_announcement_callback(void *cookie, const struct sockaddr *addr,
        socklen_t addr_len, int valid, int invitation_port) {
    int verbose = *(int *) cookie;
    char peer_addr_str[256] = "?";
    char peer_port_str[20] = "?";
    int rc = 0;

    if (valid || verbose) {
        rc = getnameinfo(addr, addr_len, peer_addr_str, sizeof(peer_addr_str),
                peer_port_str, sizeof(peer_port_str), NI_NUMERICHOST | NI_NUMERICSERV);
        if (rc != 0) {
            ttt_error(0, 0, "getnameinfo: %s", gai_strerror(rc));
        }
    }
    if (valid) {
        fprintf(stderr, "Found %s, invitation port %d\n", peer_addr_str, invitation_port);
    }
    else if (verbose) {
        fprintf(stderr, "Rejected message from %s\n", peer_addr_str);
    }
}

int
main_push(int argc, char **argv) {
    int c;
    char *passphrase = NULL;
    char *multicast_address = NULL;
    int discover_port = -1;
    int passphrase_word_count = 4;
    char **files_to_push = NULL;
    int num_files_to_push = 0;
    int exit_status = 0;
    int verbose = 0;
    struct ttt_session sess;
    int sess_valid = 0;
    int send_full_metadata = 0;
    char peer_addr[256] = "";
    char peer_port[20] = "";
    int generated_passphrase = 0;

    while ((c = getopt_long(argc, argv, "hvw:", longopts, NULL)) != -1) {
        switch (c) {
            case PUSH_PASSPHRASE:
                passphrase = strdup(optarg);
                break;

            case PUSH_DISCOVER_PORT:
                discover_port = atoi(optarg);
                if (discover_port == 0 || discover_port > 65535) {
                    ttt_error(1, 0, "--discover-port: port number must be between 1 and 65535");
                }
                break;

            case PUSH_MULTICAST_ADDRESS:
                multicast_address = optarg;
                break;

            case PUSH_SEND_FULL_METADATA:
                send_full_metadata = 1;
                break;

            case 'w':
                passphrase_word_count = atoi(optarg);
                if (passphrase_word_count < 1)
                    passphrase_word_count = 1;
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

    if (optind >= argc) {
        print_help(stderr);
        exit(1);
    }

    files_to_push = argv + optind;
    num_files_to_push = argc - optind;

    /* Quick sanity check on the named paths: does each one exist? */
    for (int i = 0; i < num_files_to_push; ++i) {
        if (access(files_to_push[i], F_OK) != 0) {
            ttt_error(0, errno, "%s", files_to_push[i]);
            exit_status = 1;
        }
    }
    if (exit_status != 0) {
        exit(exit_status);
    }

    /* If we haven't been given a passphrase, generate one. */
    if (passphrase == NULL) {
        passphrase = ttt_generate_passphrase(passphrase_word_count);
        if (passphrase == NULL) {
            ttt_error(1, 0, "failed to generate passphrase");
        }
        generated_passphrase = 1;
    }

    /* Discover the other endpoint on our network with our passphrase, and
     * connect to it. */
    if (ttt_discover_and_connect(multicast_address, discover_port,
                passphrase, strlen(passphrase), verbose,
                listening_callback, generated_passphrase ? passphrase : NULL,
                received_announcement_callback, &verbose, &sess) == 0) {
        sess_valid = 1;
    }
    else {
        ttt_error(0, 0, "failed to establish connection");
        exit_status = 1;
    }

    if (sess_valid) {
        struct ttt_file_transfer ctx;

        /* Announce that we successfully found the other endpoint */
        if (ttt_session_get_peer_addr(&sess, peer_addr, sizeof(peer_addr), peer_port, sizeof(peer_port)) < 0) {
            fprintf(stderr, "Established connection.\n");
        }
        else {
            fprintf(stderr, "Established connection to %s port %s.\n", peer_addr, peer_port);
        }

        /* Set up the file transfer session as sender */
        ttt_file_transfer_init_sender(&ctx, (const char **) files_to_push, num_files_to_push);
        ttt_file_transfer_set_send_full_metadata(&ctx, send_full_metadata);

        /* Run the file transfer session and send our files */
        exit_status = (ttt_file_transfer_session(&ctx, &sess) != 0);
        ttt_session_destroy(&sess);
        ttt_file_transfer_destroy(&ctx);
    }

    free(passphrase);

    return exit_status;
}
