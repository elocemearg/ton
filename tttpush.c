#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <getopt.h>
#include <unistd.h>
#include <errno.h>
#include <stdbool.h>

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
    PUSH_MULTICAST_ADDRESS_IPV4,
    PUSH_MULTICAST_ADDRESS_IPV6,
    PUSH_SEND_FULL_METADATA,
    PUSH_IPV4,
    PUSH_IPV6,
    PUSH_INCLUDE_GLOBAL,
    PUSH_PROMPT_PASSPHRASE,
    PUSH_HIDE_PASSPHRASE,
};

static const struct option longopts[] = {
    { "passphrase", 1, NULL, PUSH_PASSPHRASE },
    { "discover-port", 1, NULL, PUSH_DISCOVER_PORT },
    { "include-global", 0, NULL, PUSH_INCLUDE_GLOBAL },
    { "multicast-address-ipv4", 1, NULL, PUSH_MULTICAST_ADDRESS_IPV4 },
    { "multicast-address-ipv6", 1, NULL, PUSH_MULTICAST_ADDRESS_IPV6 },
    { "send-full-metadata", 0, NULL, PUSH_SEND_FULL_METADATA },
    { "ipv4", 0, NULL, PUSH_IPV4 },
    { "ipv6", 0, NULL, PUSH_IPV6 },
    { "words", 1, NULL, 'w' },
    { "prompt-passphrase", 0, NULL, PUSH_PROMPT_PASSPHRASE },
    { "hide-passphrase", 0, NULL, PUSH_HIDE_PASSPHRASE },
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
"    -4, --ipv4               Use IPv4 and not IPv6\n"
"    -6, --ipv6               Use IPv6 and not IPv4\n"
"    --discover-port <port>   Specify discovery UDP port number (default %d,\n"
"                               puller must use the same)\n"
"    --help                   Show this help\n"
"    --hide-passphrase        Don't show passphrase as you type at the prompt\n"
"    --include-global         Listen for announcements on global as well as\n"
"                               private IP addresses\n"
"    --multicast-address-ipv4 <a>\n"
"                             Specify discovery IPv4 multicast address (default\n"
"                               %s, puller must use the same)\n"
"    --multicast-address-ipv6 <a>\n"
"                             Specify discovery IPv6 multicast address (default\n"
"                               %s, puller must use the same)\n"
"    --passphrase <str>       Specify passphrase (default: auto-generate)\n"
"    --prompt-passphrase      Prompt for passphrase rather than generating it\n"
"    --send-full-metadata     Send full metadata to receiver before transfer\n"
"    -w, --words <count>      Generate passphrase of <count> words (default 4)\n"
"    -v, --verbose            Show extra diagnostic output\n"
,
        TTT_DEFAULT_DISCOVER_PORT, TTT_MULTICAST_GROUP_IPV4, TTT_MULTICAST_GROUP_IPV6);
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

    if (verbose) {
        rc = getnameinfo(addr, addr_len, peer_addr_str, sizeof(peer_addr_str),
                peer_port_str, sizeof(peer_port_str), NI_NUMERICHOST | NI_NUMERICSERV);
        if (rc != 0) {
            ttt_error(0, 0, "getnameinfo: %s", gai_strerror(rc));
        }
        if (valid) {
            fprintf(stderr, "Found %s, attempting connection to port %d...\n", peer_addr_str, invitation_port);
        }
        else {
            fprintf(stderr, "Rejected message from %s\n", peer_addr_str);
        }
    }
}

int
main_push(int argc, char **argv) {
    int c;
    char *passphrase = NULL;
    char *multicast_address_ipv4 = NULL, *multicast_address_ipv6 = NULL;
    int discover_port = -1;
    int passphrase_word_count = 4;
    char **files_to_push = NULL;
    int num_files_to_push = 0;
    int exit_status = 0;
    int verbose = 0;
    struct ttt_session sess;
    bool sess_valid = false;
    bool send_full_metadata = false;
    char peer_addr[256] = "";
    char peer_port[20] = "";
    bool generated_passphrase = 0;
    int address_families = 0;
    bool include_global = 0;
    bool prompt_for_passphrase = 0;
    bool hide_passphrase = 0;
    struct ttt_discover_options opts;

    while ((c = getopt_long(argc, argv, "hvw:46", longopts, NULL)) != -1) {
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

            case PUSH_MULTICAST_ADDRESS_IPV4:
                multicast_address_ipv4 = optarg;
                break;

            case PUSH_MULTICAST_ADDRESS_IPV6:
                multicast_address_ipv6 = optarg;
                break;

            case PUSH_SEND_FULL_METADATA:
                send_full_metadata = true;
                break;

            case 'w':
                passphrase_word_count = atoi(optarg);
                if (passphrase_word_count < 1)
                    passphrase_word_count = 1;
                break;

            case '4':
            case PUSH_IPV4:
                address_families |= TTT_IPV4;
                break;

            case '6':
            case PUSH_IPV6:
                address_families |= TTT_IPV6;
                break;

            case PUSH_INCLUDE_GLOBAL:
                include_global = true;
                break;

            case PUSH_PROMPT_PASSPHRASE:
                prompt_for_passphrase = true;
                break;

            case PUSH_HIDE_PASSPHRASE:
                hide_passphrase = true;
                break;

            case 'h':
                print_help(stdout);
                exit(0);
                break;

            case 'v':
                verbose++;
                break;

            default:
                exit(1);
        }
    }

    if (optind >= argc) {
        print_help(stderr);
        exit(1);
    }

    if (address_families == 0) {
        address_families = TTT_IP_BOTH;
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

    /* If we haven't been given a passphrase, generate or prompt for one. */
    if (passphrase == NULL) {
        if (prompt_for_passphrase) {
            passphrase = ttt_prompt_passphrase("Choose a passphrase: ", hide_passphrase);
            if (hide_passphrase) {
                char *confirmed;
                confirmed = ttt_prompt_passphrase("Confirm passphrase: ", hide_passphrase);
                if (strcmp(passphrase, confirmed)) {
                    ttt_error(1, 0, "passphrase and confirmation did not match");
                }
                free(confirmed);
            }
        }
        else {
            passphrase = ttt_generate_passphrase(passphrase_word_count);
            if (passphrase == NULL) {
                ttt_error(1, 0, "failed to generate passphrase");
            }
            generated_passphrase = 1;
        }
    }

    ttt_discover_options_init(&opts, passphrase, strlen(passphrase));
    if (multicast_address_ipv4)
        ttt_discover_set_multicast_ipv4_address(&opts, multicast_address_ipv4);
    if (multicast_address_ipv6)
        ttt_discover_set_multicast_ipv6_address(&opts, multicast_address_ipv6);
    ttt_discover_set_address_families(&opts, address_families);
    ttt_discover_set_discover_port(&opts, discover_port);
    ttt_discover_set_verbose(&opts, verbose);
    ttt_discover_set_listening_callback(&opts, listening_callback,
            generated_passphrase ? passphrase : NULL);
    ttt_discover_set_received_announcement_callback(&opts,
            received_announcement_callback, &verbose);
    ttt_discover_set_include_global_addresses(&opts, include_global);

    /* Discover the other endpoint on our network with our passphrase, and
     * connect to it. */
    if (ttt_discover_and_connect(&opts, &sess) == 0) {
        sess_valid = true;
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

    ttt_discover_options_destroy(&opts);

    free(passphrase);

    return exit_status;
}
