#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <getopt.h>
#include <unistd.h>
#include <errno.h>
#include <stdbool.h>
#include <limits.h>

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
    PUSH_OPTS_START = 256,
    PUSH_DISCOVER_PORT,
    PUSH_HIDE_PASSPHRASE,
    PUSH_INCLUDE_GLOBAL,
    PUSH_IPV4,
    PUSH_IPV6,
    PUSH_MULTICAST_ADDRESS_IPV4,
    PUSH_MULTICAST_ADDRESS_IPV6,
    PUSH_PASSPHRASE,
    PUSH_PROMPT_PASSPHRASE,
    PUSH_QUIET,
    PUSH_SEND_FULL_METADATA,
    PUSH_TIMEOUT,
};

static const struct option longopts[] = {
    { "discover-port", 1, NULL, PUSH_DISCOVER_PORT },
    { "help", 0, NULL, 'h' },
    { "hide-passphrase", 0, NULL, PUSH_HIDE_PASSPHRASE },
    { "include-global", 0, NULL, PUSH_INCLUDE_GLOBAL },
    { "ipv4", 0, NULL, PUSH_IPV4 },
    { "ipv6", 0, NULL, PUSH_IPV6 },
    { "multicast-address-ipv4", 1, NULL, PUSH_MULTICAST_ADDRESS_IPV4 },
    { "multicast-address-ipv6", 1, NULL, PUSH_MULTICAST_ADDRESS_IPV6 },
    { "passphrase", 1, NULL, PUSH_PASSPHRASE },
    { "prompt-passphrase", 0, NULL, PUSH_PROMPT_PASSPHRASE },
    { "quiet", 0, NULL, PUSH_QUIET },
    { "send-full-metadata", 0, NULL, PUSH_SEND_FULL_METADATA },
    { "timeout", 1, NULL, PUSH_TIMEOUT },
    { "verbose", 0, NULL, 'v' },
    { "words", 1, NULL, 'w' },

    { NULL, 0, NULL, 0 }
};

static void
print_help(FILE *f) {
    fprintf(f,
"ton push: send a set of files or directories over the network\n"
"\n"
"Usage:\n"
"    ton push [options] files...\n"
"Options:\n"
"    -4, --ipv4               Use IPv4 only, not IPv6\n"
"    -6, --ipv6               Use IPv6 only, not IPv4\n"
"    --discover-port <port>   Specify discovery UDP port number (default %d,\n"
"                               puller must use the same)\n"
"    -h, --help               Show this help\n"
"    --hide-passphrase        Don't show passphrase as you type at the prompt\n"
"    --include-global         Listen for announcements on global as well as\n"
"                               private IP addresses\n"
"    --multicast-address-ipv4 <a>\n"
"                             Specify discovery IPv4 multicast address (default\n"
"                               %s, puller must use the same)\n"
"    --multicast-address-ipv6 <a>\n"
"                             Specify discovery IPv6 multicast address (default\n"
"                               %s)\n"
"    --passphrase <str>       Specify passphrase (default: auto-generate)\n"
"    --prompt-passphrase      Prompt for passphrase rather than generating it\n"
"    --send-full-metadata     Send full metadata to receiver before transfer\n"
"    -t, --timeout <sec>      Time out if no connection established\n"
"    -w, --words <count>      Generate passphrase of <count> words (default 4)\n"
"    -v, --verbose            Show extra diagnostic output\n"
,
        TON_DEFAULT_DISCOVER_PORT, TON_MULTICAST_GROUP_IPV4, TON_MULTICAST_GROUP_IPV6);
}


static void
report_generated_passphrase(const char *passphrase) {
    if (passphrase != NULL) {
        /* Tell the user what passphrase we generated.
         * If we generated the passphrase rather than having it specified by
         * the user, then we asked ton_discover_and_connect to pass our
         * passphrase as the cookie. */
        fprintf(stderr, "On the destination host, run:\n    ton pull\nand enter this passphrase:\n");
        fprintf(stderr, "    %s\n", passphrase);
    }
}

static void
quiet_listening_callback(void *cookie) {
    report_generated_passphrase((const char *) cookie);
}

static void
listening_callback(void *cookie) {
    report_generated_passphrase((const char *) cookie);
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
            ton_error(0, 0, "getnameinfo: %s", gai_strerror(rc));
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
    bool quiet = false;
    struct ton_session sess;
    bool sess_valid = false;
    bool send_full_metadata = false;
    char peer_addr[256] = "";
    char peer_port[20] = "";
    bool generated_passphrase = 0;
    int address_families = 0;
    bool include_global = 0;
    bool prompt_for_passphrase = 0;
    bool hide_passphrase = 0;
    double connect_timeout_sec = 0;
    struct ton_discover_options opts;

    while ((c = getopt_long(argc, argv, "hqvt:w:46", longopts, NULL)) != -1) {
        switch (c) {
            case PUSH_PASSPHRASE:
                passphrase = strdup(optarg);
                break;

            case PUSH_DISCOVER_PORT:
                discover_port = atoi(optarg);
                if (discover_port == 0 || discover_port > 65535) {
                    ton_error(1, 0, "--discover-port: port number must be between 1 and 65535");
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
                address_families |= TON_IPV4;
                break;

            case '6':
            case PUSH_IPV6:
                address_families |= TON_IPV6;
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

            case 't':
            case PUSH_TIMEOUT:
                connect_timeout_sec = parse_double_or_exit(optarg, "--timeout");
                if (connect_timeout_sec < 0) {
                    ton_error(1, 0, "--timeout: argument must not be negative");
                }
                if (connect_timeout_sec > INT_MAX / 1000) {
                    ton_error(1, 0, "--timeout: value is too large (max is %d)", INT_MAX / 1000);
                }
                break;

            case PUSH_QUIET:
            case 'q':
                quiet = true;
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
	fprintf(stderr, "ton push: send files over the network to someone running \"ton pull\".\n");
        fprintf(stderr, "Usage is:\n    ton push [options] <filename> ...\nUse -h for help.\n");
        exit(1);
    }

    if (address_families == 0) {
        address_families = TON_IP_BOTH;
    }

    files_to_push = argv + optind;
    num_files_to_push = argc - optind;

    /* Quick sanity check on the named paths: does each one exist?
     * "-" is a special case meaning stdin. */
    for (int i = 0; i < num_files_to_push; ++i) {
        if (strcmp(files_to_push[i], "-") != 0 && access(files_to_push[i], F_OK) != 0) {
            ton_error(0, errno, "%s", files_to_push[i]);
            exit_status = 1;
        }
    }
    if (exit_status != 0) {
        exit(exit_status);
    }

    /* If we haven't been given a passphrase, generate or prompt for one. */
    if (passphrase == NULL) {
        if (prompt_for_passphrase) {
            passphrase = ton_prompt_passphrase("Choose a passphrase: ", hide_passphrase);
            if (hide_passphrase) {
                char *confirmed;
                confirmed = ton_prompt_passphrase("Confirm passphrase: ", hide_passphrase);
                if (strcmp(passphrase, confirmed)) {
                    ton_error(1, 0, "passphrase and confirmation did not match");
                }
                free(confirmed);
            }
        }
        else {
            passphrase = ton_generate_passphrase(passphrase_word_count);
            if (passphrase == NULL) {
                ton_error(1, 0, "failed to generate passphrase");
            }
            generated_passphrase = 1;
        }
    }

    ton_discover_options_init(&opts, passphrase, strlen(passphrase));
    if (multicast_address_ipv4)
        ton_discover_set_multicast_ipv4_address(&opts, multicast_address_ipv4);
    if (multicast_address_ipv6)
        ton_discover_set_multicast_ipv6_address(&opts, multicast_address_ipv6);
    ton_discover_set_address_families(&opts, address_families);
    ton_discover_set_discover_port(&opts, discover_port);
    ton_discover_set_verbose(&opts, verbose);
    ton_discover_set_listening_callback(&opts,
            quiet ? quiet_listening_callback : listening_callback,
            generated_passphrase ? passphrase : NULL);
    ton_discover_set_include_global_addresses(&opts, include_global);
    ton_discover_set_connect_timeout(&opts, (int)(connect_timeout_sec * 1000));
    if (!quiet) {
        ton_discover_set_received_announcement_callback(&opts,
                received_announcement_callback, &verbose);
    }

    /* Discover the other endpoint on our network with our passphrase, and
     * connect to it. */
    if (ton_discover_and_connect(&opts, &sess) == 0) {
        sess_valid = true;
    }
    else {
        ton_error(0, 0, "failed to establish connection");
        exit_status = 1;
    }

    if (sess_valid) {
        struct ton_file_transfer ctx;

        if (!quiet) {
            /* Tell the user we successfully found the other endpoint */
            if (ton_session_get_peer_addr(&sess, peer_addr, sizeof(peer_addr), peer_port, sizeof(peer_port)) < 0) {
                fprintf(stderr, "Established connection.\n");
            }
            else {
                fprintf(stderr, "Established connection to %s port %s.\n", peer_addr, peer_port);
            }
        }

        /* Set up the file transfer session as sender */
        ton_file_transfer_init_sender(&ctx, (const char **) files_to_push, num_files_to_push);
        ton_file_transfer_set_send_full_metadata(&ctx, send_full_metadata);

        if (quiet) {
            ton_file_transfer_set_progress_callback(&ctx, NULL);
        }

        /* Run the file transfer session and send our files */
        exit_status = (ton_file_transfer_session(&ctx, &sess) != 0);
        ton_session_destroy(&sess);
        ton_file_transfer_destroy(&ctx);
    }

    ton_discover_options_destroy(&opts);

    free(passphrase);

    return exit_status;
}
