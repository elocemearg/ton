#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <getopt.h>
#include <stdbool.h>

#include "encryption.h"
#include "utils.h"
#include "session.h"
#include "filetransfer.h"
#include "discover.h"

enum main_pull_longopts {
    PULL_MAX_ANNOUNCEMENTS = 256,
    PULL_ANNOUNCEMENT_INTERVAL,
    PULL_PASSPHRASE,
    PULL_DISCOVER_PORT,
    PULL_LISTEN_PORT,
    PULL_MULTICAST_TTL,
    PULL_MULTICAST_ADDRESS_IPV4,
    PULL_MULTICAST_ADDRESS_IPV6,
    PULL_PASSPHRASE_WORDS,
    PULL_CONFIRM_FILE_SET,
    PULL_IPV4,
    PULL_IPV6,
    PULL_MULTICAST,
    PULL_BROADCAST,
    PULL_INCLUDE_GLOBAL,
    PULL_HIDE_PASSPHRASE,
};

static const struct option longopts[] = {
    { "max-announcements", 1, NULL, PULL_MAX_ANNOUNCEMENTS },
    { "announcement-interval", 1, NULL, PULL_ANNOUNCEMENT_INTERVAL },
    { "passphrase", 1, NULL, PULL_PASSPHRASE },
    { "discover-port", 1, NULL, PULL_DISCOVER_PORT },
    { "listen-port", 1, NULL, PULL_LISTEN_PORT },
    { "multicast-ttl", 1, NULL, PULL_MULTICAST_TTL },
    { "multicast-address-ipv4", 1, NULL, PULL_MULTICAST_ADDRESS_IPV4 },
    { "multicast-address-ipv6", 1, NULL, PULL_MULTICAST_ADDRESS_IPV6 },
    { "output-dir", 1, NULL, 'o' },
    { "words", 1, NULL, PULL_PASSPHRASE_WORDS },
    { "confirm", 0, NULL, PULL_CONFIRM_FILE_SET },
    { "ipv4", 0, NULL, PULL_IPV4 },
    { "ipv6", 0, NULL, PULL_IPV6 },
    { "multicast", 0, NULL, PULL_MULTICAST },
    { "broadcast", 0, NULL, PULL_BROADCAST },
    { "include-global", 0, NULL, PULL_INCLUDE_GLOBAL },
    { "hide-passphrase", 0, NULL, PULL_HIDE_PASSPHRASE },

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
"    -4, --ipv4               Do not use IPv4\n"
"    -6, --ipv6               Do not use IPv6\n"
"    --announcement-interval <ms>\n"
"                             Discovery broadcast interval (ms) (default 1000)\n"
"    --broadcast              Do not announce to broadcast addresses\n"
"    --discover-port <port>   Specify discovery UDP port number (default %d,\n"
"                               pusher must use the same)\n"
"    -h, --help               Show this help\n"
"    --hide-passphrase        Don't show passphrase as you type at the prompt\n"
"    --include-global         Send announcements from global as well as\n"
"                               private addresses\n"
"    --max-announcements <n>  Give up after <n> discovery announcements\n"
"                               (default 0, continue indefinitely)\n"
"    --multicast              Do not announce to multicast addresses\n"
"    --multicast-address-ipv4 <a>\n"
"                             Announce to IPv4 multicast address <a> (default\n"
"                               %s, pusher must use the same)\n"
"    --multicast-address-ipv6 <a>\n"
"                             Announce to IPv6 multicast address <a> (default\n"
"                               %s)\n"
"    --multicast-ttl <n>      Set multicast TTL to <n> (default 1)\n"
"    -o <dir>                 Destination directory for received file(s).\n"
"                               Default is the current directory. The directory\n"
"                               will be created if it doesn't exist.\n"
"    --passphrase <str>       Specify passphrase (default: prompt)\n"
"    -v, --verbose            Show extra diagnostic output\n"
,
        TTT_DEFAULT_DISCOVER_PORT, TTT_MULTICAST_GROUP_IPV4, TTT_MULTICAST_GROUP_IPV6);
}

static void
file_mode_to_string(int mode, char *dest) {
    int mask = 0400;
    int pos = 0;
    static const char *mode_letters = "rwx";
    dest[pos++] = ' ';
    while (mask != 0) {
        if (mode & mask) {
            dest[pos] = mode_letters[(pos - 1) % 3];
        }
        else {
            dest[pos] = '-';
        }
        pos++;
        mask >>= 1;
    }
    dest[pos] = '\0';
}

static int
request_to_send(void *cookie, const struct ttt_file *files, long file_count,
        long long total_size) {
    struct ttt_session *sess = (struct ttt_session *) cookie;
    FILE *f = stderr;
    char size_str[12];
    char line[10];
    char addr[100];
    char port[20];

    if (ttt_session_get_peer_addr(sess, addr, sizeof(addr), port, sizeof(port)) < 0) {
        strcpy(addr, "(unknown)");
        strcpy(port, "(unknown)");
    }

    if (files) {
        int num_files_printed = 0;
        fprintf(f, "%s is offering the following file(s):\n", addr);
        for (const struct ttt_file *file = files; file; file = file->next) {
            char mode_str[12];
            file_mode_to_string(file->mode, mode_str);
            ttt_size_to_str(file->size, size_str);
            fprintf(f, "%10s %6s %s\n", mode_str, size_str, file->ttt_path);
            if (++num_files_printed >= 10) {
                fprintf(f, "...\n[%ld other files, not shown]\n", file_count - num_files_printed);
                break;
            }
        }
        fprintf(f, "\n");
    }
    else {
        fprintf(f, "%s wishes to send some files.\n", addr);
    }
    if (file_count >= 0 && total_size >= 0) {
        ttt_size_to_str(total_size, size_str);
        fprintf(f, "Total %ld files, %s.\n", file_count, size_str);
    }
    fprintf(f, "\n");
    fprintf(f, "Do you want to continue [Y/n]? ");

    if (fgets(line, 10, stdin) == NULL) {
        return -1;
    }
    else if (line[0] == 'N' || line[0] == 'n') {
        return -1;
    }
    else {
        return 0;
    }
}

static int
sent_announcement(void *cookie, int announcement_round_seq, int iface_addr_seq,
        struct sockaddr *from_addr, socklen_t from_addr_len,
        struct sockaddr *to_addr, socklen_t to_addr_len) {
    if (announcement_round_seq > 0 && announcement_round_seq % 10 == 0 && iface_addr_seq == 0) {
        fprintf(stderr, "Announced to the network %d times but no valid connection received yet.\n"
                "   Is \"ttt push\" running on the other host?\n"
                "   Is the passphrase correct?\n",
                announcement_round_seq);
    }
    return 0;
}

int
main_pull(int argc, char **argv) {
    int c;
    int verbose = 0;
    int max_announcements = 0;
    int announcement_interval_ms = 1000;
    int discover_port = -1;
    int listen_port = -1;
    int multicast_ttl = 0; // use default (1 for IPv4, route default for IPv6)
    char *passphrase = NULL;
    char *multicast_address_ipv4 = NULL, *multicast_address_ipv6 = NULL;
    struct ttt_session sess;
    bool sess_valid = 0;
    int exit_status = 0;
    char *output_dir = ".";
    bool confirm_file_set = 0;
    char peer_addr[256] = "";
    char peer_port[20] = "";
    int address_families = 0;
    int announce_types = 0;
    bool include_global = 0;
    bool hide_passphrase = 0;
    struct ttt_discover_options opts;

    while ((c = getopt_long(argc, argv, "ho:v46", longopts, NULL)) != -1) {
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

            case PULL_LISTEN_PORT:
                listen_port = atoi(optarg);
                if (listen_port < 0 || listen_port > 65535) {
                    ttt_error(1, 0, "--listen-port: port number must be between 1 and 65535, or 0 for any port");
                }
                break;

            case PULL_MULTICAST_ADDRESS_IPV4:
                multicast_address_ipv4 = optarg;
                break;

            case PULL_MULTICAST_ADDRESS_IPV6:
                multicast_address_ipv6 = optarg;
                break;

            case PULL_MULTICAST_TTL:
                multicast_ttl = atoi(optarg);
                if (multicast_ttl < 0)
                    multicast_ttl = 0;
                else if (multicast_ttl > 5)
                    ttt_error(1, 0, "--multicast-ttl: I'm not going higher than 5");
                break;

            case PULL_CONFIRM_FILE_SET:
                confirm_file_set = true;
                break;

            case '4':
            case PULL_IPV4:
                address_families |= TTT_IPV4;
                break;

            case '6':
            case PULL_IPV6:
                address_families |= TTT_IPV6;
                break;

            case PULL_BROADCAST:
                announce_types |= TTT_ANNOUNCE_BROADCAST;
                break;

            case PULL_MULTICAST:
                announce_types |= TTT_ANNOUNCE_MULTICAST;
                break;

            case PULL_INCLUDE_GLOBAL:
                include_global = true;
                break;

            case PULL_HIDE_PASSPHRASE:
                hide_passphrase = true;
                break;

            case 'o':
                output_dir = optarg;
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

    if (address_families == 0) {
        address_families = TTT_IP_BOTH;
    }

    if (announce_types == 0) {
        announce_types = TTT_ANNOUNCE_BOTH;
    }

    if (passphrase == NULL) {
        /* No passphrase supplied, so prompt for one. */
        fprintf(stderr, "Enter the passphrase generated or specified on the pushing side.\n");
        passphrase = ttt_prompt_passphrase("Passphrase? ", hide_passphrase);
        if (passphrase == NULL) {
            exit(1);
        }
    }

    ttt_discover_options_init(&opts, passphrase, strlen(passphrase));

    /* Set up opts with our options */
    if (multicast_address_ipv4)
        ttt_discover_set_multicast_ipv4_address(&opts, multicast_address_ipv4);
    if (multicast_address_ipv6)
        ttt_discover_set_multicast_ipv6_address(&opts, multicast_address_ipv4);
    ttt_discover_set_address_families(&opts, address_families);
    ttt_discover_set_announcement_types(&opts, announce_types);
    if (discover_port > 0)
        ttt_discover_set_discover_port(&opts, discover_port);
    if (listen_port >= 0)
        ttt_discover_set_listen_port(&opts, listen_port);
    ttt_discover_set_announcements(&opts, max_announcements, announcement_interval_ms);
    ttt_discover_set_multicast_ttl(&opts, multicast_ttl);
    ttt_discover_set_verbose(&opts, verbose);
    ttt_discover_set_include_global_addresses(&opts, include_global);
    ttt_discover_set_listen_port(&opts, listen_port);
    ttt_discover_set_sent_announcement_callback(&opts, sent_announcement, NULL);

    /* Discover the other endpoint with our passphrase, and let them
     * connect to us. */
    if (ttt_discover_and_accept(&opts, &sess) == 0) {
        sess_valid = true;
    }
    else {
        ttt_error(0, 0, "failed to establish incoming connection");
        exit_status = 1;
    }

    if (sess_valid) {
        struct ttt_file_transfer ctx;

        /* Announce that we successfully found the other endpoint */
        if (ttt_session_get_peer_addr(&sess, peer_addr, sizeof(peer_addr), peer_port, sizeof(peer_port)) < 0) {
            fprintf(stderr, "Established connection.\n");
        }
        else {
            fprintf(stderr, "Established connection from %s.\n", peer_addr);
        }

        /* Set up the file transfer session as receiver... */
        ttt_file_transfer_init_receiver(&ctx, output_dir);
        if (confirm_file_set) {
            ttt_file_transfer_set_callback_cookie(&ctx, &sess);
            ttt_file_transfer_set_request_to_send_callback(&ctx, request_to_send);
        }

        /* Run the file transfer session and receive files. */
        exit_status = (ttt_file_transfer_session(&ctx, &sess) != 0);
        ttt_session_destroy(&sess);
        ttt_file_transfer_destroy(&ctx);
    }

    free(passphrase);

    ttt_discover_options_destroy(&opts);

    return exit_status;
}
