#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <getopt.h>

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
    PULL_MULTICAST_TTL,
    PULL_MULTICAST_ADDRESS,
    PULL_PASSPHRASE_WORDS,
    PULL_CONFIRM_FILE_SET,
    PULL_NO_IPV4,
    PULL_NO_IPV6,
    PULL_NO_MULTICAST,
    PULL_NO_BROADCAST
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
    { "confirm", 0, NULL, PULL_CONFIRM_FILE_SET },
    { "no-ipv4", 0, NULL, PULL_NO_IPV4 },
    { "no-ipv6", 0, NULL, PULL_NO_IPV6 },
    { "no-multicast", 0, NULL, PULL_NO_MULTICAST },
    { "no-broadcast", 0, NULL, PULL_NO_BROADCAST },

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
"    --no-broadcast           Do not announce to broadcast addresses\n"
"    --no-multicast           Do not announce to multicast addresses\n"
"    --no-ipv4                Do not use IPv4\n"
"    --no-ipv6                Do not use IPv6\n"
"    -o <dir>                 Destination directory for received file(s).\n"
"                               Default is the current directory. The directory\n"
"                               will be created if it doesn't exist.\n"
"    --passphrase <str>       Specify passphrase (default: prompt)\n"
"    -v, --verbose            Show extra diagnostic output\n"
,
        TTT_DEFAULT_DISCOVER_PORT, TTT_MULTICAST_RENDEZVOUS_ADDR);
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

int
main_pull(int argc, char **argv) {
    int c;
    int verbose = 0;
    int max_announcements = 0;
    int announcement_interval_ms = 1000;
    int discover_port = -1;
    int multicast_ttl = 0; // use default (1 for IPv4, route default for IPv6)
    char *passphrase = NULL;
    char *multicast_address = NULL;
    struct ttt_session sess;
    int sess_valid = 0;
    int exit_status = 0;
    char *output_dir = ".";
    int confirm_file_set = 0;
    char peer_addr[256] = "";
    char peer_port[20] = "";
    int address_families = TTT_IP_BOTH;
    int announce_types = TTT_ANNOUNCE_BOTH;

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
                if (multicast_ttl < 0)
                    multicast_ttl = 0;
                else if (multicast_ttl > 5)
                    ttt_error(1, 0, "--multicast-ttl: I'm not going higher than 5");
                break;

            case PULL_CONFIRM_FILE_SET:
                confirm_file_set = 1;
                break;

            case PULL_NO_IPV4:
                address_families &= ~TTT_IPV4;
                break;

            case PULL_NO_IPV6:
                address_families &= ~TTT_IPV6;
                break;

            case PULL_NO_BROADCAST:
                announce_types &= ~TTT_ANNOUNCE_BROADCAST;
                break;

            case PULL_NO_MULTICAST:
                announce_types &= ~TTT_ANNOUNCE_MULTICAST;
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

    if (address_families == 0) {
        ttt_error(1, 0, "--no-ipv4 and --no-ipv6 may not be combined");
    }

    if (announce_types == 0) {
        ttt_error(1, 0, "--no-broadcast and --no-multicast may not be combined");
    }

    if (passphrase == NULL) {
        /* No passphrase supplied, so prompt for one. */
        fprintf(stderr, "Enter the passphrase generated or specified on the pushing side.\n");
        passphrase = ttt_prompt_passphrase("Passphrase? ");
        if (passphrase == NULL) {
            exit(1);
        }
    }

    /* Discover the other endpoint with our passphrase, and let them
     * connect to us. */
    if (ttt_discover_and_accept(multicast_address, NULL, address_families,
                announce_types, discover_port, max_announcements,
                announcement_interval_ms, multicast_ttl, passphrase,
                strlen(passphrase), verbose, &sess) == 0) {
        sess_valid = 1;
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

    return exit_status;
}
