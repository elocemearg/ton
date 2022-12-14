#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <getopt.h>
#include <stdbool.h>
#include <limits.h>
#include <errno.h>
#include <unistd.h>
#include <ctype.h>

#include "encryption.h"
#include "utils.h"
#include "session.h"
#include "filetransfer.h"
#include "discover.h"

enum main_pull_longopts {
    PULL_OPTS_START = 256,
    PULL_ANNOUNCEMENT_INTERVAL,
    PULL_BROADCAST,
    PULL_CONFIRM_FILE_SET,
    PULL_DISCOVER_PORT,
    PULL_FORCE,
    PULL_HIDE_PASSPHRASE,
    PULL_INCLUDE_GLOBAL,
    PULL_IPV4,
    PULL_IPV6,
    PULL_LISTEN_PORT,
    PULL_MAX_ANNOUNCEMENTS,
    PULL_MULTICAST,
    PULL_MULTICAST_TTL,
    PULL_MULTICAST_ADDRESS_IPV4,
    PULL_MULTICAST_ADDRESS_IPV6,
    PULL_OUTPUT_FILE,
    PULL_PASSPHRASE,
    PULL_QUIET,
};

static const struct option longopts[] = {
    { "announcement-interval", 1, NULL, PULL_ANNOUNCEMENT_INTERVAL },
    { "broadcast", 0, NULL, PULL_BROADCAST },
    { "confirm-transfer", 0, NULL, PULL_CONFIRM_FILE_SET },
    { "discover-port", 1, NULL, PULL_DISCOVER_PORT },
    { "force", 0, NULL, PULL_FORCE },
    { "help", 0, NULL, 'h' },
    { "hide-passphrase", 0, NULL, PULL_HIDE_PASSPHRASE },
    { "include-global", 0, NULL, PULL_INCLUDE_GLOBAL },
    { "ipv4", 0, NULL, PULL_IPV4 },
    { "ipv6", 0, NULL, PULL_IPV6 },
    { "listen-port", 1, NULL, PULL_LISTEN_PORT },
    { "max-announcements", 1, NULL, PULL_MAX_ANNOUNCEMENTS },
    { "multicast", 0, NULL, PULL_MULTICAST },
    { "multicast-address-ipv4", 1, NULL, PULL_MULTICAST_ADDRESS_IPV4 },
    { "multicast-address-ipv6", 1, NULL, PULL_MULTICAST_ADDRESS_IPV6 },
    { "multicast-ttl", 1, NULL, PULL_MULTICAST_TTL },
    { "output-dir", 1, NULL, 'o' },
    { "output-file", 1, NULL, PULL_OUTPUT_FILE },
    { "passphrase", 1, NULL, PULL_PASSPHRASE },
    { "quiet", 0, NULL, PULL_QUIET },
    { "verbose", 0, NULL, 'v' },

    { NULL, 0, NULL, 0 }
};

struct ton_ft_cookie {
    bool replace_accept_all;
    bool replace_reject_all;
    struct ton_session *sess;
};

static void
print_help(FILE *f) {
    fprintf(f,
"ton pull: receive files over a network from someone sending them with \"ton push\"\n"
"\n"
"Usage:\n"
"    ton pull [options] [destination directory]\n"
"\n"
"The default destination directory is the current working directory. If a\n"
"destination directory is given, it will be created if it does not exist.\n"
"Use - to write all received files to standard output.\n"
"\n"
"Options:\n"
"    -4, --ipv4               Use IPv4 only, not IPv6\n"
"    -6, --ipv6               Use IPv6 only, not IPv4\n"
"    --announcement-interval <sec>\n"
"                             Discovery announcement interval (sec) (default 1.0)\n"
"    --broadcast              Only announce to broadcast addresses, not multicast\n"
"    --confirm-transfer       Confirm before starting transfer of file set\n"
"    --discover-port <port>   Specify discovery UDP port number (default %d,\n"
"                               pusher must use the same)\n"
"    -f, --force              Don't ask before replacing existing files\n"
"    -h, --help               Show this help\n"
"    --hide-passphrase        Don't show passphrase as you type at the prompt\n"
"    --include-global         Send announcements from global as well as\n"
"                               private addresses\n"
"    --listen-port <port>     Specify port to invite ton push to connect to\n"
"                               (0 = arbitrary port, default %d)\n"
"    --max-announcements <n>  Give up after <n> discovery announcements\n"
"                               (default 0, continue indefinitely)\n"
"    --multicast              Only announce to multicast addresses, not broadcast\n"
"    --multicast-address-ipv4 <a>\n"
"                             Announce to IPv4 multicast address <a> (default\n"
"                               %s, pusher must use the same)\n"
"    --multicast-address-ipv6 <a>\n"
"                             Announce to IPv6 multicast address <a> (default\n"
"                               %s)\n"
"    --multicast-ttl <n>      Set multicast TTL to <n> (default 1)\n"
"    -o <dir>                 Another way to set the destination directory.\n"
"                               -o - is equivalent to --output-file -\n"
"    --output-file <file>     Concatenate all received files to one output file\n"
"    --passphrase <str>       Specify passphrase (default: prompt)\n"
"    -q, --quiet              Don't show progress updates\n"
"    -v, --verbose            Show extra diagnostic output\n"
,
        TON_DEFAULT_DISCOVER_PORT, TON_DEFAULT_LISTEN_PORT,
        TON_MULTICAST_GROUP_IPV4, TON_MULTICAST_GROUP_IPV6);
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

static char
prompt_char_choice(const char *prompt, const char *answers, char def) {
    int answer = 0;
    int c;
    do {
        fprintf(stderr, "%s", prompt);
        answer = fgetc(stdin);
        if (answer == '\n' || answer == EOF) {
            answer = def;
        }
        else {
            answer = tolower(answer);
            /* read and discard to the end of the input line */
            while ((c = fgetc(stdin)) != '\n' && c != EOF);
        }
        if (answer != EOF && strchr(answers, (char) answer) == NULL)
            answer = 0;
    } while (!answer);
    return (char) answer;
}

static int
check_file(void *cookie, const struct ton_file *file) {
    struct ton_ft_cookie *ft_cookie = (struct ton_ft_cookie *) cookie;
    TON_STAT st;
    int stat_rc = -1;
    bool file_exists = false;

    if (ton_access(file->local_path, F_OK) == 0) {
        stat_rc = ton_stat(file->local_path, &st);
        file_exists = true;
    }
    if (file_exists) {
        /* We're receiving a file we already have, so decide what to do */
        if (ft_cookie->replace_accept_all) {
            return TON_FT_ACCEPT;
        }
        else if (ft_cookie->replace_reject_all) {
            return TON_FT_SKIP;
        }
        else {
            /* Ask the user what they want to do with this file */
            char answer;
            char timestamp_str[60];
            char size_str[20];
            struct tm tm;
            const TON_LF_CHAR *local_basename;

            if (stat_rc == 0) {
                ton_localtime_r(&st.st_mtime, &tm);
                strftime(timestamp_str, sizeof(timestamp_str), "%Y-%m-%d %H:%M:%S %Z", &tm);
                ton_size_to_str(st.st_size, size_str);
            }
            else {
                strncpy(timestamp_str, "unknown timestamp", sizeof(timestamp_str));
                strncpy(size_str, "unknown size", sizeof(size_str));
            }

            local_basename = ton_lf_basename(file->local_path);

            fprintf(stderr, "\nLocal file " TON_LF_PRINTF " already exists.\n", file->local_path);
            fprintf(stderr, "  Do you want to replace the existing file:\n");
            fprintf(stderr, "      %s  %s  " TON_LF_PRINTF "\n", timestamp_str, size_str, local_basename);

            ton_localtime_r(&file->mtime, &tm);
            strftime(timestamp_str, sizeof(timestamp_str), "%Y-%m-%d %H:%M:%S %Z", &tm);
            ton_size_to_str(file->size, size_str);

            fprintf(stderr, "  with this one?\n");
            fprintf(stderr, "      %s  %s  " TON_LF_PRINTF "\n", timestamp_str, size_str, local_basename);
            answer = prompt_char_choice(
                    "  [y] Replace the existing file with the received file.\n"
                    "  [n] Keep the existing file.\n"
                    "  [a] Replace this and all existing files from now on.\n"
                    "  [k] Keep all existing files from now on.\n"
                    "  [q] Quit the file transfer.\n"
                    "  y/n/a/k/q [y]? ",
                    "ynakq", 'y');
            switch (answer) {
                case 'a':
                    ft_cookie->replace_accept_all = true;
                case 'y':
                default:
                    return TON_FT_ACCEPT;
                case 'k':
                    ft_cookie->replace_reject_all = true;
                case 'n':
                    return TON_FT_SKIP;
                case 'q':
                    return TON_FT_ABORT;
            }
        }
    }
    else {
        /* File doesn't already exist, so accept it */
        return TON_FT_ACCEPT;
    }
}

static int
request_to_send(void *cookie, const struct ton_file *files, long file_count,
        long long total_size) {
    struct ton_ft_cookie *ft_cookie = (struct ton_ft_cookie *) cookie;
    FILE *f = stderr;
    char size_str[12];
    char line[10];
    char addr[100];
    char port[20];

    if (ton_session_get_peer_addr(ft_cookie->sess, addr, sizeof(addr), port, sizeof(port)) < 0) {
        strcpy(addr, "(unknown)");
        strcpy(port, "(unknown)");
    }

    if (files) {
        int num_files_printed = 0;
        fprintf(f, "%s is offering the following file(s):\n", addr);
        for (const struct ton_file *file = files; file; file = file->next) {
            char mode_str[12];
            file_mode_to_string(file->mode, mode_str);
            ton_size_to_str(file->size, size_str);
            fprintf(f, "%10s %6s %s\n", mode_str, size_str, file->ton_path);
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
        ton_size_to_str(total_size, size_str);
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
                "   Is \"ton push\" running on the other host?\n"
                "   Is the passphrase correct?\n",
                announcement_round_seq);
    }
    return 0;
}

int
main_pull(int argc, char **argv) {
    int c;
    int verbose = 0;
    bool quiet = false;
    int max_announcements = 0;
    double announcement_interval_sec = 1.0;
    int discover_port = -1;
    int listen_port = -1;
    int multicast_ttl = 0; // use default (1 for IPv4, route default for IPv6)
    char *passphrase = NULL;
    char *multicast_address_ipv4 = NULL, *multicast_address_ipv6 = NULL;
    struct ton_session sess;
    bool sess_valid = false;
    int exit_status = 0;
    char *output_dir = NULL;
    bool confirm_file_set = false;
    char peer_addr[256] = "";
    char peer_port[20] = "";
    int address_families = 0;
    int announce_types = 0;
    bool include_global = false;
    bool hide_passphrase = false;
    char *output_filename = NULL;
    bool confirm_replace = true;
    struct ton_discover_options opts;

    while ((c = getopt_long(argc, argv, "fho:qv46", longopts, NULL)) != -1) {
        switch (c) {
            case PULL_MAX_ANNOUNCEMENTS:
                max_announcements = atoi(optarg);
                if (max_announcements < 0) {
                    max_announcements = 0;
                }
                break;

            case PULL_ANNOUNCEMENT_INTERVAL:
                announcement_interval_sec = parse_double_or_exit(optarg, "--announcement-interval");
                if (announcement_interval_sec < 0.1) {
                    ton_error(1, 0, "--announcement-interval: interval must be at least 0.1 seconds");
                }
                /* We will need to convert this to milliseconds and pass it
                 * as an int... */
                if (announcement_interval_sec > INT_MAX / 1000) {
                    ton_error(1, 0, "--announcement-interval: value is too large (max is %d)", INT_MAX / 1000);
                }
                break;

            case PULL_PASSPHRASE:
                passphrase = strdup(optarg);
                break;

            case PULL_DISCOVER_PORT:
                discover_port = atoi(optarg);
                if (discover_port == 0 || discover_port > 65535) {
                    ton_error(1, 0, "--discover-port: port number must be between 1 and 65535");
                }
                break;

            case PULL_LISTEN_PORT:
                listen_port = atoi(optarg);
                if (listen_port < 0 || listen_port > 65535) {
                    ton_error(1, 0, "--listen-port: port number must be between 1 and 65535, or 0 for any port");
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
                    ton_error(1, 0, "--multicast-ttl: I'm not going higher than 5");
                break;

            case PULL_CONFIRM_FILE_SET:
                confirm_file_set = true;
                break;

            case 'f':
            case PULL_FORCE:
                confirm_replace = false;
                break;

            case '4':
            case PULL_IPV4:
                address_families |= TON_IPV4;
                break;

            case '6':
            case PULL_IPV6:
                address_families |= TON_IPV6;
                break;

            case PULL_BROADCAST:
                announce_types |= TON_ANNOUNCE_BROADCAST;
                break;

            case PULL_MULTICAST:
                announce_types |= TON_ANNOUNCE_MULTICAST;
                break;

            case PULL_INCLUDE_GLOBAL:
                include_global = true;
                break;

            case PULL_HIDE_PASSPHRASE:
                hide_passphrase = true;
                break;

            case 'o':
                if (!strcmp(optarg, "-")) {
                    output_filename = "-";
                }
                else {
                    output_dir = optarg;
                }
                break;

            case PULL_OUTPUT_FILE:
                output_filename = optarg;
                break;

            case PULL_QUIET:
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

    if (address_families == 0) {
        address_families = TON_IP_BOTH;
    }

    if (announce_types == 0) {
        announce_types = TON_ANNOUNCE_BOTH;
    }

    /* If a positional argument is given, it's the destination directory. */
    if (optind < argc) {
        output_dir = argv[optind++];
        if (optind < argc) {
            /* But we can't have more than one. */
            ton_error(1, 0, "%s: only one destination directory may be given", argv[optind]);
        }
        if (!strcmp(output_dir, "-")) {
            /* Special case: output directory "-" means output file is stdout */
            output_dir = NULL;
            output_filename = "-";
        }
    }

    if (output_filename != NULL && output_dir != NULL) {
        /* We can't have an output file and an output directory. */
        ton_error(1, 0, "--output-file may not be supplied if a destination directory is also supplied");
    }

    if (output_dir == NULL) {
        /* Default output directory is the current directory, unless we're
         * writing everything to a single file (--output-file) */
        output_dir = ".";
    }

    if (passphrase == NULL) {
        /* No passphrase supplied, so prompt for one. */
        fprintf(stderr, "Enter the passphrase generated or specified on the pushing side.\n");
        passphrase = ton_prompt_passphrase("Passphrase? ", hide_passphrase);
        if (passphrase == NULL) {
            exit(1);
        }
    }

    ton_discover_options_init(&opts, passphrase, strlen(passphrase));

    /* Set up opts with our options */
    if (multicast_address_ipv4)
        ton_discover_set_multicast_ipv4_address(&opts, multicast_address_ipv4);
    if (multicast_address_ipv6)
        ton_discover_set_multicast_ipv6_address(&opts, multicast_address_ipv4);
    ton_discover_set_address_families(&opts, address_families);
    ton_discover_set_announcement_types(&opts, announce_types);
    if (discover_port > 0)
        ton_discover_set_discover_port(&opts, discover_port);
    if (listen_port >= 0)
        ton_discover_set_listen_port(&opts, listen_port);
    ton_discover_set_announcements(&opts, max_announcements, (int) (1000 * announcement_interval_sec));
    ton_discover_set_multicast_ttl(&opts, multicast_ttl);
    ton_discover_set_verbose(&opts, verbose);
    ton_discover_set_include_global_addresses(&opts, include_global);
    ton_discover_set_listen_port(&opts, listen_port);
    if (!quiet) {
        ton_discover_set_sent_announcement_callback(&opts, sent_announcement, NULL);
    }

    /* Discover the other endpoint with our passphrase, and let them
     * connect to us. */
    if (ton_discover_and_accept(&opts, &sess) == 0) {
        sess_valid = true;
    }
    else {
        ton_error(0, 0, "failed to establish incoming connection");
        exit_status = 1;
    }

    if (sess_valid) {
        struct ton_file_transfer ctx;
        FILE *output_file = NULL;
        struct ton_ft_cookie cookie;

        cookie.replace_accept_all = !confirm_replace;
        cookie.replace_reject_all = false;
        cookie.sess = &sess;

        if (!quiet) {
            /* Tell the user we successfully found the other endpoint */
            if (ton_session_get_peer_addr(&sess, peer_addr, sizeof(peer_addr), peer_port, sizeof(peer_port)) < 0) {
                fprintf(stderr, "Established connection.\n");
            }
            else {
                fprintf(stderr, "Established connection from %s.\n", peer_addr);
            }
        }

        /* Set up the file transfer session as receiver... */
        ton_file_transfer_init_receiver(&ctx, output_dir);
        if (confirm_file_set) {
            ton_file_transfer_set_callback_cookie(&ctx, &cookie);
            ton_file_transfer_set_request_to_send_callback(&ctx, request_to_send);
        }
        if (confirm_replace) {
                ton_file_transfer_set_callback_cookie(&ctx, &cookie);
            ton_file_transfer_set_file_start_callback(&ctx, check_file);
        }

        /* If we're writing all received files to a single output file, open
         * that file now. */
        if (output_filename != NULL) {
            if (!strcmp(output_filename, "-")) {
                /* Write everything to stdout */
                output_file = stdout;
            }
            else {
                /* Write everything to a named file */
                output_file = fopen(output_filename, "wb");
                if (output_file == NULL) {
                    ton_error(1, errno, "%s", output_filename);
                }
            }
        }
        if (output_file != NULL) {
            ton_file_transfer_set_output_file(&ctx, output_file);
        }

        if (quiet) {
            ton_file_transfer_set_progress_callback(&ctx, NULL);
        }

        /* Run the file transfer session and receive files. */
        exit_status = (ton_file_transfer_session(&ctx, &sess) != 0);
        ton_session_destroy(&sess);
        ton_file_transfer_destroy(&ctx);

        if (output_file != NULL) {
            /* Close our output file, if we have one. */
            if (fclose(output_file) == EOF) {
                ton_error(0, errno, "%s", output_filename);
                exit_status = 1;
            }
        }
    }

    free(passphrase);

    ton_discover_options_destroy(&opts);

    return exit_status;
}
