#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <getopt.h>
#include <error.h>
#include <errno.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <termios.h>
#include <signal.h>

#include "tttdiscover.h"
#include "tttaccept.h"
#include "tttsession.h"
#include "tttwordlist.h"
#include "tttcrypt.h"

static char *
read_passphrase(void) {
    int c;
    int buf_size = 80;
    int buf_pos = 0;
    struct termios t;
    char *buf = malloc(buf_size);

    fprintf(stderr, "Enter passphrase: ");

    /* Switch off terminal echo */
    if (tcgetattr(0, &t) < 0) {
        error(1, errno, "tcgetattr");
    }
    t.c_lflag &= ~ECHO;
    if (tcsetattr(0, TCSANOW, &t) < 0) {
        error(1, errno, "tcsetattr");
    }

    /* Read a single line */
    while ((c = fgetc(stdin)) != '\n') {
        if (c != '\r') {
            buf[buf_pos++] = (char) c;
            if (buf_pos >= buf_size) {
                buf = realloc(buf, buf_size *= 2);
                if (buf == NULL) {
                    error(1, errno, "realloc");
                }
            }
        }
    }
    buf[buf_pos] = '\0';

    /* Switch terminal echo back on */
    t.c_lflag |= ECHO;
    if (tcsetattr(0, TCSANOW, &t) < 0) {
        error(1, errno, "tcsetattr");
    }

    /* Echo the newline */
    putchar('\n');

    /* Return the newly allocated line */
    return buf;
}

int main(int argc, char **argv) {
    int c;
    int listen_mode = 0;
    char *secret = NULL;
    int discover_port = -1;
    PORT invitation_port = 0;
    int rc;
    int exit_status = 0;
    int multicast_ttl = 1;
    int num_announcements = 10;
    int announcement_gap_ms = 1000;
    int connect_after_discover = 1;
    char *payload_message = "I've got a lovely bunch of coconuts!";
    int use_tls = 1;
    struct sigaction pipeact;

    memset(&pipeact, 0, sizeof(pipeact));
    pipeact.sa_handler = SIG_IGN;

    sigaction(SIGPIPE, &pipeact, NULL);

    while ((c = getopt(argc, argv, "ls:p:t:na:d:Nm:")) != -1) {
        switch (c) {
            case 'a':
                num_announcements = atoi(optarg);
                break;

            case 'd':
                announcement_gap_ms = atoi(optarg);
                break;

            case 'l':
                listen_mode = 1;
                break;

            case 's':
                secret = strdup(optarg);
                break;

            case 'p':
                discover_port = atoi(optarg);
                break;

            case 'n':
                use_tls = 0;
                break;

            case 'm':
                /* If -l is given, we receive UDP announcements, then connect
                 * to the other host. We then send it this message. */
                payload_message = optarg;
                break;

            case 'N':
                connect_after_discover = 0;
                break;

            case 't':
                multicast_ttl = atoi(optarg);
                if (multicast_ttl < 1 || multicast_ttl > 10) {
                    error(1, 0, "multicast TTL must be between 1 and 10");
                }
                break;

            default:
                exit(1);
        }
    }

    if (listen_mode) {
        /* "Listen mode" means we listen at the discovery stage. When we
         * receive an announcement from the other host inviting us to connect
         * to it, we connect to the port it tells us. */
        struct tttdlctx ctx;
        struct sockaddr_storage peer_addr;
        int peer_addr_len;
        PORT peer_invitation_port;
        char peer_addr_str[100];
        char peer_port_str[30];

        if (secret == NULL || secret[0] == '\0') {
            /* No secret has been given, so generate one ourselves and tell
             * the user what it is. */
            int num_words = 4;
            int secret_pos = 0;
            secret = malloc((ttt_wordlist_get_max_word_length() + 1) * num_words);
            for (int i = 0; i < num_words; ++i) {
                int n = ttt_secure_randint(ttt_wordlist_length());
                const char *word = ttt_wordlist_get_word(n);
                if (i > 0)
                    secret[secret_pos++] = ' ';
                strcpy(secret + secret_pos, word);
                secret_pos += strlen(word);
            }
            printf("Passphrase for the other end:\n");
            printf("%s\n", secret);
        }

        /* Initialise a discovery listen context */
        memset(&ctx, 0, sizeof(ctx));
        if (tttdlctx_init(&ctx, secret, strlen(secret)) != 0) {
            error(1, 0, "failed to initialise listen context");
        }

        /* Listen for UDP announcement datagrams on a well-known port */
        if (discover_port > 0)
            tttdlctx_set_port(&ctx, discover_port);

        /* Listen until we receive a valid UDP datagram which was encrypted
         * with our secret. This datagram, when decrypted, tells us which
         * port to make a TCP connection to. */
        rc = tttdlctx_listen(&ctx, &peer_addr, &peer_addr_len, &peer_invitation_port);
        if (rc != 0) {
            error(1, 0, "discover_listen failed.");
        }

        /* Look up who sent us a valid announcement and report to the user. */
        rc = getnameinfo((struct sockaddr *) &peer_addr, sizeof(peer_addr),
                peer_addr_str, sizeof(peer_addr_str),
                peer_port_str, sizeof(peer_port_str),
                NI_NUMERICHOST | NI_NUMERICSERV);
        if (rc != 0) {
            error(0, 0, "getnameinfo: %s", gai_strerror(rc));
            exit_status = 1;
        }
        else {
            printf("Discovered: %s port %s, invitation port %hu\n", peer_addr_str, peer_port_str, peer_invitation_port);
        }
        tttdlctx_destroy(&ctx);

        if (connect_after_discover) {
            /* Connect to the host that sent us the valid announcement on
             * the port it specified, and send a message. */
            struct ttt_session s;
            ttt_session_set_key(secret, strlen(secret));
            ttt_sockaddr_set_port((struct sockaddr *) &peer_addr, peer_invitation_port);
            if (ttt_session_connect(&s, (struct sockaddr *) &peer_addr, peer_addr_len, use_tls) < 0) {
                error(0, 0, "failed to connect");
                exit_status = 1;
            }
            else if (ttt_session_handshake(&s) != 0) {
                /* This socket is blocking, so ttt_session_handshake will
                 * either block and succeed, or fail permanently. It won't
                 * fail with want_read or want_write. */
                error(0, 0, "handshake failed");
                ttt_session_destroy(&s);
                exit_status = 1;
            }
            else {
                /* If we get here, we connected to the host and successfully
                 * completed a TLS handshake using a pre-shared key, proving
                 * that that host has the same passphrase as we do. */
                /* This is where we would start a file transfer session,
                 * but in this test application we just send a short message. */
                int len = s.write(&s, payload_message, strlen(payload_message));
                if (len < 0) {
                    error(0, errno, "send");
                }
                else {
                    s.write(&s, "\n", 1);
                }
                ttt_session_destroy(&s);
            }
        }
    }
    else {
        struct tttdactx dactx;
        struct tttacctx acctx;
        int announcement;
        struct ttt_session tcp_session;
        int tcp_session_valid = 0;
        char peer_addr_str[100];
        char peer_addr_port[30];

        if (optind < argc) {
            /* If the invitation port payload has been given on the command
             * line, use that. Otherwise we default to 0, which means we
             * listen on any free port and include that port number in our
             * encrypted announcements. */
            invitation_port = atoi(argv[optind]);
        }

        if (secret == NULL) {
            /* If we don't have a passphrase, prompt for one. */
            secret = read_passphrase();
        }

        /* Initialise a "discovery announce" context, where we will send
         * UDP datagrams, encrypted with the passphrase, which contain among
         * other things the port number we're inviting the other owner of
         * this passphrase to connect to. */
        memset(&dactx, 0, sizeof(dactx));
        if (tttdactx_init(&dactx, secret, strlen(secret)) != 0) {
            error(1, 0, "failed to initialise announce context");
        }

        /* Open our listening TCP socket on the invitation port. */
        if (tttacctx_init(&acctx, NULL, invitation_port, use_tls) < 0) {
            error(1, 0, "failed to initialise connection accept context");
        }

        invitation_port = tttacctx_get_listen_port(&acctx);

        /* Set TTL, if required. This affects our outgoing announcement
         * datagrams. */
        tttdactx_set_multicast_ttl(&dactx, multicast_ttl);
        if (discover_port > 0) {
            tttdactx_set_port(&dactx, discover_port);
        }

        /* Set the secret passphrase we're going to use for our session.
         * This will be used in the TLS handshake we do with any incoming
         * connection, and the other end of it should have the same passphrase.
         */
        if (connect_after_discover) {
            ttt_session_set_key(secret, strlen(secret));
        }

        /* Send a number of announcements, with a suitable time gap in between.
         * Each announcement is a UDP datagram sent to a broadcast and/or
         * multicast address, so anything on the same network which is looking
         * for it should see it.
         * We keep sending announcements until we reach the limit
         * (num_announcements) or until we receive a connection on our TCP
         * listening socket which successfully completes a handshake proving
         * it has the right passphrase.
         */
        for (announcement = 0; announcement < num_announcements; announcement++) {
            if (announcement > 0) {
                if (connect_after_discover) {
                    /* Listen for incoming connections on our TCP socket. If
                     * announcement_gap_ms milliseconds go by with nobody
                     * connecting to us and completing a handshake, time out and
                     * make another UDP announcement. */
                    rc = tttacctx_accept(&acctx, announcement_gap_ms, &tcp_session);
                    if (rc < 0) {
                        error(1, 0, "fatal error waiting for incoming connection");
                    }
                    else if (rc == 0) {
                        /* timeout */
                    }
                    else {
                        /* Success! tcp_session now contains a session which
                         * connected to the correct port and successfully
                         * handshook with us. */
                        tcp_session_valid = 1;
                        if (ttt_session_get_peer_addr(&tcp_session, peer_addr_str, sizeof(peer_addr_str), peer_addr_port, sizeof(peer_addr_port)) == 0) {
                            fprintf(stderr, "Accepted connection from %s:%s\n", peer_addr_str, peer_addr_port);
                        }
                        break;
                    }
                }
                else {
                    usleep(((useconds_t) announcement_gap_ms) * 1000);
                }
            }

            /* No successful incoming connection yet, so send out another
             * broadcast/multicast announcement inviting anyone who decrypts
             * it to connect to us. */
            rc = tttdactx_announce(&dactx, invitation_port);
            if (rc != 0) {
                error(0, 0, "discover_announce failed.");
                exit_status = 1;
            }
        }
        tttdactx_destroy(&dactx);
        tttacctx_destroy(&acctx);

        if (tcp_session_valid) {
            /* Our peer is going to send us something. Display it. */
            /* This is where we would start a file transfer session, but in
             * this test app we just receive and print a short message. */
            char buf[100];
            int len = tcp_session.read(&tcp_session, buf, sizeof(buf));
            if (len < 0) {
                error(0, errno, "read");
                exit_status = 1;
            }
            else if (len == 0) {
                error(0, 0, "peer closed connection without sending anything");
                exit_status = 1;
            }
            else {
                printf("Message from %s: %.*s\n", peer_addr_str, len, buf);
            }
            ttt_session_destroy(&tcp_session);
        }
    }

    free(secret);

    return exit_status;
}
