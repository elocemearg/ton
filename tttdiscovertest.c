#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <getopt.h>
#include <errno.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <termios.h>
#include <signal.h>

#include "discover.h"
#include "accept.h"
#include "session.h"
#include "wordlist.h"
#include "encryption.h"
#include "utils.h"

int main(int argc, char **argv) {
    int c;
    int listen_mode = 0;
    char *secret = NULL;
    int discover_port = -1;
    int exit_status = 0;
    int multicast_ttl = 1;
    int num_announcements = 10;
    int announcement_gap_ms = 1000;
    char *payload_message = "I've got a lovely bunch of coconuts!";
    struct sigaction pipeact;

    memset(&pipeact, 0, sizeof(pipeact));
    pipeact.sa_handler = SIG_IGN;

    sigaction(SIGPIPE, &pipeact, NULL);

    while ((c = getopt(argc, argv, "ls:p:t:a:d:m:")) != -1) {
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

            case 'm':
                /* If -l is given, we receive UDP announcements, then connect
                 * to the other host. We then send it this message. */
                payload_message = optarg;
                break;

            case 't':
                multicast_ttl = atoi(optarg);
                if (multicast_ttl < 1 || multicast_ttl > 10) {
                    ttt_error(1, 0, "multicast TTL must be between 1 and 10");
                }
                break;

            default:
                exit(1);
        }
    }

    if (listen_mode) {
        struct ttt_session sess;
        int rc;

        if (secret == NULL || secret[0] == '\0') {
            secret = ttt_generate_passphrase(4);
            fprintf(stderr, "Generated passphrase:\n%s\n", secret);
        }

        rc = ttt_discover_and_connect(NULL, discover_port, secret,
                strlen(secret), 1, &sess);
        if (rc < 0) {
            ttt_error(1, 0, "failed to discover and connect to remote host");
        }

        /* If we get here, we connected to the host and successfully
         * completed a TLS handshake using a pre-shared key, proving
         * that that host has the same passphrase as we do. */
        /* This is where we would start a file transfer session,
         * but in this test application we just send a short message. */
        int len = sess.write(&sess, payload_message, strlen(payload_message));
        if (len < 0) {
            ttt_error(0, errno, "send");
        }
        else {
            sess.write(&sess, "\n", 1);
        }
        ttt_session_destroy(&sess);
    }
    else {
        struct ttt_session tcp_session;
        int tcp_session_valid = 0;
        int rc;

        if (secret == NULL || secret[0] == '\0') {
            secret = ttt_prompt_passphrase("Passphrase? ");
        }

        rc = ttt_discover_and_accept(NULL, discover_port,
                num_announcements, announcement_gap_ms, multicast_ttl,
                secret, strlen(secret), 1, &tcp_session);
        if (rc < 0) {
            ttt_error(1, 0, "failed to discover and accept connection");
        }
        else {
            tcp_session_valid = 1;
        }

        if (tcp_session_valid) {
            /* Our peer is going to send us something. Display it. */
            /* This is where we would start a file transfer session, but in
             * this test app we just receive and print a short message. */
            char buf[100];
            int len = tcp_session.read(&tcp_session, buf, sizeof(buf));
            if (len < 0) {
                ttt_error(0, errno, "read");
                exit_status = 1;
            }
            else if (len == 0) {
                ttt_error(0, 0, "peer closed connection without sending anything");
                exit_status = 1;
            }
            else {
                printf("Message: %.*s\n", len, buf);
            }
            ttt_session_destroy(&tcp_session);
        }
    }

    free(secret);

    return exit_status;
}
