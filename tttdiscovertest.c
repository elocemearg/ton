#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <getopt.h>
#include <error.h>
#include <errno.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>

#include "tttdiscover.h"

int main(int argc, char **argv) {
    int c;
    int listen_mode = 0;
    char *secret = "";
    int discover_port = -1;
    PORT invitation_port = 12345;
    int rc;
    int exit_status = 0;
    int multicast_ttl = 1;
    //int allow_unencrypted = 0;
    int num_announcements = 10;
    int announcement_gap_ms = 1000;

    while ((c = getopt(argc, argv, "ls:p:t:na:d:")) != -1) {
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
                secret = optarg;
                break;

            case 'p':
                discover_port = atoi(optarg);
                break;

            case 'n':
                //allow_unencrypted = 1;
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
        struct tttdlctx ctx;
        struct sockaddr_storage peer_addr;
        int peer_addr_len;
        PORT peer_invitation_port;
        char peer_addr_str[100];
        char peer_port_str[30];

        memset(&ctx, 0, sizeof(ctx));

        if (tttdlctx_init(&ctx, secret, strlen(secret)) != 0) {
            error(1, 0, "failed to initialise listen context");
        }

        if (discover_port > 0)
            tttdlctx_set_port(&ctx, discover_port);

        rc = tttdlctx_listen(&ctx, &peer_addr, &peer_addr_len, &peer_invitation_port);
        if (rc != 0) {
            error(1, 0, "discover_listen failed.");
        }
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
    }
    else {
        struct tttdactx ctx;
        int announcement;

        if (optind < argc) {
            /* If the invitation port payload has been given on the command
             * line, use that. */
            invitation_port = atoi(argv[optind]);
        }

        memset(&ctx, 0, sizeof(ctx));
        if (tttdactx_init(&ctx, secret, strlen(secret)) != 0) {
            error(1, 0, "failed to initialise announce context");
        }

        tttdactx_set_multicast_ttl(&ctx, multicast_ttl);
        if (discover_port > 0) {
            tttdactx_set_port(&ctx, discover_port);
        }

        for (announcement = 0; announcement < num_announcements; announcement++) {
            if (announcement > 0) {
                usleep(((useconds_t) announcement_gap_ms) * 1000);
            }
            rc = tttdactx_announce(&ctx, invitation_port);
            if (rc != 0) {
                error(0, 0, "discover_announce failed.");
                exit_status = 1;
            }
        }
        tttdactx_destroy(&ctx);
    }

    return exit_status;
}
