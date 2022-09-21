#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <assert.h>
#include <stdbool.h>

#ifdef WINDOWS
#include <winsock2.h>
#include <winsock.h>
#else
#include <sys/socket.h>
#include <sys/select.h>
#include <netdb.h>
#include <netinet/in.h>
#endif

#include <sys/types.h>
#include <sys/time.h>

#include "utils.h"
#include "accept.h"
#include "session.h"

static void
tonacctx_free_session(struct tonacctx *ctx, struct ton_session *s) {
    ton_session_destroy(s);
    free(s);
}

static struct ton_session *
tonacctx_add_session(struct tonacctx *ctx, int new_socket, struct sockaddr *addr, socklen_t addr_len) {
    struct ton_session *s;
    int rc;

    s = malloc(sizeof(struct ton_session));
    if (s == NULL) {
        return NULL;
    }

    rc = ton_session_init(s, new_socket, addr, addr_len, ctx->use_tls, true,
            ctx->use_tls ? ctx->session_key : NULL);
    if (rc < 0) {
        free(s);
        return NULL;
    }
    else {
        s->next = ctx->sessions;
        ctx->sessions = s;
        return s;
    }
}

static void
tonacctx_remove_session(struct tonacctx *ctx, struct ton_session *target) {
    ton_session_remove_from_list(&ctx->sessions, target);
}

void
tonacctx_destroy(struct tonacctx *ctx) {
    struct ton_session *next;

    if (ctx->listen_socket4 >= 0) {
        closesocket(ctx->listen_socket4);
    }
    if (ctx->listen_socket6 >= 0) {
        closesocket(ctx->listen_socket6);
    }

    for (struct ton_session *s = ctx->sessions; s; s = next) {
        next = s->next;
        tonacctx_free_session(ctx, s);
    }
}

static int
make_listening_socket(int address_family, const char *listen_addr,
        unsigned short listen_port, struct sockaddr *sockaddr,
        socklen_t *sockaddr_len) {
    char port_str[20];
    struct addrinfo hints;
#ifdef WINDOWS
    const BOOL one = 1;
#else
    const int one = 1;
#endif
    int listener = -1;
    struct addrinfo *listen_addrinfo = NULL;
    int rc;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = address_family;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    snprintf(port_str, sizeof(port_str), "%hu", listen_port);

    rc = getaddrinfo(listen_addr, port_str, &hints, &listen_addrinfo);
    if (rc != 0) {
        ton_error(0, 0, "make_listening_socket: getaddrinfo: %s", gai_strerror(rc));
        goto fail;
    }

    /* Create our listening socket. */
    listener = socket(listen_addrinfo->ai_family, listen_addrinfo->ai_socktype, listen_addrinfo->ai_protocol);

    if (listener < 0) {
        ton_socket_error(0, "make_listening_socket: socket");
        goto fail;
    }

    rc = setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, (const char *) &one, sizeof(one));
    if (rc != 0) {
        ton_socket_error(0, "make_listening_socket: setsockopt(SO_REUSEADDR)");
        goto fail;
    }

    if (address_family == AF_INET6) {
        /* Set IPV6_V6ONLY so we can bind an IPv4 socket to the same port */
        rc = setsockopt(listener, IPPROTO_IPV6, IPV6_V6ONLY, (const char *) &one, sizeof(one));
        if (rc != 0) {
            ton_socket_error(0, "make_listening_socket: setsockopt(IPV6_V6ONLY)");
            goto fail;
        }
    }

    /* Make the listening socket non-blocking, and bind it to the listen
     * address and port. */
    ton_make_socket_non_blocking(listener);

    rc = bind(listener, listen_addrinfo->ai_addr, listen_addrinfo->ai_addrlen);
    if (rc != 0) {
        ton_socket_error(0, "make_listening_socket: bind");
        goto fail;
    }

    rc = listen(listener, 10);
    if (rc != 0) {
        ton_socket_error(0, "make_listening_socket: listen");
        goto fail;
    }

    rc = getsockname(listener, sockaddr, sockaddr_len);
    if (rc != 0) {
        ton_socket_error(0, "make_listening_socket: getsockname");
        goto fail;
    }

end:
    freeaddrinfo(listen_addrinfo);
    return listener;

fail:
    if (listener >= 0) {
        closesocket(listener);
        listener = -1;
    }
    goto end;
}

int
tonacctx_init(struct tonacctx *ctx, const char *listen_addr4,
        const char *listen_addr6, int address_families,
        unsigned short listen_port, bool use_tls, const char *passphrase,
        size_t passphrase_length, const unsigned char *salt, size_t salt_length) {
    struct sockaddr_storage addr;
    socklen_t addr_len;

    memset(ctx, 0, sizeof(*ctx));
    ctx->listen_socket4 = -1;
    ctx->listen_socket6 = -1;
    ctx->use_tls = use_tls;

    if (address_families & TON_IPV4) {
        addr_len = sizeof(addr);
        ctx->listen_socket4 = make_listening_socket(AF_INET, listen_addr4,
                listen_port, (struct sockaddr *) &addr, &addr_len);
        if (ctx->listen_socket4 < 0) {
            goto fail;
        }
        ctx->listen_port4 = ntohs(((struct sockaddr_in *) &addr)->sin_port);
    }

    if (address_families & TON_IPV6) {
        addr_len = sizeof(addr);
        ctx->listen_socket6 = make_listening_socket(AF_INET6, listen_addr6,
                listen_port, (struct sockaddr *) &addr, &addr_len);
        if (ctx->listen_socket6 < 0) {
            goto fail;
        }
        ctx->listen_port6 = ntohs(((struct sockaddr_in6 *) &addr)->sin6_port);
    }

    if (ton_passphrase_to_key(passphrase, passphrase_length, salt, salt_length, ctx->session_key, sizeof(ctx->session_key)) < 0) {
        goto fail;
    }

    return 0;

fail:
    tonacctx_destroy(ctx);
    return -1;
}

unsigned short
tonacctx_get_listen_port(struct tonacctx *ctx, int address_family) {
    switch (address_family) {
        case AF_INET:
            return ctx->listen_port4;
        case AF_INET6:
            return ctx->listen_port6;
        default:
            return 0;
    }
}

int
tonacctx_accept(struct tonacctx *ctx, int timeout_ms, struct ton_session *new_session) {
    int rc;
    struct timeval start;
    struct timeval end;
    struct ton_session *chosen_session = NULL;
    bool timed_out = false;
    int listeners[2];

    /* Set start to the time we're called, and end to the time which if
     * reached means we've timed out. */
    gettimeofday(&start, NULL);
    end.tv_sec = start.tv_sec + timeout_ms / 1000;
    end.tv_usec = start.tv_usec + (timeout_ms % 1000) * 1000;
    while (end.tv_usec >= 1000000) {
        end.tv_usec -= 1000000;
        end.tv_sec++;
    }

    listeners[0] = ctx->listen_socket4;
    listeners[1] = ctx->listen_socket6;

    do {
        fd_set readsockets, writesockets;
        int maxfd = 0;
        struct timeval timeout, now;

        /* Set up readsockets and writesockets and add the sockets we want
         * information about. The listener sockets are always added to the
         * readsockets set. Sockets for pending sessions are added as
         * necessary. */
        FD_ZERO(&readsockets);
        FD_ZERO(&writesockets);

        for (int f = 0; f < 2; ++f) {
            if (listeners[f] >= 0) {
                FD_SET(listeners[f], &readsockets);
                if (listeners[f] > maxfd)
                    maxfd = listeners[f];
            }
        }
        for (struct ton_session *s = ctx->sessions; s; s = s->next) {
            if (s->want_read) {
                /* We want to know when there's data to read on this socket */
                FD_SET(s->sock, &readsockets);
                if (s->sock > maxfd)
                    maxfd = s->sock;
            }
            if (s->want_write) {
                /* We want to know when we can write to this socket */
                FD_SET(s->sock, &writesockets);
                if (s->sock > maxfd)
                    maxfd = s->sock;
            }
        }

        if (timeout_ms >= 0) {
            gettimeofday(&now, NULL);
            timeval_diff(&end, &now, &timeout);
        }
        rc = select(maxfd + 1, &readsockets, &writesockets, NULL, timeout_ms < 0 ? NULL : &timeout);
        if (rc == 0) {
            /* Timeout */
            timed_out = true;
        }
        else if (rc < 0) {
            /* Failure */
            ton_socket_error(0, "select");
            return rc;
        }
        else {
            /* Activity! */
            struct ton_session *next;

            /* Is there a new incoming connection? */
            for (int f = 0; f < 2; f++) {
                int listener = listeners[f];
                if (FD_ISSET(listener, &readsockets)) {
                    struct sockaddr_storage addr;
                    socklen_t addr_len = sizeof(addr);
                    int new_socket = accept(listener, (struct sockaddr *) &addr, &addr_len);
                    if (new_socket >= 0) {
                        /* We have accepted a new connection. Add this to our
                         * list of candidate sessions. */
                        struct ton_session *s = tonacctx_add_session(ctx, new_socket, (struct sockaddr *) &addr, addr_len);
                        if (s != NULL) {
                            /* Add this to both fdsets so that we try to
                             * handshake with this session below. */
                            s->want_read = true;
                            s->want_write = true;
                            FD_SET(s->sock, &readsockets);
                            FD_SET(s->sock, &writesockets);
                            ton_make_socket_non_blocking(new_socket);
                        }
                        else {
                            closesocket(new_socket);
                        }
                    }
                    else {
                        ton_socket_error(0, "accept");
                    }
                }
            }

            /* Can progress be made on one of the existing sessions? */
            for (struct ton_session *s = ctx->sessions; s; s = s->next) {
                if ((s->want_read && FD_ISSET(s->sock, &readsockets)) ||
                        (s->want_write && FD_ISSET(s->sock, &writesockets))) {
                    s->want_read = 0;
                    s->want_write = 0;
                    rc = ton_session_handshake(s);
                    if (rc == 0) {
                        /* Handshake completed successfully - this is the
                         * session we'll use, closing all the others. */
                        chosen_session = s;
                    }
                    else {
                        /* Otherwise, the handshake() method will have either
                         * set s->failed if the handshake failed, or
                         * s->want_read or s->want_write if it's still in
                         * progress and stalled because it was unable to read
                         * or write data. */
                        assert(s->failed || s->want_read || s->want_write);
                    }
                }
            }

            /* Remove any sessions whose handshake failed. */
            for (struct ton_session *s = ctx->sessions; s; s = next) {
                next = s->next;
                if (s->failed) {
                    /* Remove this one from the list, close the socket and
                     * free its resources. */
                    tonacctx_remove_session(ctx, s);
                    tonacctx_free_session(ctx, s);
                }
            }
        }
    } while (!timed_out && chosen_session == NULL);

    if (chosen_session) {
        /* Return this session after converting it to an ordinary
         * blocking I/O session. */
        memcpy(new_session, chosen_session, sizeof(*new_session));
        new_session->next = NULL;
        new_session->make_blocking(new_session);

        /* Remove this session from the list, so that tonacctx_destroy()
         * doesn't close it. */
        tonacctx_remove_session(ctx, chosen_session);
        free(chosen_session);
        return 1;
    }
    else if (timed_out) {
        return 0;
    }
    else {
        /* What? */
        ton_error(0, 0, "tonacctx_accept() exited for some reason, but we neither got a valid session nor timed out?");
        return -1;
    }
}

#ifdef TON_ACCEPT_MAIN
int main(int argc, char **argv) {
    struct tonacctx ctx;
    struct ton_session new_session;
    char peer_addr_str[256];
    char peer_port_str[20];
    int exit_status = 0;
    int rc;

    /* Listen on port 12345 */
    if (tonacctx_init(&ctx, NULL, NULL, TON_IP_BOTH, 12345, false)) {
        ton_error(1, 0, "tonacctx_init");
    }

    /* Wait until we get a connection on that port.
     *
     * This connection must send us "hello\n".
     * We then send it "hello\n". This is our plaintext "handshake".
     *
     * Then we print the address and port that connected to us.
     *
     * Every second while waiting for this to happen, time out and print a
     * message. In the finished tool, instead of printing a message we'd
     * send another announcement datagram asking our other end to connect
     * to us. */
    while ((rc = tonacctx_accept(&ctx, 1000, &new_session)) == 0) {
        printf("Waiting...\n");
    }

    if (rc > 0) {
        rc = getnameinfo((struct sockaddr *) &new_session.addr,
                new_session.addr_len,
                peer_addr_str, sizeof(peer_addr_str),
                peer_port_str, sizeof(peer_port_str),
                NI_NUMERICHOST | NI_NUMERICSERV);

        if (rc != 0) {
            ton_error(0, 0, "getnameinfo: %s", gai_strerror(rc));
            exit_status = 1;
        }
        else {
            printf("Connected: %s port %s\n", peer_addr_str, peer_port_str);
        }
        new_session.write(&new_session, "Thanks, now go away.\n", 21);
        new_session.destroy(&new_session);
    }
    tonacctx_destroy(&ctx);

    return exit_status;
}
#endif
