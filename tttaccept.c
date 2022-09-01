#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <error.h>
#include <unistd.h>
#include <fcntl.h>
#include <assert.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/time.h>
#include <netdb.h>
#include <netinet/in.h>

#include "tttutils.h"
#include "tttaccept.h"
#include "tttsession.h"

static void
tttacctx_free_session(struct tttacctx *ctx, struct ttt_session *s) {
    ttt_session_destroy(s);
    free(s);
}

static struct ttt_session *
tttacctx_add_session(struct tttacctx *ctx, int new_socket, struct sockaddr *addr, socklen_t addr_len) {
    struct ttt_session *s;
    int rc;

    s = malloc(sizeof(struct ttt_session));
    if (s == NULL) {
        return NULL;
    }

    rc = ttt_session_init(s, new_socket, addr, addr_len, ctx->use_tls, 1);
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
tttacctx_remove_session(struct tttacctx *ctx, struct ttt_session *target) {
    struct ttt_session *prev = NULL;
    for (struct ttt_session *cur = ctx->sessions; cur; cur = cur->next) {
        if (cur == target) {
            if (prev == NULL) {
                ctx->sessions = cur->next;
            }
            else {
                prev->next = cur->next;
            }
            break;
        }
    }
}

void
tttacctx_destroy(struct tttacctx *ctx) {
    struct ttt_session *next;

    if (ctx->listen_socket >= 0) {
        closesocket(ctx->listen_socket);
    }
    freeaddrinfo(ctx->listen_addrinfo);

    for (struct ttt_session *s = ctx->sessions; s; s = next) {
        next = s->next;
        tttacctx_free_session(ctx, s);
    }
}

int
tttacctx_init(struct tttacctx *ctx, const char *listen_addr, unsigned short listen_port, int use_tls) {
    int rc;
    char port_str[20];
    struct addrinfo hints;
    const int one = 1;
    int flags;
    struct sockaddr_storage addr;
    socklen_t addrlen;

    memset(ctx, 0, sizeof(*ctx));
    ctx->listen_socket = -1;
    ctx->use_tls = use_tls;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    snprintf(port_str, sizeof(port_str), "%hu", listen_port);

    rc = getaddrinfo(listen_addr, port_str, &hints, &ctx->listen_addrinfo);
    if (rc != 0) {
        error(0, 0, "tttacctx_init: getaddrinfo: %s", gai_strerror(rc));
        goto fail;
    }

    /* Create our listening socket. */
    ctx->listen_socket = socket(ctx->listen_addrinfo->ai_family,
            ctx->listen_addrinfo->ai_socktype,
            ctx->listen_addrinfo->ai_protocol);
    
    if (ctx->listen_socket < 0) {
        error(0, errno, "tttacctx_init: socket");
        goto fail;
    }

    rc = setsockopt(ctx->listen_socket, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    if (rc != 0) {
        error(0, errno, "tttacctx_init: setsockopt");
        goto fail;
    }

    /* Make the listening socket non-blocking, and bind it to the listen
     * address and port. */
    flags = fcntl(ctx->listen_socket, F_GETFL, 0);
    flags |= O_NONBLOCK;
    fcntl(ctx->listen_socket, F_SETFL, flags);

    rc = bind(ctx->listen_socket, ctx->listen_addrinfo->ai_addr,
            ctx->listen_addrinfo->ai_addrlen);
    if (rc != 0) {
        error(0, errno, "tttacctx_init: bind");
        goto fail;
    }

    rc = listen(ctx->listen_socket, 10);
    if (rc != 0) {
        error(0, errno, "tttacctx_init: listen");
        goto fail;
    }

    addrlen = sizeof(addr);
    rc = getsockname(ctx->listen_socket, (struct sockaddr *) &addr, &addrlen);
    if (rc != 0) {
        error(0, errno, "tttacctx_nit: getsockname");
        goto fail;
    }

    switch (((struct sockaddr *) &addr)->sa_family) {
        case AF_INET:
            ctx->listen_port = ntohs(((struct sockaddr_in *) &addr)->sin_port);
            break;
        case AF_INET6:
            ctx->listen_port = ntohs(((struct sockaddr_in6 *) &addr)->sin6_port);
            break;
        default:
            error(0, 0, "unexpected socket address family: %d", (int) ((struct sockaddr *) &addr)->sa_family);
            goto fail;
    }

    return 0;

fail:
    tttacctx_destroy(ctx);
    return -1;
}

/* If b > a, put (0, 0) in result.
 * Otherwise, set result to a - b. */
static void
timeval_diff(const struct timeval *a, const struct timeval *b, struct timeval *result) {
    result->tv_sec = a->tv_sec - b->tv_sec;
    result->tv_usec = a->tv_usec - b->tv_usec;
    while (result->tv_usec < 0) {
        result->tv_usec += 1000000;
        result->tv_sec--;
    }
    if (result->tv_sec < 0) {
        result->tv_sec = 0;
        result->tv_usec = 0;
    }
}

unsigned short
tttacctx_get_listen_port(struct tttacctx *ctx) {
    return ctx->listen_port;
}

int
tttacctx_accept(struct tttacctx *ctx, int timeout_ms, struct ttt_session *new_session) {
    int rc;
    struct timeval start;
    struct timeval end;
    struct ttt_session *chosen_session = NULL;
    int timed_out = 0;

    /* Set start to the time we're called, and end to the time which if
     * reached means we've timed out. */
    gettimeofday(&start, NULL);
    end.tv_sec = start.tv_sec + timeout_ms / 1000;
    end.tv_usec = start.tv_usec + (timeout_ms % 1000) * 1000;
    while (end.tv_usec >= 1000000) {
        end.tv_usec -= 1000000;
        end.tv_sec++;
    }
    
    do {
        fd_set readsockets, writesockets;
        int maxfd;
        struct timeval timeout, now;

        /* Set up readsockets and writesockets and add the sockets we want
         * information about. ctx->listen_socket is always added to the
         * readsockets set. Sockets for pending sessions are added as
         * necessary. */
        FD_ZERO(&readsockets);
        FD_ZERO(&writesockets);
        FD_SET(ctx->listen_socket, &readsockets);
        maxfd = ctx->listen_socket;
        for (struct ttt_session *s = ctx->sessions; s; s = s->next) {
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
            timed_out = 1;
        }
        else if (rc < 0) {
            /* Failure */
            error(0, errno, "select");
            return rc;
        }
        else {
            /* Activity! */
            struct ttt_session *next;
            /* Is there a new incoming connection? */
            if (FD_ISSET(ctx->listen_socket, &readsockets)) {
                struct sockaddr_storage addr;
                socklen_t addr_len = sizeof(addr);
                int new_socket = accept(ctx->listen_socket, (struct sockaddr *) &addr, &addr_len);
                if (new_socket >= 0) {
                    /* We have accepted a new connection. Add this to our
                     * list of candidate sessions. */
                    struct ttt_session *s = tttacctx_add_session(ctx, new_socket, (struct sockaddr *) &addr, addr_len);
                    if (s != NULL) {
                        int flags;
                        /* Add this to both fdsets so that we try to handshake
                         * with this session below. */
                        s->want_read = 1;
                        s->want_write = 1;
                        FD_SET(s->sock, &readsockets);
                        FD_SET(s->sock, &writesockets);
                        flags = fcntl(new_socket, F_GETFL, 0);
                        flags |= O_NONBLOCK;
                        fcntl(new_socket, F_SETFL, flags);
                    }
                    else {
                        closesocket(new_socket);
                    }
                }
            }

            /* Can progress be made on one of the existing sessions? */
            for (struct ttt_session *s = ctx->sessions; s; s = s->next) {
                if ((s->want_read && FD_ISSET(s->sock, &readsockets)) ||
                        (s->want_write && FD_ISSET(s->sock, &writesockets))) {
                    s->want_read = 0;
                    s->want_write = 0;
                    rc = ttt_session_handshake(s);
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
            for (struct ttt_session *s = ctx->sessions; s; s = next) {
                next = s->next;
                if (s->failed) {
                    /* Remove this one from the list, close the socket and
                     * free its resources. */
                    tttacctx_remove_session(ctx, s);
                    tttacctx_free_session(ctx, s);
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

        /* Remove this session from the list, so that tttacctx_destroy()
         * doesn't close it. */
        tttacctx_remove_session(ctx, chosen_session);
        free(chosen_session);
        return 1;
    }
    else if (timed_out) {
        return 0;
    }
    else {
        /* What? */
        return -1;
    }
}

#ifdef TTT_ACCEPT_MAIN
int main(int argc, char **argv) {
    struct tttacctx ctx;
    struct ttt_session new_session;
    char peer_addr_str[256];
    char peer_port_str[20];
    int exit_status = 0;
    int rc;

    /* Listen on port 12345 */
    if (tttacctx_init(&ctx, NULL, 12345, 0)) {
        error(1, 0, "tttacctx_init");
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
    while ((rc = tttacctx_accept(&ctx, 1000, &new_session)) == 0) {
        printf("Waiting...\n");
    }

    if (rc > 0) {
        rc = getnameinfo((struct sockaddr *) &new_session.addr,
                new_session.addr_len,
                peer_addr_str, sizeof(peer_addr_str),
                peer_port_str, sizeof(peer_port_str),
                NI_NUMERICHOST | NI_NUMERICSERV);

        if (rc != 0) {
            error(0, 0, "getnameinfo: %s", gai_strerror(rc));
            exit_status = 1;
        }
        else {
            printf("Connected: %s port %s\n", peer_addr_str, peer_port_str);
        }
        new_session.write(&new_session, "Thanks, now go away.\n", 21);
        new_session.destroy(&new_session);
    }
    tttacctx_destroy(&ctx);

    return exit_status;
}
#endif
