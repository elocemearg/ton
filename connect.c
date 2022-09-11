#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <assert.h>

#ifdef WINDOWS
#include <winsock2.h>
#include <winsock.h>
#else
#include <sys/socket.h>
#include <sys/select.h>
#endif

#include <sys/types.h>

#include "connect.h"
#include "utils.h"
#include "session.h"

static void
tttmcctx_free_session(struct tttmcctx *ctx, struct ttt_session *s) {
    ttt_session_destroy(s);
    free(s);
}

static struct ttt_session *
tttmcctx_add_session(struct tttmcctx *ctx, int new_socket, struct sockaddr *addr, socklen_t addr_len) {
    struct ttt_session *s;
    int rc;

    s = malloc(sizeof(struct ttt_session));
    if (s == NULL) {
        return NULL;
    }

    /* Initialise a TLS session, which when we do the handshake will take the
     * role of client. ttt_session doesn't need to know that new_socket hasn't
     * actually connected yet. */
    rc = ttt_session_init(s, new_socket, addr, addr_len, 1, 0);
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

void
tttmcctx_destroy(struct tttmcctx *ctx) {
    struct ttt_session *next;
    for (struct ttt_session *s = ctx->sessions; s; s = next) {
        next = s->next;
        tttmcctx_free_session(ctx, s);
    }
}

/* Make a non-blocking socket, which is in the process of connecting to
 * the given address. Return the socket on success or -1 on failure.
 * It's the caller's responsibility to check when it's cooked. */
static int
make_async_connect_socket(struct sockaddr *addr, socklen_t addr_len) {
    int sock = -1;
    int rc;

    sock = socket(addr->sa_family, SOCK_STREAM, 0);
    if (sock < 0) {
        ttt_socket_error(0, "make_async_connect_socket: socket");
        goto fail;
    }

    ttt_make_socket_non_blocking(sock);

    rc = connect(sock, addr, addr_len);
    if (rc < 0) {
        int err;
#ifdef WINDOWS
        err = WSAGetLastError();
        if (err != WSAEWOULDBLOCK && err != WSAEINPROGRESS) {
            ttt_socket_error(0, "make_async_connect_socket: connect");
            goto fail;
        }
#else
        err = errno;
        if (err != EAGAIN && err != EWOULDBLOCK && err != EINPROGRESS) {
            ttt_socket_error(0, "make_async_connect_socket: connect");
            goto fail;
        }
#endif
    }

    return sock;

fail:
    if (sock >= 0)
        closesocket(sock);
    return -1;
}

void
tttmcctx_set_verbose(struct tttmcctx *ctx, int value) {
    ctx->verbose = value;
}

int
tttmcctx_init(struct tttmcctx *ctx) {
    memset(ctx, 0, sizeof(*ctx));
    ctx->sessions = NULL;
    return 0;
}

int
tttmcctx_fdset_add_sockets(struct tttmcctx *ctx, fd_set *set) {
    int maxfd = -1;
    for (struct ttt_session *s = ctx->sessions; s; s = s->next) {
        FD_SET(s->sock, set);
        if (s->sock > maxfd)
            maxfd = s->sock;
    }
    return maxfd;
}

int
tttmcctx_fdset_contains_sockets(struct tttmcctx *ctx, fd_set *set) {
    int count = 0;
    for (struct ttt_session *s = ctx->sessions; s; s = s->next) {
        if (FD_ISSET(s->sock, set))
            count++;
    }
    return count;
}

int
tttmcctx_add_connect(struct tttmcctx *ctx, struct sockaddr *addr, socklen_t addr_len) {
    int sock = -1;
    struct ttt_session *s;

    sock = make_async_connect_socket(addr, addr_len);
    if (sock < 0) {
        return -1;
    }

    s = tttmcctx_add_session(ctx, sock, addr, addr_len);
    if (s == NULL) {
        close(sock);
        return -1;
    }

    return 0;
}

struct ttt_session *
tttmcctx_run(struct tttmcctx *ctx, fd_set *writable_fds, fd_set *exception_fds) {
    int rc;
    struct ttt_session *new_session = NULL;
    struct ttt_session *next;

    /* If a connection attempt has succeeded then return it, otherwise
     * do nothing. */
    for (struct ttt_session *s = ctx->sessions; s; s = s->next) {
        if (FD_ISSET(s->sock, writable_fds) || FD_ISSET(s->sock, exception_fds)) {
            int err;
            socklen_t err_len = sizeof(err);
            rc = getsockopt(s->sock, SOL_SOCKET, SO_ERROR, (char *) &err, &err_len);
            if (rc < 0) {
                ttt_socket_error(0, "getsockopt SO_ERROR");
                s->failed = 1;
            }
            else if (err != 0) {
                /* Failed to connect */
                if (ctx->verbose) {
                    ttt_socket_error(0, "connect");
                }
                s->failed = 1;
            }
            else {
                /* Successfully connected. */
                new_session = s;
                ttt_session_remove_from_list(&ctx->sessions, new_session);
                new_session->next = NULL;
                break;
            }
        }
    }

    /* Remove any failed sessions */
    for (struct ttt_session *s = ctx->sessions; s; s = next) {
        next = s->next;
        if (s->failed) {
            ttt_session_remove_from_list(&ctx->sessions, s);
            s->next = NULL;
            tttmcctx_free_session(ctx, s);
        }
    }

    /* If we're returning a new session, make the socket blocking. */
    if (new_session != NULL) {
        ttt_make_socket_blocking(new_session->sock);
    }

    /* Return either the successfully-connected session, or NULL if there is no
     * successfully-connected session yet. */
    return new_session;
}
