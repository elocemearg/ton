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
#endif

#include <sys/types.h>

#include "connect.h"
#include "utils.h"
#include "session.h"

static void
tonmcctx_free_session(struct tonmcctx *ctx, struct ton_session *s) {
    ton_session_destroy(s);
    free(s);
}

static struct ton_session *
tonmcctx_add_session(struct tonmcctx *ctx, int new_socket,
        struct sockaddr *addr, socklen_t addr_len, const char *passphrase,
        size_t passphrase_length) {
    struct ton_session *s;
    int rc;

    s = malloc(sizeof(struct ton_session));
    if (s == NULL) {
        return NULL;
    }

    /* Initialise a TLS session, which when we do the handshake will take the
     * role of client. ton_session doesn't need to know that new_socket hasn't
     * actually connected yet. */
    rc = ton_session_init(s, new_socket, addr, addr_len, true, false, passphrase, passphrase_length);
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
tonmcctx_destroy(struct tonmcctx *ctx) {
    struct ton_session *next;
    for (struct ton_session *s = ctx->sessions; s; s = next) {
        next = s->next;
        tonmcctx_free_session(ctx, s);
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
        ton_socket_error(0, "make_async_connect_socket: socket");
        goto fail;
    }

    ton_make_socket_non_blocking(sock);

    rc = connect(sock, addr, addr_len);
    if (rc < 0) {
        int err;
#ifdef WINDOWS
        err = WSAGetLastError();
        if (err != WSAEWOULDBLOCK && err != WSAEINPROGRESS) {
            ton_socket_error(0, "make_async_connect_socket: connect");
            goto fail;
        }
#else
        err = errno;
        if (err != EAGAIN && err != EWOULDBLOCK && err != EINPROGRESS) {
            ton_socket_error(0, "make_async_connect_socket: connect");
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
tonmcctx_set_verbose(struct tonmcctx *ctx, int value) {
    ctx->verbose = value;
}

int
tonmcctx_init(struct tonmcctx *ctx) {
    memset(ctx, 0, sizeof(*ctx));
    ctx->sessions = NULL;
    return 0;
}

int
tonmcctx_fdset_add_sockets(struct tonmcctx *ctx, fd_set *set) {
    int maxfd = -1;
    for (struct ton_session *s = ctx->sessions; s; s = s->next) {
        FD_SET(s->sock, set);
        if (s->sock > maxfd)
            maxfd = s->sock;
    }
    return maxfd;
}

int
tonmcctx_fdset_contains_sockets(struct tonmcctx *ctx, fd_set *set) {
    int count = 0;
    for (struct ton_session *s = ctx->sessions; s; s = s->next) {
        if (FD_ISSET(s->sock, set))
            count++;
    }
    return count;
}

struct ton_session *
tonmcctx_add_connect(struct tonmcctx *ctx, struct sockaddr *addr,
        socklen_t addr_len, const char *passphrase, size_t passphrase_length) {
    int sock = -1;
    struct ton_session *s;

    sock = make_async_connect_socket(addr, addr_len);
    if (sock < 0) {
        return NULL;
    }

    s = tonmcctx_add_session(ctx, sock, addr, addr_len, passphrase, passphrase_length);
    if (s == NULL) {
        close(sock);
        return NULL;
    }

    return s;
}

struct ton_session *
tonmcctx_run(struct tonmcctx *ctx, fd_set *writable_fds, fd_set *exception_fds) {
    int rc;
    struct ton_session *new_session = NULL;
    struct ton_session *next;

    /* If a connection attempt has succeeded then return it, otherwise
     * do nothing. */
    for (struct ton_session *s = ctx->sessions; s; s = s->next) {
        if (FD_ISSET(s->sock, writable_fds) || FD_ISSET(s->sock, exception_fds)) {
            int err;
            socklen_t err_len = sizeof(err);
            rc = getsockopt(s->sock, SOL_SOCKET, SO_ERROR, (char *) &err, &err_len);
            if (rc < 0) {
                ton_socket_error(0, "getsockopt SO_ERROR");
                s->failed = true;
            }
            else if (err != 0) {
                /* Failed to connect */
                if (ctx->verbose) {
                    ton_socket_error_aux(0, err, "connect");
                }
                s->failed = true;
            }
            else {
                /* Successfully connected. */
                new_session = s;
                ton_session_remove_from_list(&ctx->sessions, new_session);
                new_session->next = NULL;
                break;
            }
        }
    }

    /* Remove any failed sessions */
    for (struct ton_session *s = ctx->sessions; s; s = next) {
        next = s->next;
        if (s->failed) {
            ton_session_remove_from_list(&ctx->sessions, s);
            s->next = NULL;
            tonmcctx_free_session(ctx, s);
        }
    }

    /* If we're returning a new session, make the socket blocking. */
    if (new_session != NULL) {
        ton_make_socket_blocking(new_session->sock);
    }

    /* Return either the successfully-connected session, or NULL if there is no
     * successfully-connected session yet. */
    return new_session;
}
