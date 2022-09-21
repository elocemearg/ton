#ifndef _CONNECT_H
#define _CONNECT_H

#ifdef WINDOWS
#include <winsock2.h>
#include <winsock.h>
#else
#include <sys/socket.h>
#include <sys/select.h>
#endif

#include <sys/types.h>

#include "session.h"

/* Multi-connection context.
 *
 * It's really just a glorified list of partially-set-up outgoing connection
 * attempts, on non-blocking sockets. This is so we can make several connection
 * attempts to different places at once, and just take the first one that
 * succeeds.
 *
 * Call tonmcctx_add_connect() to start a connection attempt to a given address
 * and tonmcctx_run() when there's activity on any of the sockets.
 * tonmcctx_run() returns the connected ton_session object when finished,
 * having first set its socket to blocking.
 */

struct tonmcctx {
    /* Linked list of ton_session objects. Each has a non-blocking socket on
     * which we have called connect(). */
    struct ton_session *sessions;

    /* Report failed connections */
    int verbose;
};

/* Initialise a TON multi-connection context. It starts with an empty list
 * of sessions. */
int
tonmcctx_init(struct tonmcctx *ctx);

/* Destroy a TON multi-connection context previously initialised with
 * tonmcctx_init(). This also closes any ton_session objects still in the
 * list, including their sockets. */
void
tonmcctx_destroy(struct tonmcctx *ctx);

/* Set whether to be verbose during tonmcctx_run(). Currently this just means
 * we'll report why we couldn't complete a connection attempt. */
void
tonmcctx_set_verbose(struct tonmcctx *ctx, int value);

/* Add to the fd_set each session's socket. Return the highest-numbered socket
 * added to the set, or -1 if there are no sessions in the list. */
int
tonmcctx_fdset_add_sockets(struct tonmcctx *ctx, fd_set *set);

/* Test whether the fd_set contains the socket used by one of our sessions.
 * Return the number of sessions in our list whose socket is in the set. */
int
tonmcctx_fdset_contains_sockets(struct tonmcctx *ctx, fd_set *set);

/* Start a new outgoing connection attempt to the given socket address, and
 * add a new session to our list which uses this socket.
 *
 * key is a pointer to TON_MAX_SIZE bytes, containing the pre-shared key to
 * use with this session. This will be used in the TLS handshake.
 *
 * Return the new session if the connection is in progress, or if it
 * immediately succeeded without blocking (unlikely).
 * Return NULL if we couldn't set up the session.
 */
struct ton_session *
tonmcctx_add_connect(struct tonmcctx *ctx, struct sockaddr *addr, socklen_t addr_len, const unsigned char *key);

/* For each socket in either of the sets writable_fds or exception_fds,
 * check to see whether the connection attempt has finished.
 *
 * If the connection is successful, remove the associated session from the list
 * and return it (the caller is responsible for calling ton_session_destroy()
 * and then free() on it when it is no longer required).
 *
 * If the connection attempt failed, remove the associated session from the
 * list.
 *
 * If no connection attempts on sockets in the two fd_sets succeeded, return
 * NULL. The caller may then call select() again on the relevant sockets
 * (obtained by tonmcctx_fdset_add_sockets()) and then call tonmcctx_run()
 * again when there is activity on any of those sockets.
 */
struct ton_session *
tonmcctx_run(struct tonmcctx *ctx, fd_set *writable_fds, fd_set *exception_fds);

#endif
