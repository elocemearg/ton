#ifndef _TTTACCEPT_H
#define _TTTACCEPT_H

#include <sys/types.h>

#include "tttutils.h"
#include "tttsession.h"

/* TTT accept connection context. */
struct tttacctx {
    int listen_socket;
    struct addrinfo *listen_addrinfo;
    unsigned short listen_port;

    int use_tls;

    /* A linked list of partially-set-up sessions we've received so far.
     * We take the first one which successfully completes a handshake. */
    struct ttt_session *sessions;
};

/* Create a context to accept the right connection. This opens a listening
 * socket. */
int
tttacctx_init(struct tttacctx *ctx, const char *listen_addr, unsigned short listen_port, int use_tls);

/* Get the port number on which this accept context is listening. Useful if
 * 0 was supplied to tttacctx_init() and now you want to know what actual
 * port number was allocated. */
unsigned short
tttacctx_get_listen_port(struct tttacctx *ctx);

/* Accept the right connection. The right connection is the first one that
 * connects to our listening socket and successfully handshakes. For plain
 * text connections there is no handshake so it's just the first connection
 * to be established. For encrypted connections it's the first to connect
 * and successfully complete an SSL handshake with the correct pre-shared
 * key.
 *
 * The listening and handshaking is done in a non-blocking and resumable way.
 * It will time out of after timeout_ms, after which the process can be resumed
 * by re-calling tttacctx_accept().
 *
 * If an incoming connection's handshake fails, it is quietly dropped.
 *
 * If timeout_ms < 0, there is no timeout, and we wait indefinitely until we
 * get the right connection.
 *
 * Return value:
 * 1: we successfully accepted a connection and the handshake succeeded. The
 *    session details are in *new_session. The caller may now call
 *    tttacctx_destroy() to close the listening socket and close any other
 *    connections still open.
 * 0: we timed out. The caller can call the function again to resume.
 * -1: some error occurred.
 */
int
tttacctx_accept(struct tttacctx *ctx, int timeout_ms, struct ttt_session *new_session);

/* Destroy a TTT accept connnection context. This closes the listening socket
 * and closes any connections it received that are still open, but it does NOT
 * close any session returned by a successful call to tttacctx_accept(). */
void
tttacctx_destroy(struct tttacctx *ctx);

#endif
