#ifndef _TONACCEPT_H
#define _TONACCEPT_H

#include <stdbool.h>
#include <sys/types.h>

#include "utils.h"
#include "session.h"
#include "encryption.h"

/* TON accept connection context. */
struct tonacctx {
    int listen_socket4, listen_socket6;
    unsigned short listen_port4, listen_port6;

    bool use_tls;

    char *passphrase;
    size_t passphrase_length;

    /* A linked list of partially-set-up sessions we've received so far.
     * We take the first one which successfully completes a handshake. */
    struct ton_session *sessions;
};

/* Create a context to accept the right connection. This opens a listening
 * socket. */
int
tonacctx_init(struct tonacctx *ctx, const char *listen_addr_ipv4,
        const char *listen_addr_ipv6, int address_families,
        unsigned short listen_port, bool use_tls, const char *passphrase,
        size_t passphrase_length);

/* Get the port number on which this accept context is listening. Useful if
 * 0 was supplied to tonacctx_init() and now you want to know what actual
 * port number was allocated. */
unsigned short
tonacctx_get_listen_port(struct tonacctx *ctx, int address_family);

/* Accept the right connection. The right connection is the first one that
 * connects to our listening socket and successfully handshakes. For plain
 * text connections there is no handshake so it's just the first connection
 * to be established. For encrypted connections it's the first to connect
 * and successfully complete an SSL handshake with the correct pre-shared
 * key.
 *
 * The listening and handshaking is done in a non-blocking and resumable way.
 * It will time out of after timeout_ms, after which the process can be resumed
 * by re-calling tonacctx_accept().
 *
 * If an incoming connection's handshake fails, it is quietly dropped.
 *
 * If timeout_ms < 0, there is no timeout, and we wait indefinitely until we
 * get the right connection.
 *
 * Return value:
 * 1: we successfully accepted a connection and the handshake succeeded. The
 *    session details are in *new_session. The caller may now call
 *    tonacctx_destroy() to close the listening socket and close any other
 *    connections still open.
 * 0: we timed out. The caller can call the function again to resume.
 * -1: some error occurred.
 */
int
tonacctx_accept(struct tonacctx *ctx, int timeout_ms, struct ton_session *new_session);

/* Destroy a TON accept connnection context. This closes the listening socket
 * and closes any connections it received that are still open, but it does NOT
 * close any session returned by a successful call to tonacctx_accept(). */
void
tonacctx_destroy(struct tonacctx *ctx);

#endif
