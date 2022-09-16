#ifndef _TTTSESSION_H
#define _TTTSESSION_H

#ifdef WINDOWS
#include <winsock2.h>
#include <winsock.h>
#include <ws2tcpip.h> /* for socklen_t */
#else
#include <sys/socket.h>
#endif

#include <stdbool.h>
#include <sys/types.h>
#include <openssl/ssl.h>

/* TCP session, which can be plaintext or encrypted. Plaintext is for testing
 * only, the default will be encrypted when I've deciphered the OpenSSL docs. */
struct ttt_session {
    void (*destroy)(struct ttt_session *);
    int (*write)(struct ttt_session *, const void *buf, size_t max);
    int (*read)(struct ttt_session *, void *buf, size_t len);
    int (*make_blocking)(struct ttt_session *s);
    int (*handshake)(struct ttt_session *s);

    /* The underlying socket */
    int sock;

    /* Plain text handshake state, which we have to keep track of because the
     * handshake is done on non-blocking sockets.
     * 0 = client is sending hello, server is receiving it.
     * 1 = server is sending hello, client is receiving it.
     */
    int plaintext_handshake_state;
    char plaintext_handshake_message[10];
    int plaintext_handshake_message_pos;

    SSL *ssl;
    SSL_CTX *ssl_ctx;

    /* True if this socket was born by accepting a connection from a listening
     * socket, false if it connected out to something. */
    bool is_server;

    /* The address of the peer on the other end of the socket. */
    struct sockaddr_storage addr;
    socklen_t addr_len;

    /* Not here yet: SSL structures for encrypted connections. */

    /* Used only during connection setup */
    bool want_read, want_write, failed;
    struct ttt_session *next;
};

int
ttt_session_get_peer_addr(struct ttt_session *s, char *addr_dest, int addr_dest_len, char *port_dest, int port_dest_len);

int
ttt_session_init(struct ttt_session *s, int sock, const struct sockaddr *addr,
        socklen_t addr_len, bool use_tls, bool is_server);

int
ttt_session_connect(struct ttt_session *s, const struct sockaddr *addr,
        socklen_t addr_len, bool use_tls);

int
ttt_session_handshake(struct ttt_session *s);

void
ttt_session_destroy(struct ttt_session *s);

int
ttt_session_set_key(const char *passphrase, size_t passphrase_length);

void
ttt_session_remove_from_list(struct ttt_session **list_start, struct ttt_session *target);

#endif
