#ifndef _TTTSESSION_H
#define _TTTSESSION_H

#include <sys/types.h>

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

    /* True if this socket was born by accepting a connection from a listening
     * socket, false if it connected out to something. */
    int is_server;

    /* The address of the peer on the other end of the socket. */
    struct sockaddr_storage addr;
    socklen_t addr_len;

    /* Not here yet: SSL structures for encrypted connections. */

    /* Used only during connection setup */
    int want_read, want_write, failed;
    struct ttt_session *next;
};

int
ttt_session_get_peer_addr(struct ttt_session *s, char *addr_dest, int addr_dest_len, char *port_dest, int port_dest_len);

int
ttt_session_init(struct ttt_session *s, int sock, const struct sockaddr *addr,
        socklen_t addr_len, int use_tls, int is_server);

int
ttt_session_connect(struct ttt_session *s, const struct sockaddr *addr,
        socklen_t addr_len, int use_tls);

int
ttt_session_handshake(struct ttt_session *s);

void
ttt_session_destroy(struct ttt_session *s);

#endif
