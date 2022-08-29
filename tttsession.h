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

    /* The underlying socket */
    int sock;

    /* The address of the peer on the other end of the socket. */
    struct sockaddr_storage addr;
    socklen_t addr_len;

    /* Not here yet: SSL structures for encrypted connections. */

    /* Used only during connection setup */
    int want_read, want_write, failed;
    struct ttt_session *next;
};

int
ttt_session_plain_init(struct ttt_session *s);

int
ttt_session_plain_handshake(struct ttt_session *s);

int
ttt_session_tls_init(struct ttt_session *s);

int
ttt_session_tls_handshake(struct ttt_session *s);

#endif
