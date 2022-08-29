#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

#include <sys/types.h>
#include <sys/socket.h>

#include "tttsession.h"
#include "tttutils.h"

static void
ttt_session_plain_destroy(struct ttt_session *s) {
    closesocket(s->sock);
}

static int
ttt_session_plain_write(struct ttt_session *s, const void *buf, size_t len) {
    ssize_t bytes_sent = 0;
    do {
        ssize_t rc = send(s->sock, buf + bytes_sent, len - bytes_sent, 0);
        if (rc <= 0) {
            return (int) rc;
        }
        bytes_sent += rc;
    } while (bytes_sent < len);
    return bytes_sent;
}

static int
ttt_session_plain_read(struct ttt_session *s, void *dest, size_t len) {
    return recv(s->sock, dest, len, 0);
}

static int
ttt_session_plain_make_blocking(struct ttt_session *s) {
    int flags = fcntl(s->sock, F_GETFL, 0);
    flags &= ~O_NONBLOCK;
    fcntl(s->sock, F_SETFL, flags);
    return 0;
}

int
ttt_session_plain_init(struct ttt_session *s) {
    s->destroy = ttt_session_plain_destroy;
    s->write = ttt_session_plain_write;
    s->read = ttt_session_plain_read;
    s->make_blocking = ttt_session_plain_make_blocking;
    return 0;
}

int
ttt_session_plain_handshake(struct ttt_session *s) {
    /* No handshake needed for plaintext connection - immediately succeed. */
    return 0;
}

static void
ttt_session_tls_destroy(struct ttt_session *s) {
    /* GOZZARD: destroy SSL object, close socket */
}

static int
ttt_session_tls_make_blocking(struct ttt_session *s) {
    int flags = fcntl(s->sock, F_GETFL, 0);
    flags &= ~O_NONBLOCK;
    fcntl(s->sock, F_SETFL, flags);

    /* GOZZARD: set the BIOs for s->ssl so that they're now blocking. */
    return 0;
}

static int
ttt_session_tls_write(struct ttt_session *s, const void *buf, size_t len) {
    /* GOZZARD: SSL_write */
    return -1;
}

static int
ttt_session_tls_read(struct ttt_session *s, void *dest, size_t len) {
    /* GOZZARD: SSL_read */
    return -1;
}

int
ttt_session_tls_init(struct ttt_session *s) {
    s->destroy = ttt_session_tls_destroy;
    s->write = ttt_session_tls_write;
    s->read = ttt_session_tls_read;
    s->make_blocking = ttt_session_tls_make_blocking;

    /* GOZZARD: create an SSL object (SSL_new()?)
     * SSL_set_fd(ssl, s->sock);
     *
     * [whatever PSK cipher shit needs to be set up]
     *
     * References (so I can remember later where to find them):
     *
     * https://www.openssl.org/docs/manmaster/man3/SSL_new.html
     *
     * https://www.openssl.org/docs/manmaster/man3/SSL_set_fd.html
     *
     * https://stackoverflow.com/questions/58719595/how-to-do-tls-1-3-psk-using-openssl
     * https://github.com/openssl/openssl/blob/6af1b11848f000c900877f1289a42948d415f21c/apps/s_server.c#L185-L232
     * https://github.com/openssl/openssl/blob/6af1b11848f000c900877f1289a42948d415f21c/apps/s_client.c#L183-L243
     * https://www.openssl.org/docs/man1.1.1/man3/SSL_set_psk_find_session_callback.html
     * https://www.openssl.org/docs/man1.1.1/man3/SSL_set_psk_use_session_callback.html
     *
     * https://ciphersuite.info/cs/TLS_DHE_PSK_WITH_AES_256_GCM_SHA384/
     */
    return -1;
}

int
ttt_session_tls_handshake(struct ttt_session *s) {
    /* GOZZARD: call SSL_do_handshake(s->ssl).
     * Return 0 if handshake completed successfully, -1 if it failed
     * permanently, or 1 if it failed with WANT_READ or WANT_WRITE.
     *
     * References:
     *
     * https://www.openssl.org/docs/manmaster/man3/SSL_do_handshake.html
     */
    return -1;
}
