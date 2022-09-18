#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>

#ifdef WINDOWS
#include <winsock2.h>
#include <winsock.h>
#else
#include <sys/socket.h>
#include <netdb.h>
#endif

#include <sys/types.h>
#include <errno.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#include "session.h"
#include "utils.h"
#include "encryption.h"

/* Mapping of SSL to session key */
struct ttt_session_key {
    SSL *ssl;
    unsigned char session_key[TTT_KEY_SIZE];
    struct ttt_session_key *next;
};

/* Global list of all SSL objects we've created, and the session key we
 * should use for them. We need this because psk_client_cb and psk_server_cb
 * don't have arbitrary pointer arguments for us to pass things in like the
 * passphrase or salt, but they do have the SSL pointer passed in.
 *
 * When we create a ttt_session with an SSL session in it, we add an entry
 * to the list associating the SSL session with the key. Then the psk_client_cb
 * or psk_server_cb callback can look up the key.
 *
 * Note that these functions are not (yet) thread safe. */
struct ttt_session_key *ttt_session_key_list = NULL;

/* Add a new SSL -> key association to the global list. */
static const struct ttt_session_key *
ttt_set_session_key(SSL *ssl, const unsigned char *session_key) {
    struct ttt_session_key *k = malloc(sizeof(struct ttt_session_key));
    if (k == NULL)
        return NULL;
    memcpy(k->session_key, session_key, TTT_KEY_SIZE);
    k->ssl = ssl;
    k->next = ttt_session_key_list;
    ttt_session_key_list = k;
    return k;
}

/* Look up a key given the SSL pointer. */
static const struct ttt_session_key *
ttt_find_session_key(SSL *ssl) {
    for (struct ttt_session_key *k = ttt_session_key_list; k; k = k->next) {
        if (k->ssl == ssl)
            return k;
    }
    return NULL;
}

/* Remove an entry from the global list of keys. */
static void
ttt_remove_session_key(SSL *ssl) {
    struct ttt_session_key *prev = NULL;
    for (struct ttt_session_key *cur = ttt_session_key_list; cur; cur = cur->next) {
        if (cur->ssl == ssl) {
            if (prev == NULL)
                ttt_session_key_list = cur->next;
            else
                prev->next = cur->next;
            free(cur);
            return;
        }
        prev = cur;
    }
}

static void
show_ssl_errors(FILE *out) {
    unsigned long err;
    char buf[256];

    while ((err = ERR_get_error()) != 0) {
        ERR_error_string_n(err, buf, sizeof(buf));
        fprintf(stderr, "SSL: %s\n", buf);
    }
}

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
    return ttt_make_socket_blocking(s->sock);
}

static int
handshake_receive_hello(struct ttt_session *s) {
    const int message_length = 6;
    const char *message = "hello\n";
    int rc;

    do {
        rc = s->read(s, s->plaintext_handshake_message + s->plaintext_handshake_message_pos, message_length - s->plaintext_handshake_message_pos);
        if (rc > 0) {
            s->plaintext_handshake_message_pos += rc;
        }
    } while (rc > 0 && s->plaintext_handshake_message_pos < message_length);

    if (rc < 0) {
        if(errno == EAGAIN || errno == EWOULDBLOCK) {
            s->want_read = true;
            return -1;
        }
        else {
            ttt_error(0, errno, "handshake read");
            s->failed = true;
            show_ssl_errors(stderr);
            return -1;
        }
    }
    else if (rc == 0) {
        ttt_error(0, 0, "unexpected EOF from peer");
        s->failed = true;
        return -1;
    }
    else {
        if (!memcmp(s->plaintext_handshake_message, message, message_length)) {
            s->plaintext_handshake_state++;
            s->plaintext_handshake_message_pos = 0;
            return 0;
        }
        else {
            ttt_error(0, 0, "unexpected handshake message: %.*s", s->plaintext_handshake_message_pos, s->plaintext_handshake_message);
            s->failed = true;
            return -1;
        }
    }
}

static int
handshake_send_hello(struct ttt_session *s) {
    const int message_length = 6;
    const char *message = "hello\n";
    int rc;

    do {
        rc = s->write(s, message + s->plaintext_handshake_message_pos, message_length - s->plaintext_handshake_message_pos);
        if (rc > 0) {
            s->plaintext_handshake_message_pos += rc;
        }
    } while (rc > 0 && s->plaintext_handshake_message_pos < message_length);

    if (rc < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            s->want_write = true;
            return -1;
        }
        else {
            ttt_error(0, errno, "handshake write");
            s->failed = true;
            show_ssl_errors(stderr);
            return -1;
        }
    }
    else if (rc == 0) {
        ttt_error(0, 0, "unexpected EOF during handshake write");
        s->failed = true;
        return -1;
    }
    else {
        s->plaintext_handshake_state++;
        s->plaintext_handshake_message_pos = 0;
        return 0;
    }
}

static int
ttt_session_plain_handshake(struct ttt_session *s) {
    /* Simple toy handshake: client says hello, server replies hello.
     * This works regardless of whether the socket is blocking or
     * non-blocking. */
    int rc = 0;
    if (s->plaintext_handshake_state == 0) {
        if (s->is_server) {
            rc = handshake_receive_hello(s);
        }
        else {
            rc = handshake_send_hello(s);
        }
    }
    if (rc == 0) {
        if (s->plaintext_handshake_state == 1) {
            if (s->is_server) {
                rc = handshake_send_hello(s);
            }
            else {
                rc = handshake_receive_hello(s);
            }
        }
    }
    return rc;
}

static int
ttt_session_plain_init(struct ttt_session *s) {
    s->destroy = ttt_session_plain_destroy;
    s->write = ttt_session_plain_write;
    s->read = ttt_session_plain_read;
    s->make_blocking = ttt_session_plain_make_blocking;
    s->handshake = ttt_session_plain_handshake;
    return 0;
}

static void
ttt_session_tls_destroy(struct ttt_session *s) {
    SSL_free(s->ssl);
    SSL_CTX_free(s->ssl_ctx);
    closesocket(s->sock);
}

static int
ttt_session_tls_make_blocking(struct ttt_session *s) {
    return ttt_make_socket_blocking(s->sock);
}

static int
ttt_session_tls_write(struct ttt_session *s, const void *buf, size_t len) {
    int rc = SSL_write(s->ssl, buf, len);
    if (rc <= 0) {
        int ssl_err = SSL_get_error(s->ssl, rc);
        if (ssl_err == SSL_ERROR_WANT_READ) {
            s->want_read = true;
        }
        else if (ssl_err == SSL_ERROR_WANT_WRITE) {
            s->want_write = true;
        }
        else {
            s->failed = true;
        }
        return -1;
    }
    else {
        return rc;
    }
}

static int
ttt_session_tls_read(struct ttt_session *s, void *dest, size_t len) {
    int rc = SSL_read(s->ssl, dest, len);
    if (rc <= 0) {
        int ssl_err = SSL_get_error(s->ssl, rc);
        if (ssl_err == SSL_ERROR_WANT_READ) {
            s->want_read = true;
        }
        else if (ssl_err == SSL_ERROR_WANT_WRITE) {
            s->want_write = true;
        }
        else if (ssl_err == SSL_ERROR_ZERO_RETURN) {
            return 0;
        }
        else {
            s->failed = true;
        }
        return -1;
    }
    else {
        return rc;
    }
}

static int
ttt_session_tls_handshake(struct ttt_session *s) {
    /* Call SSL_do_handshake. If the underlying socket is blocking, this will
     * block until the handshake succeeds (returns 1) or permanently fails
     * (return <1).
     *
     * If the underlying socket is non-blocking, it may return
     * <1 if it can't read or write at the moment, and SSL_get_error() will
     * indicate this. In this case we return an error but set s->want_read
     * or s->want_write so that the caller knows to call us again when the
     * socket can next be read from or written to, respectively.
     *
     * If SSL_do_handshake() returns <1 for any other reason, we set
     * s->failed and return -1.
     */
    int rc = SSL_do_handshake(s->ssl);
    if (rc == 1) {
        /* Success */
        /*const SSL_CIPHER *cipher = SSL_get_current_cipher(s->ssl);
        fprintf(stderr, "ttt_session_tls_handshake(): negotiated cipher %s\n", SSL_CIPHER_get_name(cipher));*/
        return 0;
    }
    else {
        /* Not success: determine whether this is temporary for lack of input
         * data or output space, or something more permanent. */
        int ssl_err = SSL_get_error(s->ssl, rc);
        if (ssl_err == SSL_ERROR_WANT_READ) {
            s->want_read = true;
            return 1;
        }
        else if (ssl_err == SSL_ERROR_WANT_WRITE) {
            s->want_write = true;
            return 1;
        }
        else {
            s->failed = true;
            show_ssl_errors(stderr);
            return -1;
        }
    }
}

static unsigned int
psk_client_cb(SSL *ssl, const char *hint,
        char *identity, unsigned int max_identity_len,
        unsigned char *psk, unsigned int max_psk_len) {
    const struct ttt_session_key *key = ttt_find_session_key(ssl);

    if (key == NULL) {
        ttt_error(0, 0, "psk_client_cb: internal error: no key set for SSL %p", ssl);
        return 0;
    }

    /* We don't use this */
    strncpy(identity, "tttclient", max_identity_len);
    if (max_identity_len > 0)
        identity[max_identity_len - 1] = '\0';

    if (TTT_KEY_SIZE > max_psk_len) {
        ttt_error(0, 0, "psk_client_cb: psk buffer not big enough!");
        return 0;
    }
    memcpy(psk, key->session_key, TTT_KEY_SIZE);
    return TTT_KEY_SIZE;
}

/*
static void
ssl_trace(int write_p, int version, int content_type, const void *buf, size_t len, SSL *ssl, void *arg) {
    char context[100];
    snprintf(context, sizeof(context), "%s %d %d", write_p ? "sent" : "received", version, content_type);
    ttt_dump_hex(buf, len, context);
}
*/

static unsigned int
psk_server_cb(SSL *ssl, const char *identity, unsigned char *psk, unsigned int max_psk_len) {
    const struct ttt_session_key *key = ttt_find_session_key(ssl);

    if (key == NULL) {
        ttt_error(0, 0, "psk_server_cb: internal error: no key set for SSL %p", ssl);
        return 0;
    }

    if (TTT_KEY_SIZE > max_psk_len) {
        ttt_error(0, 0, "psk_server_cb: psk buffer not big enough!");
        return 0;
    }
    memcpy(psk, key->session_key, TTT_KEY_SIZE);
    return TTT_KEY_SIZE;
}

static int
ttt_session_tls_init(struct ttt_session *s) {
    const SSL_METHOD *method;

    s->destroy = ttt_session_tls_destroy;
    s->write = ttt_session_tls_write;
    s->read = ttt_session_tls_read;
    s->make_blocking = ttt_session_tls_make_blocking;
    s->handshake = ttt_session_tls_handshake;

    /* Set up all the SSL rubbish, gleaned from bashing head against the
     * OpenSSL docs for ages. */
    if (s->is_server)
        method = TLS_server_method();
    else
        method = TLS_client_method();

    s->ssl_ctx = SSL_CTX_new(method);
    if (s->ssl_ctx == NULL) {
        ttt_error(0, 0, "SSL_CTX_new failed");
        return -1;
    }

    /* Set callbacks to supply s->ssl with the pre-shared key when the
     * time is right. */
    if (s->is_server) {
        SSL_CTX_set_psk_server_callback(s->ssl_ctx, psk_server_cb);
    }
    else {
        SSL_CTX_set_psk_client_callback(s->ssl_ctx, psk_client_cb);
    }

    SSL_CTX_set_ciphersuites(s->ssl_ctx, "PSK");

    /* We want SSL_write to write as much as it can before blocking or
     * failing with WANT_WRITE. */
    SSL_CTX_set_mode(s->ssl_ctx, SSL_MODE_ENABLE_PARTIAL_WRITE);

    /* Open our SSL session and give it this session's socket */
    s->ssl = SSL_new(s->ssl_ctx);
    SSL_set_fd(s->ssl, s->sock);

    /* Add the mapping (s->ssl -> (session key)) to the global list, so
     * that the callbacks psk_server_cb and psk_client_cb can find it. */
    ttt_set_session_key(s->ssl, s->session_key);

    /* Set the appropriate state, ready to start the handshake */
    if (s->is_server) {
        SSL_set_accept_state(s->ssl);
    }
    else {
        SSL_set_connect_state(s->ssl);
    }

    return 0;
}

int
ttt_session_init(struct ttt_session *s, int sock, const struct sockaddr *addr,
        socklen_t addr_len, bool use_tls, bool is_server,
        const unsigned char *key) {
    int rc;

    memset(s, 0, sizeof(*s));
    s->sock = sock;
    memcpy(&s->addr, addr, addr_len > sizeof(s->addr) ? sizeof(s->addr) : addr_len);
    s->addr_len = addr_len;

    s->want_read = false;
    s->want_write = false;
    s->failed = false;
    s->is_server = is_server;
    s->next = NULL;

    if (key) {
        memcpy(s->session_key, key, TTT_KEY_SIZE);
    }

    if (use_tls) {
        rc = ttt_session_tls_init(s);
    }
    else {
        rc = ttt_session_plain_init(s);
    }
    return rc;
}

int
ttt_session_handshake(struct ttt_session *s) {
    return s->handshake(s);
}

int
ttt_session_get_peer_addr(struct ttt_session *s, char *addr_dest, int addr_dest_len, char *port_dest, int port_dest_len) {
    int rc;

    rc = getnameinfo((struct sockaddr *) &s->addr, s->addr_len,
            addr_dest, addr_dest_len, port_dest, port_dest_len,
            NI_NUMERICHOST | NI_NUMERICSERV);
    if (rc != 0) {
        ttt_error(0, 0, "getnameinfo: %s", gai_strerror(rc));
    }
    return rc;
}

void
ttt_session_destroy(struct ttt_session *s) {
    if (s->ssl) {
        ttt_remove_session_key(s->ssl);
    }
    s->destroy(s);
}

void
ttt_session_remove_from_list(struct ttt_session **list_start, struct ttt_session *target) {
    struct ttt_session *prev = NULL;
    for (struct ttt_session *cur = *list_start; cur; cur = cur->next) {
        if (cur == target) {
            if (prev == NULL) {
                *list_start = cur->next;
            }
            else {
                prev->next = cur->next;
            }
            break;
        }
        prev = cur;
    }
}
