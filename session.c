#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include <assert.h>

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

/* Test if the reason why the last socket call failed is because it would block. */
static bool
ttt_would_block(void) {
#ifdef WINDOWS
    switch (WSAGetLastError()) {
        case WSAEINPROGRESS:
        case WSAEWOULDBLOCK:
            return true;
        default:
            return false;
    }
#else
    return (errno == EAGAIN || errno == EWOULDBLOCK);
#endif
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
        if (ttt_would_block()) {
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
        if (ttt_would_block()) {
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

/* Make progress on a pre-TLS-handshake "hello" exchange, where the client
 * sends the server a TTT_HELLO_SIZE-byte hello message, and the server replies
 * with its own hello message. This contains information like which version of
 * the wire protocol each side supports.
 *
 * This may be called with s->sock blocking or non-blocking.
 *
 * Return < 0 if there was some unrecoverable error, like a connection error
 *     or a protocol version mismatch.
 * Return 0 if the hello exchange completed and was successful, in which case
 *     s->protocol_version is set to the negotiated protocol version.
 * Return 1 if we can temporarily not proceed because the socket is
 *     non-blocking and there's no data to receive or we can't currently send.
 */
static int
ttt_session_hello(struct ttt_session *s) {
    int rc;

    while (s->client_hello_pos < TTT_HELLO_SIZE) {
        /* Client sends their hello first */
        if (s->is_server)
            rc = recv(s->sock, (char *) s->client_hello + s->client_hello_pos,
                    TTT_HELLO_SIZE - s->client_hello_pos, 0);
        else
            rc = send(s->sock, (char *) s->client_hello + s->client_hello_pos,
                    TTT_HELLO_SIZE - s->client_hello_pos, 0);
        if (rc < 0 && ttt_would_block()) {
            /* Can't proceed without blocking */
            if (s->is_server)
                s->want_read = true;
            else
                s->want_write = true;
            return 1;
        }
        else if (rc <= 0) {
            /* Fail. Don't report errors here, because we may have received
             * multiple connections of which one completed first, and the
             * others then all legitimately closed. */
            /*if (rc == 0)
                ttt_error(0, 0, "unexpected EOF during client hello");
            else
                ttt_socket_error(0, "connection failed during client hello");*/
            goto fail;
        }
        else {
            /* No error and we sent or received 1 or more bytes */
            s->client_hello_pos += rc;
        }
    }

    while (s->client_hello_pos == TTT_HELLO_SIZE && s->server_hello_pos < TTT_HELLO_SIZE) {
        /* Then the server replies with their hello */
        if (s->is_server)
            rc = send(s->sock, (char *) s->server_hello + s->server_hello_pos,
                    TTT_HELLO_SIZE - s->server_hello_pos, 0);
        else
            rc = recv(s->sock, (char *) s->server_hello + s->server_hello_pos,
                    TTT_HELLO_SIZE - s->server_hello_pos, 0);
        if (rc < 0 && ttt_would_block()) {
            /* We can't proceed without blocking */
            if (s->is_server)
                s->want_write = true;
            else
                s->want_read = true;
            return 1;
        }
        else if (rc <= 0) {
            /* Don't report errors, because as above, they can legitimately
             * happen if another connection won the race. */
            /*if (rc == 0)
                ttt_error(0, 0, "unexpected EOF during client hello");
            else
                ttt_socket_error(0, "connection failed during server hello");*/
            goto fail;
        }
        else {
            /* We sent/received some data */
            s->server_hello_pos += rc;
        }
    }

    /* If we get here, we have completed the hello exchange. Check that the
     * client and server protocol ranges are compatible and return some
     * good or bad news. */
    assert(s->client_hello_pos == TTT_HELLO_SIZE);
    assert(s->server_hello_pos == TTT_HELLO_SIZE);

    unsigned char *their_hello = (s->is_server ? s->client_hello : s->server_hello);
    const uint16_t our_min = TTT_OUR_MIN_PROTOCOL_VERSION;
    const uint16_t our_max = TTT_OUR_MAX_PROTOCOL_VERSION;
    const uint32_t their_magic = ntohl(*(uint32_t *)(their_hello + TTT_HELLO_MAGIC_OFFSET));
    const uint16_t their_min = ntohs(*(uint16_t *)(their_hello + TTT_HELLO_MIN_PROT_OFFSET));
    const uint16_t their_max = ntohs(*(uint16_t *)(their_hello + TTT_HELLO_MAX_PROT_OFFSET));
    const uint16_t their_flags = ntohl(*(uint32_t *)(their_hello + TTT_HELLO_FLAGS_OFFSET));

    if (their_magic != TTT_HELLO_MAGIC) {
        ttt_error(0, 0, "incorrect magic number in hello message: expected 0x%08x, received 0x%08x", TTT_HELLO_MAGIC, their_magic);
        goto fail;
    }
    if (their_min > our_max) {
        ttt_error(0, 0, "TTT protocol version mismatch: remote host requires version %hu but we only support up to version %hu", their_min, our_max);
        goto fail;
    }
    if (our_min > their_max) {
        ttt_error(0, 0, "TTT protocol version mismatch: we require version %hu but remote host only supports up to version %hu", our_min, their_max);
        goto fail;
    }
    s->their_flags = their_flags;
    s->protocol_version = ((their_max < our_max) ? their_max : our_max);

    /* fprintf(stderr, "their magic 0x%08x, their min %hu, their max %hu, their flags 0x%08x, negotiated protocol version %hu\n", their_magic, their_min, their_max, their_flags, s->protocol_version); */

    /* Indicate hello exchange was successful, and we're talking to a client
     * that's going to understand us */
    return 0;

fail:
    s->failed = true;
    return -1;
}

static int
ttt_session_tls_handshake(struct ttt_session *s) {
    int rc;

    /* If we haven't got the pre-handshake hello out of the way, make some
     * progress with that. */
    if (s->server_hello_pos < TTT_HELLO_SIZE) {
        rc = ttt_session_hello(s);
        if (rc < 0) {
            /* *fail horns* */
            return rc;
        }
        else if (rc > 0) {
            /* Hello exchange not failed, but not yet complete */
            return 1;
        }

        /* Otherwise, hello exchange should have completed, and we can move
         * on to the TLS handshake. */
        assert(s->server_hello_pos == TTT_HELLO_SIZE);
        assert(s->protocol_version > 0);
    }

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
    rc = SSL_do_handshake(s->ssl);
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

/* Initialise a TTT_HELLO_SIZE-byte hello message with the given information.
 * msg must point to a buffer of TTT_HELLO_SIZE bytes. */
static void
ttt_session_init_hello_msg(unsigned char *msg, unsigned short min_prot_ver,
        unsigned short max_prot_ver, unsigned long flags) {
    *((uint32_t *) (msg + TTT_HELLO_MAGIC_OFFSET)) = htonl(TTT_HELLO_MAGIC);
    *((uint16_t *) (msg + TTT_HELLO_MIN_PROT_OFFSET)) = htons(min_prot_ver);
    *((uint16_t *) (msg + TTT_HELLO_MAX_PROT_OFFSET)) = htons(max_prot_ver);
    *((uint32_t *) (msg + TTT_HELLO_FLAGS_OFFSET)) = htonl(flags);
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

    /* Not yet sent/received either hello message */
    s->client_hello_pos = 0;
    s->server_hello_pos = 0;

    /* Set flags to zero until we find a use for them */
    s->our_flags = 0;

    /* Set our own hello message ready to send to the other host */
    ttt_session_init_hello_msg(s->is_server ? s->server_hello : s->client_hello,
            TTT_OUR_MIN_PROTOCOL_VERSION, TTT_OUR_MAX_PROTOCOL_VERSION,
            s->our_flags);

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
