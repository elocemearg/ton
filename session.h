#ifndef _TONSESSION_H
#define _TONSESSION_H

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

#include "encryption.h"

/* The hello message sent by the client has 20 bytes, and the hello message
 * sent by the server has 12 bytes. All the integers are in network byte order.
 *
 * Bytes   Type        Description
 * 0-3     int32       Magic number 0x544f4e48 ("TONH")
 * 4-5     int16       Minimum supported protocol version
 * 6-7     int16       Maximum supported protocol version
 * 8-11    int32       Flags (reserved for future use, currently 0)
 *
 * (Client hello only)
 * 12-19   char[8]     Random salt to combine with the passphrase to make the
 *                     complete pre-shared key for the TLS handshake
 *
 * First the client sends the hello message to the server, then the server
 * replies with its own hello message.
 *
 * If the minimum supported protocol version of either host is greater than
 * the maximum supported protocol version of the other host, there is a
 * protocol version mismatch and both sides close the connection and report
 * an error.
 *
 * Otherwise, the protocol version for the ensuing session will be
 * MIN(client_max_version, server_max_version).
 *
 * Currently the only protocol version in existence is version 1, which is the
 * one implemented by this code. The protocol version exchange is intended so
 * that the protocol can be changed later on but stay backwardly compatible
 * with older versions where possible.
 *
 * The flags parameter is intended to enable each host to indicate support for
 * optional features without having to make a whole new protocol version every
 * time such an optional feature is added.
 */
#define TON_OUR_MIN_PROTOCOL_VERSION 1
#define TON_OUR_MAX_PROTOCOL_VERSION 1

#define TON_SERVER_HELLO_SIZE 12
#define TON_CLIENT_HELLO_SIZE 20
#define TON_HELLO_MAGIC 0x544f4548
#define TON_HELLO_MAGIC_OFFSET 0
#define TON_HELLO_MIN_PROT_OFFSET 4
#define TON_HELLO_MAX_PROT_OFFSET 6
#define TON_HELLO_FLAGS_OFFSET 8
#define TON_HELLO_SALT_OFFSET 12
#define TON_HELLO_SALT_LENGTH 8

/* TCP session, which can be plaintext or encrypted. Plaintext is for testing
 * only, the default will be encrypted when I've deciphered the OpenSSL docs. */
struct ton_session {
    void (*destroy)(struct ton_session *);
    int (*write)(struct ton_session *, const void *buf, size_t max);
    int (*read)(struct ton_session *, void *buf, size_t len);
    int (*make_blocking)(struct ton_session *s);
    int (*handshake)(struct ton_session *s);

    /* The underlying socket */
    int sock;

    /* Pre-SSL hello state, where the client sends its protocol version number
     * and the server replies with its protocol version number. */
    unsigned char client_hello[TON_CLIENT_HELLO_SIZE];
    int client_hello_pos;
    unsigned char server_hello[TON_SERVER_HELLO_SIZE];
    int server_hello_pos;

    /* Negotiated protocol version */
    unsigned short protocol_version;
    unsigned long our_flags;
    unsigned long their_flags;

    /* OpenSSL session context. */
    SSL *ssl;
    SSL_CTX *ssl_ctx;

    /* The passphrase from which to derive this session's pre-shared key. */
    char *passphrase;
    size_t passphrase_length;

    /* Pre-shared key with which to encrypt and authenticate this session,
     * derived from the pre-shared passphrase, and the salt sent by the client
     * in the hello message. */
    unsigned char session_key[TON_KEY_SIZE];

    /* True if this socket was born by accepting a connection from a listening
     * socket, false if it connected out to something. */
    bool is_server;

    /* The address of the peer on the other end of the socket. */
    struct sockaddr_storage addr;
    socklen_t addr_len;

    /* Used only during connection setup */
    bool want_read, want_write, failed;
    struct ton_session *next;
};

int
ton_session_get_peer_addr(struct ton_session *s, char *addr_dest, int addr_dest_len, char *port_dest, int port_dest_len);

int
ton_session_init(struct ton_session *s, int sock, const struct sockaddr *addr,
        socklen_t addr_len, bool use_tls, bool is_server,
        const char *passphrase, size_t passphrase_length);

int
ton_session_handshake(struct ton_session *s);

void
ton_session_destroy(struct ton_session *s);

void
ton_session_remove_from_list(struct ton_session **list_start, struct ton_session *target);

#endif
