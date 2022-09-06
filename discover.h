#ifndef _TTTDISCOVER_H
#define _TTTDISCOVER_H

#include <sys/types.h>

#include "session.h"

/* Arbitrary multicast address which the announcer multicasts to and the
 * listener subscribes to. */
#define TTT_MULTICAST_RENDEZVOUS_ADDR "239.14.42.200"

#define TTT_DEFAULT_DISCOVER_PORT 51205

typedef uint16_t PORT;

/* Callback function which tttdlctx_listen will call to say it's successfully
 * set things up and is now waiting for announcements. */
typedef void (*tttdl_listening_cb)(void *);

/* Callback to tell the caller when we receive an announcement datagram,
 * valid or not */
typedef void (*tttdl_announcement_cb)(void *, const struct sockaddr *, socklen_t, int valid, int invitation_port);

/* TTT discovery listen context */
struct tttdlctx {
    /* Address in the 239.x.x.x range which we subscribe to for
     * announcements. The announcing process must send to this address. */
    char *multicast_rendezvous_addr;

    /* Port on which to listen for announcements. */
    PORT listen_port;

    /* Shared secret, or passphrase, we use to decrypt a received datagram. */
    char *secret;
    size_t secret_length;

    /* If this is zero (the default) then we ignore datagrams which are not
     * encrypted. */
    int allow_unencrypted;

    /* tttdlctx_listen() calls listening_cb() when it has set up a socket which
     * is waiting to receive announcement packets over UDP. */
    tttdl_listening_cb listening_cb;
    void *listening_cb_cookie;

    /* tttdlctx_listen() calls announcement_cb() whenever it receives an
     * announcement datagram, and passes details of where it came from and
     * whether it was valid. */
    tttdl_announcement_cb announcement_cb;
    void *announcement_cb_cookie;

    /* If set, we write to stderr when we reject an announcement datagram. */
    int verbose;
};

/* TTT discovery announce context */
struct tttdactx {
    /* The multicast address, in the 239.x.x.x range, which the listener
     * subscribes to and which the announcer sends to. */
    char *multicast_rendezvous_addr;

    /* Port on which to send announcements. */
    PORT announce_port;

    /* Multicast rendezvous address converted to an addrinfo structure. */
    struct addrinfo *multicast_rendezvous_addrinfo;

    /* The shared secret, or passphrase. */
    char *secret;
    size_t secret_length;

    /* List of network interfaces which have a broadcast address. */
    struct sockaddr **broadcast_if_addrs;
    int num_broadcast_if_addrs;

    /* List of network interfaces which we can use to send multicast packets. */
    struct sockaddr **multicast_if_addrs;
    int num_multicast_if_addrs;

    /* Array of sockets, one per applicable network interface. This consists
     * of num_broadcast_if_addrs sockets we can broadcast on, followed by
     * num_multicast_if_addrs sockets we can multicast on. At all times,
     * num_sockets == num_broadcast_if_addrs + num_multicast_if_addrs. */
    int *sockets;
    int num_sockets;
};

int
tttdactx_init(struct tttdactx *ctx,
        const char *secret, size_t secret_length);

void
tttdactx_set_port(struct tttdactx *ctx, PORT port);

void
tttdactx_set_multicast_ttl(struct tttdactx *ctx, int ttl);

int
tttdactx_announce(struct tttdactx *ctx, PORT invitation_port);

void
tttdactx_destroy(struct tttdactx *ctx);

int
tttdlctx_init(struct tttdlctx *ctx,
        const char *secret, size_t secret_length);

void
tttdlctx_set_port(struct tttdlctx *ctx, PORT port);

int
tttdlctx_listen(struct tttdlctx *ctx,
        struct sockaddr_storage *peer_addr_r, int *peer_addr_length_r,
        PORT *invitation_port_r);

void
tttdlctx_set_listening_cb(struct tttdlctx *ctx, tttdl_listening_cb listening_cb);

void
tttdlctx_set_listening_callback_cookie(struct tttdlctx *ctx, void *cookie);

void
tttdlctx_set_announcement_callback(struct tttdlctx *ctx, tttdl_announcement_cb announcement_cb);

void
tttdlctx_set_announcement_callback_cookie(struct tttdlctx *ctx, void *cookie);

void
tttdlctx_set_verbose(struct tttdlctx *ctx, int value);

void
tttdlctx_destroy(struct tttdlctx *ctx);

int
ttt_discover_and_connect(const char *multicast_address, int discover_port,
        const char *passphrase, size_t passphrase_length, int verbose,
        tttdl_listening_cb listening_cb, void *callback_cookie,
        tttdl_announcement_cb announcement_cb, void *announcement_callback_cookie,
        struct ttt_session *new_sess);

int
ttt_discover_and_accept(const char *multicast_address, int discover_port,
        int max_announcements, int announcement_interval_ms, int multicast_ttl,
        const char *passphrase, size_t passphrase_length, int verbose,
        struct ttt_session *new_sess);

#endif
