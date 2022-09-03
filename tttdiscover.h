#ifndef _TTTDISCOVER_H
#define _TTTDISCOVER_H

#include <sys/types.h>

#include "tttsession.h"

/* Arbitrary multicast address which the announcer multicasts to and the
 * listener subscribes to. */
#define TTT_MULTICAST_RENDEZVOUS_ADDR "239.14.42.200"

#define TTT_DEFAULT_DISCOVER_PORT 51205

typedef uint16_t PORT;

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
tttdlctx_destroy(struct tttdlctx *ctx);

int
ttt_discover_and_connect(const char *multicast_address, int discover_port,
        const char *passphrase, size_t passphrase_length, int verbose,
        struct ttt_session *new_sess);

int
ttt_discover_and_accept(const char *multicast_address, int discover_port,
        int max_announcements, int announcement_interval_ms, int multicast_ttl,
        const char *passphrase, size_t passphrase_length, int verbose,
        struct ttt_session *new_sess);

#endif
