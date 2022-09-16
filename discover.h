#ifndef _TTTDISCOVER_H
#define _TTTDISCOVER_H

#include <sys/types.h>
#include <stdbool.h>

#include "session.h"
#include "defaults.h"

typedef uint16_t PORT;

/* Callback function which tttdlctx_receive will call to say it's successfully
 * set things up and is now waiting for announcements. */
typedef void (*tttdl_listening_cb)(void *);

/* Callback to tell the caller when we receive an announcement datagram,
 * valid or not */
typedef void (*tttdl_announcement_cb)(void *, const struct sockaddr *, socklen_t, int valid, int invitation_port);

/* Options struct for ttt_discover_and_connect() and ttt_discover_and_accept(),
 * the two functions called by the pushing and pulling side respectively to
 * find each other and set up a TCP connection. */
struct ttt_discover_options {
    /* The passphrase with which to generate the key to encrypt and decrypt
     * announcement datagrams, and to use as a pre-shared key with the TLS
     * session we set up on the connection. */
    char *passphrase;
    int passphrase_length;

    /* multicast_address_ipv4, multicast_address_ipv6: the IPv4 and IPv6
     * multicast addresses we expect to receive announcements on. If this is
     * NULL we use the default, TTT_MULTICAST_GROUP_IPV4 and
     * TTT_MULTICAST_GROUP_IPV6. The other host must use the same address. */
    char *multicast_address_ipv4;
    char *multicast_address_ipv6;

    /* address_families: whether to listen for announcement datagrams on IPv4,
       IPv6, or both. Set it to TTT_IPV4_ONLY, TTT_IPV6_ONLY, or TTT_IP_BOTH. */
    int address_families;

    /* announcement_types: for ttt_discover_and_accept(), whether to send out
     * the announcement messages using broadcast, multicast, or both. Set it to
     * TTT_ANNOUNCE_BROADCAST, TTT_ANNOUNCE_MULTICAST or TTT_ANNOUNCE_BOTH. */
    int announcement_types;

    /* The UDP port on which to send or receive announcement datagrams. The
     * default is TTT_DEFAULT_DISCOVER_PORT, and both ends must use the same. */
    int discover_port;

    /* The TCP port the connection-accepting side should open and listen on
     * for incoming connections. This port number is contained in the payload
     * of the announcements we send. */
    int listen_port;

    /* Be less economical with ttt_error(). */
    int verbose;

    /* listening_cb: callback to call when we start listening for announcement
     * packet. We call tttdlctx_set_listening_cb() with this, using the
     * discover-listen context we set up.
     * If NULL, the callback is not used. */
    tttdl_listening_cb listening_cb;
    void *listening_cb_cookie;

    /* announcement_cb: callback to call when we receive an announcement
     * datagram, valid or not. See tttdlctx_set_announcement_cb().
     * If NULL, the callback is not used. */
    tttdl_announcement_cb announcement_cb;
    void *announcement_cb_cookie;

    /* The maximum number of announcements to send on each suitable network
     * interface. If we send this many announcements and we still don't get a
     * valid incoming TCP connection, we fail. */
    int max_announcements;

    /* The number of milliseconds to wait between annoucements, during which we
     * wait for incoming connections on our listening socket. */
    int announcement_interval_ms;

    /* The TTL or hop limit to set on our multicast announcement datagrams.
     * Warning: the ip(7) man page strongly warns against setting this to
     * anything higher than it needs to be. The recommended value is 0, which
     * leaves it at the default (1 for IPv4, route default for IPv6). */
    int multicast_ttl;

    /* Whether to include non-private IP addresses when selecting the network
     * interfaces to send announcements from. */
    bool include_global_addresses;
};

/* TTT discovery listen context */
struct tttdlctx {
    /* Address in the 239.x.x.x range which we subscribe to for
     * announcements. The announcing process must send to this address. */
    char *multicast_address_ipv4;

    /* Address in the ff08:... rannge which we subscribe to for
     * announcements on IPv6 multicast. */
    char *multicast_address_ipv6;

    /* IPv4 and IPv6 receiving sockets */
    int receivers[2];

    /* Initially 0. Set to 1 when we listen for announcements, so that if we
     * have cause to re-listen we don't call the callback again. */
    int listening_cb_called;
};

/* TTT discovery announce context */
struct tttdactx {
    /* The multicast address, in the 239.x.x.x range, which the listener
     * subscribes to and which the announcer sends to. */
    char *multicast_address_ipv4;

    /* Address in the ff08:... rannge which we subscribe to for
     * announcements on IPv6 multicast. */
    char *multicast_address_ipv6;

    /* Port on which to send announcements. */
    PORT announce_port;

    /* Ports we're inviting hosts to connect on. */
    PORT invitation_port4, invitation_port6;

    /* IPv4 multicast group address converted to an addrinfo. */
    struct addrinfo *multicast_addrinfo_ipv4;

    /* IPv6 multicast group address converted to an addrinfo. */
    struct addrinfo *multicast_addrinfo_ipv6;

    /* List of network interfaces which have a broadcast address, each of
     * which contains a socket we will bind to that interface's address. */
    struct ttt_netif *broadcast_ifs;

    /* List of network interfaces which we can use to send multicast packets.
     * Each contains a socket we will bind to that interface's address. */
    struct ttt_netif *multicast_ifs;
};

/* Initialise a discover-announce context with the passphrase and other
 * options in opts. This also initialises a list of sockets in dactx.
 *
 * Return 0 on success, or nonzero on error. We might return an error if there
 * are no suitable network interfaces, for example. */
int
tttdactx_init(struct tttdactx *dactx, struct ttt_discover_options *opts);

/* Send out an announcement datagram on every suitable network interface.
 * The datagram is encrypted with the passphrase. When decrypted by the
 * receiving host, it invites the decrypter to TCP-connect to us on the
 * invitation port number previously supplied with
 * tttdactx_set_invitation_port(). If the invitation port for a particular
 * address family is not set (or set to 0), no announcement is sent on sockets
 * for that address family.
 *
 * It is the caller's responsibility to have already set up a listening socket
 * to listen on the invitation port. (Alternatively, see
 * ttt_discover_and_connect().)
 *
 * Return 0 on success or nonzero on failure. */
int
tttdactx_announce(struct tttdactx *ctx, struct ttt_discover_options *opts);

/* Destroy a previously-initialise TTT discover-announce context and free any
 * resources associated with it. */
void
tttdactx_destroy(struct tttdactx *ctx);

/* Initialise a TTT discover-listen context with the passphrase and options
 * in opts. This is called by the other endpoint to the one that called
 * tttdactx_init(). It does not actually receive announcement datagrams: you
 * need to call tttdlctx_receive(). */
int
tttdlctx_init(struct tttdlctx *ctx, struct ttt_discover_options *opts);

/* Listen for UDP datagrams on the discover port, on all suitable network
 * interfaces.
 *
 * ctx must have been initialised with tttdlctx_init().
 *
 * We hope to receive a datagram which looks like a TTT announcement datagram
 * (meaning it begins with the right magic number), and which when decrypted
 * with the passphrase results in a valid decryption (correct second magic
 * number, CRC, timestamp).
 *
 * When we receive a valid announcement datagram, we put the address that
 * sent it in *peer_addr_r and the length of the sockaddr in
 * *peer_addr_length_r, and we put the invitation port number from the
 * decrypted datagram is put in *invitation_port_r. Then we return 0 for
 * success.
 *
 * Return 0 if there was nothing to receive.
 * Return 1 if we received a valid announcement. In this case the source
 *   address of the announcement is placed in *peer_addr_r and the length
 *   of the sockaddr in *peer_addr_length_r. The invitation port number
 *   in the announcement is placed in *invitation_port_r.
 * Return a negative number in the event of an error.
 */
int
tttdlctx_receive(struct tttdlctx *ctx, struct ttt_discover_options *opts,
        struct sockaddr_storage *peer_addr_r, int *peer_addr_length_r,
        PORT *invitation_port_r);

/* Add this discover-listen context's receiving socket(s), created upon the
 * initialisation of the tttdlctx, to the given fd_set using FD_SET().
 *
 * Return the highest-numbered file descriptor added to the set, or -1 if
 * no file descriptors were added. */
int
tttdlctx_fdset_add_receivers(struct tttdlctx *ctx, fd_set *set);

/* Test whether any of this discover-listen context's receiving socket(s),
 * created upon the initialisation of the tttdlctx, are in the given fd_set.
 *
 * If this returns 1, then there is something to receive on at least one of
 * our receiving sockets, and a call to tttdlctx_receive() will not block.
 *
 * If this returns 0, then there is nothing to receive. */
int
tttdlctx_fdset_contains_receivers(struct tttdlctx *ctx, fd_set *set);

/* Destroy a previously-initialised TTT discover-listen context and free any
 * resources associated with it. */
void
tttdlctx_destroy(struct tttdlctx *ctx);


/* Initialise a TTT discover context, suitable for setting options in and
 * passing to ttt_discover_and_connect() or ttt_discover_and_accept().
 * The passphrase and length are mandatory. */
int
ttt_discover_options_init(struct ttt_discover_options *opts, const char *passphrase, int passphrase_length);

/* Set the IPv4 multicast group to send announcements to, or to receive
 * announcements on. This must be an address in the range
 * "224.0.0.0" to "239.255.255.255".
 *
 * The default is TTT_MULTICAST_GROUP_IPV4. */
int
ttt_discover_set_multicast_ipv4_address(struct ttt_discover_options *opts, const char *addr);

/* Set the IPv6 multicast group to send announcements to, or to receive
 * announcements on. This must be a valid IPv6 multicast address. These
 * begin with "ff".
 *
 * The default is TTT_MULTICAST_GROUP_IPV6. */
int
ttt_discover_set_multicast_ipv6_address(struct ttt_discover_options *opts, const char *addr);

/* Set which address families to use to send or receive announcements or to
 * accept or make a TCP connection. value must be TTT_IPV4_ONLY, TTT_IPV6_ONLY
 * or TTT_IP_BOTH.
 *
 * The default is TTT_IP_BOTH.
 */
void
ttt_discover_set_address_families(struct ttt_discover_options *opts, int value);

/* Set which announcement strategies we should use to send announcements for
 * the discovery stage.
 * Valid values are:
 * TTT_ANNOUNCE_BROADCAST_ONLY: announce on broadcast addresses only.
 * TTT_ANNOUNCE_MULTICAST_ONLY: announce on multicast addresses only.
 * TTT_ANNOUNCE_BOTH: announce on both broadcast and multicast addresses.
 *
 * The default is TTT_ANNOUNCE_BOTH.
 */
void
ttt_discover_set_announcement_types(struct ttt_discover_options *opts, int value);

/* Set the UDP port on which we send, or expect to receive, announcement
 * datagrams for the discovery stage. The default is TTT_DEFAULT_DISCOVER_PORT.
 */
void
ttt_discover_set_discover_port(struct ttt_discover_options *opts, int port);

/* Set the TCP port we open and listen on for incoming connections. The default
 * is TTT_DEFAULT_LISTEN_PORT. If this is 0, we listen on any arbitrary port. */
void
ttt_discover_set_listen_port(struct ttt_discover_options *opts, int port);

/* Set verbose to 0 or 1 for frugal or profligate use of ttt_error().
 * The default is 0. */
void
ttt_discover_set_verbose(struct ttt_discover_options *opts, int verbose);

/* Set the callback to be called when ttt_discover_and_connect() starts
 * listening for announcement datagrams. If we get this far then the initial
 * setup up to that point has succeeded. cookie is passed as the cookie
 * argument to listening_cb() when called.
 * By default, no callback is called for this event. */
void
ttt_discover_set_listening_callback(struct ttt_discover_options *opts,
        tttdl_listening_cb listening_cb, void *cookie);

/* Set the callback to be called when ttt_discover_and_connect() receives an
 * announcement packet. It is called regardless of whether the announcement
 * packet was deciphered and produced a valid decryption. cookie is passed as
 * the cookie argument to announcement_cb() when called.
 * By default, no callback is called for this event. */
void
ttt_discover_set_announcement_callback(struct ttt_discover_options *opts,
        tttdl_announcement_cb announcement_cb, void *cookie);

/* Set the maximum number of announcements ttt_discover_and_accept() should
 * send, and the interval in milliseconds between them. The default is
 * 0 for max_announcements, which means to apply no maximum - keep announcing
 * until interrupted. The default for announcement_interval_ms is 1000. */
void
ttt_discover_set_announcements(struct ttt_discover_options *opts,
        int max_announcements, int announcement_interval_ms);

/* Set the TTL or hop limit to be associated with announcement datagrams sent
 * by ttt_discover_and_accept(). */
void
ttt_discover_set_multicast_ttl(struct ttt_discover_options *opts, int ttl);

/* Specify whether to include globally routable IP addresses in the list of
 * interfaces to send announcements from. Default is false. */
void
ttt_discover_set_include_global_addresses(struct ttt_discover_options *opts, bool include_global);

/* Convenience function to discover the other host on our network which has
 * our passphrase, and make a TCP connection to them, returning that in
 * *new_sess.
 *
 * Return 0 on success, which means we received a valid announcement,
 * successfully connected to the port we were invited to, and successfully
 * handshook with the other end and created a ttt_session. Nonzero on failure.
 */
int
ttt_discover_and_connect(struct ttt_discover_options *opts,
        struct ttt_session *new_sess);

/* Convenience function to discover the other host on our network which has
 * our passphrase. We do this by listening for incoming connections on an
 * arbitrary TCP port, and sending encrypted announcement datagrams inviting the
 * recipient to connect to us. When we get an incoming connection, we perform a
 * TLS handshake with it, and if that succeeds (proving they have the
 * passphrase and encrypting the session), we return the session in *new_sess.
 *
 * This is the "other side" to ttt_discover_and_connect().
 *
 * *new_sess: set to a new ttt_session object if we received a connection on
 *   the port we specified in an announcement datagram, and we successfully
 *   completed a handshake with the other side, proving they have the
 *   passphrase and encrypting the session with the passphrase. It is the
 *   caller's responsibility to destroy this session (ttt_session_destroy())
 *   when it is no longer required.
 *
 * Return 0 on success, which means we opened a TCP port to listen on, sent at
 * least one announcement over UDP, received a connection to our TCP port, and
 * successfully handshook with the other end. Return nonzero on failure.
 */
int
ttt_discover_and_accept(struct ttt_discover_options *opts,
        struct ttt_session *new_sess);

/* Free any resources associated with the ttt_discover_options created with
 * ttt_discover_options_init(). */
void
ttt_discover_options_destroy(struct ttt_discover_options *opts);

#endif
