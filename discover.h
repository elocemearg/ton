#ifndef _TTTDISCOVER_H
#define _TTTDISCOVER_H

#include <sys/types.h>

#include "session.h"
#include "defaults.h"

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

    /* List of network interfaces which have a broadcast address, each of
     * which contains a socket we will bind to that interface's address. */
    struct ttt_netif *broadcast_ifs;

    /* List of network interfaces which we can use to send multicast packets.
     * Each contains a socket we will bind to that interface's address. */
    struct ttt_netif *multicast_ifs;
};

/* Initialise a discover-announce context with the given passphrase. This also
 * initialises a list of sockets.
 *
 * The caller may set options using tttdactx_set_port(),
 * tttdactx_set_multicast_ttl() etc before actually starting the announcement
 * stage using tttdactx_announce().
 *
 * Return 0 on success, or nonzero on error. We might return an error if there
 * are no suitable network interfaces, for example. */
int
tttdactx_init(struct tttdactx *ctx, const char *passphrase, size_t passphrase_length);

/* Set the port number on which to send announcement datagrams.
 * The default is TTT_DEFAULT_DISCOVER_PORT. */
void
tttdactx_set_port(struct tttdactx *ctx, PORT port);

/* Set the TTL of multicast datagrams we send. By default this is 1. The
 * ip(7) man page strongly warns against setting this higher than necessary. */
void
tttdactx_set_multicast_ttl(struct tttdactx *ctx, int ttl);

/* Send out an announcement datagram on every suitable network interface.
 * The datagram is encrypted with the passphrase. When decrypted by the
 * receiving host, it invites the decrypter to TCP-connect to us on the
 * invitation port number.
 *
 * It is the caller's responsibility to have already set up a listening socket
 * to listen on this invitation port. (Alternatively, see
 * ttt_discover_and_connect().)
 *
 * Return 0 on success or nonzero on failure. */
int
tttdactx_announce(struct tttdactx *ctx, PORT invitation_port);

/* Destroy a previously-initialise TTT discover-announce context and free any
 * resources associated with it. */
void
tttdactx_destroy(struct tttdactx *ctx);

/* Initialise a TTT discover-listen context with the given passphrase. This
 * is called by the other endpoint to the one that called tttdactx_init(). It
 * does not actually receive announcement datagrams: you need to call
 * tttdlctx_listen() after setting up any required options. */
int
tttdlctx_init(struct tttdlctx *ctx, const char *passphrase, size_t passphrase_length);

/* Set the port number on which we expect to receive announcement datagrams
 * over UDP. The default is TTT_DEFAULT_DISCOVER_PORT. */
void
tttdlctx_set_port(struct tttdlctx *ctx, PORT port);

/* "Listening" callback.
 * Set a callback to be called by tttdlctx_listen() when we start listening
 * for announcement datagrams. This indicates that we've configured all the
 * network interfaces successfully and are now proceeding to the bit where we
 * wait for announcements.
 * See the typedef for tttdl_listening_cb above. */
void
tttdlctx_set_listening_cb(struct tttdlctx *ctx, tttdl_listening_cb listening_cb);

/* Set an arbitrary pointer to be passed to the "listening" callback (see
 * above). */
void
tttdlctx_set_listening_callback_cookie(struct tttdlctx *ctx, void *cookie);

/* Announcement callback.
 * Set a callback to be called by tttdlctx_listen() when we receive an
 * announcement datagram, valid or invalid.
 * See the typedef for tttdl_announcement_cb above. */
void
tttdlctx_set_announcement_callback(struct tttdlctx *ctx, tttdl_announcement_cb announcement_cb);

/* Set an arbitrary pointer to be passed to the "announcement" callback (see
 * above). */
void
tttdlctx_set_announcement_callback_cookie(struct tttdlctx *ctx, void *cookie);

/* Set whether we want to be verbose during the discover-listen stage. If we
 * do, we get more diagnostic output written to stderr.
 * value = 0: not verbose.
 * value = 1: verbose.
 */
void
tttdlctx_set_verbose(struct tttdlctx *ctx, int value);


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
 * Return nonzero on error.
 */
int
tttdlctx_listen(struct tttdlctx *ctx,
        struct sockaddr_storage *peer_addr_r, int *peer_addr_length_r,
        PORT *invitation_port_r);

/* Destroy a previously-initialised TTT discover-listen context and free any
 * resources associated with it. */
void
tttdlctx_destroy(struct tttdlctx *ctx);

/* Convenience function to discover the other host on our network which has
 * our passphrase, and make a TCP connection to them, returning that in
 * *new_sess.
 *
 * multicast_address: the multicast address we expect to receive announcements
 *   on. If this is NULL we use the default, TTT_MULTICAST_RENDEZVOUS_ADDR.
 *   The other host must use the same address.
 *
 * discover_port: the port on which we expect to receive announcement
 *   datagrams. If this is <= 0 we use TTT_DEFAULT_DISCOVER_PORT. The other
 *   host must use the same port.
 *
 * passphrase, passphrase_length: the passphrase to use, and its length in
 *   bytes. The other host must use exactly the same passphrase. If it doesn't,
 *   you won't find each other.
 *
 * verbose: 1 to be verbose and write more stuff to stderr, 0 to not do that.
 *
 * listening_cb, listening_callback_cookie: callback to call when we start
 *   listening for announcement packets, and an arbitrary pointer to pass to
 *   the callback. See tttdlctx_set_listening_cb(). These can be set to NULL
 *   if not used.
 *
 * announcement_cb, announcement_callback_cookie: callback to call when we
 *   receive an announcement datagram, valid or not. See
 *   tttdlctx_set_announcement_cb(). These can be set to NULL if not used.
 *
 * new_sess: *new_sess is set to a new ttt_session object. It is the caller's
 * responsibility to destroy this session (ttt_session_destroy()) when it is
 * no longer required.
 *
 * Return 0 on success, which means we received a valid announcement,
 * successfully connected to the port we were invited to, and successfully
 * handshook with the other end and created a ttt_session. Nonzero on failure.
 */
int
ttt_discover_and_connect(const char *multicast_address, int discover_port,
        const char *passphrase, size_t passphrase_length, int verbose,
        tttdl_listening_cb listening_cb, void *listening_callback_cookie,
        tttdl_announcement_cb announcement_cb, void *announcement_callback_cookie,
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
 * multicast_address: the multicast address to send announcements on. If this
 *   is NULL we use the default, TTT_MULTICAST_RENDEZVOUS_ADDR. The other host
 *   must use the same address.
 *
 * discover_port: the port on which to send announcements. If this is <= 0 we
 *   use TTT_DEFAULT_DISCOVER_PORT. The other host must use the same port.
 *
 * max_announcements: the maximum number of announcements to send on each
 *   suitable network interface. If we send this many announcements and we
 *   still don't get a valid incoming TCP connection, we fail.
 *
 * announcement_interval_ms: the number of milliseconds to wait between
 *   annoucnements, during which we wait for incoming connections on our
 *   listening socket.
 *
 * multicast_ttl: the TTL to set on our multicast announcement datagrams.
 *   Warning: the ip(7) man page strongly warns against setting this to
 *   anything higher than it needs to be. The recommended value is 0, which
 *   leaves it at the default (1 for IPv4, route default for IPv6).
 *
 * passphrase, passphrase_length: the passphrase to use, and its length in
 *   bytes. The other host must use exactly the same passphrase. If it doesn't,
 *   the announcement datagrams we send will be ignored and you won't find
 *   the other host.
 *
 * verbose: 1 to enable more descriptive waffling on stderr. 0 to not.
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
ttt_discover_and_accept(const char *multicast_address, int discover_port,
        int max_announcements, int announcement_interval_ms, int multicast_ttl,
        const char *passphrase, size_t passphrase_length, int verbose,
        struct ttt_session *new_sess);

#endif