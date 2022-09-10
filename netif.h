#ifndef _TTTNETIF_H
#define _TTTNETIF_H

#ifdef WINDOWS
#include <winsock2.h>
#include <winsock.h>
#include <ws2ipdef.h> /* for struct sockaddr_in6 */
#include <ws2tcpip.h>
#else
#include <sys/types.h>
#include <sys/socket.h>
#endif

/* Windows/Linux-independent struct describing a network interface on this
 * computer. */
struct ttt_netif {
    /* Address family: AF_INET or AF_INET6 */
#ifdef WINDOWS
    u_short family;
#else
    sa_family_t family;
#endif

    /* The IP address of this interface. Cast it to struct sockaddr if
     * family == AF_INET, or struct sockaddr_in if family == AF_INET6. */
    struct sockaddr_storage if_addr;

    /* Length of the sockaddr in if_addr. */
    socklen_t if_addr_len;

    /* OS-level identifier for this interface, for IPv4 and IPv6. */
#ifdef WINDOWS
    DWORD if_index_ipv4;
    DWORD if_index_ipv6;
#else
    int if_index_ipv4;
    int if_index_ipv6;
#endif

    /* True if bc_addr is valid */
    int bc_valid;

    /* The broadcast address of this interface, if applicable. IPv6 doesn't
     * use broadcast addresses, so if this is valid it will be a
     * struct sockaddr_in. */
    struct sockaddr_storage bc_addr;

    /* Length of the sockaddr in bc_addr. */
    socklen_t bc_addr_len;

    /* netif.c initialises this to -1 upon creation of the ttt_netif object.
     * It's only for the caller to store a socket alongside this interface.
     * In particular, ttt_netif_list_free() will close it if asked to. */
    int sock;

    /* Next interface in the list. */
    struct ttt_netif *next;
};

/* Get a list of all suitable network interfaces which support multicast.
 * We return a pointer to a linked list of struct ttt_netif.
 *
 * It is the caller's responsibility to pass the return value to
 * ttt_free_addrs() when it's no longer needed. */
struct ttt_netif *
ttt_get_multicast_ifs(void);

/* Get a list of all suitable network interfaces which have a broadcast
 * address we can use. We return a pointer to a linked list of struct ttt_netif.
 *
 * It is the caller's responsibility to pass the return value to
 * ttt_free_addrs() when it's no longer needed. */
struct ttt_netif *
ttt_get_broadcast_ifs(void);

/* Free a list of interfaces previously returned by ttt_get_multicast_ifs()
 * or ttt_get_broadcast_ifs(). num_addrs must be the *num_ifaces value
 * yielded by that function.
 *
 * If close_sockets is nonzero, then ttt_netif_list_free() calls closesocket()
 * on each ttt_netif's sock value if that is non-negative.
 */
void
ttt_netif_list_free(struct ttt_netif *list, int close_sockets);

/* Find all the multicast-enabled interfaces we can and enable them to receive
 * multicast datagrams on this socket to the given address, which must be in
 * the multicast range. If multicast_addr_str is NULL, use the default
 * TTT_MULTICAST_RENDEZVOUS_ADDR.
 *
 * Return the number of interfaces on which we successfully subscribed to this
 * address. */
int
multicast_interfaces_subscribe(int sock, const char *multicast_addr_str);

/* Undo multicast_interfaces_subscribe(): make it so that the socket no longer
 * receives datagrams to the given multicast address on all multicast-enabled
 * interfaces. If multicast_addr_str is NULL, use the default
 * TTT_MULTICAST_RENDEZVOUS_ADDR.
 *
 * Return the number of interfaces on which we successfully unsubscribed from
 * datagrams to this address.
 */
int
multicast_interfaces_unsubscribe(int sock, const char *multicast_addr_str);

#endif
