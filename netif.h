#ifndef _TTTNETIF_H
#define _TTTNETIF_H

#include <sys/types.h>

/* Get a list of all suitable network interfaces which support multicast.
 * We return an array of pointers to struct sockaddr *. There is one
 * (struct sockaddr *) per interface, and set *num_ifaces to the number of
 * elements in the array.
 *
 * It is the caller's responsibility to pass the return value to
 * ttt_free_addrs() when it's no longer needed. */
struct sockaddr **
ttt_get_multicast_if_addrs(int *num_ifaces);

/* Get a list of all suitable network interfaces which have a broadcast
 * address we can use. We return an array of pointers to struct sockaddr *.
 * There is one (struct sockaddr *) per interface. Each sockaddr is a broadcast
 * address. We  set *num_ifaces to the number of elements in the array.
 *
 * It is the caller's responsibility to pass the return value to
 * ttt_free_addrs() when it's no longer needed. */
struct sockaddr **
ttt_get_broadcast_if_addrs(int *num_ifaces);

/* Free a list of addresses previously returned by ttt_get_multicast_if_addrs()
 * or ttt_get_broadcast_if_addrs(). num_addrs must be the *num_ifaces value
 * yielded by that function. */
void
ttt_free_addrs(struct sockaddr **addrs, int num_addrs);

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
