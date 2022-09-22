#ifndef _DEFAULTS_H
#define _DEFAULTS_H

/* Arbitrary multicast address which the announcer multicasts to and the
 * listener subscribes to. This is in the 239.192.0.0/14 range for multicast
 * on private networks. */
#define TON_MULTICAST_GROUP_IPV4 "239.199.77.5"

/* Randomly chosen ff08:... address for announcements on IPv6 multicast.
 * ff08:... is the range for private multicast addresses with
 * organization-local scope. I generated a random 112-bit group ID and
 * called it mine. */
#define TON_MULTICAST_GROUP_IPV6 "ff08:5206:dd93:4290:0891:d264:1444:bd21"

/* Default port number on which to send UDP datagrams announcing ourselves,
 * and on which to expect said datagrams. */
#define TON_DEFAULT_DISCOVER_PORT 51205

/* Default TCP port number to listen on for incoming connections from hosts
 * who successfully decrypt the announcement datagram. */
#define TON_DEFAULT_LISTEN_PORT 51205

#endif
