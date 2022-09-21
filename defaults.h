#ifndef _DEFAULTS_H
#define _DEFAULTS_H

/* Arbitrary multicast address which the announcer multicasts to and the
 * listener subscribes to. */
#define TON_MULTICAST_GROUP_IPV4 "239.14.42.200"

/* Randomly chosen ff08:... address */
#define TON_MULTICAST_GROUP_IPV6 "ff08:5206:dd93:4290:0891:d264:1444:bd21"

/* Default port number on which to send UDP datagrams announcing ourselves,
 * and on which to expect said datagrams. */
#define TON_DEFAULT_DISCOVER_PORT 51205

/* Default TCP port number to listen on for incoming connections from hosts
 * who successfully decrypt the announcement datagram. */
#define TON_DEFAULT_LISTEN_PORT 51205

#endif
