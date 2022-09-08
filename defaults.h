#ifndef _DEFAULTS_H
#define _DEFAULTS_H

/* Arbitrary multicast address which the announcer multicasts to and the
 * listener subscribes to. */
#define TTT_MULTICAST_RENDEZVOUS_ADDR "239.14.42.200"

/* Default port number on which to send UDP datagrams announcing ourselves,
 * and on which to expect said datagrams. */
#define TTT_DEFAULT_DISCOVER_PORT 51205

#endif
