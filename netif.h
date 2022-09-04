#ifndef _TTTNETIF_H
#define _TTTNETIF_H

#include <sys/types.h>

struct sockaddr **
ttt_get_multicast_if_addrs(int *num_ifaces);

struct sockaddr **
ttt_get_broadcast_if_addrs(int *num_ifaces);

void
ttt_free_addrs(struct sockaddr **addrs, int num_addrs);

#endif
