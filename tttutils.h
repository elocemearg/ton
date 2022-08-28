#ifndef _TTTUTILS_H
#define _TTTUTILS_H

#include <sys/types.h>

struct sockaddr **
ttt_get_multicast_if_addrs(int *num_ifaces);

struct sockaddr **
ttt_get_broadcast_if_addrs(int *num_ifaces);

void
ttt_free_addrs(struct sockaddr **addrs, int num_addrs);

void
ttt_dump_hex(const void *data, size_t length, const char *context);

#endif
