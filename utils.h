#ifndef _TTTUTILS_H
#define _TTTUTILS_H

#include <stdarg.h>
#include <sys/socket.h>

void
ttt_dump_hex(const void *data, size_t length, const char *context);

int
closesocket(int);

int
ttt_sockaddr_set_port(struct sockaddr *addr, unsigned short port);

void
ttt_error(int exit_status, int err, const char *format, ...);

char *
ttt_vfalloc(const char *fmt, va_list ap);

int
ttt_mkdir_parents(const char *path, int mode, int parents_only, char dir_sep);

void
ttt_size_to_str(long long size, char *dest);

#endif
