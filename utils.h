#ifndef _TTTUTILS_H
#define _TTTUTILS_H

#ifdef WINDOWS
#include <winsock2.h>
#include <ws2tcpip.h> /* for socklen_t */
#include <winsock.h>
#else
#include <sys/socket.h>
#endif

#include <stdarg.h>
#include <sys/types.h>
#include <sys/stat.h>

#ifdef WINDOWS
#define PRINTF_INT64 "I64"
#else
#define PRINTF_INT64 "ll"
#endif

#ifdef WINDOWS
typedef struct __stat64 STAT;
#define ttt_stat _stat64
#else
typedef struct stat STAT;
#define ttt_stat lstat
#endif

void
ttt_dump_hex(const void *data, size_t length, const char *context);

#ifndef WINDOWS
int
closesocket(int);
#endif

int
ttt_sockaddr_set_port(struct sockaddr *addr, unsigned short port);

void
ttt_error(int exit_status, int err, const char *format, ...);

void
ttt_socket_error(int exit_status, const char *format, ...);

char *
ttt_vfalloc(const char *fmt, va_list ap);

int
ttt_mkdir_parents(const char *path, int mode, int parents_only, char dir_sep);

void
ttt_size_to_str(long long size, char *dest);

void
ttt_sockets_setup();

void
ttt_sockets_teardown();

int
ttt_make_socket_blocking(int sock);

int
ttt_make_socket_non_blocking(int sock);

#endif
