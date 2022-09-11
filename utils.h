/* The generic "utils" file that all projects end up getting, containing
 * general-purpose functions used in multiple places or wrapper functions
 * which have to do different things on Linux and Windows. */

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

/* Address families bitmasks */
#define TTT_IPV4 1
#define TTT_IPV6 2
#define TTT_IPV4_ONLY TTT_IPV4
#define TTT_IPV6_ONLY TTT_IPV6
#define TTT_IP_BOTH (TTT_IPV4 | TTT_IPV6)

/* Address types bitmasks: broadcast, multicast or both */
#define TTT_ANNOUNCE_BROADCAST 1
#define TTT_ANNOUNCE_MULTICAST 2
#define TTT_ANNOUNCE_BROADCAST_ONLY TTT_ANNOUNCE_BROADCAST
#define TTT_ANNOUNCE_MULTICAST_ONLY TTT_ANNOUNCE_MULTICAST
#define TTT_ANNOUNCE_BOTH (TTT_ANNOUNCE_BROADCAST | TTT_ANNOUNCE_MULTICAST)

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

/* Standard "argh just dump this as hex to stdout for generic debugging
 * purposes" function.*/
void
ttt_dump_hex(const void *data, size_t length, const char *context);

#ifndef WINDOWS
/* Throughout TTT we use closesocket() to close a socket because that's what
 * we have to do on Windows (as opposed to calling close()). For non-Windows
 * systems, we define closesocket() to call close(). */
int
closesocket(int);
#endif

/* Set the port number of the given struct sockaddr. port must be in
 * host byte order - the function will convert it to network byte order for
 * copying into addr. */
int
ttt_sockaddr_set_port(struct sockaddr *addr, unsigned short port);

/* Error reporting function. Behaves very much like error(3) except that
 * error() is very Linux-specific. */
void
ttt_error(int exit_status, int err, const char *format, ...);

/* Call ttt_error() with err=errno (on Linux) or err=WSAGetLastError()
 * (on Windows). */
void
ttt_socket_error(int exit_status, const char *format, ...);

/* Return a newly-allocated string whose contents are equivalent to
 * what vsnprintf(str, size, fmt, ap) would copy into str if the size were
 * big enough.
 *
 * It is the caller's responsibility to free() the return value. */
char *
ttt_vfalloc(const char *fmt, va_list ap);

/* Create the directory named in "path" and give it the permission bits "mode".
 * If parents_only is set, ignore the last component of "path".
 * dir_sep is the directory separator according to the local OS.
 *
 * Returns 0 on success, nonzero on error.
 */
int
ttt_mkdir_parents(const char *path, int mode, int parents_only, char dir_sep);

/* Convert a size, in bytes, to a human-readable string with an appropriately
 * sized suffix, such as "4.32MB" or "636KB". dest must point to a buffer with
 * space for at least 7 bytes.
 * If size < 0, dest will contain "?".
 * If size is 1024 yottabytes or more, dest will contain "huge!"
 */
void
ttt_size_to_str(long long size, char *dest);

/* (best-effort) platform-independent chmod(). */
#ifdef WINDOWS
int
ttt_chmod(const char *path, int unix_mode);
#else
int
ttt_chmod(const char *path, mode_t mode);
#endif

/* Set up the sockets API. On Linux this is not needed and is a no-op. On
 * Windows the socket library won't work unless you call this before doing
 * anything sockety. */
void
ttt_sockets_setup();

/* Tear down the sockets API. On Linux this is not needed and is a no-op. */
void
ttt_sockets_teardown();

/* Cross-platform function to make a socket blocking. */
int
ttt_make_socket_blocking(int sock);

/* Cross-platform function to make a socket non-blocking. */
int
ttt_make_socket_non_blocking(int sock);

#endif
