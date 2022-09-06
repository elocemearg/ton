#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/stat.h>

#ifdef WINDOWS
#include <winsock2.h>
#include <winsock.h>
#include <ws2ipdef.h> /* for struct sockaddr_in6 */
#include <windows.h>
#else
#include <sys/socket.h>
#include <netinet/in.h>
#endif

#include <errno.h>

#include "utils.h"

void
ttt_dump_hex(const void *data, size_t length, const char *context) {
    const unsigned char *d = (const unsigned char *)data;

    printf("%s\n", context);
    printf("%" PRINTF_INT64 "u bytes...\n", (unsigned long long) length);
    for (size_t pos = 0; pos < length; pos += 16) {
        for (size_t i = 0; i < 16; ++i) {
            if (pos + i >= length)
                printf("   ");
            else
                printf("%02x ", d[pos + i]);
        }
        printf("  ");
        for (size_t i = 0; i < 16; ++i) {
            if (pos + i >= length)
                break;
            if (isprint(d[pos + i]))
                putchar(d[pos + i]);
            else
                putchar('.');
        }
        putchar('\n');
    }
    printf("\n");
}

#ifndef WINDOWS
/* Don't need to define this on Windows */
int
closesocket(int fd) {
    return close(fd);
}
#endif

int
ttt_sockaddr_set_port(struct sockaddr *addr, unsigned short port) {
    switch (addr->sa_family) {
        case AF_INET:
            ((struct sockaddr_in *) addr)->sin_port = htons(port);
            break;

        case AF_INET6:
            ((struct sockaddr_in6 *) addr)->sin6_port = htons(port);
            break;

        default:
            return -1;
    }
    return 0;
}

void
ttt_verror(int exit_status, const char *errstr, const char *format, va_list ap) {
    fflush(stdout);
    fprintf(stderr, "ttt: ");
    vfprintf(stderr, format, ap);
    if (errstr != NULL) {
        fprintf(stderr, ": %s", errstr);
    }
    fprintf(stderr, "    \n");
    if (exit_status != 0)
        exit(exit_status);
}

void
ttt_error(int exit_status, int err, const char *format, ...) {
    va_list ap;
    va_start(ap, format);
    ttt_verror(exit_status, err == 0 ? NULL : strerror(err), format, ap);
    va_end(ap);
}

#ifdef WINDOWS
void
ttt_socket_error(int exit_status, const char *format, ...) {
    va_list ap;
    int err = WSAGetLastError();
    char errstr[256] = "";
    int rc;

    rc = FormatMessageA(
            FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
            NULL, err, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
            errstr, sizeof(errstr), NULL
    );
    errstr[sizeof(errstr) - 1] = '\0';
    if (rc == 0) {
        snprintf(errstr, sizeof(errstr), "Winsock error %d", err);
    }

    va_start(ap, format);
    ttt_verror(exit_status, errstr, format, ap);
    va_end(ap);
}
#else
void ttt_socket_error(int exit_status, const char *format, ...) {
    va_list ap;
    int err = errno;
    va_start(ap, format);
    ttt_verror(exit_status, err == 0 ? NULL : strerror(err), format, ap);
    va_end(ap);
}
#endif

char *
ttt_vfalloc(const char *fmt, va_list ap) {
    char *buf;
    int buf_size;
    int ret;

    buf_size = 100;
    buf = malloc(buf_size);
    if (buf == NULL)
        return NULL;

    while (1) {
        va_list ap_copy;
        va_copy(ap_copy, ap);
        ret = vsnprintf(buf, buf_size, fmt, ap_copy);
        va_end(ap_copy);
        if (ret < 0 || ret >= buf_size) {
            char *new_buf;
            int new_buf_size;
            if (ret < 0) {
                /* Not enough space, but we don't know how much we need... */
                new_buf_size = buf_size * 2;
            }
            else {
                new_buf_size = ret + 1;
            }
            new_buf = realloc(buf, new_buf_size);
            if (new_buf == NULL) {
                free(buf);
                return NULL;
            }
            buf = new_buf;
            buf_size = new_buf_size;
        }
        else {
            break;
        }
    }
    return buf;
}

static int
ttt_mkdir(const char *pathname, int mode) {
#ifdef WINDOWS
    return mkdir(pathname);
#else
    return mkdir(pathname, mode);
#endif
}

int
ttt_mkdir_parents(const char *pathname_orig, int mode, int parents_only, char dir_sep) {
    size_t pathname_len;
    char *pathname = strdup(pathname_orig);
    int return_value = 0;

    if (pathname == NULL)
        return -1;

    /* Remove any trailing directory separators from pathname */
    pathname_len = strlen(pathname);
    while (pathname_len > 0 && pathname[pathname_len - 1] == dir_sep)
        pathname[--pathname_len] = '\0';

    /* For every sub-path that's a prefix of this one, check if the directory
     * exists and create it if it doesn't.
     * Note we also iterate round the loop when pos == pathname_len, so that
     * we create the last level directory as well if parents_only is not set.
     * Start at pos = 1 so that if pathname is an absolute path e.g.
     * /tmp/dest/a.txt we don't try to create "/" */
    for (size_t pos = 1; pos <= pathname_len; pos++) {
        if (pathname[pos] == dir_sep || (!parents_only && pathname[pos] == '\0')) {
            STAT st;
            /* Does pathname[0 to pos] exist as a directory? */
            pathname[pos] = '\0';
            if (ttt_stat(pathname, &st) < 0 && errno == ENOENT) {
                /* Doesn't exist - create it. */
                if (ttt_mkdir(pathname, mode) < 0) {
                    goto fail;
                }
            }
            else if (!S_ISDIR(st.st_mode)) {
                /* Exists but not as a directory */
                errno = ENOTDIR;
                goto fail;
            }
            /* Otherwise, this directory already exists. Put the directory
             * separator back if we replaced it, and continue. */
            if (pos < pathname_len) {
                pathname[pos] = dir_sep;
            }
        }
    }
end:
    free(pathname);
    return return_value;

fail:
    return_value = -1;
    goto end;
}

/* Convert "size", which is a size in bytes, into a human-readable string
 * such as "4.32MB" and write it to dest.
 * dest must point to a buffer of at least 7 bytes. */
void
ttt_size_to_str(long long size, char *dest) {
    static const char *power_letters = " KMGTPEZY";
    if (size < 0) {
        strcpy(dest, "?");
    }
    else if (size < 1024) {
        sprintf(dest, "%4d B", (int) size);
    }
    else {
        double d = size;
        const char *p = power_letters;
        while (d >= 1024 && p[1]) {
            d /= 1024;
            p++;
        }
        if (d >= 1024) {
            /* 1024 yottabytes or more? */
            strcpy(dest, "huuuuge!");
        }
        else if (d >= 100) {
            snprintf(dest, 7, "%4d%cB", (int) d, *p);
        }
        else if (d >= 10) {
            snprintf(dest, 7, "%4.1f%cB", d, *p);
        }
        else {
            snprintf(dest, 7, "%4.2f%cB", d, *p);
        }
    }
}

#ifdef WINDOWS
int
ttt_chmod(const char *path, int unix_mode) {
    /* Translate the Unix-style chmod mode bits into what's required by the
     * Windows _chmod call, which only supports one read and write bit.
     * Take those from the owner-readable and owner-writable bits of
     * unix_mode. */
    int windows_mode_bits = 0;
    if (unix_mode & 0400) {
        windows_mode_bits |= _S_IREAD;
    }
    if (unix_mode & 0200) {
        windows_mode_bits |= _S_IWRITE;
    }
    return _chmod(path, windows_mode_bits);
}
#else
int
ttt_chmod(const char *path, mode_t mode) {
    return chmod(path, mode);
}
#endif

#ifdef WINDOWS
void
ttt_sockets_setup() {
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(1, 1), &wsaData) != 0) {
        fprintf(stderr, "WSAStartup() failed.\n");
        exit(1);
    }
}

void
ttt_sockets_teardown() {
    WSACleanup();
}
#else
void
ttt_sockets_setup() {
}

void
ttt_sockets_teardown() {
}
#endif

#ifdef WINDOWS
int
ttt_make_socket_blocking(int sock) {
    u_long mode = 0;
    if (ioctlsocket(sock, FIONBIO, &mode) != NO_ERROR)
        return -1;
    return 0;
}

int
ttt_make_socket_non_blocking(int sock) {
    u_long mode = 1;
    if (ioctlsocket(sock, FIONBIO, &mode) != NO_ERROR)
        return -1;
    return 0;
}
#else
#include <unistd.h>
#include <fcntl.h>
int
ttt_make_socket_blocking(int sock) {
    int flags = fcntl(sock, F_GETFL, 0);
    flags &= ~O_NONBLOCK;
    if (fcntl(sock, F_SETFL, flags) < 0)
        return -1;
    return 0;
}

int
ttt_make_socket_non_blocking(int sock) {
    int flags = fcntl(sock, F_GETFL, 0);
    flags |= O_NONBLOCK;
    if (fcntl(sock, F_SETFL, flags) < 0)
        return -1;
    return 0;
}
#endif
