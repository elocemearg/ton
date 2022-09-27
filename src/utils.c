#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <ctype.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <errno.h>
#include <math.h>

#include "utils.h"

#ifdef WINDOWS
#include <winsock2.h>
#include <winsock.h>
#include <ws2ipdef.h> /* for struct sockaddr_in6 */
#include <windows.h>
#else
#include <sys/socket.h>
#include <netinet/in.h>
#endif

void
ton_dump_hex(const void *data, size_t length, const char *context) {
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
ton_sockaddr_set_port(struct sockaddr *addr, unsigned short port) {
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
ton_verror(int exit_status, const char *errstr, const char *format, va_list ap) {
    fflush(stdout);
    fprintf(stderr, "ton: ");
    vfprintf(stderr, format, ap);
    if (errstr != NULL) {
        fprintf(stderr, ": %s", errstr);
    }
    fprintf(stderr, "    \n");
    if (exit_status != 0)
        exit(exit_status);
}

void
ton_error(int exit_status, int err, const char *format, ...) {
    va_list ap;
    va_start(ap, format);
    ton_verror(exit_status, err == 0 ? NULL : strerror(err), format, ap);
    va_end(ap);
}

#ifdef WINDOWS

void
ton_socket_error_aux_v(int exit_status, int err, const char *format, va_list ap) {
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

    ton_verror(exit_status, errstr, format, ap);
    va_end(ap);
}

void
ton_socket_error_aux(int exit_status, int err, const char *format, ...) {
    va_list ap;
    va_start(ap, format);
    ton_socket_error_aux_v(exit_status, err, format, ap);
    va_end(ap);
}

void
ton_socket_error(int exit_status, const char *format, ...) {
    va_list ap;
    int err = WSAGetLastError();
    va_start(ap, format);
    ton_socket_error_aux_v(exit_status, err, format, ap);
    va_end(ap);
}

#else

void ton_socket_error(int exit_status, const char *format, ...) {
    va_list ap;
    int err = errno;
    va_start(ap, format);
    ton_verror(exit_status, err == 0 ? NULL : strerror(err), format, ap);
    va_end(ap);
}

void ton_socket_error_aux(int exit_status, int err, const char *format, ...) {
    va_list ap;
    va_start(ap, format);
    ton_verror(exit_status, err == 0 ? NULL : strerror(err), format, ap);
    va_end(ap);
}

#endif

char *
ton_vfalloc(const char *fmt, va_list ap) {
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

/* Add two struct timevals and put the result in *dest. */
void
timeval_add(const struct timeval *t1, const struct timeval *t2, struct timeval *dest) {
    dest->tv_sec = t1->tv_sec + t2->tv_sec;
    dest->tv_usec = t1->tv_usec + t2->tv_usec;
    dest->tv_sec += dest->tv_usec / 1000000;
    dest->tv_usec %= 1000000;
}


/* If b > a, put (0, 0) in result.
 * Otherwise, set result to a - b. */
void
timeval_diff(const struct timeval *a, const struct timeval *b, struct timeval *result) {
    result->tv_sec = a->tv_sec - b->tv_sec;
    result->tv_usec = a->tv_usec - b->tv_usec;
    while (result->tv_usec < 0) {
        result->tv_usec += 1000000;
        result->tv_sec--;
    }
    if (result->tv_sec < 0) {
        result->tv_sec = 0;
        result->tv_usec = 0;
    }
}

/* Convert "size", which is a size in bytes, into a human-readable string
 * such as "4.32MB" and write it to dest.
 * dest must point to a buffer of at least 7 bytes. */
void
ton_size_to_str(long long size, char *dest) {
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
            strcpy(dest, "huge!");
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

double
parse_double_or_exit(const char *str, const char *option) {
    char *endptr = NULL;
    double d = strtod(str, &endptr);
    if (*str && endptr != NULL && *endptr == '\0') {
        if (!isnormal(d)) {
            ton_error(1, 0, "%s: argument %s is out of range", option, str);
        }
        return d;
    }
    else {
        ton_error(1, 0, "%s: argument %s is not a number", option, str);
        return 0;
    }
}


#ifdef WINDOWS
void
ton_sockets_setup() {
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(1, 1), &wsaData) != 0) {
        fprintf(stderr, "WSAStartup() failed.\n");
        exit(1);
    }
}

void
ton_sockets_teardown() {
    WSACleanup();
}
#else
void
ton_sockets_setup() {
}

void
ton_sockets_teardown() {
}
#endif

#ifdef WINDOWS
int
ton_make_socket_blocking(int sock) {
    u_long mode = 0;
    if (ioctlsocket(sock, FIONBIO, &mode) != NO_ERROR)
        return -1;
    return 0;
}

int
ton_make_socket_non_blocking(int sock) {
    u_long mode = 1;
    if (ioctlsocket(sock, FIONBIO, &mode) != NO_ERROR)
        return -1;
    return 0;
}
#else
#include <unistd.h>
#include <fcntl.h>
int
ton_make_socket_blocking(int sock) {
    int flags = fcntl(sock, F_GETFL, 0);
    flags &= ~O_NONBLOCK;
    if (fcntl(sock, F_SETFL, flags) < 0)
        return -1;
    return 0;
}

int
ton_make_socket_non_blocking(int sock) {
    int flags = fcntl(sock, F_GETFL, 0);
    flags |= O_NONBLOCK;
    if (fcntl(sock, F_SETFL, flags) < 0)
        return -1;
    return 0;
}
#endif

/*****************************************************************************/

#ifdef TON_UNIT_TESTS

#include <CUnit/CUnit.h>

void
test_timeval_add(void) {
    struct {
        struct timeval t1;
        struct timeval t2;
        struct timeval expected;
    } test_cases[] = {
        { { 0, 0 }, { 0, 0 }, { 0, 0 } },
        { { 5, 400000 }, { 6, 700000 }, { 12, 100000 } },
        { { 1663420372, 900000 }, { 0, 500000 }, { 1663420373, 400000 } },
        { { 1663420372, 500000 }, { 0, 500000 }, { 1663420373, 0 } },
        { { 1663420372, 400000 }, { 0, 500000 }, { 1663420372, 900000 } },
        { { 1663420372, 600000 }, { 0, 10500000 }, { 1663420383, 100000 } },
        { { 1663420372, 999999 }, { 0, 1 }, { 1663420373, 0 } },
        { { 1663420372, 123456 }, { 0, 0 }, { 1663420372, 123456 } }
    };

    for (int i = 0; i < sizeof(test_cases) / sizeof(test_cases[0]); i++) {
        struct timeval observed;
        struct timeval *t1 = &test_cases[i].t1;
        struct timeval *t2 = &test_cases[i].t2;
        struct timeval *expected = &test_cases[i].expected;

        timeval_add(t1, t2, &observed);

        if (expected->tv_sec != observed.tv_sec || expected->tv_usec != observed.tv_usec) {
            fprintf(stderr, "test_timeval_add: t1 (%d, %d), t2 (%d, %d), expected (%d, %d), observed (%d, %d)\n",
                    (int) t1->tv_sec, (int) t1->tv_usec,
                    (int) t2->tv_sec, (int) t2->tv_usec,
                    (int) expected->tv_sec, (int) expected->tv_usec,
                    (int) observed.tv_sec, (int) observed.tv_usec);
        }
        CU_ASSERT_EQUAL(observed.tv_sec, expected->tv_sec);
        CU_ASSERT_EQUAL(observed.tv_usec, expected->tv_usec);
    }
}

void
test_timeval_diff(void) {
    struct {
        struct timeval t1;
        struct timeval t2;
        struct timeval expected;
    } test_cases[] = {
        /* If t1 < t2, result is expected to be 0 */
        { { 0, 0 }, { 0, 0 }, { 0, 0 } },
        { { 1663499680, 400000 }, { 1663499680, 300000 }, { 0, 100000 } },
        { { 1663499680, 400000 }, { 1663499680, 500000 }, { 0, 0 } },
        { { 1663499680, 900000 }, { 1663499681, 100000 }, { 0, 0 } },
        { { 1663499680, 100000 }, { 1663499679, 900000 }, { 0, 200000 } },
        { { 1663499680, 200000 }, { 1663499000, 300000 }, { 679, 900000 } },
        { { 1663499680, 500000 }, { 1663500000, 0 }, { 0, 0 } },
        { { 1663499680, 246802 }, { 0, 0 }, { 1663499680, 246802 } },
        { { 1672531200, 654321 }, { 1640995200, 123456 }, { 31536000, 530865 }},
        { { 1672531200, 123456 }, { 1640995200, 654321 }, { 31535999, 469135 }},
    };

    for (int i = 0; i < sizeof(test_cases) / sizeof(test_cases[0]); i++) {
        struct timeval observed;
        struct timeval *t1 = &test_cases[i].t1;
        struct timeval *t2 = &test_cases[i].t2;
        struct timeval *expected = &test_cases[i].expected;

        timeval_diff(t1, t2, &observed);

        if (expected->tv_sec != observed.tv_sec || expected->tv_usec != observed.tv_usec) {
            fprintf(stderr, "test_timeval_diff: t1 (%d, %d), t2 (%d, %d), expected (%d, %d), observed (%d, %d)\n",
                    (int) t1->tv_sec, (int) t1->tv_usec,
                    (int) t2->tv_sec, (int) t2->tv_usec,
                    (int) expected->tv_sec, (int) expected->tv_usec,
                    (int) observed.tv_sec, (int) observed.tv_usec);
        }
        CU_ASSERT_EQUAL(observed.tv_sec, expected->tv_sec);
        CU_ASSERT_EQUAL(observed.tv_usec, expected->tv_usec);
    }
}

CU_ErrorCode
ton_utils_register_tests(void) {
    CU_TestInfo tests[] = {
        { "timeval_add", test_timeval_add },
        { "timeval_diff", test_timeval_diff },
        CU_TEST_INFO_NULL
    };

    CU_SuiteInfo suites[] = {
        { "utils", NULL, NULL, NULL, NULL, tests },
        CU_SUITE_INFO_NULL
    };

    return CU_register_suites(suites);
}

#endif
