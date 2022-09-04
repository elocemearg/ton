#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <errno.h>
#include <netinet/in.h>

void
ttt_dump_hex(const void *data, size_t length, const char *context) {
    const unsigned char *d = (const unsigned char *)data;

    printf("%s\n", context);
    printf("%zd bytes...\n", length);
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

/* Don't need to define this on Windows */
int
closesocket(int fd) {
    return close(fd);
}

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
ttt_error(int exit_status, int err, const char *format, ...) {
    va_list ap;

    va_start(ap, format);

    fflush(stdout);
    fprintf(stderr, "ttt: ");
    vfprintf(stderr, format, ap);
    if (err != 0) {
        fprintf(stderr, ": %s", strerror(err));
    }
    fprintf(stderr, "   \n");

    va_end(ap);

    if (exit_status != 0)
        exit(exit_status);
}

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
            struct stat st;
            /* Does pathname[0 to pos] exist as a directory? */
            pathname[pos] = '\0';
            if (stat(pathname, &st) < 0 && errno == ENOENT) {
                /* Doesn't exist - create it. */
                if (mkdir(pathname, mode) < 0) {
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
        sprintf(dest, "%4lld B", size);
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
