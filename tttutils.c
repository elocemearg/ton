#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <unistd.h>

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
