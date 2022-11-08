#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>

#ifndef WINDOWS
#include <arpa/inet.h>
#endif

#include "protocol.h"
#include "session.h"
#include "utils.h"

struct ton_msg_def {
    /* Message tag, e.g. TON_MSG_FILE_METADATA. */
    int tag;

    /* String encoding the format of the body. Each value in the body is
     * represented by a character in this string, as follows:
     *
     * Character     Description
     *         4     int32
     *         8     int64
     *         s     '\0'-terminated string
     *         t     time_t (64-bit)
     *         *     arbitrary data up to the end of the message
     */
    char *bodydef;

    /* If the body length is less than this, it's not a valid message. */
    int min_body_length;
};

/* This is searched with bsearch() so the tags must be in ascending order. */
static struct ton_msg_def msg_defs[] = {
    { TON_MSG_OK,                      "",       0 },
    { TON_MSG_ERROR,                   "4s",     5 },
    { TON_MSG_FATAL_ERROR,             "4s",     5 },
    { TON_MSG_FILE_METADATA_SET_START, "",       0 },
    { TON_MSG_FILE_METADATA,           "8t4ss", 21 },
    { TON_MSG_FILE_METADATA_SUMMARY,   "88",    16 },
    { TON_MSG_FILE_METADATA_SET_END,   "",       0 },
    { TON_MSG_FILE_SET_START,          "",       0 },
    { TON_MSG_FILE_DATA_CHUNK,         "*",      0 },
    { TON_MSG_FILE_DATA_END,           "4s",     5 },
    { TON_MSG_FILE_SET_END,            "",       0 },
    { TON_MSG_SWITCH_ROLES,            "",       0 },
    { TON_MSG_END_SESSION,             "",       0 }
};
#define msg_defs_length (sizeof(msg_defs) / sizeof(msg_defs[0]))

static int32_t
int32_ntoh(const unsigned char *buf, int offset) {
    return ntohl(*(const int32_t *)(buf + offset));
}

static int64_t
int64_ntoh(const unsigned char *buf, int offset) {
    return (int64_t) (
            (((uint64_t) ntohl(*(const uint32_t *)(buf + offset))) << 32) |
            ((uint64_t) ntohl(((uint64_t) *(const uint32_t *)(buf + offset + 4))))
    );
}

static void
int32_hton(unsigned char *buf, int offset, int32_t value) {
    value = htonl(value);
    memcpy(buf + offset, &value, sizeof(value));
}

static void
int64_hton(unsigned char *buf, int offset, int64_t value) {
    uint32_t hi = htonl((((uint64_t) value) >> 32) & 0xffffffffUL);
    uint32_t lo = htonl(((uint64_t) value) & 0xffffffffUL);
    memcpy(buf + offset, &hi, sizeof(hi));
    memcpy(buf + offset + 4, &lo, sizeof(lo));
}

struct ton_msg *
ton_msg_alloc(void) {
    struct ton_msg *msg = malloc(sizeof(struct ton_msg));
    if (msg == NULL) {
        ton_error(0, errno, "failed to allocate memory for new message");
    }
    else {
        msg->position = 0;
        msg->length = 0;
    }
    return msg;
}

void
ton_msg_free(struct ton_msg *msg) {
    free(msg);
}

void
ton_msg_clear(struct ton_msg *msg) {
    msg->position = 0;
    msg->length = 0;
}

int
ton_msg_decode_header(struct ton_msg *msg, const void *header, int *tag,
        int *body_length_bytes, void **body_dest) {
    memcpy(msg->data, header, TON_MSG_HEADER_SIZE);
    *tag = int32_ntoh(header, 0);
    *body_length_bytes = int32_ntoh(header, 4);
    if (*body_length_bytes < 0 || *body_length_bytes > TON_MSG_MAX - TON_MSG_HEADER_SIZE) {
        ton_error(0, 0, "invalid message header: body length %d", *body_length_bytes);
        return TON_ERR_PROTOCOL;
    }
    *body_dest = msg->data + TON_MSG_HEADER_SIZE;
    msg->position = TON_MSG_HEADER_SIZE;
    return 0;
}

void
ton_msg_set_header(struct ton_msg *msg, int tag, int length) {
    int32_hton(msg->data, 0, tag);
    int32_hton(msg->data, 4, length);
    msg->length = length + TON_MSG_HEADER_SIZE;
}

void
ton_msg_file_data_chunk(struct ton_msg *msg) {
    msg->position = 0;
    ton_msg_set_header(msg, TON_MSG_FILE_DATA_CHUNK, 0);
}

int
ton_msg_file_data_chunk_get_max_length(struct ton_msg *msg) {
    return TON_MSG_MAX - TON_MSG_HEADER_SIZE;
}

void
ton_msg_file_data_chunk_set_length(struct ton_msg *msg, int length) {
    ton_msg_set_header(msg, TON_MSG_FILE_DATA_CHUNK, length);
}

void *
ton_msg_file_data_chunk_data_ptr(struct ton_msg *msg) {
    return msg->data + TON_MSG_HEADER_SIZE;
}

static int
msg_defs_tag_cmp(const void *tagv, const void *defv) {
    return *(int *) tagv - ((struct ton_msg_def *) defv)->tag;
}

int
ton_build_message(struct ton_msg *msg, int tag, va_list ap) {
    struct ton_msg_def *def;

    def = bsearch(&tag, msg_defs, msg_defs_length, sizeof(msg_defs[0]), msg_defs_tag_cmp);

    if (def == NULL) {
        ton_error(0, 0, "INTERNAL ERROR: ton_send_message() called with unrecognised tag %d", tag);
        return -1;
    }

    ton_msg_clear(msg);
    msg->position = TON_MSG_HEADER_SIZE;
    for (char *body = def->bodydef; *body; body++) {
        char *s;
        size_t len;
        switch (*body) {
            case '4':
                int32_hton(msg->data, msg->position, va_arg(ap, int));
                msg->position += 4;
                break;

            case '8':
                int64_hton(msg->data, msg->position, va_arg(ap, long long));
                msg->position += 8;
                break;

            case 't':
                int64_hton(msg->data, msg->position, va_arg(ap, time_t));
                msg->position += 8;
                break;

            case 's':
                s = va_arg(ap, char *);
                if (s == NULL) {
                    len = 0;
                }
                else {
                    len = strlen(s);
                }
                if (len + 1 > TON_MSG_MAX - msg->position) {
                    ton_error(0, 0, "INTERNAL ERROR: ton_send_message() tried to fit a %zd-byte string into a message with only %d bytes left in it", len, TON_MSG_MAX - msg->position);
                    return -1;
                }
                if (len > 0) {
                    memcpy(msg->data + msg->position, s, len);
                    msg->position += len;
                }
                msg->data[msg->position++] = '\0';
                break;

            case '*':
                ton_error(0, 0, "INTERNAL ERROR: ton_send_message() cannot be called for message type %d", tag);
                return -1;

            default:
                ton_error(0, 0, "INTERNAL ERROR: ton_send_message() encountered unknown format character in own protocol definition?! (%c)", *body);
                return -1;
        }
    }

    ton_msg_set_header(msg, tag, msg->position - TON_MSG_HEADER_SIZE);

    return 0;
}

int
ton_msg_decode(struct ton_msg *msg, struct ton_decoded_msg *decoded) {
    int tag = int32_ntoh(msg->data, 0);
    int body_length = int32_ntoh(msg->data, 4);
    struct ton_msg_def *def;
    void *body;
    char *str_end;

    decoded->tag = tag;
    def = bsearch(&tag, msg_defs, msg_defs_length, sizeof(msg_defs[0]), msg_defs_tag_cmp);
    if (def == NULL) {
        ton_error(0, 0, "received message with unrecognised tag %d", tag);
        return TON_ERR_UNRECOGNISED_TAG;
    }

    if (body_length < def->min_body_length) {
        ton_error(0, 0, "message with tag %d is invalid, body length too short (%d)", tag, body_length);
        return TON_ERR_PROTOCOL;
    }
    body = msg->data + TON_MSG_HEADER_SIZE;

    decoded->tag = tag;
    switch (tag) {
        case TON_MSG_FILE_METADATA:
            decoded->u.metadata.size = int64_ntoh(body, 0);
            decoded->u.metadata.mtime = int64_ntoh(body, 8);
            decoded->u.metadata.mode = int32_ntoh(body, 16);

            /* Up to 2 string arguments follow: filename and symlink target. */
            decoded->u.metadata.name = (char *) body + 20;
            str_end = memchr(decoded->u.metadata.name, '\0', body_length - 20);
            if (str_end == NULL) {
                goto badstring;
            }
            if (str_end + 1 >= (char *) body + body_length) {
                /* Second string is the symlink target. If the message ends
                 * here and there is no second string, point symlink_target to
                 * the terminating null of the first string, thus defaulting it
                 * to the empty string. */
                decoded->u.metadata.symlink_target = str_end;
            }
            else {
                /* Ensure the second string has a terminating null within the
                 * message body. */
                decoded->u.metadata.symlink_target = str_end + 1;
                if (memchr(decoded->u.metadata.symlink_target, '\0', body_length - (decoded->u.metadata.symlink_target - (char *) body)) == NULL) {
                    goto badstring;
                }
            }
            break;

        case TON_MSG_FILE_METADATA_SUMMARY:
            decoded->u.metadata_summary.file_count = int64_ntoh(body, 0);
            decoded->u.metadata_summary.total_size = int64_ntoh(body, 8);
            break;

        case TON_MSG_ERROR:
        case TON_MSG_FATAL_ERROR:
        case TON_MSG_FILE_DATA_END:
            decoded->u.err.code = int32_ntoh(body, 0);
            decoded->u.err.message = (char *) body + 4;
            if (memchr(decoded->u.err.message, '\0', body_length - 4) == NULL) {
                goto badstring;
            }
            break;

        case TON_MSG_FILE_DATA_CHUNK:
            decoded->u.chunk.length = body_length;
            decoded->u.chunk.data = body;
            break;
    }

    return 0;

badstring:
    ton_error(0, 0, "message with tag %d is invalid because body length is %d but string is not NUL-terminated early enough.", tag, body_length);
    return TON_ERR_PROTOCOL;
}

#undef msg_defs_length
