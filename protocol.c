#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <arpa/inet.h>

#include "protocol.h"
#include "session.h"
#include "utils.h"

struct ttt_msg_def {
    /* Message tag, e.g. TTT_MSG_FILE_METADATA. */
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
static struct ttt_msg_def msg_defs[] = {
    { TTT_MSG_OK,                      "",      0 },
    { TTT_MSG_ERROR,                   "4s",    5 },
    { TTT_MSG_FATAL_ERROR,             "4s",    5 },
    { TTT_MSG_FILE_METADATA_SET_START, "",      0 },
    { TTT_MSG_FILE_METADATA,           "8t4s", 21 },
    { TTT_MSG_FILE_METADATA_SUMMARY,   "88",   16 },
    { TTT_MSG_FILE_METADATA_SET_END,   "",      0 },
    { TTT_MSG_FILE_SET_START,          "",      0 },
    { TTT_MSG_FILE_DATA_CHUNK,         "*",     0 },
    { TTT_MSG_FILE_DATA_END,           "",      0 },
    { TTT_MSG_FILE_SET_END,            "",      0 },
    { TTT_MSG_SWITCH_ROLES,            "",      0 },
    { TTT_MSG_END_SESSION,             "",      0 }
};
#define msg_defs_length (sizeof(msg_defs) / sizeof(msg_defs[0]))

static int32_t
int32_ntoh(const unsigned char *buf, int offset) {
    return ntohl(*(const int32_t *)(buf + offset));
}

static int64_t
int64_ntoh(const unsigned char *buf, int offset) {
    return (int64_t) (
            ((uint64_t) ntohl(((uint64_t) *(const uint32_t *)(buf + offset)) << 32)) |
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

void
ttt_msg_clear(struct ttt_msg *msg) {
    msg->position = 0;
    msg->length = 0;
}

int
ttt_msg_decode_header(struct ttt_msg *msg, const void *header, int *tag,
        int *body_length_bytes, void **body_dest) {
    memcpy(msg->data, header, TTT_MSG_HEADER_SIZE);
    *tag = int32_ntoh(header, 0);
    *body_length_bytes = int32_ntoh(header, 4);
    if (*body_length_bytes < 0 || *body_length_bytes > TTT_MSG_MAX - TTT_MSG_HEADER_SIZE) {
        ttt_error(0, 0, "invalid message header: body length %d", *body_length_bytes);
        return -1;
    }
    *body_dest = msg->data + TTT_MSG_HEADER_SIZE;
    msg->position = TTT_MSG_HEADER_SIZE;
    return 0;
}

void
ttt_msg_set_header(struct ttt_msg *msg, int tag, int length) {
    int32_hton(msg->data, 0, tag);
    int32_hton(msg->data, 4, length);
    msg->length = length + TTT_MSG_HEADER_SIZE;
}

void
ttt_msg_file_data_chunk(struct ttt_msg *msg) {
    msg->position = 0;
    ttt_msg_set_header(msg, TTT_MSG_FILE_DATA_CHUNK, 0);
}

int
ttt_msg_file_data_chunk_get_max_length(struct ttt_msg *msg) {
    return TTT_MSG_MAX - TTT_MSG_HEADER_SIZE;
}

void
ttt_msg_file_data_chunk_set_length(struct ttt_msg *msg, int length) {
    ttt_msg_set_header(msg, TTT_MSG_FILE_DATA_CHUNK, length);
}

void *
ttt_msg_file_data_chunk_data_ptr(struct ttt_msg *msg) {
    return msg->data + TTT_MSG_HEADER_SIZE;
}

static int
msg_defs_tag_cmp(const void *tagv, const void *defv) {
    return *(int *) tagv - ((struct ttt_msg_def *) defv)->tag;
}

int
ttt_build_message(struct ttt_msg *msg, int tag, va_list ap) {
    struct ttt_msg_def *def;

    def = bsearch(&tag, msg_defs, msg_defs_length, sizeof(msg_defs[0]), msg_defs_tag_cmp);

    if (def == NULL) {
        ttt_error(0, 0, "INTERNAL ERROR: ttt_send_message() called with unrecognised tag %d", tag);
        return -1;
    }

    ttt_msg_clear(msg);
    msg->position = TTT_MSG_HEADER_SIZE;
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
                if (len + 1 > TTT_MSG_MAX - msg->position) {
                    ttt_error(0, 0, "INTERNAL ERROR: ttt_send_message() tried to fit a %zd-byte string into a message with only %d bytes left in it", len, TTT_MSG_MAX - msg->position);
                    return -1;
                }
                if (len > 0) {
                    memcpy(msg->data + msg->position, s, len);
                    msg->position += len;
                }
                msg->data[msg->position++] = '\0';
                break;

            case '*':
                ttt_error(0, 0, "INTERNAL ERROR: ttt_send_message() cannot be called for message type %d", tag);
                return -1;

            default:
                ttt_error(0, 0, "INTERNAL ERROR: ttt_send_message() encountered unknown format character in own protocol definition?! (%c)", *body);
                return -1;
        }
    }

    ttt_msg_set_header(msg, tag, msg->position - TTT_MSG_HEADER_SIZE);

    return 0;
}

int
ttt_msg_decode(struct ttt_msg *msg, struct ttt_decoded_msg *decoded) {
    int tag = int32_ntoh(msg->data, 0);
    int body_length = int32_ntoh(msg->data, 4);
    struct ttt_msg_def *def;
    void *body;
    char *str;
    int str_offset = 0;

    def = bsearch(&tag, msg_defs, msg_defs_length, sizeof(msg_defs[0]), msg_defs_tag_cmp);
    if (def == NULL) {
        ttt_error(0, 0, "received message with unrecognised tag %d", tag);
        return TTT_ERR_UNRECOGNISED_TAG;
    }

    if (body_length < def->min_body_length) {
        ttt_error(0, 0, "message with tag %d is invalid, body length too short (%d)", tag, body_length);
        return TTT_ERR_PROTOCOL;
    }
    body = msg->data + TTT_MSG_HEADER_SIZE;

    decoded->tag = tag;
    str = NULL;
    switch (tag) {
        case TTT_MSG_FILE_METADATA:
            decoded->u.metadata.size = int64_ntoh(body, 0);
            decoded->u.metadata.mtime = int64_ntoh(body, 8);
            decoded->u.metadata.mode = int32_ntoh(body, 16);
            decoded->u.metadata.name = body + 20;
            str = decoded->u.metadata.name;
            str_offset = 20;
            break;

        case TTT_MSG_FILE_METADATA_SUMMARY:
            decoded->u.metadata_summary.file_count = int64_ntoh(body, 0);
            decoded->u.metadata_summary.total_size = int64_ntoh(body, 8);
            break;

        case TTT_MSG_ERROR:
        case TTT_MSG_FATAL_ERROR:
            decoded->u.err.code = int32_ntoh(body, 0);
            decoded->u.err.message = body + 4;
            str_offset = 4;
            break;

        case TTT_MSG_FILE_DATA_CHUNK:
            decoded->u.chunk.length = body_length;
            decoded->u.chunk.data = body;
            break;
    }

    /* If there's a string, make sure it is NUL-terminated and the NUL is
     * inside the message body. */
    if (str) {
        char *str_end = memchr(str, '\0', body_length - str_offset);
        if (str_end == NULL) {
            ttt_error(0, 0, "message with tag %d is invalid because body length is %d but string is not NUL-terminated early enough.", tag, body_length);
            return TTT_ERR_PROTOCOL;
        }
    }

    return 0;
}

#undef msg_defs_length
