#ifndef _TONPROTOCOL_H
#define _TONPROTOCOL_H

#include <stdarg.h>

/* Maximum permitted length of a TON message. */
#define TON_MSG_MAX 65536

/* TON message header length in bytes. This is currently eight bytes: four for
 * the message tag and four for the body length. See details below. */

#define TON_MSG_HEADER_SIZE 8

/* TON message tags. These three are replies by the receiver, but
 * TON_MSG_FATAL_ERROR can be sent by either side to say "I'm off" */
#define TON_MSG_OK                      0x000
#define TON_MSG_ERROR                   0x001
#define TON_MSG_FATAL_ERROR             0x002

/* Message tags used in the metadata section of a file transfer session */
#define TON_MSG_FILE_METADATA_SET_START 0x101
#define TON_MSG_FILE_METADATA           0x102
#define TON_MSG_FILE_METADATA_SUMMARY   0x103
#define TON_MSG_FILE_METADATA_SET_END   0x104

/* Message tags used in the actual file transfer */
#define TON_MSG_FILE_SET_START          0x201
#define TON_MSG_FILE_DATA_CHUNK         0x202
#define TON_MSG_FILE_DATA_END           0x203
#define TON_MSG_FILE_SET_END            0x204

/* Sender sends this after the end of the file transfer if it wants to give the
 * receiver an opportunity to send files. It can also send this at the start
 * of the session if it has no files to send and wants to switch roles
 * immediately. */
#define TON_MSG_SWITCH_ROLES            0x301

/* Sender sends this if it has just sent files and doesn't want to receive
 * any, or if it's just been given the sender role but doesn't want to send
 * any files. */
#define TON_MSG_END_SESSION             0x401


/* A message contains a header followed by a body. The header is always
 * exactly eight bytes long, and the body can be any length from 0 to
 * TON_MSG_MAX - 8 inclusive.
 *
 * All integer values in the header or any message body are sent in network
 * byte order.
 *
 * HEADER
 *
 * Byte offset   Length    Type   Description
 *           0        4   int32   Message tag, describing what type of message
 *                                this is. The format of the body depends on
 *                                this value.
 *           4        4   int32   Body length, in the range [0, TON_MSG_MAX - 8]
 *
 *
 * BODY
 *
 * The format of the body depends on the message tag. Any message MAY have a
 * body of length up to TON_MSG_MAX - 8 bytes, but some messages don't have a
 * body defined. If the body length is greater than the format for the tag
 * requires, or if the body exists but the receiver thinks the message
 * shouldn't have a body, the receiver should ignore any excess bytes in the
 * body. If the body length is too small to contain a valid body for this
 * message tag, the receiver should reply to the message sequence with
 * TON_MSG_ERROR.
 *
 *
 * PROTOCOL
 *
 * At the start of a session, the host who made the connection has the SENDER
 * role, and the host who accepted the connection has the RECEIVER role.
 *
 * Messages are sent in logical groups before waiting for an acknowledgement.
 * These groups are "message sequences". A message sequence consists of one or
 * more messages. The type of message sequence is implied by the tag of the
 * first message.
 *
 * The sender sends a message sequence, and the receiver replies with an
 * acknowledgement. This continues until the session ends, or the sender and
 * receiver switch roles (see below).
 *
 *
 * VALID MESSAGE SEQUENCES
 *
 * Metadata message sequence. This gives the receiver warning of what files are
 * going to be sent, or the number and total size of the files to be sent.
 * This should be treated as information only, to give the user an indication
 * of progress. The actual files sent may be different.
 *     TON_MSG_FILE_METADATA_SET_START
 *     Either:
 *         Zero or more TON_MSG_FILE_METADATA
 *     or:
 *         Exactly one TON_MSG_FILE_METADATA_SUMMARY
 *     TON_MSG_FILE_METADATA_SET_END
 *
 * File set sequence. This is where the actual files are sent. For each file
 * we send its metadata followed by its data as zero or more chunks.
 *     TON_MSG_FILE_SET_START
 *     Zero or more of:
 *         TON_MSG_FILE_METADATA
 *         Zero or more of:
 *             TON_MSG_FILE_DATA_CHUNK
 *         TON_MSG_FILE_DATA_END
 *     TON_MSG_FILE_SET_END
 *
 * Switch roles. When the sender has finished sending files, it can tell the
 * receiver that it's now the sender, and the receiver-turned-sender may send
 * some files of its own if required.
 *     TON_MSG_SWITCH_ROLES
 *
 * End session. This may be sent by the sender to terminate the session, or,
 * more usually, by the receiver-turned-sender after it's just been made the
 * sender but doesn't have any files to send.
 *     TON_MSG_END_SESSION
 *
 * Finally, at any point in a message sequence, the sender can send a:
 *     TON_MSG_FATAL_ERROR
 * message. This means the sender wishes to abort the session. If sent in the
 * middle of a file data message sequence, the last chunk sent may contain
 * garbage. The only permissible reply to TON_MSG_FATAL_ERROR is to close the
 * session.
 */
/*
 * TON_MSG_FILE_METADATA_SET_START: the sender intends to send metadata
 * information about zero or more files.
 * No body.
 *
 * TON_MSG_FILE_METADATA: contains file name, size, etc.
 * Body (minimum length 21):
 *     Byte offset     Length     Type     Description
 * from body start
 *               0          8     int64    File size in bytes. -1 if unknown.
 *               8          8     time_t   Modification time of file, as a
 *                                         Unix timestamp. 0 if unknown.
 *              16          4     int32    File mode/permissions, as in the
 *                                         st_mode field of struct stat.
 *              20   variable     string   File name as a '\0'-terminated
 *                                         string. This is a relative path with
 *                                         directory components delimited by
 *                                         the slash character ('/'). There is
 *                                         no support for directory components
 *                                         or filenames containing '/' or '\0'.
 *                                         The string must be valid UTF-8.
 *      after name   variable     string   Symlink target as a '\0'-terminated
 *                                         string. This is only meaningful if
 *                                         the file mode field indicates this
 *                                         is a symlink. This field is optional;
 *                                         if the message ends after the
 *                                         filename field the symlink target is
 *                                         taken as an empty string.
 *
 * TON_MSG_FILE_METADATA_SUMMARY: contains a summary of the files to be sent,
 * if the sender doesn't want to send an itemised list of all the files.
 * Body (minimum length 16):
 *     Byte offset  Length  Type   Description
 * from body start
 *               0       8  int64  Number of files to be sent.
 *               8       8  int64  Total size of all files to be sent, in bytes.
 *
 * TON_MSG_FILE_METADATA_SET_END: the sender has finished sending file metadata.
 * No body.
 * Receiver replies with TON_MSG_OK or TON_MSG_ERROR.
 */
/*
 * TON_MSG_FILE_SET_START: the sender is about to send data for a set of files.
 * No body.
 * The sender must then, for each file, send a TON_MSG_FILE_METADATA message
 * for the relevant file, followed by zero or more TON_MSG_FILE_DATA_CHUNK
 * messages containing the file's data from start to finish, followed by a
 * TON_MSG_FILE_DATA_END message.
 *
 * TON_MSG_FILE_DATA_CHUNK: a chunk of data for the file whose metadata
 * message was most recently sent.
 * The entire body of the message is the chunk data. The body length tells the
 * receiver how many data bytes there are. The position of this chunk within
 * the file is implied by the sum of the lengths of the previous data chunks
 * for this file.
 *
 * TON_MSG_FILE_DATA_END: the sender has finished sending data for this file.
 * The body indicates whether the file was sent successfully. If it wasn't,
 * this is not a fatal error but the receiver should delete the file and
 * inform the user that this file was not transferred.
 * Body (minimum 5 bytes):
 * Offset    Length     Type     Description
 *      0         4     int32    Error code (see table of error codes). If this
 *                               is zero the file was transferred successfully.
 *      4  variable     string   '\0'-terminated string to be shown to the
 *                               other end's user.
 *
 * TON_MSG_FILE_SET_END: there are no more files in the set.
 * No body.
 * Receiver replies with TON_MSG_OK or TON_MSG_ERROR.
 */

/*
 * TON_MSG_SWITCH_ROLES: the sender has no more files to send, and it is now
 * the receiver. The end that was the receiver is now the sender.
 * No body.
 * Receiver does not reply - it is now the sender.
 */

/*
 * TON_MSG_END_SESSION: the sender has no more files to send, and the receiver
 * either has already indicated it has no more files (by an earlier request to
 * switch roles) or the sender isn't interested in receiving any files.
 * There is no reply. The sender closes the session after sending this message.
 */

/*
 * TON_MSG_OK: positive acknowledgement by receiver in response to a valid
 * message sequence.
 * No body.
 */

/*
 * TON_MSG_FATAL_ERROR: the sender has encountered an error condition and
 * wishes to abort the session. Any partially-sent file should not be
 * considered valid.
 * Body (minimum 5 bytes):
 * Offset    Length     Type     Description
 *      0         4     int32    Error code (see table of error codes)
 *      4  variable     string   '\0'-terminated string to be shown to the
 *                               other end's user.
 */

/*
 * TON_MSG_ERROR: negative acknowledgement by receiver in response to a
 * message sequence it can't deal with, or a message tag it does not
 * recognise, or a message tag which is not allowed at this point in a
 * sequence.
 *
 * Body (minimum 5 bytes)
 * Offset    Length     Type     Description
 *      0         4     int32    Error code (see table of error codes)
 *      4  variable     string   '\0'-terminated string to be shown to the
 *                               other end's user.
 */

/* TABLE OF ERROR CODES
 *
 * Code    Description
 *
 *    0    Success.
 *
 *    1    Unrecognised tag. Receiver did not recognise sender's message tag.
 *         This is always a fatal error.
 *
 *    2    Protocol error. Message was too short, or contained invalid
 *         values, or appeared elsewhere than allowed in a message sequence.
 *         This is always a fatal error.
 *
 *    3    User rejected file set. Receiver received a metadata sequence
 *         but decided it didn't want to receive those files, perhaps because
 *         there isn't enough space on disk.
 *
 *    4    Failed to write file. The receiver failed to write a data chunk
 *         to its local copy of the file. The receiver should send this as a
 *         fatal error and close the session, so that the sender does not
 *         waste time continuing to sending a potentially huge file.
 *
 *    5    Failed to read file. Similar to 4 but sent by the sender, perhaps
 *         because it tried to read from a file it wanted to send but there was
 *         some I/O error.
 */

#define TON_ERR_UNRECOGNISED_TAG 1
#define TON_ERR_PROTOCOL 2
#define TON_ERR_FILE_SET_REJECTED 3
#define TON_ERR_FAILED_TO_WRITE_FILE 4
#define TON_ERR_FAILED_TO_READ_FILE 5

/* Errors for which we don't send a "fatal error" message to the other side,
 * because they've gone away. */
#define TON_ERR_CONNECTION_FAILURE -1
#define TON_ERR_EOF -2
#define TON_ERR_REMOTE_ERROR -3
#define TON_ERR_REMOTE_FATAL_ERROR -4

struct ton_msg {
    /* For keeping track of how much of the message we've written so far */
    int position;

    /* Message length including header and body */
    int length;

    /* Message data, including header and body */
    unsigned char data[TON_MSG_MAX];
};


struct ton_decoded_msg {
    /* Type of decoded message */
    int tag;

    union {
        /* tag == TON_MSG_FILE_METADATA */
        struct {
            long long size;
            time_t mtime;
            int mode;
            char *name;
            char *symlink_target;
        } metadata;

        /* tag == TON_MSG_FILE_METADATA_SUMMARY */
        struct {
            long long file_count;
            long long total_size;
        } metadata_summary;

        /* tag == TON_MSG_FILE_DATA_END, TON_MSG_ERROR or TON_MSG_FATAL_ERROR */
        struct {
            int code;
            char *message;
        } err;

        /* tag == TON_MSG_FILE_DATA_CHUNK */
        struct {
            int length;
            void *data;
        } chunk;

        /* Other message types don't have a body defined. */
    } u;
};

/* Allocate and return a pointer to a new ton_msg object. The position and
 * length fields will be initialised to 0. The contents of the data array
 * is undefined.
 * If we fail to allocate enough memory, an error message is printed with
 * ton_error() and we return NULL. */
struct ton_msg *
ton_msg_alloc(void);

/* Free a ton_msg previously created by ton_msg_alloc(). */
void
ton_msg_free(struct ton_msg *msg);

/* Set the position and length fields of a ton_msg to 0. */
void
ton_msg_clear(struct ton_msg *msg);

/* Functions for creating and sending a TON_MSG_FILE_DATA_CHUNK.
 * Example:
 *
 * struct ton_msg msg;
 * const char *file_data = "Hello world!";
 * void *data_ptr;
 *
 * ton_msg_file_data_chunk(&msg);
 * data_ptr = ton_msg_file_data_chunk_data_ptr(&msg);
 * memcpy(data_ptr, file_data, strlen(file_data));
 * ton_msg_file_data_chunk_set_length(&msg, strlen(file_data));
 */

/* Initialise msg to set the tag to TON_MSG_FILE_DATA_CHUNK. Leave the length
 * unset for now - caller will set this using
 * ton_msg_file_data_chunk_set_length() when it is known. */
void
ton_msg_file_data_chunk(struct ton_msg *msg);

/* Return the maximum number of data bytes we can write to a
 * TON_MSG_FILE_DATA_CHUNK message. */
int
ton_msg_file_data_chunk_get_max_length(struct ton_msg *msg);

/* Set the number of data bytes in a TON_MSG_FILE_DATA_CHUNK. */
void
ton_msg_file_data_chunk_set_length(struct ton_msg *msg, int length);

/* Get a pointer into msg, into which the caller may copy the data bytes
 * for this TON_MSG_FILE_DATA_CHUNK message. The caller may not copy more
 * than ton_msg_file_data_chunk_get_max_length() bytes into this, and the
 * caller must also call ton_msg_file_data_chunk_set_length() to the number
 * of data bytes copied in before sending the message. */
void *
ton_msg_file_data_chunk_data_ptr(struct ton_msg *msg);

/* Caller supplies exactly TON_MSG_HEADER_SIZE bytes pointed to by header.
 * We return the message tag number in *tag, the message both length in
 * *body_length_bytes, and a pointer to where the caller should place the
 * message body in *body_dest.
 *
 * Some messages have no body, in which case we set *body_length_bytes to 0 and
 * *body_dest to something undefined.
 *
 * Return 0 if the header is valid, or <0 if it isn't.
 * */
int
ton_msg_decode_header(struct ton_msg *msg, const void *header, int *tag, int *body_length_bytes, void **body_dest);

/* Build a message with the given tag type. ap must contain the correct number
 * of arguments of the correct type for the tag, as defined in msg_defs in
 * protocol.c. */
int
ton_build_message(struct ton_msg *msg, int tag, va_list ap);

/* Decode the content of msg, writing the tag to decoded->tag and any body
 * payload to the relevant element of the union decoded->u.
 * The relevant struct in decoded->u may contain pointers. These are pointers
 * into msg, so they only remain valid for as long as msg is valid.
 */
int
ton_msg_decode(struct ton_msg *msg, struct ton_decoded_msg *decoded);

#endif
