#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>
#include <utime.h>
#include <sys/time.h>
#include <errno.h>

#include "filetransfer.h"
#include "session.h"
#include "protocol.h"
#include "utils.h"

#ifdef NAME_MAX
#define MAX_PATH_COMPONENT_LEN NAME_MAX
#else
#define MAX_PATH_COMPONENT_LEN 256
#endif

/* Enable random failures for testing */
static int ttt_random_file_open_failures = 0;
static int ttt_random_file_read_failures = 0;
static int ttt_random_file_write_failures = 0;

#ifdef WINDOWS
#define DIR_SEP_STR "\\"
#else
#define DIR_SEP_STR "/"
#endif
const char DIR_SEP = DIR_SEP_STR[0];

#define TIMEVAL_X_GE_Y(X, Y) ((X).tv_sec > (Y).tv_sec || ((X).tv_sec == (Y).tv_sec && (X).tv_usec >= (Y).tv_usec))

/* dest must point to at least strlen(path1) + strlen(path2) + 2 bytes */
static void
join_paths(const char *path1, const char *path2, char *dest) {
    /* Decide whether we need to put a directory separator between these */
    size_t path1_len = strlen(path1);
    int add_sep;

    if (path1[0]) {
        add_sep = (path1[path1_len - 1] != DIR_SEP);
    }
    else {
        add_sep = 1;
    }

    /* Translate / back into the local directory separator */
    sprintf(dest, "%s%s%s", path1, add_sep ? DIR_SEP_STR : "", path2);
}

#ifdef WINDOWS
static int
ends_with_icase(const char *path, const char *ending) {
    size_t len = strlen(path);
    if (len < strlen(ending))
        return 0;
    if (!strcasecmp(path + len - strlen(ending), ending))
        return 1;
    else
        return 0;
}
#endif


/* Recursively search the directory named in "path", calling callback for each
 * file found. If "path" is a file not a directory, we just call callback once
 * for that file.
 * initial_path is the path supplied to the top-level call to ttt_dir_walk().
 * The callback should return 0 normally, or -1 to terminate the walk with
 * an error.
 * Return value is 0 on success, 1 if some files could not be statted, or -1
 * if there was a fatal error. */
static int
ttt_dir_walk_aux(const char *path, const char *initial_path,
        int (*callback)(void *cookie, const char *file_path, STAT *st,
            const char *initial_path),
        void *cookie) {
    int ret = 0;
    STAT st;
    if (ttt_stat(path, &st) < 0) {
        ttt_error(0, errno, "%s", path);
        return 1;
    }

    if (S_ISDIR(st.st_mode)) {
        /* This is a directory. Recursively walk each of its children. */
        char *new_path = NULL;
        DIR *dir = opendir(path);
        struct dirent *ent = NULL;

        if (dir == NULL) {
            ttt_error(0, errno, "%s", path);
            return 1;
        }

        new_path = malloc(strlen(path) + 1 + MAX_PATH_COMPONENT_LEN + 1);
        if (new_path == NULL) {
            ttt_error(0, errno, "malloc");
            ret = -1;
        }
        errno = 0;
        while (ret >= 0 && (ent = readdir(dir)) != NULL) {
            int subret;

            if (!strcmp(ent->d_name, ".") || !strcmp(ent->d_name, ".."))
                continue;
#ifdef WINDOWS
            if (ends_with_icase(ent->d_name, ".lnk"))
                continue;
#endif
            if (strlen(ent->d_name) > MAX_PATH_COMPONENT_LEN) {
                ttt_error(0, 0, "can't open %s/%s: subdirectory name too long", path, ent->d_name);
                ret = 1;
                continue;
            }
            join_paths(path, ent->d_name, new_path);

            subret = ttt_dir_walk_aux(new_path, initial_path, callback, cookie);
            if (subret > 0) {
                ret = subret;
            }
            else if (subret < 0) {
                ret = -1;
            }
            errno = 0;
        }
        free(new_path);

        if (ent == NULL && errno != 0) {
            ttt_error(0, errno, "error reading directory entries in %s", path);
            ret = -1;
        }
        closedir(dir);
    }
    else if (S_ISREG(st.st_mode)) {
        /* This is an ordinary file. Call the callback for it. */
        int cbret = callback(cookie, path, &st, initial_path);
        if (cbret < 0) {
            ret = -1;
        }
    }

    /* Don't bother with special files such as symlinks (yet), sockets,
     * device files, etc. */

    return ret;
}

static int
ttt_dir_walk(const char *path,
        int (*callback)(void *cookie, const char *file_path, STAT *st,
            const char *initial_path),
        void *cookie) {
    return ttt_dir_walk_aux(path, path, callback, cookie);
}

/*
 * ("alpha/bravo/charlie/delta.txt", "alpha/bravo") => "charlie/delta.txt"
 * ("./alpha/bravo/charlie.txt", ".") => "alpha/bravo/charlie.txt"
 * ("alpha/bravo.txt", "alpha") => "bravo.txt"
 * ("alpha/bravo/charlie.txt", "alpha/bravo/charlie.txt") => "charlie.txt"
 * ("alpha/../bravo//charlie/delta.txt", "alpha/../bravo") => "charlie/delta.txt"
 */
static char *
local_path_to_ttt_path(const char *path, const char *initial_path) {
    char *ttt_path;
    int start;
    if (strncmp(path, initial_path, strlen(initial_path)) == 0) {
        start = strlen(initial_path);
    }
    else {
        start = 0;
    }
    if (start > 0 && path[start] != DIR_SEP) {
        /* Go back to the last directory separator before this point */
        for (--start; start > 0 && path[start] != DIR_SEP; --start);
    }
    /* Then position ourselves immediately after this directory separator */
    while (path[start] == DIR_SEP)
        ++start;

    /* Take all the path components after this point. */
    ttt_path = strdup(path + start);
    if (ttt_path == NULL) {
        ttt_error(0, errno, "strdup");
        return NULL;
    }

    /* Substitute all DIR_SEP characters for '/' */
    if (DIR_SEP != '/') {
        for (int i = 0; ttt_path[i]; ++i) {
            if (ttt_path[i] == DIR_SEP) {
                ttt_path[i] = '/';
            }
        }
    }
    return ttt_path;
}

/* ("alpha/bravo/charlie.txt", "/home/fred") => "/home/fred/alpha/bravo/charlie.txt"
 * ("alpha.txt", "/home/fred/") => "/home/fred/alpha.txt"
 * ("alpha/bravo.txt", "/home/fred///") => "/home/fred///alpha/bravo.txt"
 * ("alpha/bravo.txt", ".") => "./alpha/bravo.txt"
 */
static char *
ttt_path_to_local_path(const char *path, const char *local_base_dir) {
    char *new_path = malloc(strlen(local_base_dir) + 1 + strlen(path) + 1);
    if (new_path == NULL)
        return NULL;

    while (*path == '/')
        path++;

    join_paths(local_base_dir, path, new_path);
    if (DIR_SEP != '/') {
        for (size_t i = strlen(local_base_dir); new_path[i]; i++) {
            if (new_path[i] == '/')
                new_path[i] = DIR_SEP;
        }
    }
    return new_path;
}

static void
ttt_file_free(struct ttt_file *file) {
    free(file->local_path);
    free(file->ttt_path);
    free(file);
}

static void
ttt_file_list_init(struct ttt_file_list *list) {
    list->start = NULL;
    list->last = NULL;
}

static void
ttt_file_list_destroy(struct ttt_file_list *list) {
    struct ttt_file *cur, *next;
    for (cur = list->start; cur != NULL; cur = next) {
        next = cur->next;
        ttt_file_free(cur);
    }
    list->start = NULL;
    list->last = NULL;
}

static struct ttt_file *
ttt_file_new(const char *local_path, const char *ttt_path, time_t mtime,
        int mode, long long size) {
    struct ttt_file *f = malloc(sizeof(struct ttt_file));
    if (f == NULL) {
        return NULL;
    }
    memset(f, 0, sizeof(*f));
    if (local_path) {
        f->local_path = strdup(local_path);
        if (f->local_path == NULL)
            goto fail;
    }
    else {
        f->local_path = NULL;
    }
    if (ttt_path) {
        f->ttt_path = strdup(ttt_path);
        if (f->ttt_path == NULL)
            goto fail;
    }
    else {
        f->ttt_path = NULL;
    }
    f->mtime = mtime;
    f->mode = mode;
    f->size = size;
    f->next = NULL;

    return f;

fail:
    ttt_file_free(f);
    return NULL;
}

static int
add_local_file_to_list(void *cookie, const char *path, STAT *st, const char *initial_path) {
    struct ttt_file_list *list = (struct ttt_file_list *) cookie;
    struct ttt_file *file = NULL;

    file = ttt_file_new(path, NULL, st->st_mtime, st->st_mode, st->st_size);
    if (file == NULL) {
        ttt_error(0, errno, "failed to create new file object structure for %s", path);
        return -1;
    }
    file->next = NULL;

    file->ttt_path = local_path_to_ttt_path(path, initial_path);
    if (file->ttt_path == NULL) {
        ttt_file_free(file);
        return -1;
    }

    if (list->last) {
        list->last->next = file;
        list->last = file;
    }
    else {
        list->start = file;
        list->last = file;
    }
    return 0;
}

static int
add_ttt_file_to_list(struct ttt_file_list *list, long long size, time_t mtime,
        int mode, const char *ttt_name, const char *local_base_dir) {
    struct ttt_file *file = NULL;

    file = ttt_file_new(NULL, ttt_name, mtime, mode, size);
    if (file == NULL) {
        ttt_error(0, errno, "failed to create new file object structure for %s", ttt_name);
        return -1;
    }
    file->next = NULL;

    file->local_path = ttt_path_to_local_path(ttt_name, local_base_dir);
    if (file->local_path == NULL) {
        ttt_file_free(file);
        return -1;
    }

    if (list->last) {
        list->last->next = file;
        list->last = file;
    }
    else {
        list->start = file;
        list->last = file;
    }
    return 0;
}

static int
readall(struct ttt_session *sess, void *buf, int length) {
    size_t bytes_read = 0;
    do {
        int rc = sess->read(sess, buf + bytes_read, length - bytes_read);
        if (rc <= 0) {
            if (rc < 0 && errno == EINTR)
                continue;
            return rc;
        }
        bytes_read += rc;
    } while (bytes_read < length);
    return bytes_read;
}

static int
ttt_msg_recv(struct ttt_session *sess, struct ttt_msg *msg) {
    unsigned char header[TTT_MSG_HEADER_SIZE];
    int rc;
    int tag, body_length_bytes;
    void *body_dest;

    rc = readall(sess, header, TTT_MSG_HEADER_SIZE);
    if (rc == 0) {
        ttt_error(0, 0, "connection terminated");
        return TTT_ERR_EOF;
    }
    else if (rc < 0) {
        ttt_error(0, 0, "connection interrupted");
        return TTT_ERR_CONNECTION_FAILURE;
    }

    rc = ttt_msg_decode_header(msg, header, &tag, &body_length_bytes, &body_dest);
    if (rc != 0) {
        return rc;
    }

    if (body_length_bytes > 0) {
        rc = readall(sess, body_dest, body_length_bytes);
        if (rc != body_length_bytes) {
            if (rc < 0) {
                ttt_error(0, 0, "connection interrupted");
                return TTT_ERR_CONNECTION_FAILURE;
            }
            else {
                ttt_error(0, 0, "unexpected EOF during message body");
                return TTT_ERR_EOF;
            }
        }
    }
    return 0;
}

static int
ttt_msg_send(struct ttt_session *sess, struct ttt_msg *msg) {
    size_t bytes_sent = 0;
    do {
        int rc;
        errno = 0;
        rc = sess->write(sess, msg->data + bytes_sent, msg->length - bytes_sent);
        if (rc <= 0) {
            if (rc < 0 && errno == EINTR)
                continue;
            ttt_error(0, errno, "connection interrupted");
            return -1;
        }
        bytes_sent += rc;
    } while (bytes_sent < msg->length);
    return bytes_sent;
}

static int
ttt_send_message(struct ttt_session *sess, int tag, ...) {
    struct ttt_msg msg;
    va_list ap;
    int rc;

    va_start(ap, tag);
    rc = ttt_build_message(&msg, tag, ap);
    va_end(ap);

    if (rc != 0)
        return rc;

    rc = ttt_msg_send(sess, &msg);
    if (rc < 0)
        return -1;

    return 0;
}

static int
ttt_reply_ok(struct ttt_session *sess) {
    return ttt_send_message(sess, TTT_MSG_OK);
}

static int
ttt_send_fatal_error(struct ttt_session *sess, int code, const char *fmt, ...) {
    va_list ap;
    char *message;
    int rc;

    va_start(ap, fmt);

    message = ttt_vfalloc(fmt, ap);
    rc = ttt_send_message(sess, TTT_MSG_FATAL_ERROR, code, message);
    free(message);

    va_end(ap);

    return rc;
}

static int
ttt_reply_error(struct ttt_session *sess, int code, const char *fmt, ...) {
    va_list ap;
    char *message;
    int rc;

    va_start(ap, fmt);

    message = ttt_vfalloc(fmt, ap);
    rc = ttt_send_message(sess, TTT_MSG_ERROR, code, message);
    free(message);

    va_end(ap);

    return rc;
}

static int
ttt_send_file_data_end(struct ttt_session *sess, int error_code, const char *error_format, ...) {
    int rc;

    if (error_format == NULL) {
        rc = ttt_send_message(sess, TTT_MSG_FILE_DATA_END, error_code, "");
    }
    else {
        va_list ap;
        char *message;
        va_start(ap, error_format);
        message = ttt_vfalloc(error_format, ap);
        rc = ttt_send_message(sess, TTT_MSG_FILE_DATA_END, error_code, message);
        free(message);
        va_end(ap);
    }

    return rc;
}

static int
ttt_get_next_message(struct ttt_session *sess, struct ttt_msg *msg, struct ttt_decoded_msg *decoded) {
    int rc = ttt_msg_recv(sess, msg);
    if (rc != 0) {
        return rc;
    }
    rc = ttt_msg_decode(msg, decoded);
    if (rc != 0) {
        ttt_send_fatal_error(sess, rc, "failed to decode message");
        return rc;
    }
    return 0;
}

static int
ttt_receive_reply_report_error(struct ttt_session *sess) {
    struct ttt_msg msg;
    struct ttt_decoded_msg decoded;
    int rc;

    rc = ttt_get_next_message(sess, &msg, &decoded);
    if (rc != 0)
        return rc;

    switch (decoded.tag) {
        case TTT_MSG_OK:
            return 0;
        case TTT_MSG_ERROR:
        case TTT_MSG_FATAL_ERROR:
            ttt_error(0, 0, "received %serror from remote host: 0x%08x: %s",
                    decoded.tag == TTT_MSG_FATAL_ERROR ? "fatal " : "",
                    decoded.u.err.code, decoded.u.err.message);
            return decoded.tag == TTT_MSG_ERROR ? TTT_ERR_REMOTE_ERROR : TTT_ERR_REMOTE_FATAL_ERROR;
        default:
            ttt_error(0, 0, "received unexpected reply tag %d, expecting OK, ERROR or FATAL ERROR", decoded.tag);
            return TTT_ERR_PROTOCOL;
    }
}

static void
timeval_add(const struct timeval *t1, const struct timeval *t2, struct timeval *dest) {
    dest->tv_sec = t1->tv_sec + t2->tv_sec;
    dest->tv_usec = t1->tv_usec + t2->tv_usec;
    dest->tv_sec += dest->tv_usec / 1000000;
    dest->tv_usec %= 1000000;
}

static void
make_progress_report(struct ttt_file_transfer *ctx, int is_sender,
        const char *filename, long file_number, long file_count,
        long long file_position, long long file_size, long long bytes_sent,
        long long bytes_total, long files_skipped, int finished) {
    if (ctx->progress) {
        struct timeval now;
        ctx->progress(ctx->callback_cookie, is_sender, filename, file_number,
                file_count, file_position, file_size, bytes_sent, bytes_total,
                files_skipped, finished);
        gettimeofday(&now, NULL);
        timeval_add(&now, &ctx->progress_report_interval, &ctx->next_progress_report);
    }
}

static int
is_progress_report_due(struct ttt_file_transfer *ctx) {
    if (ctx->progress) {
        struct timeval now;
        gettimeofday(&now, NULL);
        if (TIMEVAL_X_GE_Y(now, ctx->next_progress_report)) {
            return 1;
        }
    }
    return 0;
}

/* Already within a TTT_MSG_FILE_SET_START/TTT_MSG_FILE_SET_END block, send
 * a TTT_MSG_FILE_METADATA message, data chunks and TTT_MSG_FILE_DATA_END
 * message for the given file.
 *
 * Return 0 if we successfully sent the TTT_MSG_FILE_DATA_END message. Note
 * this does not mean we actually succeeded in sending the complete file, only
 * that the session is still alive and there was no fatal error
 *
 * If we failed to open or send any part of the file, we include the error
 * information in the TTT_MSG_FILE_DATA_END message we sent to the receiver,
 * set *file_failed to 1, and return 0. If we successfully send the complete
 * file, we set *file_failed to 0 and return 0.
 *
 * Return <0 if there was a fatal error such as a communication or protocol
 * error and the session should be aborted.
 */
int
ttt_send_file(struct ttt_file_transfer *ctx, struct ttt_session *sess,
        long file_number, long file_count, long long *bytes_sent_so_far,
        long long *total_size, long num_files_skipped, struct ttt_file *f,
        int *file_failed) {
    struct ttt_msg msg;
    FILE *stream;
    size_t bytes_read = 0;
    int return_value = 0;
    long long file_position = 0;

    *file_failed = 0;

    /* Send a metadata message, so the receiver knows to expect a file. */
    if (ttt_send_message(sess, TTT_MSG_FILE_METADATA, f->size, f->mtime, f->mode, f->ttt_path) < 0) {
        goto fail;
    }

    /* Open the file we want to send. If this fails, tell the receiver that
     * there will be no data for this file and that we failed to send it. */
    stream = fopen(f->local_path, "rb");
    if (ttt_random_file_open_failures && stream != NULL && rand() % 50 == 0) {
        fclose(stream);
        stream = NULL;
        errno = EPERM;
    }
    if (stream == NULL) {
        int err = errno;
        ttt_error(0, err, "%s", f->local_path);
        if (ttt_send_file_data_end(sess, TTT_ERR_FAILED_TO_READ_FILE, "%s", strerror(err)) != 0)
            goto fail;
        *file_failed = 1;
        return 0;
    }

    do {
        void *msg_data_dest;
        int max_length;

        /* Initialise a file data chunk */
        ttt_msg_file_data_chunk(&msg);

        max_length = ttt_msg_file_data_chunk_get_max_length(&msg);
        msg_data_dest = ttt_msg_file_data_chunk_data_ptr(&msg);

        /* Read up to max_length bytes from the file into the message */
        errno = 0;
        bytes_read = fread(msg_data_dest, 1, max_length, stream);
        if (ttt_random_file_read_failures && bytes_read != 0 && rand() % 100 == 0) {
            bytes_read = 0;
            errno = EIO;
        }
        if (bytes_read == 0) {
            if (ferror(stream) || (ttt_random_file_read_failures && errno == EIO)) {
                /* Error reading from the file. Send a TTT_MSG_FILE_DATA_END
                 * message with an error code, to tell the receiver this file
                 * failed to send. The session continues. */
                int err = errno;
                ttt_error(0, err, "%s", f->local_path);
                *file_failed = 1;
                if (ttt_send_file_data_end(sess, TTT_ERR_FAILED_TO_READ_FILE, "%s", strerror(err)) != 0) {
                    goto fail;
                }
                *total_size -= f->size - file_position;
            }
            else {
                /* End of file. We read and sent everything successfully. */
                if (ttt_send_file_data_end(sess, 0, NULL) != 0)
                    goto fail;
            }
        }
        else {
            /* Set the length field of the chunk message... */
            ttt_msg_file_data_chunk_set_length(&msg, (int) bytes_read);

            /* Now send the chunk message */
            if (ttt_msg_send(sess, &msg) < 0)
                goto fail;

            file_position += bytes_read;
            *bytes_sent_so_far += bytes_read;
        }

        if (is_progress_report_due(ctx)) {
            make_progress_report(ctx, 1, f->local_path, file_number,
                    file_count, file_position, f->size, *bytes_sent_so_far,
                    *total_size, num_files_skipped, 0);
        }
    } while (bytes_read > 0);

end:
    if (stream)
        fclose(stream);

    return return_value;

fail:
    return_value = -1;
    goto end;
}

static int
ttt_file_transfer_session_sender(struct ttt_file_transfer *ctx,
        struct ttt_session *sess, long long *total_files_out,
        long long *num_file_failures_out) {
    struct ttt_file_list file_list;
    int walk_failures = 0;
    int return_value = 0;
    long num_file_failures = 0;
    long long progress_bytes_sent_so_far = 0;
    long long progress_total_size = 0;
    long file_number = 0;
    long total_files = 0;
    int rc;

    if (ctx->num_source_paths <= 0) {
        /* Nothing to do */
        return 0;
    }

    /* Build a list of all the files we want to send */
    ttt_file_list_init(&file_list);
    for (int i = 0; i < ctx->num_source_paths; ++i) {
        rc = ttt_dir_walk(ctx->source_paths[i], add_local_file_to_list, &file_list);
        if (rc < 0) {
            goto fail;
        }
        else if (rc > 0) {
            walk_failures = 1;
        }
    }

    if (walk_failures && file_list.start == NULL) {
        /* All files failed to be walked */
        ttt_error(0, 0, "couldn't stat any files!");
        goto fail;
    }

    /* Now send a file metadata set message sequence. We send either a
     * metadata mesage for each file, or just a total file and byte count,
     * depending on whether ctx->send_full_metadata is set. */
    if (ttt_send_message(sess, TTT_MSG_FILE_METADATA_SET_START) < 0)
        goto fail;
    total_files = 0;
    for (struct ttt_file *f = file_list.start; f; f = f->next) {
        if (ctx->send_full_metadata) {
            if (ttt_send_message(sess, TTT_MSG_FILE_METADATA, f->size, f->mtime, f->mode, f->ttt_path) < 0) {
                goto fail;
            }
        }
        ++total_files;
        progress_total_size += f->size;
    }
    if (!ctx->send_full_metadata) {
        /* Send metadata summary */
        if (ttt_send_message(sess, TTT_MSG_FILE_METADATA_SUMMARY, (long long) total_files, progress_total_size) < 0) {
            goto fail;
        }
    }
    if (ttt_send_message(sess, TTT_MSG_FILE_METADATA_SET_END) < 0)
        goto fail;

    rc = ttt_receive_reply_report_error(sess);
    if (rc == 0) {
        /* Now send a file data set message sequence, in which for each file in
         * file_list, we send a metadata message and the file's data broken up
         * into data chunks... */
        if (ttt_send_message(sess, TTT_MSG_FILE_SET_START) < 0)
            goto fail;
        for (struct ttt_file *f = file_list.start; f; f = f->next) {
            int file_failed = 0;
            if (access(f->local_path, F_OK) != 0 && errno == ENOENT) {
                /* File existed when we walked the directories, but it's gone now.
                 * Report this as a non-fatal error. */
                ttt_error(0, 0, "%s no longer exists, not sending it.", f->local_path);
                continue;
            }
            file_number++;
            if (ttt_send_file(ctx, sess, file_number, total_files,
                        &progress_bytes_sent_so_far, &progress_total_size,
                        num_file_failures, f, &file_failed) < 0) {
                goto fail;
            }

            if (file_failed) {
                /* Session is still running but we couldn't open the file on our
                 * side, so sent a half-hearted apology in lieu of the file. */
                num_file_failures++;
            }
        }
        if (ttt_send_message(sess, TTT_MSG_FILE_SET_END) < 0)
            goto fail;

        if (ctx->progress) {
            struct ttt_file *last_file = file_list.last;
            make_progress_report(ctx, 1,
                    last_file ? last_file->local_path : NULL, file_number,
                    total_files, last_file ? last_file->size : 0,
                    last_file ? last_file->size : 0, progress_bytes_sent_so_far,
                    progress_bytes_sent_so_far, num_file_failures, 1);
        }

        if (ttt_receive_reply_report_error(sess) != 0)
            goto fail;
    }
    else if (rc == TTT_ERR_REMOTE_ERROR) {
        /* Remote host replied to metadata with non-fatal error. */
        num_file_failures = total_files;
    }
    else {
        goto fail;
    }

end:
    /* Now we've finished. */
    if (total_files_out)
        *total_files_out = total_files;
    if (num_file_failures_out)
        *num_file_failures_out = num_file_failures;
    ttt_file_list_destroy(&file_list);
    return return_value;

fail:
    return_value = -1;
    goto end;
}

static int
ttt_receive_file_metadata_set(struct ttt_session *sess,
        const char *output_dir, struct ttt_file_list *list,
        long long *file_count_out, long long *total_size_out) {
    struct ttt_msg msg;
    struct ttt_decoded_msg decoded;
    long long file_count = 0, total_size = 0;
    int received_summary = 0;

    do {
        if (ttt_get_next_message(sess, &msg, &decoded) != 0) {
            goto fail;
        }
        if (decoded.tag == TTT_MSG_FILE_METADATA_SUMMARY) {
            file_count = decoded.u.metadata_summary.file_count;
            total_size = decoded.u.metadata_summary.total_size;
            received_summary = 1;
        }
        else if (decoded.tag == TTT_MSG_FILE_METADATA) {
            int rc = add_ttt_file_to_list(list, decoded.u.metadata.size,
                    decoded.u.metadata.mtime, decoded.u.metadata.mode,
                    decoded.u.metadata.name, output_dir);
            if (rc < 0) {
                goto fail;
            }
            if (!received_summary) {
                file_count++;
                total_size += decoded.u.metadata.size;
            }
        }
        else if (decoded.tag == TTT_MSG_FATAL_ERROR) {
            ttt_error(0, 0, "received fatal error from sender: 0x%08x: %s", decoded.u.err.code, decoded.u.err.message);
            goto fail;
        }
        else if (decoded.tag != TTT_MSG_FILE_METADATA_SET_END) {
            ttt_error(0, 0, "sender sent unexpected tag 0x%x in a metadata list", decoded.tag);
            ttt_send_fatal_error(sess, TTT_ERR_PROTOCOL, "sender sent unexpected tag 0x%x in a metadata list", decoded.tag);
            goto fail;
        }
    } while (decoded.tag != TTT_MSG_FILE_METADATA_SET_END);

    if (file_count_out)
        *file_count_out = file_count;
    if (total_size_out)
        *total_size_out = total_size;

    return 0;

fail:
    ttt_file_list_destroy(list);
    return -1;
}

static void
ttt_update_progress(const char *current_filename,
        long long files_received, long long file_count,
        long long total_bytes_received, long long total_size) {
    const char *display_filename = NULL;
    const int filename_limit = 44;
    int filename_trimmed = 0;
    char bytes_received_str[10];
    char total_size_str[10];

    if (current_filename != NULL) {
        /* Show only the last filename_limit characters of the filename */
        size_t len = strlen(current_filename);
        if (len > filename_limit) {
            display_filename = current_filename + len - filename_limit + 3;
            filename_trimmed = 1;
        }
        else {
            display_filename = current_filename;
        }
    }
    else {
        display_filename = "";
    }

    ttt_size_to_str(total_bytes_received, bytes_received_str);
    fprintf(stderr, "%6" PRINTF_INT64 "d/%" PRINTF_INT64 "d %s%-*s | %6s",
            files_received, file_count,
            filename_trimmed ? "..." : "",
            filename_limit - (filename_trimmed ? 3 : 0), display_filename,
            bytes_received_str);
    if (total_size > 0) {
        ttt_size_to_str(total_size, total_size_str);
        fprintf(stderr, "/%6s  %3d%%\r",
                total_size_str, (int) (100 * total_bytes_received / total_size));
    }
    else {
        fprintf(stderr, "\r");
    }
}

static void
default_progress_callback(void *callback_cookie, int is_sender,
            const char *filename, long file_number, long total_files,
            long long file_position, long long file_size,
            long long bytes_so_far, long long total_bytes,
            long skipped_files, int finished) {
    ttt_update_progress(filename, file_number, total_files, bytes_so_far,
            total_bytes);
    if (finished) {
        char size_str[10];
        ttt_size_to_str(bytes_so_far, size_str);
        fprintf(stderr, "\n%s %ld file%s,", is_sender ? "Sent" : "Received",
                file_number - skipped_files,
                (file_number - skipped_files) == 1 ? "" : "s");
        if (skipped_files != 0) {
            fprintf(stderr, " skipped %ld file%s,", skipped_files,
                    skipped_files == 1 ? "" : "s");
        }
        fprintf(stderr, " total %6s.\n", size_str);
    }
}

static int
ttt_receive_file_set(struct ttt_file_transfer *ctx, struct ttt_session *sess,
        struct ttt_file_list *list, long long file_count, long long total_size,
        long long *sender_failed_file_count) {
    struct ttt_msg msg;
    struct ttt_decoded_msg decoded;
    FILE *current_file = NULL; /* destination for current file */
    char *local_filename = NULL; /* name of current or last file received */
    int in_file_transfer = 0; /* are we between FILE_METADATA and DATA_END */
    char *ttt_filename = NULL; /* filename according to FILE_METADATA */
    time_t current_file_mtime = 0;
    long long current_file_position = 0;
    long long current_file_size = 0;
    long long total_bytes_received = 0;
    long long total_bytes_remaining = total_size;
    long long current_file_number = 0;
    long files_sender_failed = 0;
    int current_file_mode = 0;
    int return_value = 0;
    struct timeval now, next_progress_report;
    const struct timeval progress_report_interval = { 0, 500000 };

    gettimeofday(&now, NULL);
    timeval_add(&now, &progress_report_interval, &next_progress_report);

    do {
        if (ttt_get_next_message(sess, &msg, &decoded) != 0) {
            goto fail;
        }
        gettimeofday(&now, NULL);

        if (decoded.tag == TTT_MSG_FILE_METADATA) {
            if (in_file_transfer) {
                ttt_error(0, 0, "TTT_MSG_FILE_METADATA tag received out of sequence!");
                ttt_send_fatal_error(sess, TTT_ERR_PROTOCOL, "sender sent TTT_MSG_FILE_METADATA tag but didn't end previous file %s", ttt_filename);
                goto fail;
            }

            /* Copy the details about the current file so we have them for
             * progress reports and so we can set the file's mode and
             * timestamp after we close it. */
            current_file_mtime = decoded.u.metadata.mtime;
            current_file_mode = decoded.u.metadata.mode;
            current_file_size = decoded.u.metadata.size;
            current_file_position = 0;
            current_file_number++;

            /* We are now in a file transfer, which means we can only receive
             * TTT_MSG_FILE_DATA_CHUNK, TTT_MSG_FILE_DATA_END or
             * TTT_MSG_FATAL_ERROR until the transfer is finished. */
            in_file_transfer = 1;

            /* Replace ttt_filename and local_filename with the details of the
             * new file - this is now our current file. */
            free(ttt_filename);
            ttt_filename = strdup(decoded.u.metadata.name);
            free(local_filename);
            local_filename = ttt_path_to_local_path(decoded.u.metadata.name, ctx->output_dir);
            if (local_filename == NULL) {
                ttt_error(0, errno, "failed to allocate path name");
                goto fail;
            }

            if (S_ISREG(current_file_mode)) {
                /* This is a regular file. Open its local pathname for
                 * writing. */
                current_file = fopen(local_filename, "wb");
                if (ttt_random_file_write_failures && current_file == NULL && rand() % 50 == 0) {
                    fclose(current_file);
                    unlink(local_filename);
                    current_file = NULL;
                    errno = EPERM;
                }
                if (current_file == NULL && errno == ENOENT) {
                    /* Try to create the directory structure prefixing local_filename */
                    if (ttt_mkdir_parents(local_filename, 0777, 1, DIR_SEP) < 0) {
                        int err = errno;
                        ttt_error(0, err, "failed to create directory for %s", local_filename);
                        ttt_send_fatal_error(sess, TTT_ERR_FAILED_TO_WRITE_FILE, "failed to create directory for %s: %s", local_filename, strerror(err));
                        goto fail;
                    }

                    /* Try to open the file again... */
                    current_file = fopen(local_filename, "wb");
                    if (current_file == NULL) {
                        ttt_error(0, errno, "skipping %s: failed to open for writing", local_filename);
                    }
                }
            }
            else if (S_ISDIR(current_file_mode)) {
                /* This is a directory entry, so create it. */
                if (ttt_mkdir_parents(local_filename, current_file_mode & 0777, 0, DIR_SEP) < 0) {
                    ttt_error(0, errno, "failed to create directory %s", local_filename);
                }
            }
        }
        else if (decoded.tag == TTT_MSG_FILE_DATA_CHUNK) {
            /* A data chunk to be appended to the currently-open file. */
            if (!in_file_transfer) {
                ttt_error(0, 0, "TTT_MSG_FILE_DATA_CHUNK sent without TTT_MSG_FILE_METADATA!");
                ttt_send_fatal_error(sess, TTT_ERR_PROTOCOL, "sender sent TTT_MSG_FILE_DATA_CHUNK but there was no TTT_MSG_FILE_METADATA before it");
                goto fail;
            }

            /* current_file may be NULL if for some reason we don't want
             * to save this file. */
            if (current_file != NULL) {
                size_t ret = fwrite(decoded.u.chunk.data, 1, decoded.u.chunk.length, current_file);
                if (ttt_random_file_write_failures && ret != 0 && rand() % 100 == 0) {
                    ret = 0;
                    errno = EIO;
                }
                if (ret != decoded.u.chunk.length) {
                    int err = errno;
                    ttt_error(0, err, "failed to write to %s", local_filename);
                    ttt_send_fatal_error(sess, TTT_ERR_FAILED_TO_WRITE_FILE, "failed to write data to %s: %s", ttt_filename, strerror(err));
                    goto fail;
                }
            }
            total_bytes_remaining -= decoded.u.chunk.length;
            current_file_position += decoded.u.chunk.length;
            total_bytes_received += decoded.u.chunk.length;
        }
        else if (decoded.tag == TTT_MSG_FILE_DATA_END) {
            struct utimbuf timbuf;
            if (!in_file_transfer) {
                ttt_error(0, 0, "TTT_MSG_FILE_DATA_END sent without TTT_MSG_FILE_METADATA!");
                ttt_send_fatal_error(sess, TTT_ERR_PROTOCOL, "sender sent TTT_MSG_FILE_DATA_END but there was no TTT_MSG_FILE_METADATA before it");
                goto fail;
            }

            /* End of the data for this file. If the error code in this message
             * is zero, we have the complete file, otherwise the sender is
             * telling us there's been a problem. Either way, we want to
             * close our current file. */
            if (current_file != NULL) {
                if (fclose(current_file) == EOF) {
                    /* If we fail to write out a file locally, we treat this
                     * as a fatal error and abort the session. */
                    int err = errno;
                    ttt_error(0, err, "error on close of %s", local_filename);
                    ttt_send_fatal_error(sess, TTT_ERR_FAILED_TO_WRITE_FILE, "failed to close %s: %s", ttt_filename, strerror(err));

                    /* Try to delete the file */
                    unlink(local_filename);
                    goto fail;
                }
                current_file = NULL;
            }

            if (decoded.u.err.code == 0) {
                /* Sender reports that it sent the file successfully.
                 * Set the file's mode and timestamp according to the metadata
                 * message we received before the file data. */
                timbuf.actime = time(NULL);
                timbuf.modtime = current_file_mtime;
                if (utime(local_filename, &timbuf) < 0) {
                    ttt_error(0, errno, "warning: failed to set modification time of %s", local_filename);
                }

                if (ttt_chmod(local_filename, current_file_mode & 0777) < 0) {
                    ttt_error(0, errno, "warning: failed to set mode %03o on %s", current_file_mode & 0777, local_filename);
                }
            }
            else {
                /* The transfer of this file ended because the sender failed
                 * to read from or open it. This is not a fatal error, but we
                 * report and remember it, and delete any partially-transferred
                 * file. */
                unlink(local_filename);
                files_sender_failed++;

                /* Don't expect the rest of this file */
                total_bytes_remaining -= current_file_size - current_file_position;
                ttt_error(0, 0, "warning: did not receive %s: %s", local_filename, decoded.u.err.message);
            }

            /* We're no longer inside a file transfer, so the next message
             * must be TTT_MSG_FILE_METADATA or TTT_MSG_FILE_SET_END */
            in_file_transfer = 0;
        }
        else if (decoded.tag == TTT_MSG_FATAL_ERROR) {
            ttt_error(0, 0, "received fatal error from sender: 0x%08x: %s", decoded.u.err.code, decoded.u.err.message);
            goto fail;
        }
        else if (decoded.tag == TTT_MSG_FILE_SET_END) {
            /* There are no more files. We'll exit the loop here. */
            if (in_file_transfer) {
                ttt_error(0, 0, "received unexpected TTT_MSG_FILE_SET_END but current file still open");
                ttt_send_fatal_error(sess, TTT_ERR_PROTOCOL, "sender sent TTT_MSG_FILE_SET_END during file send but there was no TTT_FILE_DATA_END.");
                goto fail;
            }
        }
        else {
            ttt_error(0, 0, "received unexpected tag %d from sender during set of files", decoded.tag);
            ttt_send_fatal_error(sess, TTT_ERR_PROTOCOL, "sender sent unexpected tag %d while receiving file data", decoded.tag);
            goto fail;
        }
        if (is_progress_report_due(ctx)) {
            make_progress_report(ctx, 0, local_filename,
                    current_file_number, file_count, current_file_position,
                    current_file_size, total_bytes_received,
                    total_bytes_received + total_bytes_remaining,
                    files_sender_failed, 0);
        }
    } while (decoded.tag != TTT_MSG_FILE_SET_END);

    make_progress_report(ctx, 0, local_filename, current_file_number,
            file_count, current_file_position, current_file_size,
            total_bytes_received, total_bytes_received, files_sender_failed, 1);

end:
    *sender_failed_file_count = files_sender_failed;
    free(local_filename);
    free(ttt_filename);
    if (current_file)
        fclose(current_file);
    return return_value;

fail:
    return_value = -1;
    goto end;
}

static int
ttt_file_transfer_session_receiver(struct ttt_file_transfer *ctx,
        struct ttt_session *sess, long long *file_count_out,
        long long *sender_failed_file_count_out) {
    struct ttt_file_list list;
    struct ttt_msg msg;
    struct ttt_decoded_msg decoded;
    int return_value = 0;
    int rc;
    long long file_count = -1, total_size = -1;
    long long sender_failed_file_count = 0;
    int file_set_rejected = 0;

    ttt_file_list_init(&list);

    do {
        rc = ttt_get_next_message(sess, &msg, &decoded);
        if (rc != 0) {
            goto fail;
        }

        switch (decoded.tag) {
            case TTT_MSG_SWITCH_ROLES:
                return_value = 1;
                break;

            case TTT_MSG_END_SESSION:
                return_value = 0;
                break;

            case TTT_MSG_FILE_METADATA_SET_START:
                /* Receive file metadata into list */
                ttt_file_list_destroy(&list);
                ttt_file_list_init(&list);
                rc = ttt_receive_file_metadata_set(sess, ctx->output_dir, &list, &file_count, &total_size);
                if (rc < 0)
                    goto fail;

                if (ctx->request_to_send != NULL) {
                    rc = ctx->request_to_send(ctx->callback_cookie, list.start, file_count, total_size);
                }
                else {
                    rc = 0;
                }

                if (rc == 0) {
                    /* Reply to sender to tell it to go ahead and send us
                     * the files. */
                    if (ttt_reply_ok(sess) < 0)
                        goto fail;
                }
                else {
                    /* User rejected the files. */
                    file_set_rejected = 1;
                    if (ttt_reply_error(sess, TTT_ERR_FILE_SET_REJECTED, "remote user rejected file set") < 0)
                        goto fail;
                }
                break;

            case TTT_MSG_FILE_SET_START:
                if (file_set_rejected) {
                    /* Um excuse me I thought I said... */
                    ttt_error(0, 0, "sender tried to send a file set despite us refusing it. Aborting session...");
                    ttt_send_fatal_error(sess, TTT_ERR_PROTOCOL, "file set sent despite receiver refusing it");
                    goto fail;
                }

                /* Receive files and write them to output_dir */
                rc = ttt_receive_file_set(ctx, sess, &list, file_count, total_size, &sender_failed_file_count);
                if (rc < 0)
                    goto fail;

                /* Reply to sender */
                if (ttt_reply_ok(sess) < 0)
                    goto fail;
                break;

            case TTT_MSG_FATAL_ERROR:
                ttt_error(0, 0, "received fatal error from sender: 0x%08x: %s", decoded.u.err.code, decoded.u.err.message);
                goto fail;
                break;

            default:
                ttt_error(0, 0, "protocol error: received unexpected tag %d at start of message sequence", decoded.tag);
                ttt_send_fatal_error(sess, TTT_ERR_PROTOCOL, "receiver got unexpected tag %d at start of message sequence", decoded.tag);
                goto fail;
        }
    } while (decoded.tag != TTT_MSG_SWITCH_ROLES && decoded.tag != TTT_MSG_END_SESSION);

end:
    if (file_count_out)
        *file_count_out = file_count;
    if (sender_failed_file_count_out)
        *sender_failed_file_count_out = sender_failed_file_count;

    ttt_file_list_destroy(&list);
    return return_value;

fail:
    ttt_error(0, 0, "file transfer failed with fatal error");
    return_value = -1;
    goto end;
}

static int
ttt_file_transfer_session_switch_roles(struct ttt_session *sess) {
    return ttt_send_message(sess, TTT_MSG_SWITCH_ROLES);
}

static int
ttt_file_transfer_session_end(struct ttt_session *sess) {
    return ttt_send_message(sess, TTT_MSG_END_SESSION);
}


static void
ttt_file_transfer_init(struct ttt_file_transfer *ctx, int start_as_sender) {
    memset(ctx, 0, sizeof(*ctx));
    ctx->start_as_sender = start_as_sender;

    ctx->progress_report_interval.tv_sec = 0;
    ctx->progress_report_interval.tv_usec = 500000;

    ctx->next_progress_report.tv_sec = 0;
    ctx->next_progress_report.tv_usec = 0;

    ttt_file_transfer_set_progress_callback(ctx, default_progress_callback);
}

int
ttt_file_transfer_init_sender(struct ttt_file_transfer *ctx, const char **source_paths, int num_source_paths) {
    ttt_file_transfer_init(ctx, 1);

    /* Copy each string from source_paths to ctx->source_paths */
    if (num_source_paths > 0) {
        ctx->source_paths = malloc(sizeof(char *) * num_source_paths);
        if (ctx->source_paths == NULL)
            goto fail;
        ctx->num_source_paths = num_source_paths;
        memset(ctx->source_paths, 0, sizeof(char *) * num_source_paths);
        for (int i = 0; i < num_source_paths; ++i) {
            ctx->source_paths[i] = strdup(source_paths[i]);
            if (ctx->source_paths[i] == NULL) {
                goto fail;
            }
        }
    }
    else {
        ctx->source_paths = NULL;
        ctx->num_source_paths = 0;
    }

    return 0;

fail:
    ttt_file_transfer_destroy(ctx);
    return -1;
}

int
ttt_file_transfer_init_receiver(struct ttt_file_transfer *ctx, const char *output_dir) {
    ttt_file_transfer_init(ctx, 0);

    ctx->output_dir = strdup(output_dir);
    if (ctx->output_dir == NULL)
        goto fail;

    return 0;

fail:
    ttt_file_transfer_destroy(ctx);
    return -1;
}

void
ttt_file_transfer_set_callback_cookie(struct ttt_file_transfer *ctx, void *cookie) {
    ctx->callback_cookie = cookie;
}

void
ttt_file_transfer_set_request_to_send_callback(struct ttt_file_transfer *ctx, ttt_ft_request_to_send_cb cb) {
    ctx->request_to_send = cb;
}

void
ttt_file_transfer_set_send_full_metadata(struct ttt_file_transfer *ctx, int value) {
    ctx->send_full_metadata = value;
}

void
ttt_file_transfer_set_progress_callback(struct ttt_file_transfer *ctx, ttt_ft_progress_cb cb) {
    ctx->progress = cb;
}

int
ttt_file_transfer_session(struct ttt_file_transfer *ctx, struct ttt_session *sess) {
    int finished = 0;
    int is_sender = ctx->start_as_sender;
    int have_been_sender = 0;
    int have_been_receiver = 0;
    int rc;
    int failed = 0;

    while (!finished) {
        long long total_files_to_send = 0, num_files_failed = 0;
        if (is_sender) {
            if (have_been_sender) {
                /* Already been sender, so finish, don't send all the
                 * files again. */
                rc = 0;
            }
            else {
                rc = ttt_file_transfer_session_sender(ctx, sess,
                        &total_files_to_send, &num_files_failed);
                have_been_sender = 1;
            }
        }
        else {
            rc = ttt_file_transfer_session_receiver(ctx, sess,
                    &total_files_to_send, &num_files_failed);
            have_been_receiver = 1;
        }
        if (rc == 0 && num_files_failed > 0) {
            ttt_error(0, 0, "warning: %lld of %lld files were not sent%s",
                    num_files_failed, total_files_to_send,
                    is_sender ? " to receiver" : " to us");
            failed = 1;
        }

        if (rc < 0) {
            /* Fatal error: abort the session. */
            finished = 1;
            failed = 1;
        }
        else if (rc > 0) {
            /* Send function shouldn't return this! */
            assert(!is_sender);
            /* We're the receiver and the sender has asked to switch roles. */
            is_sender = 1;
        }
        else {
            /* rc == 0 */
            if (is_sender) {
                /* We're the sender, and we ran out of files to send.
                 * If output_dir is NULL (meaning we don't want to receive
                 * files), or if we've already taken a turn at being receiver,
                 * then end the session here. Otherwise, switch roles. */
                if (ctx->output_dir == NULL || have_been_receiver) {
                    ttt_file_transfer_session_end(sess);
                    finished = 1;
                }
                else {
                    if (ttt_file_transfer_session_switch_roles(sess) < 0) {
                        finished = 1;
                        failed = 1;
                    }
                    else {
                        is_sender = 0;
                    }
                }
            }
            else {
                /* We're the receiver, and the sender told us to end the
                 * session. */
                finished = 1;
            }
        }
    }

    /* Did we want to push files but didn't get an opportunity to be sender? */
    if (!failed && ctx->num_source_paths > 0 && !have_been_sender) {
        ttt_error(0, 0, "couldn't push: remote host did not accept any files");
        failed = 1;
    }

    if (failed)
        return -1;
    else
        return 0;
}

void
ttt_file_transfer_destroy(struct ttt_file_transfer *ctx) {
    for (int i = 0; i < ctx->num_source_paths; ++i) {
        free(ctx->source_paths[i]);
    }
    free(ctx->source_paths);
    free(ctx->output_dir);
}
