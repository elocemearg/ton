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

#include "tttfiletransfer.h"
#include "tttsession.h"
#include "tttprotocol.h"
#include "tttutils.h"

#define DIR_SEP_STR "/"
const char DIR_SEP = DIR_SEP_STR[0];

#define TIMEVAL_X_GE_Y(X, Y) ((X).tv_sec > (Y).tv_sec || ((X).tv_sec == (Y).tv_sec && (X).tv_usec >= (Y).tv_usec))

struct ttt_file {
    /* Source or destination path to the file on our system. */
    char *local_path;

    /* How the file is named in the TTT_MSG_FILE_METADATA message. This
     * will have all directory separators replaced with '/' no matter what
     * the directory separator on the local system is. The path will also be
     * relative to the path specified on the command line. */
    char *ttt_path;

    /* Modified time of the file. */
    time_t mtime;

    /* File mode/permissions. */
    int mode;

    /* Size of the file in bytes. */
    long long size;

    /* Next file in the list. */
    struct ttt_file *next;
};

struct ttt_file_list {
    struct ttt_file *start;
    struct ttt_file *last;
};

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


/* Recursively search the directory named in "path", calling callback for each
 * file found. If "path" is a file not a directory, we just call callback once
 * for that file.
 * initial_path is the path supplied to the top-level call to ttt_dir_walk().
 * The callback should return 0 normally, or -1 to terminate the walk with
 * an error.
 * Return value is 0 on success, 1 if some files could not be statted, or -1
 * if there was a fatal error. */
int
ttt_dir_walk_aux(const char *path, const char *initial_path,
        int (*callback)(void *cookie, const char *file_path, struct stat *st,
            const char *initial_path),
        void *cookie) {
    struct stat st;
    int ret = 0;

    if (lstat(path, &st) < 0) {
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

        new_path = malloc(strlen(path) + 1 + NAME_MAX + 1);
        if (new_path == NULL) {
            ttt_error(0, errno, "malloc");
            ret = -1;
        }
        errno = 0;
        while (ret >= 0 && (ent = readdir(dir)) != NULL) {
            int subret;

            if (!strcmp(ent->d_name, ".") || !strcmp(ent->d_name, ".."))
                continue;
            if (strlen(ent->d_name) > NAME_MAX) {
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

    return 0;
}

int
ttt_dir_walk(const char *path,
        int (*callback)(void *cookie, const char *file_path, struct stat *st,
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
add_local_file_to_list(void *cookie, const char *path, struct stat *st, const char *initial_path) {
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
        return -1;
    }
    else if (rc < 0) {
        ttt_error(0, 0, "connection interrupted");
        return -1;
    }
    else if (rc < TTT_MSG_HEADER_SIZE) {
        ttt_error(0, 0, "unexpected EOF during message header");
        return -1;
    }

    rc = ttt_msg_decode_header(msg, header, &tag, &body_length_bytes, &body_dest);
    if (rc != 0) {
        return -1;
    }

    if (body_length_bytes > 0) {
        rc = readall(sess, body_dest, body_length_bytes);
        if (rc != body_length_bytes) {
            if (rc < 0) {
                ttt_error(0, 0, "connection interrupted");
            }
            else {
                ttt_error(0, 0, "unexpected EOF during message body");
            }
            return -1;
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

    return ttt_msg_send(sess, &msg);
}

int
ttt_reply_ok(struct ttt_session *sess) {
    return ttt_send_message(sess, TTT_MSG_OK);
}

int
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
ttt_get_next_message(struct ttt_session *sess, struct ttt_msg *msg, struct ttt_decoded_msg *decoded) {
    int rc = ttt_msg_recv(sess, msg);
    if (rc < 0) {
        return -1;
    }
    rc = ttt_msg_decode(msg, decoded);
    if (rc != 0) {
        ttt_send_fatal_error(sess, rc, "failed to decode message");
        return -1;
    }
    return 0;
}

static int
ttt_receive_reply_report_error(struct ttt_session *sess) {
    struct ttt_msg msg;
    struct ttt_decoded_msg decoded;
    int rc;

    rc = ttt_get_next_message(sess, &msg, &decoded);
    if (rc < 0)
        return -1;

    switch (decoded.tag) {
        case TTT_MSG_OK:
            return 0;
        case TTT_MSG_ERROR:
        case TTT_MSG_FATAL_ERROR:
            ttt_error(0, 0, "received %s error from remote host: 0x%08x: %s",
                    decoded.tag == TTT_MSG_FATAL_ERROR ? "fatal" : "",
                    decoded.u.err.code, decoded.u.err.message);
            return -1;
        default:
            ttt_error(0, 0, "received unexpected reply tag %d, expecting OK, ERROR or FATAL ERROR", decoded.tag);
            return -1;
    }
}


/* Already within a TTT_MSG_FILE_SET_START/TTT_MSG_FILE_SET_END block, send
 * a TTT_MSG_FILE_METADATA message, data chunks and TTT_MSG_FILE_DATA_END
 * message for the given file.
 */
int
ttt_send_file(struct ttt_session *sess, struct ttt_file *f) {
    struct ttt_msg msg;
    FILE *stream;
    size_t bytes_read = 0;
    int return_value = 0;

    stream = fopen(f->local_path, "rb");
    if (stream == NULL) {
        int err = errno;
        ttt_error(0, err, "%s", f->local_path);
        ttt_send_fatal_error(sess, TTT_ERR_FAILED_TO_READ_FILE, "unable to open %s: %s", f->local_path, strerror(err));
        return -1;
    }

    if (ttt_send_message(sess, TTT_MSG_FILE_METADATA, f->size, f->mtime, f->mode, f->ttt_path) < 0) {
        goto fail;
    }

    do {
        void *msg_data_dest;
        int max_length;

        /* Initialise a file data chunk */
        ttt_msg_file_data_chunk(&msg);

        max_length = ttt_msg_file_data_chunk_get_max_length(&msg);
        msg_data_dest = ttt_msg_file_data_chunk_data_ptr(&msg);

        /* Read up to max_length bytes from the file into the message */
        bytes_read = fread(msg_data_dest, 1, max_length, stream);
        if (bytes_read == 0) {
            if (ferror(stream)) {
                int err = errno;
                ttt_error(0, err, "%s", f->local_path);
                ttt_send_fatal_error(sess, TTT_ERR_FAILED_TO_READ_FILE, "unable to read from %s: %s", f->local_path, strerror(err));
                goto fail;
            }
            else {
                /* End of file */
                if (ttt_send_message(sess, TTT_MSG_FILE_DATA_END) < 0)
                    goto fail;
            }
        }
        else {
            /* Set the length field of the chunk message... */
            ttt_msg_file_data_chunk_set_length(&msg, (int) bytes_read);

            /* Now send the chunk message */
            if (ttt_msg_send(sess, &msg) < 0)
                goto fail;
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

int
ttt_file_transfer_session_sender(struct ttt_session *sess,
        const char **paths_to_push, int num_paths_to_push) {
    struct ttt_file_list file_list;
    int walk_failures = 0;
    int return_value = 0;
    int rc;

    if (num_paths_to_push <= 0) {
        /* Nothing to do */
        return 0;
    }

    /* Build a list of all the files we want to send */
    ttt_file_list_init(&file_list);
    for (int i = 0; i < num_paths_to_push; ++i) {
        rc = ttt_dir_walk(paths_to_push[i], add_local_file_to_list, &file_list);
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

    /* Now send a file metadata set message sequence... */
    if (ttt_send_message(sess, TTT_MSG_FILE_METADATA_SET_START) < 0)
        goto fail;
    for (struct ttt_file *f = file_list.start; f; f = f->next) {
        if (ttt_send_message(sess, TTT_MSG_FILE_METADATA, f->size, f->mtime, f->mode, f->ttt_path) < 0) {
            goto fail;
        }
    }
    if (ttt_send_message(sess, TTT_MSG_FILE_METADATA_SET_END) < 0)
        goto fail;

    if (ttt_receive_reply_report_error(sess) < 0)
        goto fail;

    /* Now send a file data set message sequence, in which for each file in
     * file_list, we send a metadata message and the file's data broken up
     * into data chunks... */
    if (ttt_send_message(sess, TTT_MSG_FILE_SET_START) < 0)
        goto fail;
    for (struct ttt_file *f = file_list.start; f; f = f->next) {
        if (access(f->local_path, F_OK) != 0 && errno == ENOENT) {
            /* File existed when we walked the directories, but it's gone now.
             * Report this as a non-fatal error. */
            ttt_error(0, 0, "%s no longer exists, not sending it.", f->local_path);
            continue;
        }
        if (ttt_send_file(sess, f) < 0) {
            goto fail;
        }
    }
    if (ttt_send_message(sess, TTT_MSG_FILE_SET_END) < 0)
        goto fail;

    if (ttt_receive_reply_report_error(sess) < 0)
        goto fail;

end:
    /* Now we've finished. */
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
        if (ttt_get_next_message(sess, &msg, &decoded) < 0) {
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
            snprintf(dest, 10, "%4d%cB", (int) d, *p);
        }
        else if (d >= 10) {
            snprintf(dest, 10, "%4.1f%cB", d, *p);
        }
        else {
            snprintf(dest, 10, "%4.2f%cB", d, *p);
        }
    }
}

static void
ttt_update_progress(const char *current_filename,
        long long files_received, long long file_count,
        long long total_bytes_received, long long total_size) {
    const char *display_filename = NULL;
    const int filename_limit = 40;
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
    fprintf(stderr, "%6lld/%lld %s%-*s | %6s",
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
timeval_add(const struct timeval *t1, const struct timeval *t2, struct timeval *dest) {
    dest->tv_sec = t1->tv_sec + t2->tv_sec;
    dest->tv_usec = t1->tv_usec + t2->tv_usec;
    dest->tv_sec += dest->tv_usec / 1000000;
    dest->tv_usec %= 1000000;
}

static int
ttt_receive_file_set(struct ttt_session *sess, const char *output_dir,
        struct ttt_file_list *list, long long file_count, long long total_size) {
    struct ttt_msg msg;
    struct ttt_decoded_msg decoded;
    FILE *current_file = NULL;
    char *local_filename = NULL;
    char *ttt_filename = NULL;
    time_t current_file_mtime = 0;
    long long current_file_position = 0;
    long long current_file_size = 0;
    long long total_bytes_received = 0;
    long long files_received = 0;
    int current_file_mode = 0;
    int return_value = 0;
    struct timeval now, next_progress_report;
    const struct timeval progress_report_interval = { 0, 500000 };

    gettimeofday(&now, NULL);
    timeval_add(&now, &progress_report_interval, &next_progress_report);

    do {
        if (ttt_get_next_message(sess, &msg, &decoded) < 0) {
            goto fail;
        }
        gettimeofday(&now, NULL);

        if (decoded.tag == TTT_MSG_FILE_METADATA) {
            if (local_filename != NULL) {
                ttt_error(0, 0, "TTT_MSG_FILE_METADATA tag received out of sequence!");
                ttt_send_fatal_error(sess, TTT_ERR_PROTOCOL, "sender sent TTT_MSG_FILE_METADATA tag but didn't end previous file %s", ttt_filename);
                goto fail;
            }
            current_file_mtime = decoded.u.metadata.mtime;
            current_file_mode = decoded.u.metadata.mode;
            current_file_size = decoded.u.metadata.size;
            current_file_position = 0;
            ttt_filename = strdup(decoded.u.metadata.name);
            local_filename = ttt_path_to_local_path(decoded.u.metadata.name, output_dir);
            if (local_filename == NULL) {
                ttt_error(0, errno, "failed to allocate path name");
                goto fail;
            }

            if (S_ISREG(current_file_mode)) {
                current_file = fopen(local_filename, "wb");
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
                if (ttt_mkdir_parents(local_filename, current_file_mode & 0777, 0, DIR_SEP) < 0) {
                    ttt_error(0, errno, "failed to create directory %s", local_filename);
                }
            }
        }
        else if (decoded.tag == TTT_MSG_FILE_DATA_CHUNK) {
            if (local_filename == NULL) {
                ttt_error(0, 0, "TTT_MSG_FILE_DATA_CHUNK sent without TTT_MSG_FILE_METADATA!");
                ttt_send_fatal_error(sess, TTT_ERR_PROTOCOL, "sender sent TTT_MSG_FILE_DATA_CHUNK but there was no TTT_MSG_FILE_METADATA before it");
                goto fail;
            }
            if (current_file != NULL) {
                size_t ret = fwrite(decoded.u.chunk.data, 1, decoded.u.chunk.length, current_file);
                if (ret != decoded.u.chunk.length) {
                    int err = errno;
                    ttt_error(0, err, "failed to write to %s", local_filename);
                    ttt_send_fatal_error(sess, TTT_ERR_FAILED_TO_WRITE_FILE, "failed to write data to %s: %s", ttt_filename, strerror(err));
                    goto fail;
                }
            }
            current_file_position += decoded.u.chunk.length;
            total_bytes_received += decoded.u.chunk.length;
        }
        else if (decoded.tag == TTT_MSG_FILE_DATA_END) {
            struct utimbuf timbuf;
            if (local_filename == NULL) {
                ttt_error(0, 0, "TTT_MSG_FILE_DATA_END sent without TTT_MSG_FILE_METADATA!");
                ttt_send_fatal_error(sess, TTT_ERR_PROTOCOL, "sender sent TTT_MSG_FILE_DATA_END but there was no TTT_MSG_FILE_METADATA before it");
                goto fail;
            }
            if (current_file != NULL) {
                if (fclose(current_file) == EOF) {
                    int err = errno;
                    ttt_error(0, err, "error on close of %s", local_filename);
                    ttt_send_fatal_error(sess, TTT_ERR_FAILED_TO_WRITE_FILE, "failed to flush data to %s: %s", ttt_filename, strerror(err));
                }
            }

            /* Set file mode */
            if (chmod(local_filename, current_file_mode & 0777) < 0) {
                ttt_error(0, errno, "warning: failed to set mode %03o on %s", current_file_mode & 0777, local_filename);
            }

            /* Set file timestamp */
            timbuf.actime = time(NULL);
            timbuf.modtime = current_file_mtime;
            if (utime(local_filename, &timbuf) < 0) {
                ttt_error(0, errno, "warning: failed to set modification time of %s", local_filename);
            }

            files_received++;
            free(local_filename);
            free(ttt_filename);
            local_filename = NULL;
            ttt_filename = NULL;
            current_file = NULL;
        }
        else if (decoded.tag == TTT_MSG_FATAL_ERROR) {
            ttt_error(0, 0, "received fatal error from sender: 0x%08x: %s", decoded.u.err.code, decoded.u.err.message);
            goto fail;
        }
        else if (decoded.tag == TTT_MSG_FILE_SET_END) {
            if (local_filename != NULL) {
                ttt_error(0, 0, "received unexpected TTT_MSG_FILE_SET_END but current file still open");
                ttt_send_fatal_error(sess, TTT_ERR_PROTOCOL, "sender sent TTT_MSG_FILE_SET_END during file send but there was no TTT_FILE_DATA_END.");
                goto fail;
            }
            ttt_update_progress(local_filename, files_received, file_count,
                    total_bytes_received, total_size);
            fprintf(stderr, "\n");
        }
        else {
            ttt_error(0, 0, "received unexpected tag %d from sender during set of files", decoded.tag);
            ttt_send_fatal_error(sess, TTT_ERR_PROTOCOL, "sender sent unexpected tag %d while receiving file data", decoded.tag);
            goto fail;
        }
        if (TIMEVAL_X_GE_Y(now, next_progress_report)) {
            ttt_update_progress(local_filename, files_received, file_count,
                    total_bytes_received, total_size);
            timeval_add(&now, &progress_report_interval, &next_progress_report);
        }
    } while (decoded.tag != TTT_MSG_FILE_SET_END);

end:
    free(local_filename);
    free(ttt_filename);
    if (current_file)
        fclose(current_file);
    return return_value;

fail:
    return_value = -1;
    goto end;
}

int
ttt_file_transfer_session_receiver(struct ttt_session *sess, const char *output_dir) {
    struct ttt_file_list list;
    struct ttt_msg msg;
    struct ttt_decoded_msg decoded;
    int return_value = 0;
    int rc;
    long long file_count = -1, total_size = -1;

    ttt_file_list_init(&list);

    do {
        rc = ttt_get_next_message(sess, &msg, &decoded);
        if (rc < 0) {
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
                rc = ttt_receive_file_metadata_set(sess, output_dir, &list, &file_count, &total_size);
                if (rc < 0)
                    goto fail;

                /* Reply to sender */
                if (ttt_reply_ok(sess) < 0)
                    goto fail;
                break;

            case TTT_MSG_FILE_SET_START:
                /* Receive files and write them to output_dir */
                rc = ttt_receive_file_set(sess, output_dir, &list, file_count, total_size);
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
    ttt_file_list_destroy(&list);
    return return_value;

fail:
    return_value = -1;
    goto end;
}

int
ttt_file_transfer_session_switch_roles(struct ttt_session *sess) {
    return ttt_send_message(sess, TTT_MSG_SWITCH_ROLES);
}

int
ttt_file_transfer_session_end(struct ttt_session *sess) {
    return ttt_send_message(sess, TTT_MSG_END_SESSION);
}

int
ttt_file_transfer_session(struct ttt_session *sess, int is_sender,
        const char *output_dir, const char **paths_to_push,
        int num_paths_to_push) {
    int finished = 0;
    int have_been_sender = is_sender;
    int have_been_receiver = !is_sender;
    int rc;
    int failed = 0;

    while (!finished) {
        if (is_sender) {
            rc = ttt_file_transfer_session_sender(sess, paths_to_push, num_paths_to_push);
        }
        else {
            rc = ttt_file_transfer_session_receiver(sess, output_dir);
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
            have_been_sender = 1;
        }
        else {
            /* rc == 0 */
            if (is_sender) {
                /* We're the sender, and we ran out of files to send.
                 * If output_dir is NULL (meaning we don't want to receive
                 * files), or if we've already taken a turn at being receiver,
                 * then end the session here. Otherwise, switch roles. */
                num_paths_to_push = 0;
                if (output_dir == NULL || have_been_receiver) {
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
                        have_been_receiver = 1;
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
    if (!failed && num_paths_to_push > 0 && !have_been_sender) {
        ttt_error(0, 0, "couldn't push: remote host did not accept any files");
        failed = 1;
    }

    if (failed)
        return -1;
    else
        return 0;
}
