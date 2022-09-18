/* Code for doing the actual file transfer once a session (struct ttt_session)
 * has been established. This code sends messages defined in protocol.c. */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
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

/* DIR_SEP_STR and DIR_SEP is the directory separator we have to use in
 * pathnames passed to OS calls. On Windows it's a backslash and on everything
 * else it's a slash.
 *
 * This is distinct from the directory separator we use in pathnames in
 * protocol messages we send such as TTT_MSG_FILE_METADATA. This is always
 * a slash.
 */
#ifdef WINDOWS
#define DIR_SEP_STR "\\"
#else
#define DIR_SEP_STR "/"
#endif
const char DIR_SEP = DIR_SEP_STR[0];

/* Enable random failures for testing */
static int ttt_random_file_open_failures = 0;
static int ttt_random_file_read_failures = 0;
static int ttt_random_file_write_failures = 0;

/* Join two path fragments together, inserting DIR_SEP between them if there
 * is no DIR_SEP at the end of path1 nor the start of path2. Write the joined
 * path to dest.
 * dest must point to at least strlen(path1) + strlen(path2) + 2 bytes. */
static void
join_paths(const char *path1, const char *path2, char *dest) {
    /* Decide whether we need to put a directory separator between these */
    size_t path1_len = strlen(path1);
    bool add_sep;

    if (path1[0] == '\0' || path2[0] == '\0') {
        add_sep = false;
    }
    else {
        add_sep = (path1[path1_len - 1] != DIR_SEP && path2[0] != DIR_SEP);
        if (path1[path1_len - 1] == DIR_SEP && path2[0] == DIR_SEP) {
            /* If path1 ends with a separator and path2 begins with one,
             * skip the separators after the start of path2 */
            while (path2[0] == DIR_SEP)
                path2++;
        }
    }

    sprintf(dest, "%s%s%s", path1, add_sep ? DIR_SEP_STR : "", path2);
}

#ifdef WINDOWS
/* Windows only: determine whether a path ends with a given ending,
 * case-insensitively. */
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

static char *
alloc_real_path_name(const char *path) {
    char *real_path_name;
    size_t len;
#ifdef WINDOWS
    real_path_name = _fullpath(NULL, path, 0);
#else
    real_path_name = realpath(path, NULL);
#endif
    if (real_path_name == NULL)
        return NULL;

    /* Remove any trailing directory separators, because Windows doesn't like
     * it when you try to stat "c:\foo\bar\" - it prefers "c:\foo\bar".
     *
     * On Linux, don't remove the first character from the string, so that
     * if all we have is "/", we keep that.
     *
     * On Windows, don't remove a backslash if it immediately follows a colon,
     * so if we have "D:\", we want to keep it as "D:\" (the root directory
     * of the D drive) not "D:" (our current directory on the D drive).
     *
     * We don't have to deal with the case where we have a drive letter and a
     * relative path ("D:my\relative\path") because _fullpath() above has
     * given us an absolute path.
     */
    len = strlen(real_path_name);
    while (len > 1 && real_path_name[len - 1] == DIR_SEP) {
#ifdef WINDOWS
        if (real_path_name[len - 2] == ':')
            break;
#endif
        real_path_name[--len] = '\0';
    }
    return real_path_name;
}


static int
ttt_dir_walk_aux(const char *path, int orig_path_start,
        int (*callback)(void *cookie, const char *file_path, STAT *st,
            int orig_path_start),
        void *cookie) {
    int ret = 0;
    STAT st;
    if (ttt_stat(path, &st) < 0) {
        ttt_error(0, errno, "skipping %s: stat failed", path);
        return 1;
    }

    /* If it's not a regular file, set the size to 0. */
    if (!S_ISREG(st.st_mode)) {
        st.st_size = 0;
    }

    if (S_ISDIR(st.st_mode)) {
        /* This is a directory. Recursively walk each of its children. */
        char *new_path = NULL;
        DIR *dir = opendir(path);
        struct dirent *ent = NULL;
        long num_entries_in_dir = 0;
        int subret;

        if (dir == NULL) {
            ttt_error(0, errno, "skipping directory %s", path);
            return 1;
        }

        new_path = malloc(strlen(path) + 1 + MAX_PATH_COMPONENT_LEN + 1);
        if (new_path == NULL) {
            ttt_error(0, errno, "malloc");
            ret = -1;
        }
        errno = 0;
        while (ret >= 0 && (ent = readdir(dir)) != NULL) {
            if (!strcmp(ent->d_name, ".") || !strcmp(ent->d_name, ".."))
                continue;
#ifdef WINDOWS
            /* Skip Windows shortcuts */
            if (ends_with_icase(ent->d_name, ".lnk"))
                continue;
#endif
            if (strlen(ent->d_name) > MAX_PATH_COMPONENT_LEN) {
                ttt_error(0, 0, "can't open %s/%s: subdirectory name too long", path, ent->d_name);
                ret = 1;
                continue;
            }
            join_paths(path, ent->d_name, new_path);

            subret = ttt_dir_walk_aux(new_path, orig_path_start, callback, cookie);
            if (subret > 0) {
                ret = subret;
            }
            else if (subret < 0) {
                ret = -1;
            }
            num_entries_in_dir++;
            errno = 0;
        }
        free(new_path);

        if (ent == NULL && errno != 0) {
            if (num_entries_in_dir == 0) {
                /* If we failed to read the first entry, then just skip this
                 * directory, write a warning, and continue. Sometimes this
                 * happens with phantom hidden directories on Windows. */
                ttt_error(0, errno, "skipping directory %s, failed to read contents", path);
                ret = 1;
            }
            else {
                ttt_error(0, errno, "error reading directory entries in %s", path);
                ret = -1;
            }
        }
        closedir(dir);

        /* Finally, add an entry for the directory itself.
         * We add this last because the receiving end must set the directory's
         * permissions *after* writing the directory's contents, to avoid
         * having to write files to a read-only directory. */
        subret = callback(cookie, path, &st, orig_path_start);
        if (subret < 0) {
            ret = -1;
        }
    }
    else if (S_ISREG(st.st_mode) || S_ISFIFO(st.st_mode)) {
        /* This is an ordinary file or FIFO. Call the callback on it. */
        int cbret = callback(cookie, path, &st, orig_path_start);
        if (cbret < 0) {
            ret = -1;
        }
    }

    /* Don't bother with special files such as symlinks, Unix sockets,
     * device files, etc. */

    return ret;
}

/* Recursively search the directory named in "path", calling callback for each
 * file found. If "path" is a file not a directory, we just call callback once
 * for that file.
 * This may be useful to the callback function to derive a relative path from
 * the initial path to an individual file.
 *
 * The callback is called once for every file or directory entry we find.
 * The callback should return 0 normally, or -1 to terminate the walk with
 * an error. Its parameters are:
 *     void *cookie
 *         The cookie argument to ttt_dir_walk_aux. This has meaning
 *         only to the callback.
 *     char *file_path
 *         The path to the file we found. In ttt_dir_walk_aux(), whatever
 *         level of recursion depth, this always begins with the file_path
 *         originally passed to the top-level ttt_dir_walk().
 *     STAT *st
 *         File metadata in the form of a struct stat or struct __stat64.
 *     int orig_path_start
 *         Offset in bytes from the start of path, pointing to the start of
 *         the last component of the initial path supplied to ttt_dir_walk().
 *         For example, if the initial path was "foo/bar/baz", orig_path_start
 *         is 8, pointing to the start of "baz". Trailing slashes are ignored,
 *         so if the initial path was "foo/bar/baz/", orig_path_start would
 *         still be 8. If the initial path was "/", orig_path_start is 0.
 *
 * Return value is 0 on success, 1 if some files could not be statted, or -1
 * if there was a fatal error. */
static int
ttt_dir_walk(const char *path,
        int (*callback)(void *cookie, const char *file_path, STAT *st,
            int orig_path_start),
        void *cookie) {
    int rc;
    int pos;
    char *full_path = alloc_real_path_name(path);
    if (full_path == NULL) {
        ttt_error(0, errno, "%s", path);
        return -1;
    }

    /* If full_path is a file, point orig_path_start to the start of the file's
     * basename.
     * If full_path is "/", orig_path_start is 1.
     * If full_path is a directory, point orig_path_start to the start of the
     * last directory component of the path. */
    pos = strlen(full_path);
    if (pos > 0)
        --pos;

    /* Find the last directory separator, and we want to point to the character
     * after it. */
    while (pos > 0 && full_path[pos] != DIR_SEP)
        pos--;

    if (full_path[pos] == DIR_SEP)
        pos++;

    rc = ttt_dir_walk_aux(full_path, pos, callback, cookie);

    free(full_path);

    return rc;
}

/*
 * Convert an operating system pathname (path) into a TTT path suitable for
 * sending in a file transfer session.
 *
 * The returned TTT path:
 *     * has directory components separated by slash ('/') regardless of what
 *       the local operating system's directory separator is, and
 *     * does not begin with a slash.
 *
 * The returned path is allocated by malloc() and it is the caller's
 * responsibility to free() it.
 */
static char *
local_path_to_ttt_path(const char *path) {
    char *ttt_path;

    /* Skip any leading slashes */
    while (*path == DIR_SEP)
        path++;

    /* Take all the path components after this point. */
    ttt_path = strdup(path);
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

#ifdef WINDOWS

/* p is a string containing a slash-delimited path.
 *
 * If the directory component pointed to by p is legal under Windows then
 * leave it alone, otherwise change it to replace any problematic characters
 * with underscores.
 *
 * Return a pointer to the next directory separator of the possibly-modified
 * string, or a pointer to the string's null-terminator if there is no
 * next directory separator. */
static char *
make_dir_component_legal_on_windows(char *p) {
    int pos;
    for (pos = 0; p[pos] != '/' && p[pos] != '\0'; ++pos) {
        unsigned char c = (unsigned char) (p[pos]);
        if (c < 32 || strchr("<>:\"\\|?*", c) != NULL) {
            c = '_';
        }
        p[pos] = (char) c;
    }
    return p + pos;
}
#endif

/* Convert a path received over a TTT file transfer session to a local
 * path name. It is the opposite of local_path_to_ttt_path(). If the resulting
 * local filename would be illegal, make it legal.
 *
 * path: the TTT path to convert, which must use slashes as delimiters and
 *       not begin with a slash.
 * local_base_dir: the local directory name to prepend to the converted path.
 *
 * The returned path is <local_base_dir><DIR_SEP><path>, except that we don't
 * add DIR_SEP if local_base_dir already ends with DIR_SEP. Any slashes in
 * path are translated into the local directory separator DIR_SEP when copying
 * to the returned string.
 *
 * The returned string is created by malloc() and it is the caller's
 * responsibility to free() it.
 */
static char *
ttt_path_to_local_path(const char *ttt_path, const char *local_base_dir) {
    char *full_path = NULL; /* local_base_dir joined to localised path */
    char *localised_path = NULL; /* path with any problematic characters replaced */

#ifdef WINDOWS
    char *path_ptr;
    int r, w;

    /* Skip any leading slashes */
    while (*ttt_path == '/')
        ttt_path++;

    localised_path = strdup(ttt_path);
    if (localised_path == NULL)
        return NULL;

    /* First, if we have any repeated slashes, condense them down into one
     * like a directory-separating accordion. */
    strcpy(localised_path, ttt_path);
    r = 0;
    w = 0;
    for (; localised_path[r]; r++) {
        char c = localised_path[r];
        if (c != '/' || (r > 0 && localised_path[r - 1] != '/')) {
            localised_path[w++] = c;
        }
    }
    localised_path[w] = '\0';

    /* Fix every directory component, replacing the separators with
     * backslashes as we go */
    path_ptr = localised_path;
    while (*path_ptr) {
        path_ptr = make_dir_component_legal_on_windows(path_ptr);
        if (*path_ptr == '/') {
            *path_ptr = '\\';
            path_ptr++;
        }
    }
#else
    /* ttt_path is already a valid Unix-style path delimited by slashes. */
    localised_path = strdup(ttt_path);
    if (localised_path == NULL)
        return NULL;
#endif

    full_path = malloc(strlen(local_base_dir) + 1 + strlen(localised_path) + 1);
    if (full_path == NULL) {
        free(localised_path);
        return NULL;
    }

    join_paths(local_base_dir, localised_path, full_path);

    free(localised_path);

    return full_path;
}

/* Functions to create and destroy ttt_file and ttt_file_list objects... */

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

/* Allocate a new struct ttt_file with the given attributes. Either local_path
 * or ttt_path may be NULL.
 *
 * local_path: the pathname of this file as our OS knows it.
 * ttt_path: the pathname of this file as we would refer to it in a
 *           TTT_MSG_FILE_METADATA message to a remote host.
 * mtime: the modified-time of the file, which is a Unix timestamp (seconds
 *        since 1970-01-01 00:00:00).
 * mode: the Unix-style mode bits for the file.
 * size: the size of the file, in bytes. -1 if not known.
 */
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

/* ttt_dir_walk() callback function used by ttt_file_transfer_session_sender().
 * Adds a ttt_file object for the named file to a list (=cookie), deriving
 * the ttt_file object's ttt_path fields from path and orig_path_start. */
static int
add_local_file_to_list(void *cookie, const char *path, STAT *st, int orig_path_start) {
    struct ttt_file_list *list = (struct ttt_file_list *) cookie;
    struct ttt_file *file = NULL;

    file = ttt_file_new(path, NULL, st->st_mtime, st->st_mode, st->st_size);
    if (file == NULL) {
        ttt_error(0, errno, "failed to create new file object structure for %s", path);
        return -1;
    }
    file->next = NULL;

    file->ttt_path = local_path_to_ttt_path(path + orig_path_start);
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

/* Add a ttt_file with the given properties to the list. This takes a ttt_name
 * as might be received from a remote TTT host.
 * Derive the local_path attribute by the ttt_name given and local_base_dir. */
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

/* Read a fixed number of bytes from a ttt_session into buf, blocking until
 * we've received exactly that many bytes.
 * Return the number of bytes read if successful, or <=0 on failure. */
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

/* Receive a file transfer session message from sess, blocking until we've
 * received the complete message. Put the message in *msg.
 * Return 0 on success or nonzero on error. */
static int
ttt_msg_recv(struct ttt_session *sess, struct ttt_msg *msg) {
    unsigned char header[TTT_MSG_HEADER_SIZE];
    int rc;
    int tag, body_length_bytes;
    void *body_dest;

    /* Read the header, and fail if that can't be done. */
    rc = readall(sess, header, TTT_MSG_HEADER_SIZE);
    if (rc == 0) {
        ttt_error(0, 0, "connection terminated");
        return TTT_ERR_EOF;
    }
    else if (rc < 0) {
        ttt_error(0, 0, "connection interrupted");
        return TTT_ERR_CONNECTION_FAILURE;
    }

    /* Hopefully the header is valid... */
    rc = ttt_msg_decode_header(msg, header, &tag, &body_length_bytes, &body_dest);
    if (rc != 0) {
        return rc;
    }

    /* If it is valid, and there is a message body, read the body into
     * body_dest and msg will then contain a complete TTT file transfer
     * session message. */
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

/* Send a ttt_msg on the given ttt_session.
 * Return the number of bytes sent on success (this will always be greater
 * than 0) or -1 on failure. */
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

/* Construct a TTT message of the given type and send it on the given
 * ttt_session.
 * The arguments after "tag" depend on the value of "tag", and they must be
 * correct according to msg_defs in protocol.c or undefined behaviour occurs.
 *
 * For example:
 *    ttt_send_message(sess, TTT_MSG_FILE_METADATA, (long long) size, (time_t) mtime, (int) mode, (char *) filename);
 *    ttt_send_message(sess, TTT_MSG_ERROR, TTT_ERR_PROTOCOL, "expected message, received rotting fish");
 *    ttt_send_message(sess, TTT_MSG_FILE_SET_END);
 *
 * This function cannot be used to send messages of type
 * TTT_MSG_FILE_DATA_CHUNK. These must be built using the
 * ttt_msg_file_data_chunk_* functions defined in protocol.c.
 *
 * Return 0 on success or nonzero on failure.
 */
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

/* Send an OK message in reply to a message sequence sent by file transfer's
 * sender end. */
static int
ttt_reply_ok(struct ttt_session *sess) {
    return ttt_send_message(sess, TTT_MSG_OK);
}

/* Send a TTT_MSG_FATAL_ERROR message with the given code and string.
 * fmt is a printf-style format string, and its arguments should follow. */
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

/* Send a TTT_MSG_ERROR message with the given code and string.
 * fmt is a printf-style format string, and its arguments should follow. */
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

/* Send a TTT_MSG_FILE_DATA_END message, to tell the receiver there are no
 * more data chunks (or simply no data chunks) for the file we're sending.
 *
 * If error_code is 0, it indicates the file was sent correctly. Otherwise,
 * it indicates there was an error and the receiver should discard the file.
 * Set error_format to NULL if error_code == 0.
 *
 * error_format and its following printf-style arguments build the error
 * message which will be sent to the receiver and displayed to its user. */
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

/* Receive a TTT protocol message on ttt_session, decode it, place the
 * message's encoded form in *msg and its decoded form in *decoded.
 * "decoded" may contain pointers to character strings in "msg", so decoded is
 * only valid for as long as the memory in msg remains valid.
 *
 * Return 0 if we received a valid message, or nonzero if there was a
 * communication error or we received a message we couldn't decode or which
 * was in some way invalid.
 */
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

/* Called by the sender end of a TTT file transfer session to receive a reply
 * to a message sequence. The reply should be TTT_MSG_OK, TTT_MSG_ERROR or
 * TTT_MSG_FATAL_ERROR.
 *
 * Return 0 if we got TTT_MSG_OK.
 * Return TTT_MSG_ERROR or TTT_MSG_FATAL_ERROR as appropriate if we got
 * either of those, and call ttt_error() to report the error's code and
 * message.
 * Return some other nonzero value if there was a communication error or we
 * received an invalid response.
 */
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

/* Call the progress report callback in ctx and update
 * ctx->next_progress_report to the expected time of the next progress report.
 */
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

/* Return 1 if ctx->progress is set and it's time to print a progress report
 * (that is, at least ctx->progress_report_interval has elapsed since the
 * last one). Return 0 otherwise. */
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
 * We update *bytes_sent_so_far according to the number of bytes from the
 * file we sent.
 *
 * If we stopped early due to a failure to read the file, we decrease
 * *total_size by the number of bytes of the file we failed to send (according
 * to the size of the file given in f), and we set *file_failed to 1.
 *
 * file_number, file_count, *bytes_sent_so_far, *total_size and
 * num_files_skipped are used to update the progress indicator if
 * necessary.
 *
 * Return <0 if there was a fatal error such as a communication or protocol
 * error and the session should be aborted.
 */
int
ttt_send_file(struct ttt_file_transfer *ctx, struct ttt_session *sess,
        long file_number, long file_count, long long *bytes_sent_so_far,
        long long *total_size, long num_files_skipped, struct ttt_file *f,
        bool *file_failed) {
    struct ttt_msg msg;
    FILE *stream = NULL;
    size_t bytes_read = 0;
    int return_value = 0;
    long long file_position = 0;

    *file_failed = 0;

    /* Send a metadata message, so the receiver knows to expect a file. */
    if (ttt_send_message(sess, TTT_MSG_FILE_METADATA, f->size, f->mtime, f->mode, f->ttt_path) < 0) {
        goto fail;
    }

    if (S_ISREG(f->mode)) {
        /* This is a regular file.
         * Open the file we want to send. If this fails, tell the receiver that
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
            *file_failed = true;
            return 0;
        }

        /* Now read the whole file in ttt_msg-sized chunks, and send them to
         * the receiver. */
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
                /* End of file or error... */
                if (ferror(stream) || (ttt_random_file_read_failures && errno == EIO)) {
                    /* Error reading from the file. Send a TTT_MSG_FILE_DATA_END
                     * message with an error code, to tell the receiver this
                     * file failed to send. The session continues. */
                    int err = errno;
                    ttt_error(0, err, "%s", f->local_path);
                    *file_failed = true;
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

            /* Update the progress indicator if necessary */
            if (is_progress_report_due(ctx)) {
                make_progress_report(ctx, 1, f->local_path, file_number,
                        file_count, file_position, f->size, *bytes_sent_so_far,
                        *total_size, num_files_skipped, 0);
            }

            /* Keep going until we reach the end of the file or we fail to
             * read some of it. */
        } while (bytes_read > 0);
    }
    else {
        /* This is some other kind of file, like a directory or FIFO. There's
         * no data associated with this file, so behave like it's a zero-byte
         * file and send an "end of data" message. */
        if (ttt_send_file_data_end(sess, 0, NULL) != 0)
            goto fail;
    }

end:
    if (stream)
        fclose(stream);

    return return_value;

fail:
    return_value = -1;
    goto end;
}

/* Play the "sender" role in a TTT file transfer session set up in ctx. The
 * other end of the ttt_session sess should be playing the "receiver" role at
 * the same time or things aren't going to go well.
 *
 * On return, set *total_files_out to the number of files we sent, and
 * *num_file_failures_out to the number of files we wanted to send but
 * couldn't. */
static int
ttt_file_transfer_session_sender(struct ttt_file_transfer *ctx,
        struct ttt_session *sess, long long *total_files_out,
        long long *num_file_failures_out) {
    struct ttt_file_list file_list;
    bool walk_failures = false;
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
            walk_failures = true;
        }
    }

    if (walk_failures && file_list.start == NULL) {
        /* All files failed to be walked */
        ttt_error(0, 0, "couldn't stat any files!");
        goto fail;
    }

    /* Now send a file metadata set message sequence. We send either a
     * metadata message for each file, or just a total file and byte count,
     * depending on whether ctx->send_full_metadata is set. */
    if (ttt_send_message(sess, TTT_MSG_FILE_METADATA_SET_START) < 0)
        goto fail;
    total_files = 0;
    for (struct ttt_file *f = file_list.start; f; f = f->next) {
        if (ctx->send_full_metadata) {
            /* Send a metadata description for every file */
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

    /* Tell the receiver that's the end of the metadata */
    if (ttt_send_message(sess, TTT_MSG_FILE_METADATA_SET_END) < 0)
        goto fail;

    /* Get a reply from the receiver. The receiver might decide to refuse the
     * file set based on the metadata we've sent (there might not be enough
     * disk space available for the size we've reported, for example). */
    rc = ttt_receive_reply_report_error(sess);
    if (rc == 0) {
        /* Receiver agrees to receive the files, so we can start.
         * Now send a file data set message sequence, in which for each file in
         * file_list, we send a metadata message and the file's data broken up
         * into data chunks... */
        if (ttt_send_message(sess, TTT_MSG_FILE_SET_START) < 0)
            goto fail;
        for (struct ttt_file *f = file_list.start; f; f = f->next) {
            bool file_failed = false;
            if (access(f->local_path, F_OK) != 0 && errno == ENOENT) {
                /* File existed when we walked the directories, but it's gone
                 * now. Report this as a non-fatal error. */
                ttt_error(0, 0, "%s no longer exists, not sending it.", f->local_path);
                num_file_failures++;
                continue;
            }
            file_number++;

            /* Send file f to the receiver. */
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

/* Called by the side playing the Receiver role.
 * Having already received a TTT_MSG_FILE_METADATA_START, receive the file
 * metadata and the TTT_MSG_FILE_METADATA_END message.
 * If the received file metadata contains a list of files the sender wants to
 * send us, add them to list, setting the local_path attribute of each
 * ttt_file object by appending the path to output_dir.
 * Otherwise, the received file metadata will contain only a summary containing
 * the file count and total size.
 *
 * *file_count_out and *total_size_out are set to the file count and total
 * size, regardless of whether we got a summary or the full list. Either value
 * may be -1 if the sender does not know or does not care to tell us how many
 * files there are or how big they are.
 *
 * Return 0 on success or nonzero on failure.
 */
static int
ttt_receive_file_metadata_set(struct ttt_session *sess,
        const char *output_dir, struct ttt_file_list *list,
        long long *file_count_out, long long *total_size_out) {
    struct ttt_msg msg;
    struct ttt_decoded_msg decoded;
    long long file_count = 0, total_size = 0;
    bool received_summary = false;

    do {
        if (ttt_get_next_message(sess, &msg, &decoded) != 0) {
            goto fail;
        }
        if (decoded.tag == TTT_MSG_FILE_METADATA_SUMMARY) {
            /* Summary only */
            file_count = decoded.u.metadata_summary.file_count;
            total_size = decoded.u.metadata_summary.total_size;
            received_summary = true;
        }
        else if (decoded.tag == TTT_MSG_FILE_METADATA) {
            /* Full list of files */
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

/* Write a progress counter to stderr showing how far we are through the
 * file transfer. */
static void
ttt_update_progress(const char *current_filename,
        long long files_received, long long file_count,
        long long total_bytes_received, long long total_size) {
    const char *display_filename = NULL;
    const int filename_limit = 44;
    bool filename_trimmed = false;
    char bytes_received_str[10];
    char total_size_str[10];

    if (current_filename != NULL) {
        /* Show only the last filename_limit characters of the filename */
        size_t len = strlen(current_filename);
        if (len > filename_limit) {
            display_filename = current_filename + len - filename_limit + 3;
            filename_trimmed = true;
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

/* Default progress callback for a struct ttt_file_transfer object. */
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

/* Called by the endpoint playing the Receiver role.
 *
 * Having already received a TTT_MSG_FILE_SET_START message on the session
 * "sess", receive all the files the sender sends us and write them out under
 * ctx->output_dir, until we receive a TTT_MSG_FILE_SET_END message.
 *
 * list, file_count and total_size are all received from the metadata section
 * which the sender should have sent us immediately before. file_count and
 * total_size are only used to update the progress indicator.
 *
 * This function doesn't use list, but maybe we might at some point.
 *
 * If the sender starts sending a file (i.e. it sends us the
 * TTT_MSG_FILE_METADATA message it has to send before sending the data
 * chunks), but then it encounters an error reading the file, it tells us
 * via an error code in the TTT_MSG_FILE_DATA_END message and we increment
 * *sender_failed_file_count each time this happens.
 *
 * Return 0 on success (even if the sender failed to send some files) or
 * nonzero if we hit some unrecoverable error such as the session falling
 * apart. */
static int
ttt_receive_file_set(struct ttt_file_transfer *ctx, struct ttt_session *sess,
        struct ttt_file_list *list, long long file_count, long long total_size,
        long long *sender_failed_file_count) {
    struct ttt_msg msg;
    struct ttt_decoded_msg decoded;
    FILE *current_file = NULL; /* destination for current file */
    char *local_filename = NULL; /* name of current or last file received */
    bool in_file_transfer = false; /* are we between FILE_METADATA and DATA_END */
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
            /* Metadata message which precedes a new file */
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
            in_file_transfer = true;

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
                    /* We failed to create the file because one or more of its
                     * parent directories don't exist. Try to create the
                     * directory structure prefixing local_filename... */
                    if (ttt_mkdir_parents(local_filename, 0777, true, DIR_SEP) < 0) {
                        int err = errno;
                        ttt_error(0, err, "failed to create directory for %s", local_filename);
                        ttt_send_fatal_error(sess, TTT_ERR_FAILED_TO_WRITE_FILE, "failed to create directory for %s: %s", local_filename, strerror(err));
                        goto fail;
                    }

                    /* ... and try to open the file again. If we fail again,
                     * report the error to our user and just ignore the
                     * file's data which the sender is going to send us
                     * anyway. */
                    current_file = fopen(local_filename, "wb");
                    if (current_file == NULL) {
                        ttt_error(0, errno, "skipping %s: failed to open for writing", local_filename);
                    }
                }
            }
#ifndef WINDOWS
            else if (S_ISFIFO(current_file_mode)) {
                /* Create a FIFO, creating its containing directories if necessary. */
                if (mkfifo(local_filename, current_file_mode & 07777) != 0) {
                    if (errno == ENOENT) {
                        if (ttt_mkdir_parents(local_filename, 0777, true, DIR_SEP) < 0) {
                            int err = errno;
                            ttt_error(0, err, "failed to create directory for fifo %s", local_filename);
                            ttt_send_fatal_error(sess, TTT_ERR_FAILED_TO_WRITE_FILE, "failed to create directory for fifo %s: %s", local_filename, strerror(err));
                            goto fail;
                        }

                        if (mkfifo(local_filename, current_file_mode & 07777) != 0) {
                            ttt_error(0, errno, "skipping fifo %s", local_filename);
                        }
                    }
                }
            }
#endif
            else if (S_ISDIR(current_file_mode)) {
                /* This is a directory entry. It arrives *after* any files it
                 * contains, so it should already exist unless it contains no
                 * files. Create the directory if we haven't already.
                 * When we get the TTT_MSG_FILE_DATA_END message, we'll set
                 * its timestamp and permissions. */
                if (access(local_filename, F_OK) != 0) {
                    if (ttt_mkdir_parents(local_filename, current_file_mode & 0777, false, DIR_SEP) < 0) {
                        ttt_error(0, errno, "failed to create directory %s", local_filename);
                    }
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
             * to save this file (for example, we couldn't open it on our
             * end for writing). */
            if (current_file != NULL) {
                size_t ret = fwrite(decoded.u.chunk.data, 1, decoded.u.chunk.length, current_file);
                if (ttt_random_file_write_failures && ret != 0 && rand() % 100 == 0) {
                    ret = 0;
                    errno = EIO;
                }
                if (ret != decoded.u.chunk.length) {
                    /* Failing to write to a file we've already opened is a
                     * fatal error and we don't try to recover from that.
                     * Perhaps instead we could just report the error to our
                     * user and ignore the rest of the data for this file? */
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
            /* End of the data for this file. If the error code in this message
             * is zero, we have the complete file, otherwise the sender is
             * telling us there's been a problem. Either way, we want to
             * close our current file. */
            if (!in_file_transfer) {
                /* TTT_MSG_FILE_DATA_END sent at the wrong point! */
                ttt_error(0, 0, "TTT_MSG_FILE_DATA_END sent without TTT_MSG_FILE_METADATA!");
                ttt_send_fatal_error(sess, TTT_ERR_PROTOCOL, "sender sent TTT_MSG_FILE_DATA_END but there was no TTT_MSG_FILE_METADATA before it");
                goto fail;
            }

            if (current_file != NULL) {
                /* Try to close the file and fatal error if we can't. */
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
#ifdef WINDOWS
                /* utime() can't set a directory's modification time on Windows */
                if (!S_ISDIR(current_file_mode))
#endif
                {
                    struct utimbuf timbuf;
                    timbuf.actime = time(NULL);
                    timbuf.modtime = current_file_mtime;
                    if (utime(local_filename, &timbuf) < 0) {
                        ttt_error(0, errno, "warning: failed to set modification time of %s", local_filename);
                    }
                }

                if (ttt_chmod(local_filename, current_file_mode & 07777) < 0) {
                    ttt_error(0, errno, "warning: failed to set mode %03o on %s", current_file_mode & 07777, local_filename);
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
                ttt_error(0, 0, "warning: sender skipped %s: %s", local_filename, decoded.u.err.message);
            }

            /* We're no longer inside a file transfer, so the next message
             * must be TTT_MSG_FILE_METADATA or TTT_MSG_FILE_SET_END */
            in_file_transfer = false;
        }
        else if (decoded.tag == TTT_MSG_FATAL_ERROR) {
            ttt_error(0, 0, "received fatal error from sender: 0x%08x: %s", decoded.u.err.code, decoded.u.err.message);
            goto fail;
        }
        else if (decoded.tag == TTT_MSG_FILE_SET_END) {
            /* There are no more files. Exit the loop on this iteration. */
            if (in_file_transfer) {
                ttt_error(0, 0, "received unexpected TTT_MSG_FILE_SET_END but current file still open");
                ttt_send_fatal_error(sess, TTT_ERR_PROTOCOL, "sender sent TTT_MSG_FILE_SET_END during file send but there was no TTT_FILE_DATA_END.");
                goto fail;
            }
        }
        else {
            /* Whatever this is, we don't want it... */
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

    /* Write a final "we've finished!" progress report. */
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

/* Play the "receiver" role in a TTT file transfer session set up in ctx. The
 * other end of the ttt_session sess should be playing the "sender" role at
 * the same time, or things will go rapidly downhill.
 *
 * The sender should send us a TTT_MSG_FILE_METADATA_SET_START message followed
 * by the metadata section, then a TTT_FILE_SET_START message followed by the
 * actual files, then either TTT_MSG_SWITCH_ROLES or TTT_MSG_END_SESSION.
 *
 * After the metadata section, if ctx->request_to_send is set, we call it
 * passing the metadata information to give the user the opportunity to cancel
 * the transfer if required.
 *
 * On return, set *file_count_out to the number of files we were supposed to
 * receive according to the metadata section, and *sender_failed_file_count_out
 * to the number of files the sender failed to send.
 *
 * Return <0 if there was a fatal error (i.e. the session died or we got some
 * sort of file I/O error, not the sender simply failed to send some of the
 * files).
 *
 * Also return <0 if the ctx->request_to_send() callback told us to reject the
 * file set.
 *
 * Return 0 if the sender sent us TTT_MSG_END_SESSION.
 * Return 1 if the sender sent us TTT_MSG_SWITCH_ROLES, after which we are
 * the sender side.
 */
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
    bool file_set_rejected = false;

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
                    /* User rejected the files. Send an error reply and
                     * make this a fatal error. */
                    file_set_rejected = true;
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

/* Set up a struct ttt_file_transfer context structure for either the sender
 * or receiver role. Called by ttt_file_transfer_init_sender() and
 * ttt_file_transfer_init_receiver() to initialise things not specific to
 * either role. */
static void
ttt_file_transfer_init(struct ttt_file_transfer *ctx, bool start_as_sender) {
    memset(ctx, 0, sizeof(*ctx));
    ctx->start_as_sender = start_as_sender;

    ctx->progress_report_interval.tv_sec = 0;
    ctx->progress_report_interval.tv_usec = 500000;

    ctx->next_progress_report.tv_sec = 0;
    ctx->next_progress_report.tv_usec = 0;

    ttt_file_transfer_set_progress_callback(ctx, default_progress_callback);
}

/* Initialise a struct ttt_file_transfer where we want to be the sender first. */
int
ttt_file_transfer_init_sender(struct ttt_file_transfer *ctx, const char **source_paths, int num_source_paths) {
    ttt_file_transfer_init(ctx, true);

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

/* Initialise a struct ttt_file_transfer where we want to be the receiver first. */
int
ttt_file_transfer_init_receiver(struct ttt_file_transfer *ctx, const char *output_dir) {
    ttt_file_transfer_init(ctx, false);

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
ttt_file_transfer_set_send_full_metadata(struct ttt_file_transfer *ctx, bool value) {
    ctx->send_full_metadata = value;
}

void
ttt_file_transfer_set_progress_callback(struct ttt_file_transfer *ctx, ttt_ft_progress_cb cb) {
    ctx->progress = cb;
}

int
ttt_file_transfer_session(struct ttt_file_transfer *ctx, struct ttt_session *sess) {
    bool finished = false;
    bool is_sender = ctx->start_as_sender;
    bool have_been_sender = false;
    bool have_been_receiver = false;
    bool failed = false;
    int rc;

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
                have_been_sender = true;
            }
        }
        else {
            rc = ttt_file_transfer_session_receiver(ctx, sess,
                    &total_files_to_send, &num_files_failed);
            have_been_receiver = true;
        }
        if (rc == 0 && num_files_failed > 0) {
            ttt_error(0, 0, "warning: %lld of %lld files were not sent%s",
                    num_files_failed, total_files_to_send,
                    is_sender ? " to receiver" : " to us");
            failed = true;
        }

        if (rc < 0) {
            /* Fatal error: abort the session. */
            finished = true;
            failed = true;
        }
        else if (rc > 0) {
            /* Send function shouldn't return this! */
            assert(!is_sender);
            /* We're the receiver and the sender has asked to switch roles. */
            is_sender = true;
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
                    finished = true;
                }
                else {
                    if (ttt_file_transfer_session_switch_roles(sess) < 0) {
                        finished = true;
                        failed = true;
                    }
                    else {
                        is_sender = false;
                    }
                }
            }
            else {
                /* We're the receiver, and the sender told us to end the
                 * session. */
                finished = true;
            }
        }
    }

    /* Did we want to push files but didn't get an opportunity to be sender? */
    if (!failed && ctx->num_source_paths > 0 && !have_been_sender) {
        ttt_error(0, 0, "couldn't push: remote host did not accept any files");
        failed = true;
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

/*****************************************************************************/

#ifdef TTT_UNIT_TESTS

#include <CUnit/CUnit.h>

static void
str_replace(char *str, char out, char in) {
    for (; *str; str++) {
        if (*str == out)
            *str = in;
    }
}

static void
test_join_paths(void) {
    struct {
        const char *path1;
        const char *path2;
        const char *expected;
    } test_cases[] = {
        { "alpha/bravo", "charlie/delta", "alpha/bravo/charlie/delta" },
        { "", "", "" },
        { "alpha", "bravo", "alpha/bravo" },
        { "/absolute/path/", "/foo/bar/", "/absolute/path/foo/bar/" },
        { "foo/", "/bar", "foo/bar" },
        { "foo", "/bar", "foo/bar" },
        { "foo/", "bar", "foo/bar" },
        { "foo/bar/baz", "", "foo/bar/baz" },
        { "", "foo/bar/baz", "foo/bar/baz" },
    };

    for (int i = 0; i < sizeof(test_cases) / sizeof(test_cases[0]); i++) {
        char *path1 = strdup(test_cases[i].path1);
        char *path2 = strdup(test_cases[i].path2);
        char *expected = strdup(test_cases[i].expected);
        char *observed = malloc(strlen(path1) + strlen(path2) + 2);
        char test_num[20];
        sprintf(test_num, "%d", i);

        /* Replace / with the local directory separator */
        str_replace(path1, '/', DIR_SEP);
        str_replace(path2, '/', DIR_SEP);
        str_replace(expected, '/', DIR_SEP);

        join_paths(path1, path2, observed);

        if (strcmp(observed, expected)) {
            fprintf(stderr, "test_join_paths: path1 \"%s\", path2 \"%s\", expected \"%s\", observed \"%s\"\n", path1, path2, expected, observed);
        }
        CU_ASSERT_STRING_EQUAL(observed, expected);

        free(path1);
        free(path2);
        free(expected);
        free(observed);
    }
}

static void
test_local_path_to_ttt_path(void) {
    struct {
        const char *local_path;
        const char *expected;
    } test_cases[] = {
        { "/foo/bar/baz", "foo/bar/baz" },
        { "foo/bar/baz", "foo/bar/baz" },
        { "foo", "foo" }
    };

    for (int i = 0; i < sizeof(test_cases) / sizeof(test_cases[0]); i++) {
        char *local_path = strdup(test_cases[i].local_path);
        const char *expected = test_cases[i].expected;
        char *observed;

        str_replace(local_path, '/', DIR_SEP);

        observed = local_path_to_ttt_path(local_path);
        if (strcmp(observed, expected) != 0) {
            fprintf(stderr, "test_local_path_to_ttt_path: local_path \"%s\", expected \"%s\", observed \"%s\"\n", local_path, expected, observed);
        }
        CU_ASSERT_STRING_EQUAL(observed, expected);

        free(observed);
        free(local_path);
    }
}

static void
test_ttt_path_to_local_path(void) {
    struct {
        const char *ttt_path;
        const char *local_base_dir;
        const char *expected;
    } test_cases[] = {
        { "alpha/bravo/charlie.txt", "/home/fred", "/home/fred/alpha/bravo/charlie.txt" },
        { "alpha.txt", "/home/fred/", "/home/fred/alpha.txt" },
        { "alpha/bravo.txt", "/home/fred///", "/home/fred///alpha/bravo.txt" },
        { "alpha/bravo.txt", ".", "./alpha/bravo.txt" },
        { "foo/bar/baz", "../some/dest", "../some/dest/foo/bar/baz" },
#ifdef WINDOWS
        { "s<om>e/ill:egal\\file|name/te*st?txt", "C:\\my\\dir",
            "C:\\my\\dir\\s_om_e\\ill_egal_file_name\\te_st_txt" }
#endif
    };

    for (int i = 0; i < sizeof(test_cases) / sizeof(test_cases[0]); i++) {
        const char *ttt_path = test_cases[i].ttt_path;
        char *local_base_dir = strdup(test_cases[i].local_base_dir);
        char *expected = strdup(test_cases[i].expected);
        char *observed;

        str_replace(local_base_dir, '/', DIR_SEP);
        str_replace(expected, '/', DIR_SEP);

        observed = ttt_path_to_local_path(ttt_path, local_base_dir);
        if (strcmp(observed, expected) != 0) {
            fprintf(stderr, "test_ttt_path_to_local_path(): ttt_path \"%s\", local_base_dir \"%s\", expected \"%s\", observed \"%s\"\n",
                    ttt_path, local_base_dir, expected, observed);
        }
        CU_ASSERT_STRING_EQUAL(observed, expected);

        free(observed);
        free(local_base_dir);
        free(expected);
    }
}

CU_ErrorCode
ttt_filetransfer_register_tests(void) {
    CU_TestInfo tests[] = {
        { "join_paths", test_join_paths },
        { "local_path_to_ttt_path", test_local_path_to_ttt_path },
        { "ttt_path_to_local_path", test_ttt_path_to_local_path },
        CU_TEST_INFO_NULL
    };

    CU_SuiteInfo suites[] = {
        { "filetransfer", NULL, NULL, NULL, NULL, tests },
        CU_SUITE_INFO_NULL
    };

    return CU_register_suites(suites);
}

#endif
