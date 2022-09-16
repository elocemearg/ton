#ifndef _TTTFILETRANSFER_H
#define _TTTFILETRANSFER_H

#include <sys/time.h>

#include "session.h"

struct ttt_file {
    /* Source or destination path to the file on our system. */
    char *local_path;

    /* How the file is named in the TTT_MSG_FILE_METADATA message. This
     * will have all directory separators replaced with '/' no matter what
     * the directory separator on the local system is. The path will also be
     * relative to the path specified on the command line. */
    char *ttt_path;

    /* Modified time of the file. This is a Unix timestamp. */
    time_t mtime;

    /* File mode/permissions (Unix style) */
    int mode;

    /* Size of the file in bytes. */
    long long size;

    /* Next file in the list. */
    struct ttt_file *next;
};

/* Linked list of ttt_file objects with a pointer to the last entry for
 * ease of adding to the end. */
struct ttt_file_list {
    struct ttt_file *start;
    struct ttt_file *last;
};

typedef int (*ttt_ft_request_to_send_cb)(void *callback_cookie,
        const struct ttt_file *file_list, long file_count,
        long long total_size);

typedef void (*ttt_ft_progress_cb)(void *callback_cookie, int is_sender,
            const char *filename, long file_number, long total_files,
            long long file_position, long long file_size,
            long long bytes_so_far, long long total_bytes,
            long skipped_files, int finished);

/* TTT file transfer context. Contains options and callbacks related to a
 * file transfer session.
 * It does not contain the actual ttt_session object - this is expected to
 * be set up separately (see session.c and discover.c).
 *
 * I've not called this tttftctx, in the same manner as tttdactx and tttdlctx,
 * because tttftctx appears to be impossible for me to type without multiple
 * attempts.
 */
struct ttt_file_transfer {
    /* If nonzero, this side initially has the "sender" role in the file
     * transfer session (see protocol.c and protocol.h). If zero, this side
     * initially has the "receiver" role. The other endpoint had better have
     * the opposite role to us or things won't go well. */
    bool start_as_sender;

    /* Destination directory for any files we receive. If start_as_sender is 1,
     * then if this is NULL we won't ask to switch roles after we've finished
     * sending, we'll just close the session. If start_as_sender is 0,
     * output_dir isn't allowed to be NULL. */
    char *output_dir;

    /* The list of files or directories we want to send if and when we get
     * to be the sender on this session. */
    char **source_paths;

    /* The number of strings in source_paths. */
    int num_source_paths;

    /* Called during ttt_file_transfer_session() when the sender has sent us
     * the list of files it intends to send (or just the summary file count and
     * total size).
     *
     * callback_cookie: cookie set with ttt_file_transfer_set_callback_cookie().
     * file_list: linked list of file metadata entries which the sender wants to
     *        send us. The sender doesn't have to give us this detail. If it
     *        doesn't, files is NULL.
     * file_count: the total number of files the sender intends to send. This
     *        may be set even if files is NULL. If it's not known, it's -1.
     * total_size: the total size of all the files the sender intends to send,
     *        in bytes. This may be set even if files is NULL. If it's not
     *        known, it's -1.
     *
     * Return 0 to accept the files and start the transfer.
     * Return -1 to reject the files.
     */
    ttt_ft_request_to_send_cb request_to_send;

    /* Called during ttt_file_transfer_session() periodically while sending or
     * receiving files, to provide an update on progress.
     *
     * callback_cookie: Cookie set with ttt_file_transfer_set_callback_cookie().
     * is_sender: 0 if we're receiving files, 1 if we're sending them.
     * filename: The name of the file we're currently receiving or writing to.
     *           This is the path in our local filesystem, which starts
     *           with output_dir. NULL if no transfer has been started yet.
     * file_number: The sequential number of this file in this transfer. The
     *           first file is 1.
     * total_files: The total number of files we expect the sender to try to
     *           send. This may be different from the number of files which
     *           actually arrive. -1 if not known.
     * file_position: The current position in the file we're writing.
     * file_size: The size of the file we're writing in bytes, according to the
     *            sender. -1 if not known.
     * bytes_so_far: The total number of bytes transferred so far.
     * total_bytes: The total number of bytes we expect to be transferred when
     *              we've finished. The sender can skip sending files if they
     *              become unavailable, so this may decrease through the course
     *              of the transfer.
     * skipped_files: The number of files the sender has skipped because they
     *                were not available.
     * finished: 1 if we have finished the file transfer, 0 if not.
     */
    ttt_ft_progress_cb progress;

    /* Time at which the next progress report is due, if progress is set. */
    struct timeval next_progress_report;

    /* Interval between progress reports: default 0.5 seconds */
    struct timeval progress_report_interval;

    /* If 1, then when we are sender, the TTT_MSG_FILE_METADATA_SET_START /
     * TTT_MSG_FILE_METADATA_SET_END message sequence will contain one
     * TTT_MSG_FILE_METADATA message per file we intend to send.
     * If 0, that message sequence will contain only a
     * TTT_MSG_FILE_METADATA_SUMMARY message. */
    bool send_full_metadata;

    /* Opaque pointer set by ttt_file_transfer_set_callback_cookie() and passed
     * to the callback functions. */
    void *callback_cookie;
};

/* Initialise a file transfer context in which we initially have the sender
 * role. source_paths must point to num_source_paths strings, which will be
 * copied into ctx. All files and directories named in source_paths will be
 * sent to the receiver. Directory contents will be sent as well. Only
 * regular files and directories will be sent - no special files or symlinks.
 * When we recurse into a directory structure, symlinks are not followed. */
int
ttt_file_transfer_init_sender(struct ttt_file_transfer *ctx, const char **source_paths, int num_source_paths);

/* Initialise a file transfer context in which we initially have the receiver
 * role. Received files will be written to the directory named by output_dir,
 * which will be created if it does not exist. */
int
ttt_file_transfer_init_receiver(struct ttt_file_transfer *ctx, const char *output_dir);

/* Set the callback cookie which ttt_file_transfer_session() will pass to any
 * callbacks it calls. This is treated as an opaque pointer which has meaning
 * only to the callback function. */
void
ttt_file_transfer_set_callback_cookie(struct ttt_file_transfer *ctx, void *cookie);

/* Set the callback function to be called when as a receiver we receive the
 * metadata section of the file transfer. The callback function can return -1
 * to cancel the transfer. */
void
ttt_file_transfer_set_request_to_send_callback(struct ttt_file_transfer *ctx, ttt_ft_request_to_send_cb cb);

/* Set the callback function to be called periodically during the transfer to
 * update the user on prgoress. */
void
ttt_file_transfer_set_progress_callback(struct ttt_file_transfer *ctx, ttt_ft_progress_cb cb);

/* When we're the sender sending the metadata section, specify whether we're to
 * send the full metadata list containing metadata for every file we intend to
 * send (value == 1) or just a summary containing the count and total size of
 * the files (value == 0). */
void
ttt_file_transfer_set_send_full_metadata(struct ttt_file_transfer *ctx, bool value);

/* Starts a file transfer session set up with a previous call to
 * ttt_file_transfer_init_sender() or ttt_file_transfer_init_receiver(), using
 * the given ttt_session for communication.
 *
 * Return zero if all files were transferred successfully, or nonzero otherwise.
 */
int
ttt_file_transfer_session(struct ttt_file_transfer *ctx, struct ttt_session *sess);

/* Destroy a file transfer context and free any resources associated with it.
 * This does not close the session. */
void
ttt_file_transfer_destroy(struct ttt_file_transfer *ctx);

#endif
