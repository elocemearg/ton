#ifndef _LOCALFS_H
#define _LOCALFS_H

/* On Windows, we internally represent local filenames as wide-character
 * strings (wchar_t *) because at the OS level, filenames are Unicode strings.
 *
 * On Linux, a filename is a string of bytes with an unknown character
 * encoding, so we internally represent a filename as a multibyte character
 * string (char *).
 *
 * When we send a filename over the wire, we send it in UTF-8.
 * Filenames originating on Linux which are not valid UTF-8 will be made into
 * valid UTF-8 by replacing troublesome bytes with '_'.
 * Filenames originating on Windows are obtained as wchar_t strings and
 * converted to UTF-8 for sending to the other host.
 *
 * We define a type TON_LF_CHAR which is the character used to make strings
 * containing local filenames on the host OS. This is char on Linux and wchar_t
 * on Windows. We then provide some wrapper functions such as ton_fopen(),
 * ton_stat() etc which call the relevant function for the OS.
 */

#include <stdbool.h>
#include <utime.h>
#include <sys/time.h>
#include "utils.h"

/* DIR_SEP_STR and DIR_SEP is the directory separator we have to use in
 * pathnames passed to OS calls. On Windows it's a backslash and on everything
 * else it's a slash.
 *
 * This is distinct from the directory separator we use in pathnames in
 * protocol messages we send such as TON_MSG_FILE_METADATA. This is always
 * a slash.
 */
#ifdef WINDOWS
#define DIR_SEP_STR L"\\"
#define DIR_SEP '\\'
#else
#define DIR_SEP_STR "/"
#define DIR_SEP '/'
#endif

#ifdef WINDOWS
/* On Windows, the FindFirstFile/FindNextFile functions give a filename of
 * up to PATH_MAX characters. */
#define MAX_PATH_COMPONENT_LEN PATH_MAX
#else
/* On Linux, it's a bit more hit and miss... */
#ifdef NAME_MAX
#define MAX_PATH_COMPONENT_LEN NAME_MAX
#else
#define MAX_PATH_COMPONENT_LEN 256
#endif
#endif

#ifdef WINDOWS
#define LOCAL_FILENAME_IS_WCHAR
#endif

#ifdef LOCAL_FILENAME_IS_WCHAR
#include <wchar.h>

typedef wchar_t TON_LF_CHAR;
typedef struct __stat64 TON_STAT;

/* Data structures and types for our Windows-based attempt to mimic opendir(),
 * readdir(), and closedir(). */
struct ton_dir_entry {
    wchar_t d_name[MAX_PATH];
};

struct ton_dir_handle {
    HANDLE hFind;
    WIN32_FIND_DATAW find_data;
    bool finished;
    wchar_t *path;
    struct ton_dir_entry entry;
};

typedef struct ton_dir_entry *TON_DIR_ENTRY;
typedef struct ton_dir_handle *TON_DIR_HANDLE;
typedef struct _utimbuf TON_UTIMBUF;

#define TON_LF_EMPTY L""
#define TON_LF_CURRENT_DIR L"."
#define TON_LF_PARENT_DIR L".."
#define TON_LF_STDIN L"-"

#define TON_LF_PRINTF "%ls"
#define TON_LF_PRINTF_WIDTH "%-*ls"

#define TON_LF_MODE_WB L"wb"
#define TON_LF_MODE_RB L"rb"

#else

#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <utime.h>

typedef char TON_LF_CHAR;
typedef DIR *TON_DIR_HANDLE;
typedef struct dirent *TON_DIR_ENTRY;
typedef struct stat TON_STAT;
typedef struct utimbuf TON_UTIMBUF;

#define TON_LF_EMPTY ""
#define TON_LF_CURRENT_DIR "."
#define TON_LF_PARENT_DIR ".."
#define TON_LF_STDIN "-"

#define TON_LF_PRINTF "%s"
#define TON_LF_PRINTF_WIDTH "%-*s"

#define TON_LF_MODE_WB "wb"
#define TON_LF_MODE_RB "rb"

#endif

size_t
ton_lf_char_size(void);

size_t
ton_lf_len(const TON_LF_CHAR *str);

void
ton_lf_copy(TON_LF_CHAR *dest, const TON_LF_CHAR *src);

int
ton_lf_casecmp(const TON_LF_CHAR *str1, const TON_LF_CHAR *str2);

int
ton_lf_cmp(const TON_LF_CHAR *str1, const TON_LF_CHAR *str2);

TON_LF_CHAR *
ton_lf_dup(const TON_LF_CHAR *str);

TON_DIR_HANDLE
ton_opendir(const TON_LF_CHAR *path);

TON_DIR_ENTRY
ton_readdir(TON_DIR_HANDLE handle);

int
ton_closedir(TON_DIR_HANDLE handle);

FILE *
ton_fopen(const TON_LF_CHAR *path, TON_LF_CHAR *mode);

int
ton_stat(const TON_LF_CHAR *path, TON_STAT *st);

int
ton_unlink(const TON_LF_CHAR *path);

/* Create the directory named in "path" and give it the permission bits "mode".
 * If parents_only is set, ignore the last component of "path".
 * dir_sep is the directory separator according to the local OS.
 *
 * Returns 0 on success, nonzero on error.
 */
int
ton_mkdir_parents(const TON_LF_CHAR *path, int mode, bool parents_only);

#ifdef WINDOWS
int
ton_chmod(const TON_LF_CHAR *path, int unix_mode);
#else
int
ton_chmod(const TON_LF_CHAR *path, mode_t mode);
#endif

int
ton_utime(const TON_LF_CHAR *path, TON_UTIMBUF *timbuf);

int
ton_access(const TON_LF_CHAR *path, int mode);

/* Return a pointer to the basename part of the given path. */
const TON_LF_CHAR *
ton_lf_basename(const TON_LF_CHAR *path);

#ifndef WINDOWS
/* Return the target of the given symlink. It is the caller's responsibility to
 * free the return value. On error, NULL is returned. */
char *
ton_get_symlink_target(TON_LF_CHAR *symlink_path);
#endif

char *
ton_lf_to_utf8(const TON_LF_CHAR *filename);

TON_LF_CHAR *
ton_lf_from_utf8(const char *filename);

TON_LF_CHAR *
ton_lf_from_locale(const char *filename);

#ifdef TON_UNIT_TESTS

#include <CUnit/CUnit.h>

CU_ErrorCode
ton_localfs_register_tests(void);

#endif

#endif
