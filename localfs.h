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
 * We define a type TTT_LF_CHAR which is the character used to make strings
 * containing local filenames on the host OS. This is char on Linux and wchar_t
 * on Windows. We then provide some wrapper functions such as ttt_fopen(),
 * ttt_stat() etc which call the relevant function for the OS.
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
 * protocol messages we send such as TTT_MSG_FILE_METADATA. This is always
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

typedef wchar_t TTT_LF_CHAR;
typedef struct __stat64 TTT_STAT;

/* Data structures and types for our Windows-based attempt to mimic opendir(),
 * readdir(), and closedir(). */
struct ttt_dir_entry {
    wchar_t d_name[MAX_PATH];
};

struct ttt_dir_handle {
    HANDLE hFind;
    WIN32_FIND_DATAW find_data;
    bool finished;
    wchar_t *path;
    struct ttt_dir_entry entry;
};

typedef struct ttt_dir_entry *TTT_DIR_ENTRY;
typedef struct ttt_dir_handle *TTT_DIR_HANDLE;
typedef struct _utimbuf TTT_UTIMBUF;

#define TTT_LF_EMPTY L""
#define TTT_LF_CURRENT_DIR L"."
#define TTT_LF_PARENT_DIR L".."
#define TTT_LF_STDIN L"-"

#define TTT_LF_PRINTF "%ls"
#define TTT_LF_PRINTF_WIDTH "%-*ls"

#define TTT_LF_MODE_WB L"wb"
#define TTT_LF_MODE_RB L"rb"

#else

#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <utime.h>

typedef char TTT_LF_CHAR;
typedef DIR *TTT_DIR_HANDLE;
typedef struct dirent *TTT_DIR_ENTRY;
typedef struct stat TTT_STAT;
typedef struct utimbuf TTT_UTIMBUF;

#define TTT_LF_EMPTY ""
#define TTT_LF_CURRENT_DIR "."
#define TTT_LF_PARENT_DIR ".."
#define TTT_LF_STDIN "-"

#define TTT_LF_PRINTF "%s"
#define TTT_LF_PRINTF_WIDTH "%-*s"

#define TTT_LF_MODE_WB "wb"
#define TTT_LF_MODE_RB "rb"

#endif

size_t
ttt_lf_char_size(void);

size_t
ttt_lf_len(const TTT_LF_CHAR *str);

void
ttt_lf_copy(TTT_LF_CHAR *dest, const TTT_LF_CHAR *src);

int
ttt_lf_casecmp(const TTT_LF_CHAR *str1, const TTT_LF_CHAR *str2);

int
ttt_lf_cmp(const TTT_LF_CHAR *str1, const TTT_LF_CHAR *str2);

TTT_LF_CHAR *
ttt_lf_dup(const TTT_LF_CHAR *str);

TTT_DIR_HANDLE
ttt_opendir(const TTT_LF_CHAR *path);

TTT_DIR_ENTRY
ttt_readdir(TTT_DIR_HANDLE handle);

int
ttt_closedir(TTT_DIR_HANDLE handle);

FILE *
ttt_fopen(const TTT_LF_CHAR *path, TTT_LF_CHAR *mode);

int
ttt_stat(const TTT_LF_CHAR *path, TTT_STAT *st);

int
ttt_unlink(const TTT_LF_CHAR *path);

/* Create the directory named in "path" and give it the permission bits "mode".
 * If parents_only is set, ignore the last component of "path".
 * dir_sep is the directory separator according to the local OS.
 *
 * Returns 0 on success, nonzero on error.
 */
int
ttt_mkdir_parents(const TTT_LF_CHAR *path, int mode, bool parents_only);

#ifdef WINDOWS
int
ttt_chmod(const TTT_LF_CHAR *path, int unix_mode);
#else
int
ttt_chmod(const TTT_LF_CHAR *path, mode_t mode);
#endif

int
ttt_utime(const TTT_LF_CHAR *path, TTT_UTIMBUF *timbuf);

int
ttt_access(const TTT_LF_CHAR *path, int mode);

TTT_LF_CHAR *
ttt_realpath(const TTT_LF_CHAR *path);

char *
ttt_lf_to_utf8(const TTT_LF_CHAR *filename);

TTT_LF_CHAR *
ttt_lf_from_utf8(const char *filename);

TTT_LF_CHAR *
ttt_lf_from_locale(const char *filename);

#ifdef TTT_UNIT_TESTS

#include <CUnit/CUnit.h>

CU_ErrorCode
ttt_localfs_register_tests(void);

#endif

#endif
