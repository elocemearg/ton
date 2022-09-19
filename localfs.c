#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <dirent.h>
#include <stdbool.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "localfs.h"
#include "utils.h"

size_t
ttt_lf_char_size(void) {
    return sizeof(TTT_LF_CHAR);
}

size_t
ttt_lf_len(const TTT_LF_CHAR *str) {
#ifdef LOCAL_FILENAME_IS_WCHAR
    return wcslen(str);
#else
    return strlen(str);
#endif
}

void
ttt_lf_copy(TTT_LF_CHAR *dest, const TTT_LF_CHAR *src) {
#ifdef LOCAL_FILENAME_IS_WCHAR
    wcscpy(dest, src);
#else
    strcpy(dest, src);
#endif
}

int
ttt_lf_casecmp(const TTT_LF_CHAR *str1, const TTT_LF_CHAR *str2) {
#ifdef LOCAL_FILENAME_IS_WCHAR
    return _wcsicmp(str1, str2);
#else
    return strcasecmp(str1, str2);
#endif
}

int
ttt_lf_cmp(const TTT_LF_CHAR *str1, const TTT_LF_CHAR *str2) {
#ifdef LOCAL_FILENAME_IS_WCHAR
    return wcscmp(str1, str2);
#else
    return strcmp(str1, str2);
#endif
}

TTT_LF_CHAR *
ttt_lf_dup(const TTT_LF_CHAR *str) {
#ifdef LOCAL_FILENAME_IS_WCHAR
    return wcsdup(str);
#else
    return strdup(str);
#endif
}

TTT_LF_CHAR *
ttt_lf_strrchr(const TTT_LF_CHAR *str, TTT_LF_CHAR c) {
#ifdef LOCAL_FILENAME_IS_WCHAR
    return wcsrchr(str, c);
#else
    return strrchr(str, c);
#endif
}

TTT_DIR_HANDLE
ttt_opendir(const TTT_LF_CHAR *path) {
#ifdef WINDOWS
    struct ttt_dir_handle *handle;
    wchar_t *path_with_wildcard;
    size_t pos;

    handle = malloc(sizeof(struct ttt_dir_handle));
    if (handle == NULL)
        return NULL;

    handle->finished = false;

    path_with_wildcard = malloc((wcslen(path) + 3) * sizeof(TTT_LF_CHAR));
    if (path_with_wildcard == NULL) {
        free(handle);
        return NULL;
    }
    wcscpy(path_with_wildcard, path);
    pos = wcslen(path);
    while (pos > 0 && path_with_wildcard[pos - 1] == '\\') {
        --pos;
    }

    /* Having wound pos back to point to the last directory separator, if it
     * exists, in path_with_wildcard, append a directory separator and an
     * asterisk, to list all files in the directory. */
    path_with_wildcard[pos++] = '\\';
    path_with_wildcard[pos++] = '*';
    path_with_wildcard[pos++] = 0;

    /* Read the first entry, which also opens the handle. However, the API of
     * ttt_opendir() and ttt_readdir() is like opendir() and readdir() in that
     * it doesn't return the first entry from ttt_opendir(). So we'll store
     * this in "handle" and return it when ttt_readdir() is called. */
    handle->hFind = FindFirstFileW(path_with_wildcard, &handle->find_data);
    if (handle->hFind == INVALID_HANDLE_VALUE) {
        handle->finished = true;
    }

    handle->path = path_with_wildcard;

    return handle;
#else
    return opendir(path);
#endif
}

TTT_DIR_ENTRY
ttt_readdir(TTT_DIR_HANDLE handle) {
#ifdef WINDOWS
    if (handle->finished) {
        return NULL;
    }

    /* Take the filename we last read and copy it into handle->entry... */
    wcsncpy(handle->entry.d_name, handle->find_data.cFileName, MAX_PATH);

    /* Now fetch the next entry from FindNextFile() into handle->find_data.
     * If that returns an entry then we'll return it on the next ttt_readdir()
     * call. If there are no more entries then the next ttt_readdir() call will
     * return NULL. */
    if (FindNextFileW(handle->hFind, &handle->find_data) == 0) {
        DWORD err = GetLastError();
        if (err != ERROR_NO_MORE_FILES) {
            ttt_error(0, 0, TTT_LF_PRINTF ": failed to read directory", handle->path);
            errno = EPERM;
            return NULL;
        }

        /* No more after this one */
        handle->finished = true;
    }

    /* Return the stored entry */
    return &handle->entry;
#else
    return readdir(handle);
#endif
}

int
ttt_closedir(TTT_DIR_HANDLE handle) {
#ifdef WINDOWS
    if (handle->hFind != INVALID_HANDLE_VALUE) {
        FindClose(handle->hFind);
    }
    free(handle->path);
    free(handle);
    return 0;
#else
    return closedir(handle);
#endif
}

FILE *
ttt_fopen(const TTT_LF_CHAR *path, TTT_LF_CHAR *mode) {
#ifdef LOCAL_FILENAME_IS_WCHAR
    return _wfopen(path, mode);
#else
    return fopen(path, mode);
#endif
}

int
ttt_stat(const TTT_LF_CHAR *path, TTT_STAT *st) {
#ifdef WINDOWS
    return _wstat64(path, st);
#else
    return stat(path, st);
#endif
}

int
ttt_unlink(const TTT_LF_CHAR *path) {
#ifdef WINDOWS
    return _wunlink(path);
#else
    return unlink(path);
#endif
}

int
ttt_mkdir(const TTT_LF_CHAR *pathname, int mode) {
#ifdef WINDOWS
    return _wmkdir(pathname);
#else
    return mkdir(pathname, mode);
#endif
}

int
ttt_mkdir_parents(const TTT_LF_CHAR *pathname_orig, int mode, bool parents_only) {
    size_t pathname_len;
    TTT_LF_CHAR *pathname = ttt_lf_dup(pathname_orig);
    TTT_LF_CHAR *last_dir_sep = NULL;
    int return_value = 0;
    TTT_STAT st;

    if (pathname == NULL)
        return -1;

    /* Remove any trailing directory separators from pathname */
    pathname_len = ttt_lf_len(pathname);
    while (pathname_len > 0 && pathname[pathname_len - 1] == DIR_SEP)
        pathname[--pathname_len] = '\0';

    /* First, check if this path, (or its parent if parents_only is set),
     * already exists as a directory. If so, there's nothing to do and we
     * don't need to check each component in turn. */
    if (parents_only) {
        last_dir_sep = ttt_lf_strrchr(pathname, DIR_SEP);
        if (last_dir_sep) {
            *last_dir_sep = '\0';
        }
    }
    if (ttt_stat(pathname, &st) == 0 && S_ISDIR(st.st_mode)) {
        /* deepest level directory we would create already exists */
        free(pathname);
        return 0;
    }
    /* Undo our vandalism of the pathname and carry on... */
    if (last_dir_sep)
        *last_dir_sep = DIR_SEP;

    /* For every sub-path that's a prefix of this one, check if the directory
     * exists and create it if it doesn't.
     * Note we also iterate round the loop when pos == pathname_len, so that
     * we create the last level directory as well if parents_only is not set.
     * Start at pos = 1 so that if pathname is an absolute path e.g.
     * /tmp/dest/a.txt we don't try to create "/" */
    for (size_t pos = 1; pos <= pathname_len; pos++) {
        if (pathname[pos] == DIR_SEP || (!parents_only && pathname[pos] == '\0')) {
            /* Does pathname[0 to pos] exist as a directory? */
            pathname[pos] = '\0';
            if (ttt_stat(pathname, &st) < 0 && errno == ENOENT) {
                /* Doesn't exist - create it. */
                if (ttt_mkdir(pathname, mode) < 0) {
                    goto fail;
                }
            }
            else if (!S_ISDIR(st.st_mode)) {
                /* Exists but not as a directory */
                errno = ENOTDIR;
                goto fail;
            }
            /* Otherwise, this directory already exists. Put the directory
             * separator back if we replaced it, and continue. */
            if (pos < pathname_len) {
                pathname[pos] = DIR_SEP;
            }
        }
    }
end:
    free(pathname);
    return return_value;

fail:
    return_value = -1;
    goto end;
}

#ifdef WINDOWS
int
ttt_chmod(const TTT_LF_CHAR *path, int unix_mode) {
    /* Translate the Unix-style chmod mode bits into what's required by the
     * Windows _chmod call, which only supports one read and write bit.
     * Take those from the owner-readable and owner-writable bits of
     * unix_mode. */
    int windows_mode_bits = 0;
    if (unix_mode & 0400) {
        windows_mode_bits |= _S_IREAD;
    }
    if (unix_mode & 0200) {
        windows_mode_bits |= _S_IWRITE;
    }
    return _wchmod(path, windows_mode_bits);
}
#else
int
ttt_chmod(const TTT_LF_CHAR *path, mode_t mode) {
    return chmod(path, mode);
}
#endif

int
ttt_utime(const TTT_LF_CHAR *path, TTT_UTIMBUF *timbuf) {
#ifdef LOCAL_FILENAME_IS_WCHAR
    return _wutime(path, timbuf);
#else
    return utime(path, timbuf);
#endif
}

int
ttt_access(const TTT_LF_CHAR *path, int mode) {
#ifdef LOCAL_FILENAME_IS_WCHAR
    return _waccess(path, mode);
#else
    return access(path, mode);
#endif
}

TTT_LF_CHAR *
ttt_realpath(const TTT_LF_CHAR *path) {
#ifdef LOCAL_FILENAME_IS_WCHAR
    return _wfullpath(NULL, path, 0);
#else
    return realpath(path, NULL);
#endif
}

/* If *p points to a valid UTF-8 byte sequence, point *p to the first byte
 * after the sequence and return the character.
 * Otherwise, leave *p unchanged and return (wchar_t) -1. */
static int32_t
consume_utf8_char(const char **p) {
    const char *s = *p;
    int num_extra_bytes = 0;
    int32_t c = 0;
    if ((*s & 0x80) == 0) {
        num_extra_bytes = 0;
        c = *s;
    }
    else if ((*s & 0xe0) == 0xc0) {
        num_extra_bytes = 1;
        c = (*s & 0x1f);
    }
    else if ((*s & 0xf0) == 0xe0) {
        num_extra_bytes = 2;
        c = (*s & 0x0f);
    }
    else if ((*s & 0xf8) == 0xf0) {
        num_extra_bytes = 3;
        c = (*s & 0x07);
    }
    else {
        /* We don't support UTF-8 sequences longer than 4 bytes */
        return -1;
    }

    ++s;
    for (int i = 0; i < num_extra_bytes; i++) {
        /* num_extra_bytes expected, each of the form 10xxxxxx */
        c <<= 6;
        c |= *s & 0x3f;
        if ((*s & 0xc0) != 0x80) {
            return -1;
        }
        ++s;
    }
    *p = s;

    return c;
}

#ifdef LOCAL_FILENAME_IS_WCHAR

/* Convert codepoint to a UTF-8 byte sequence, copy it to *outp, and advance
 * *outp by the number of bytes written. */
static void
codepoint_to_utf8(char **outp, int32_t codepoint) {
    int num_extra_bytes;

    if (codepoint < 0x80) {
        **outp = (char) codepoint;
        num_extra_bytes = 0;
    }
    else if (codepoint < 0x800) {
        **outp = 0xc0 | (char) (codepoint >> 6);
        num_extra_bytes = 1;
    }
    else if (codepoint < 0x10000) {
        **outp = 0xe0 | (char) (codepoint >> 12);
        num_extra_bytes = 2;
    }
    else if (codepoint < 0x200000) {
        **outp = 0xf0 | (char) (codepoint >> 18);
        num_extra_bytes = 3;
    }
    else if (codepoint < 0x4000000) {
        **outp = 0xf8 | (char) (codepoint >> 24);
        num_extra_bytes = 4;
    }
    else {
        **outp = 0xfc | (char) ((codepoint >> 30) & 1);
        num_extra_bytes = 5;
    }
    ++*outp;

    for (int i = 0; i < num_extra_bytes; i++) {
        **outp = 0x80 | ((codepoint >> (6 * (num_extra_bytes - i - 1))) & 0x3f);
        ++*outp;
    }
}

/* Convert the wide character pointed to by *in to a UTF-8 byte sequence,
 * which will be written to *outp.
 *
 * *in is advanced by the number of wchar_t values read (usually 1, unless
 * we see a surrogate pair), and *outp is advanced by the number of UTF-8
 * bytes written.
 *
 * If (*in)[0] is the first half of a surrogate pair, we also read (*in)[1]
 * and advance *in by two.
 *
 * If we read an invalid surrogate pair, then we replace the invalid code
 * unit with the UTF-8 representation of the replacement codepoint repl in the
 * output. */
static void
wchar_to_utf8(char **outp, const wchar_t **in, int32_t repl) {
    int32_t codepoint;
    if ((**in & 0xFC00) == 0xD800) {
        codepoint = 0x10000 + (((int32_t) **in & 0x3ff) << 10);
        ++*in;
        if ((**in & 0xFC00) == 0xDC00) {
            codepoint |= ((int32_t) **in & 0x3ff);
            ++*in;
        }
        else {
            codepoint = repl;
        }
    }
    else {
        codepoint = **in;
        ++*in;
    }

    codepoint_to_utf8(outp, codepoint);
}
#endif

char *
ttt_lf_to_utf8(const TTT_LF_CHAR *filename) {
#ifdef LOCAL_FILENAME_IS_WCHAR
    char *out;
    const wchar_t *in = filename;
    char *outp;

    /* Maximum space needed is four bytes per character, plus '\0' */
    out = malloc(ttt_lf_len(filename) * 4 + 1);
    if (out == NULL)
        return NULL;
    outp = out;

    while (*in) {
        wchar_to_utf8(&outp, &in, '_');
    }
    *outp = '\0';
    return out;
#else
    char *out = strdup(filename);
    char *p;
    if (out == NULL)
        return NULL;
    p = out;
    while (*p) {
        int32_t c = consume_utf8_char((const char **) &p);
        if (c == -1) {
            /* If we find a non-UTF-8 byte sequence, replace bytes with '_'
             * until we find a valid UTF-8 byte sequence again. */
            *p = '_';
            p++;
        }
    }
    return out;
#endif
}

TTT_LF_CHAR *
ttt_lf_from_utf8(const char *filename) {
#ifdef LOCAL_FILENAME_IS_WCHAR
    wchar_t *out;
    const char *inp;
    wchar_t *outp;
    int32_t c;

    out = malloc((strlen(filename) + 1) * sizeof(wchar_t));
    if (out == NULL) {
        errno = ENOMEM;
        return NULL;
    }
    inp = filename;
    outp = out;
    while ((c = consume_utf8_char(&inp)) != 0) {
        if (c == -1) {
            /* This indicates a bug in whatever sent us this filename and
             * told us it was UTF-8. */
            free(out);
            return NULL;
        }
        else if (c > WCHAR_MAX) {
            /* Encode as surrogate pair */
            outp[0] = 0xD800 + (((c - 0x10000) >> 10) & 0x3ff);
            outp[1] = 0xDC00 + ((c - 0x10000) & 0x3ff);
            outp += 2;
        }
        else {
            /* This codepoint can be encoded directly as one wchar_t */
            *outp = c;
            outp++;
        }
    }
    *outp = 0;
    return out;
#else
    return strdup(filename);
#endif
}

TTT_LF_CHAR *
ttt_lf_from_locale(const char *filename) {
#ifdef LOCAL_FILENAME_IS_WCHAR
    size_t num_chars;
    wchar_t *out;

    num_chars = mbstowcs(NULL, filename, 0);
    if (num_chars == (size_t) -1) {
        return NULL;
    }

    out = malloc(sizeof(wchar_t) * (num_chars + 1));
    if (out == NULL) {
        return NULL;
    }

    mbstowcs(out, filename, num_chars + 1);

    return out;
#else
    return strdup(filename);
#endif
}

/*****************************************************************************/

#ifdef TTT_UNIT_TESTS

#include <CUnit/CUnit.h>

static void
test_ttt_lf_from_utf8(void) {
#ifdef LOCAL_FILENAME_IS_WCHAR
    struct {
        char *utf8;
        wchar_t *expected;
    } tests[] = {
        { "hello world", L"hello world" },
        { "\xc2\xa3" "100", L"\u00a3100" },
        { "\xf0\x9f\x8d\x86.txt", L"\U0001f346.txt" }, /* aubergine emoji */
        { "\xf0\x9f\x98\x82\xf0\x9f\x98\x82\xf0\x9f\x98\x82", L"😂😂😂" },
    };

    for (int i = 0; i < sizeof(tests) / sizeof(tests[0]); i++) {
        char *utf8 = tests[i].utf8;
        wchar_t *expected = tests[i].expected;
        wchar_t *observed;

        observed = ttt_lf_from_utf8(utf8);
        if (wcscmp(observed, expected)) {
            fprintf(stderr, "test_ttt_lf_from_utf8(): utf8 \"%s\", expected \"%ls\", observed \"%ls\"\n",
                    utf8, expected, observed);
            CU_FAIL("output not as expected");
        }
        free(observed);
    }

    /* If LOCAL_FILENAME_IS_WCHAR is not defined, then
     * ttt_lf_from_utf8() is just strdup(). */
#endif
}

static void
test_ttt_lf_to_utf8(void) {
#ifdef LOCAL_FILENAME_IS_WCHAR
    struct {
        wchar_t *local;
        char *expected;
    } tests[] = {
        { L"hello world", "hello world" },
        { L"\u00a3" L"100", "\xc2\xa3" "100" },
        { L"\U0001f346.txt", "\xf0\x9f\x8d\x86.txt" },
        { L"😂😂😂", "\xf0\x9f\x98\x82\xf0\x9f\x98\x82\xf0\x9f\x98\x82" },
    };
#else
    /* On Linux a local filename is just a bag of bytes, so
     * ttt_lf_to_utf8() should leave it unchanged unless it happens
     * to be invalid UTF-8. */
    struct {
        char *local;
        char *expected;
    } tests[] = {
        { "hello world", "hello world" },
        { "\xc2\xa3" "100", "\xc2\xa3" "100" },
        { "\xf0\x9f\x8d\x86.txt", "\xf0\x9f\x8d\x86.txt" },
        { "\xf0\x9f\x98\x82\xf0\x9f\x98\x82\xf0\x9f\x98\x82", "\xf0\x9f\x98\x82\xf0\x9f\x98\x82\xf0\x9f\x98\x82" },
        { "\xf0\x9flolwat", "__lolwat" },
    };
#endif

    for (int i = 0; i < sizeof(tests) / sizeof(tests[0]); i++) {
        TTT_LF_CHAR *local = tests[i].local;
        char *expected = tests[i].expected;
        char *observed;

        observed = ttt_lf_to_utf8(local);
        if (strcmp(observed, expected)) {
            fprintf(stderr, "test_ttt_lf_from_utf8(): local \"" TTT_LF_PRINTF "\", expected \"%s\", observed \"%s\"\n",
                    local, expected, observed);
            ttt_dump_hex(observed, strlen(observed), "observed");
            ttt_dump_hex(expected, strlen(expected), "expected");
        }
        CU_ASSERT_STRING_EQUAL(observed, expected);
        free(observed);
    }
}

CU_ErrorCode
ttt_localfs_register_tests(void) {
    CU_TestInfo tests[] = {
        { "ttt_lf_from_utf8", test_ttt_lf_from_utf8 },
        { "ttt_lf_to_utf8", test_ttt_lf_to_utf8 },
        CU_TEST_INFO_NULL
    };

    CU_SuiteInfo suites[] = {
        { "localfs", NULL, NULL, NULL, NULL, tests },
        CU_SUITE_INFO_NULL
    };

    return CU_register_suites(suites);
}

#endif
