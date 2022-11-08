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
ton_lf_char_size(void) {
    return sizeof(TON_LF_CHAR);
}

size_t
ton_lf_len(const TON_LF_CHAR *str) {
#ifdef LOCAL_FILENAME_IS_WCHAR
    return wcslen(str);
#else
    return strlen(str);
#endif
}

void
ton_lf_copy(TON_LF_CHAR *dest, const TON_LF_CHAR *src) {
#ifdef LOCAL_FILENAME_IS_WCHAR
    wcscpy(dest, src);
#else
    strcpy(dest, src);
#endif
}

int
ton_lf_casecmp(const TON_LF_CHAR *str1, const TON_LF_CHAR *str2) {
#ifdef LOCAL_FILENAME_IS_WCHAR
    return _wcsicmp(str1, str2);
#else
    return strcasecmp(str1, str2);
#endif
}

int
ton_lf_cmp(const TON_LF_CHAR *str1, const TON_LF_CHAR *str2) {
#ifdef LOCAL_FILENAME_IS_WCHAR
    return wcscmp(str1, str2);
#else
    return strcmp(str1, str2);
#endif
}

TON_LF_CHAR *
ton_lf_dup(const TON_LF_CHAR *str) {
#ifdef LOCAL_FILENAME_IS_WCHAR
    return wcsdup(str);
#else
    return strdup(str);
#endif
}

TON_LF_CHAR *
ton_lf_strrchr(const TON_LF_CHAR *str, TON_LF_CHAR c) {
#ifdef LOCAL_FILENAME_IS_WCHAR
    return wcsrchr(str, c);
#else
    return strrchr(str, c);
#endif
}

TON_DIR_HANDLE
ton_opendir(const TON_LF_CHAR *path) {
#ifdef WINDOWS
    struct ton_dir_handle *handle;
    wchar_t *path_with_wildcard;
    size_t pos;

    handle = malloc(sizeof(struct ton_dir_handle));
    if (handle == NULL)
        return NULL;

    handle->finished = false;

    path_with_wildcard = malloc((wcslen(path) + 3) * sizeof(TON_LF_CHAR));
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
     * ton_opendir() and ton_readdir() is like opendir() and readdir() in that
     * it doesn't return the first entry from ton_opendir(). So we'll store
     * this in "handle" and return it when ton_readdir() is called. */
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

TON_DIR_ENTRY
ton_readdir(TON_DIR_HANDLE handle) {
#ifdef WINDOWS
    if (handle->finished) {
        return NULL;
    }

    /* Take the filename we last read and copy it into handle->entry... */
    wcsncpy(handle->entry.d_name, handle->find_data.cFileName, MAX_PATH);

    /* Now fetch the next entry from FindNextFile() into handle->find_data.
     * If that returns an entry then we'll return it on the next ton_readdir()
     * call. If there are no more entries then the next ton_readdir() call will
     * return NULL. */
    if (FindNextFileW(handle->hFind, &handle->find_data) == 0) {
        DWORD err = GetLastError();
        if (err != ERROR_NO_MORE_FILES) {
            ton_error(0, 0, TON_LF_PRINTF ": failed to read directory", handle->path);
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
ton_closedir(TON_DIR_HANDLE handle) {
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
ton_fopen(const TON_LF_CHAR *path, TON_LF_CHAR *mode) {
#ifdef LOCAL_FILENAME_IS_WCHAR
    return _wfopen(path, mode);
#else
    return fopen(path, mode);
#endif
}

int
ton_stat(const TON_LF_CHAR *path, TON_STAT *st) {
#ifdef WINDOWS
    return _wstat64(path, st);
#else
    return lstat(path, st);
#endif
}

int
ton_unlink(const TON_LF_CHAR *path) {
#ifdef WINDOWS
    return _wunlink(path);
#else
    return unlink(path);
#endif
}

int
ton_mkdir(const TON_LF_CHAR *pathname, int mode) {
#ifdef WINDOWS
    return _wmkdir(pathname);
#else
    return mkdir(pathname, mode);
#endif
}

int
ton_mkdir_parents(const TON_LF_CHAR *pathname_orig, int mode, bool parents_only) {
    size_t pathname_len;
    TON_LF_CHAR *pathname = ton_lf_dup(pathname_orig);
    TON_LF_CHAR *last_dir_sep = NULL;
    int return_value = 0;
    TON_STAT st;

    if (pathname == NULL)
        return -1;

    /* Remove any trailing directory separators from pathname */
    pathname_len = ton_lf_len(pathname);
    while (pathname_len > 0 && pathname[pathname_len - 1] == DIR_SEP)
        pathname[--pathname_len] = '\0';

    /* First, check if this path, (or its parent if parents_only is set),
     * already exists as a directory. If so, there's nothing to do and we
     * don't need to check each component in turn. */
    if (parents_only) {
        last_dir_sep = ton_lf_strrchr(pathname, DIR_SEP);
        if (last_dir_sep) {
            *last_dir_sep = '\0';
        }
    }
    if (ton_stat(pathname, &st) == 0 && S_ISDIR(st.st_mode)) {
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
            if (pathname[pos - 1] == DIR_SEP) {
                /* We already did this one */
                continue;
            }
#ifdef WINDOWS
            if (pathname[pos - 1] == ':') {
                /* Don't try to stat or create "C:" */
                continue;
            }
#endif
            /* Does pathname[0 to pos] exist as a directory? */
            pathname[pos] = '\0';
            if (ton_stat(pathname, &st) < 0 && errno == ENOENT) {
                /* Doesn't exist - create it. */
                if (ton_mkdir(pathname, mode) < 0) {
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
ton_chmod(const TON_LF_CHAR *path, int unix_mode) {
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
ton_chmod(const TON_LF_CHAR *path, mode_t mode) {
    return chmod(path, mode);
}
#endif

int
ton_utime(const TON_LF_CHAR *path, TON_UTIMBUF *timbuf) {
#ifdef LOCAL_FILENAME_IS_WCHAR
    return _wutime(path, timbuf);
#else
    return utime(path, timbuf);
#endif
}

int
ton_access(const TON_LF_CHAR *path, int mode) {
#ifdef LOCAL_FILENAME_IS_WCHAR
    return _waccess(path, mode);
#else
    return access(path, mode);
#endif
}

const TON_LF_CHAR *
ton_lf_basename(const TON_LF_CHAR *path) {
    const TON_LF_CHAR *bn = path + ton_lf_len(path);
    while (bn > path && *bn != DIR_SEP) {
        --bn;
    }
    if (*bn == DIR_SEP) {
        ++bn;
    }
    return bn;
}

#ifndef WINDOWS
static TON_LF_CHAR *
ton_getcwd(void) {
    size_t cwd_size = 100;
    char *cwd = malloc(cwd_size);
    char *ret;
    do {
        ret = getcwd(cwd, cwd_size);
        if (ret == NULL) {
            if (errno == ERANGE) {
                char *new_cwd = realloc(cwd, cwd_size * 2);
                if (new_cwd == NULL) {
                    free(cwd);
                    return NULL;
                }
                cwd = new_cwd;
                cwd_size *= 2;
            }
            else {
                free(cwd);
                return NULL;
            }
        }
    } while (ret == NULL);
    return cwd;
}
#endif

TON_LF_CHAR *
ton_dedotify_path(const TON_LF_CHAR *path) {
#ifdef WINDOWS
    /* On Windows just use _wfullpath() - we don't care about resolving
     * symlinks because we're going to stick our fingers in our ears and
     * pretend there aren't any. */
    return _wfullpath(NULL, path, 0);
#else
    TON_LF_CHAR *ret = NULL;
    int r, w, len, skip_components;

    if (path[0] != DIR_SEP) {
        /* If the path is not absolute, make it absolute. */
        TON_LF_CHAR *cwd = ton_getcwd();
        if (cwd == NULL) {
            goto nomem;
        }
        ret = malloc(ton_lf_len(path) + ton_lf_len(cwd) + 2);
        if (ret == NULL) {
            free(cwd);
            goto nomem;
        }
        sprintf(ret, "%s/%s", cwd, path);
    }
    else {
        /* Make a copy of path and put it in ret. */
        ret = malloc(ton_lf_len(path) + 1);
        if (ret == NULL) {
            goto nomem;
        }
        strcpy(ret, path);
    }

    /* We do the following transformations:
     * Any two or more consecutive DIR_SEP characters get shrunk into one.
     * Any directory component named "." is removed.
     * Any directory component named ".." is removed, and we also remove the
     * previous component. So "/foo/bar/../baz" becomes "/foo/baz".
     *
     * Each transformation can only make the string shorter, not longer. */

    /* Rewrite the string in place, but not writing a DIR_SEP character if
     * that's the last character we wrote. */
    w = 0;
    for (r = 0; ret[r]; r++) {
        if (ret[r] != DIR_SEP || w == 0 || ret[w - 1] != DIR_SEP) {
            ret[w++] = ret[r];
        }
    }
    ret[w] = '\0';

    /* Remove "." components. Note that we made the path absolute so the
     * path will never begin with a dot. */
    w = 0;
    for (r = 0; ret[r]; r++) {
        if (ret[r] == DIR_SEP && ret[r + 1] == '.' && (ret[r + 2] == DIR_SEP || ret[r + 2] == '\0')) {
            /* Skip this directory component. Increment r to point to the dot,
             * then the for loop increment will point it to the next DIR_SEP,
             * which we'll copy. */
            r++;
        }
        else {
            ret[w++] = ret[r];
        }
    }

    /* The above can result in the leading slash getting removed, if for
     * example we have "/." - we want "/" not "". */
    if (r > 0 && w == 0)
        ret[w++] = DIR_SEP;
    ret[w] = '\0';

    /* Remove ".." components. We do this by working backwards from the end.
     * If we see a ".." component, we put NULs over it and increase the count
     * of non-.. components before it that we have to skip. */
    len = strlen(ret);
    skip_components = 0;
    w = len;
    while (w > 0) {
        /* ret[w] points to the character after a directory component */
        if (w >= 2 && ret[w - 1] == '.' && ret[w - 2] == '.' &&
                (w == 2 || ret[w - 3] == DIR_SEP)) {
            skip_components++;
            w -= 2;
            memset(&ret[w], '\0', 3);
            w--;
        }
        else {
            /* w points to a directory separator or end of string */
            int comp_start;
            for (comp_start = w - 1; comp_start >= 0 && ret[comp_start] != DIR_SEP; comp_start--);
            comp_start++;
            if (skip_components > 0) {
                memset(&ret[comp_start], '\0', 1 + w - comp_start);
                skip_components--;
            }
            w = comp_start;
            if (w > 0)
                w--;
        }
    }

    /* Now remove all '\0' characters from the string, of which we know the
     * real length. */
    r = 0;
    w = 0;
    for (r = 0; r < len; r++) {
        if (ret[r] != '\0')
            ret[w++] = ret[r];
    }
    ret[w] = '\0';

    return ret;

nomem:
    free(ret);
    return NULL;
#endif
}

#ifndef WINDOWS
char *
ton_get_symlink_target(TON_LF_CHAR *symlink_path) {
    char *target = NULL;
    size_t target_size = 0;
    const size_t target_initial_size = 50;
    const size_t target_max_size = 10000;
    ssize_t ret;

    do {
        /* If target_size is 0 then set it to an initial value, otherwise
         * double it from what it was last time. */
        char *new_target;
        if (target_size == 0) {
            target_size = target_initial_size;
        }
        else if (target_size >= target_max_size) {
            errno = E2BIG;
            goto fail;
        }
        else {
            target_size *= 2;
        }
        new_target = realloc(target, target_size);
        if (new_target == NULL) {
            goto fail;
        }
        target = new_target;

        /* Read the symlink target. If the return value is target_size or more
         * then truncation may have occurred, and we need to try again with a
         * larger buffer. */
        ret = readlink(symlink_path, target, target_size);
        if (ret < 0) {
            goto fail;
        }
        else if (ret < target_size) {
            target[ret] = '\0';
        }
    } while (ret >= target_size);

    return target;

fail:
    free(target);
    return NULL;
}
#endif


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
ton_lf_to_utf8(const TON_LF_CHAR *filename) {
#ifdef LOCAL_FILENAME_IS_WCHAR
    char *out;
    const wchar_t *in = filename;
    char *outp;

    /* Maximum space needed is four bytes per character, plus '\0' */
    out = malloc(ton_lf_len(filename) * 4 + 1);
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

TON_LF_CHAR *
ton_lf_from_utf8(const char *filename) {
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

TON_LF_CHAR *
ton_lf_from_locale(const char *filename) {
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

#ifdef TON_UNIT_TESTS

#include <CUnit/CUnit.h>

static void
test_ton_dedotify_path(void) {
#ifndef LOCAL_FILENAME_IS_WCHAR
    struct {
        char *path;
        char *expected;
    } tests[] = {
        { "/foo/bar/baz/", "/foo/bar/baz/" },
        { "/foo/./bar/./baz", "/foo/bar/baz" },
        { "/foo/././././/////bar///baz", "/foo/bar/baz" },
        { "/foo/bar/baz/.", "/foo/bar/baz" },
        { "/.", "/" },
        { "///.///", "/" },
        { "/foo/bar/../baz", "/foo/baz" },
        { "/one/two/../three/four/../five/../..", "/one/" },
        { "/one/two/../../../", "/" },
        { "/one/two/three/.././../four/five/six/seven/.././..", "/one/four/five/" },
        { "/..", "/" },
        { "/../", "/" },
        { "/one/../two/../three/../four/five/six", "/four/five/six" },
        { "/one/two/three/four/five/six/seven/eight/../nine/./ten/../../../../../", "/one/two/three/four/" },
        { "/one/two/three/four//../five/six/../../..//myfile.txt", "/one/two/myfile.txt" },
    };

    for (int i = 0; i < sizeof(tests) / sizeof(tests[0]); i++) {
        char *input_path = tests[i].path;
        char *expected = tests[i].expected;
        char *observed;

        observed = ton_dedotify_path(input_path);
        if (strcmp(observed, expected)) {
            fprintf(stderr, "test_ton_dedotify_path(): input path \"%s\", expected \"%s\", observed \"%s\"\n",
                    input_path, expected, observed);
            CU_FAIL("output not as expected");
        }
        free(observed);
    }
#endif
}

static void
test_ton_lf_from_utf8(void) {
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

        observed = ton_lf_from_utf8(utf8);
        if (wcscmp(observed, expected)) {
            fprintf(stderr, "test_ton_lf_from_utf8(): utf8 \"%s\", expected \"%ls\", observed \"%ls\"\n",
                    utf8, expected, observed);
            CU_FAIL("output not as expected");
        }
        free(observed);
    }

    /* If LOCAL_FILENAME_IS_WCHAR is not defined, then
     * ton_lf_from_utf8() is just strdup(). */
#endif
}

static void
test_ton_lf_to_utf8(void) {
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
     * ton_lf_to_utf8() should leave it unchanged unless it happens
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
        TON_LF_CHAR *local = tests[i].local;
        char *expected = tests[i].expected;
        char *observed;

        observed = ton_lf_to_utf8(local);
        if (strcmp(observed, expected)) {
            fprintf(stderr, "test_ton_lf_from_utf8(): local \"" TON_LF_PRINTF "\", expected \"%s\", observed \"%s\"\n",
                    local, expected, observed);
            ton_dump_hex(observed, strlen(observed), "observed");
            ton_dump_hex(expected, strlen(expected), "expected");
        }
        CU_ASSERT_STRING_EQUAL(observed, expected);
        free(observed);
    }
}

CU_ErrorCode
ton_localfs_register_tests(void) {
    CU_TestInfo tests[] = {
        { "ton_lf_from_utf8", test_ton_lf_from_utf8 },
        { "ton_lf_to_utf8", test_ton_lf_to_utf8 },
        { "ton_dedotify_path", test_ton_dedotify_path },
        CU_TEST_INFO_NULL
    };

    CU_SuiteInfo suites[] = {
        { "localfs", NULL, NULL, NULL, NULL, tests },
        CU_SUITE_INFO_NULL
    };

    return CU_register_suites(suites);
}

#endif
