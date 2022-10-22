#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>

#include "wordlist.h"

/* Interface to the word list we use for generating random passphrases. */

/* These two symbols are given to us by the linker and point to the start and
 * end of wordlist.txt, which is built into the executable. This is just a
 * series of words separated by newlines. */
extern const char _binary_src_wordlist_txt_start[];
extern const char _binary_src_wordlist_txt_end[];

/* ton_wordlist_init() derives the values of the following: */

/* The contents of wordlist.txt, lowercased, with '\n' replaced with '\0'.
 * The length is inferred from the difference between the start and end
 * symbols above. */
static char *words_string_data = NULL;

/* An array of strings, each containing one word. There are num_words pointers.
 * Each pointer points to the start of a word in words_string_data. */
static const char **words = NULL;

/* The number of entries in words[]. */
static size_t num_words = 0;

/* The length of the longest word. */
static size_t max_word_length = 0;

void
ton_wordlist_free(void) {
    free(words_string_data);
    free(words);
    num_words = 0;
    max_word_length = 0;
    words_string_data = NULL;
    words = NULL;
}

int
ton_wordlist_init(void) {
    /* If words != NULL then we've already initialised, and this is a no-op. */

    if (words == NULL) {
        const char *rptr;
        char *wptr;

        if (_binary_src_wordlist_txt_start == _binary_src_wordlist_txt_end) {
            /* wordlist.txt has zero length? */
            fprintf(stderr, "ton_wordlist_init(): word list has zero length!\n");
            return -1;
        }

        /* Allocate space equal to the size of wordlist.txt + 1 */
        words_string_data = malloc(1 + _binary_src_wordlist_txt_end - _binary_src_wordlist_txt_start);
        if (words_string_data == NULL) {
            fprintf(stderr, "ton_wordlist_init(): out of memory\n");
            goto fail;
        }

        /* Make a copy of the wordlist.txt file which is compiled into the
         * binary, but with every '\n' replaced with '\0' and with every
         * letter lowercased. */
        num_words = 0;
        wptr = words_string_data;
        for (rptr = _binary_src_wordlist_txt_start; rptr < _binary_src_wordlist_txt_end; rptr++) {
            if (*rptr == '\n') {
                *wptr = '\0';
                num_words++;
            }
            else {
                *wptr = tolower(*rptr);
            }
            wptr++;
        }

        /* If there was no newline on the end, still terminate the last word
         * with '\0'. */
        if (wptr[-1] != '\0') {
            *wptr = '\0';
            num_words++;
        }

        /* Make an array of strings... */
        words = malloc(sizeof(char *) * num_words);
        if (words == NULL) {
            fprintf(stderr, "ton_wordlist_init(): out of memory\n");
            goto fail;
        }

        /* ... each of which points to a word in words_string_data. */
        rptr = words_string_data;
        for (size_t i = 0; i < num_words; i++) {
            size_t len;
            words[i] = rptr;
            len = strlen(rptr);
            if (len > max_word_length) {
                max_word_length = len;
            }
            rptr += len + 1;
        }
    }

    return 0;

fail:
    ton_wordlist_free();
    return -1;
}

size_t
ton_wordlist_get_max_word_length(void) {
    if (ton_wordlist_init() != 0) {
        fprintf(stderr, "ton: failed to initialise word list\n");
        exit(1);
    }
    return max_word_length;
}

const char *
ton_wordlist_get_word(int n) {
    if (ton_wordlist_init() != 0) {
        fprintf(stderr, "ton: failed to initialise word list\n");
        exit(1);
    }
    if (n < 0 || n >= num_words) {
        return NULL;
    }
    else {
        return words[n];
    }
}

size_t
ton_wordlist_length(void) {
    if (ton_wordlist_init() != 0) {
        fprintf(stderr, "ton: failed to initialise word list\n");
        exit(1);
    }
    return num_words;
}
