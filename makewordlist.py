#!/usr/bin/python3

import sys

word_list_filename = sys.argv[1]

print("""
#include <stdlib.h>
#include "tttwordlist.h"

static const char *words[] = {""")

num_words = 0
max_length = 0

with open(word_list_filename) as f:
    for line in f:
        word = line.strip().lower()
        if word:
            print("\t\"" + word + "\",")
            num_words += 1
            if len(word) > max_length:
                max_length = len(word)

print("""};

static const int num_words = %d;
static const int max_word_length = %d;
""" % (num_words, max_length))

print("""
int ttt_wordlist_get_max_word_length(void) {
    return max_word_length;
}

const char *ttt_wordlist_get_word(int n) {
    if (n < 0 || n >= num_words) {
        return NULL;
    }
    else {
        return words[n];
    }
}

int ttt_wordlist_length(void) {
    return num_words;
}
""")
