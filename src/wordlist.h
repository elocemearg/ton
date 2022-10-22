#ifndef _TONWORDLIST_H
#define _TONWORDLIST_H

/* Initialise the list of words for use in passphrases. This is called
 * automatically on the first call to ton_wordlist_get_max_word_length(),
 * ton_wordlist_get_word() or ton_wordlist_length() but no protection is
 * provided against concurrent calls by different threads. */
int ton_wordlist_init(void);

/* Free word list resources created by ton_wordlist_init(). This is only
 * really useful just before exiting the program, and then only to avoid
 * memcheck flagging it as a memory leak. */
void ton_wordlist_free(void);

/* Return the length of the longest word in the list, in bytes. */
size_t ton_wordlist_get_max_word_length(void);

/* Return a pointer to the word at index n. This will be a pointer to a
 * null-terminated string. If n is less than 0 or not less than
 * ton_wordlist_length(), NULL is returned. */
const char *ton_wordlist_get_word(int n);

/* Return the number of words in the list. */
size_t ton_wordlist_length(void);

#endif
