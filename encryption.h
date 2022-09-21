#ifndef _TONCRYPT_H
#define _TONCRYPT_H

#include <stdbool.h>

#define TON_KEY_SIZE 32

int
ton_aes_256_cbc_decrypt(const char *src, size_t src_len, char *dest,
        size_t dest_max, const char *secret, size_t secret_len,
        unsigned char *salt /* pointer to 8 bytes */);

int
ton_aes_256_cbc_encrypt(const char *src, size_t src_len, char *dest,
        size_t dest_max, const char *secret, size_t secret_len,
        const unsigned char *salt /* pointer to 8 bytes */);

int
ton_set_random_bytes(char *dest, size_t length);

/* Use OpenSSL's RAND_bytes to generate and return a random integer between 0
 * and max - 1 inclusive. exit(1) if we fail to do this. */
int
ton_secure_randint(int max);

int
ton_passphrase_to_key(const char *passphrase, size_t passphrase_len,
        const unsigned char *salt, size_t salt_len, unsigned char *key_dest,
        size_t key_dest_size);

char *
ton_prompt_passphrase(const char *prompt, bool hide_passphrase);

char *
ton_generate_passphrase(int num_words);

#endif
