#ifndef _TTTCRYPT_H
#define _TTTCRYPT_H

int
ttt_aes_256_cbc_decrypt(const char *src, size_t src_len, char *dest,
        size_t dest_max, const char *secret, size_t secret_len);

int
ttt_aes_256_cbc_encrypt(const char *src, size_t src_len, char *dest,
        size_t dest_max, const char *secret, size_t secret_len);

int
ttt_set_random_bytes(char *dest, size_t length);

/* Use OpenSSL's RAND_bytes to generate and return a random integer between 0
 * and max - 1 inclusive. exit(1) if we fail to do this. */
int
ttt_secure_randint(int max);

int
ttt_passphrase_to_key(const char *passphrase, size_t passphrase_len,
        unsigned char *salt, size_t salt_len, unsigned char *key_dest,
        size_t key_dest_size);

#endif
