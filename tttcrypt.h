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

#endif
