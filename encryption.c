#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <errno.h>

#ifdef UNIX
#include <termios.h>
#endif

#include "encryption.h"
#include "wordlist.h"
#include "utils.h"

int
ton_passphrase_to_key(const char *passphrase, size_t passphrase_len,
        const unsigned char *salt, size_t salt_len, unsigned char *key_dest,
        size_t key_dest_size) {
    if (PKCS5_PBKDF2_HMAC_SHA1(passphrase, passphrase_len, salt, salt_len, 1000, key_dest_size, key_dest) != 1) {
        ton_error(0, 0, "ton_aes_256_cbc_encrypt: PKCS5_PBKDF2_HMAC_SHA1() failed");
        return -1;
    }
    return 0;
}

int
ton_aes_256_cbc_decrypt(const char *src, size_t src_len, char *dest,
        size_t dest_max, const char *secret, size_t secret_len,
        unsigned char *salt_ret /* pointer to 8 bytes */) {
    EVP_CIPHER_CTX *ctx = NULL;
    const EVP_CIPHER *cipher = NULL;
    const unsigned char *iv, *salt;
    const unsigned char *ciphertext;
    unsigned char key[TON_KEY_SIZE];
    unsigned char *dest_ptr;
    int ciphertext_len;
    int l;
    int rc = 0;

    /* Message begins with the salt and the IV */
    if (src_len < 24) {
        goto fail;
    }
    salt = (const unsigned char *) src;
    iv = (const unsigned char *) src + 8;

    if (salt_ret != NULL)
        memcpy(salt_ret, salt, 8);

    ciphertext = (const unsigned char *) src + 24;
    ciphertext_len = src_len - 24;

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        goto fail;
    }

    cipher = EVP_aes_256_cbc();
    if (cipher == NULL) {
        goto fail;
    }

    /* Convert the passphrase into a key of TON_KEY_SIZE bytes */
    if (ton_passphrase_to_key(secret, secret_len, salt, 8, key, sizeof(key)) < 0) {
        goto fail;
    }

    if (EVP_DecryptInit_ex(ctx, cipher, NULL, key, iv) != 1) {
        goto fail;
    }

    if (dest_max < ciphertext_len + 16) {
        ton_error(0, 0, "ton_aes_256_cbc_decrypt(): dest_max too small (%zd)!", dest_max);
        goto fail;
    }

    dest_ptr = (unsigned char *) dest;
    if (EVP_DecryptUpdate(ctx, dest_ptr, &l, ciphertext, ciphertext_len) != 1) {
        goto fail;
    }
    dest_ptr += l;

    if (EVP_DecryptFinal_ex(ctx, dest_ptr, &l) != 1) {
        goto fail;
    }
    dest_ptr += l;

    rc = dest_ptr - (unsigned char *) dest;
end:
    EVP_CIPHER_CTX_free(ctx);
    return rc;

fail:
    rc = -1;
    goto end;
}

int
ton_set_random_bytes(char *dest, size_t length) {
    if (RAND_bytes((unsigned char *) dest, length) != 1)
        return -1;
    else
        return 0;
}

int
ton_aes_256_cbc_encrypt(const char *src, size_t src_len, char *dest,
        size_t dest_max, const char *secret, size_t secret_len,
        const unsigned char *salt /* 8 bytes */) {
    EVP_CIPHER_CTX *ctx = NULL;
    const EVP_CIPHER *cipher = NULL;
    unsigned char key[TON_KEY_SIZE], iv[16];
    unsigned char *dest_ptr;
    const size_t salt_len = 8;
    char err_buf[256];
    int rc = 0;
    int l;

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        ton_error(0, 0, "ton_aes_256_cbc_encrypt: EVP_CIPHER_CTX_new() failed");
        goto fail;
    }

    cipher = EVP_aes_256_cbc();
    if (cipher == NULL) {
        ton_error(0, 0, "ton_aes_256_cbc_encrypt: EVP_aws_256_cbc() failed");
        goto fail;
    }

    if (ton_set_random_bytes((char *) iv, sizeof(iv))) {
        ton_error(0, 0, "ton_aes_256_cbc_encrypt: RAND_bytes() failed");
        goto fail;
    }

    /* Convert our passphrase into a key of TON_KEY_SIZE bytes */
    if (ton_passphrase_to_key(secret, secret_len, salt, salt_len, key, sizeof(key)) < 0) {
        goto fail;
    }

    if (EVP_EncryptInit_ex(ctx, cipher, NULL, key, iv) != 1) {
        ton_error(0, 0, "ton_aes_256_cbc_encrypt: EVP_EncryptInit_ex() failed");
        goto fail;
    }

    /* Check we have enough space for the salt, the initialisation vector,
     * and the maximum size the ciphertext could possibly be, which is the
     * plaintext length plus the maximum padding (1x block size = 16 bytes). */
    if (dest_max < salt_len + sizeof(iv) + src_len + 16) {
        ton_error(0, 0, "ton_aes_256_cbc_encrypt(): dest_max (%zd) too small!", dest_max);
        goto fail;
    }

    /* Write the 8-byte salt followed by the 16-byte IV to dest, because the
     * decryption will need these. */
    dest_ptr = (unsigned char *) dest;
    memcpy(dest_ptr, salt, salt_len);
    dest_ptr += salt_len;
    memcpy(dest_ptr, iv, sizeof(iv));
    dest_ptr += sizeof(iv);

    /* Now write the encrypted data after that. */
    if (EVP_EncryptUpdate(ctx, dest_ptr, &l, (const unsigned char *) src, src_len) != 1) {
        ton_error(0, 0, "ton_aes_256_cbc_encrypt: EVP_EncryptUpdate() failed");
        goto fail;
    }
    dest_ptr += l;

    if (EVP_EncryptFinal(ctx, dest_ptr, &l) != 1) {
        ton_error(0, 0, "ton_aes_256_cbc_encrypt: EVP_EncryptFinal() failed");
        goto fail;
    }
    dest_ptr += l;
    l = dest_ptr - (unsigned char *) dest;

    /* Return number of bytes written to dest */
    rc = l;

end:
    EVP_CIPHER_CTX_free(ctx);
    return rc;

fail:
    rc = -1;
    ERR_error_string_n(ERR_get_error(), err_buf, sizeof(err_buf));
    ton_error(0, 0, "openssl: %s", err_buf);
    goto end;
}

int
ton_secure_randint(int max) {
    union {
	    uint64_t n;
		unsigned char s[8];
    } u;
    max = abs(max);

    if (RAND_bytes(u.s, sizeof(u.n)) != 1) {
        ton_error(1, 0, "RAND_bytes failed!");
	}
	return (int) (u.n % max);
}


char *
ton_generate_passphrase(int num_words) {
    int pos = 0;
    char *passphrase = malloc((ton_wordlist_get_max_word_length() + 1) * num_words);

    if (passphrase == NULL)
        return NULL;

    for (int i = 0; i < num_words; ++i) {
        int n = ton_secure_randint(ton_wordlist_length());
        const char *word = ton_wordlist_get_word(n);
        if (i > 0)
            passphrase[pos++] = ' ';
        strcpy(passphrase + pos, word);
        pos += strlen(word);
    }
    return passphrase;
}

char *
ton_prompt_passphrase(const char *prompt, bool hide_passphrase) {
    int c;
    int buf_size = 80;
    int buf_pos = 0;
    char *buf = malloc(buf_size);
#ifdef UNIX
    struct termios t;
#endif

    fprintf(stderr, "%s", prompt);

#ifdef UNIX
    if (hide_passphrase) {
        /* Switch off terminal echo */
        if (tcgetattr(0, &t) < 0) {
            ton_error(0, errno, "tcgetattr");
            goto fail;
        }
        t.c_lflag &= ~ECHO;
        if (tcsetattr(0, TCSANOW, &t) < 0) {
            ton_error(0, errno, "tcsetattr");
            goto fail;
        }
    }
#endif

    /* Read a single line */
    while ((c = fgetc(stdin)) != '\n' && c != EOF) {
        if (c != '\r') {
            buf[buf_pos++] = (char) c;
            if (buf_pos >= buf_size) {
                char *new_buf = realloc(buf, buf_size *= 2);
                if (new_buf == NULL) {
                    ton_error(0, errno, "realloc");
                    goto fail;
                }
                buf = new_buf;
            }
        }
    }
    buf[buf_pos] = '\0';

end:
#ifdef UNIX
    if (hide_passphrase) {
        /* Switch terminal echo back on */
        t.c_lflag |= ECHO;
        if (tcsetattr(0, TCSANOW, &t) < 0) {
            ton_error(0, errno, "tcsetattr");
            goto fail;
        }

        /* Echo the newline */
        putchar('\n');
    }
#endif

    /* Return the newly allocated line */
    return buf;

fail:
    free(buf);
    buf = NULL;
    goto end;
}
