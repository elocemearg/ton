#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <errno.h>

#ifdef UNIX
#include <termios.h>
#endif

#include "wordlist.h"
#include "utils.h"

int
ttt_passphrase_to_key(const char *passphrase, size_t passphrase_len,
        const unsigned char *salt, size_t salt_len, unsigned char *key_dest,
        size_t key_dest_size) {
    if (PKCS5_PBKDF2_HMAC_SHA1(passphrase, passphrase_len, salt, salt_len, 1000, key_dest_size, key_dest) != 1) {
        ttt_error(0, 0, "ttt_aes_256_cbc_encrypt: PKCS5_PBKDF2_HMAC_SHA1() failed");
        return -1;
    }
    return 0;
}

int
ttt_aes_256_cbc_decrypt(const char *src, size_t src_len, char *dest,
        size_t dest_max, const char *secret, size_t secret_len) {
    EVP_CIPHER_CTX *ctx = NULL;
    const EVP_CIPHER *cipher = NULL;
    const unsigned char *iv, *salt;
    const unsigned char *ciphertext;
    unsigned char key[32];
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

    /* Convert the passphrase into a 32-byte key */
    if (ttt_passphrase_to_key(secret, secret_len, salt, 8, key, sizeof(key)) < 0) {
        goto fail;
    }

    if (EVP_DecryptInit_ex(ctx, cipher, NULL, key, iv) != 1) {
        goto fail;
    }

    if (dest_max < ciphertext_len + 16) {
        ttt_error(0, 0, "ttt_aes_256_cbc_decrypt(): dest_max too small (%zd)!", dest_max);
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
ttt_set_random_bytes(unsigned char *dest, size_t length) {
    if (RAND_bytes(dest, length) != 1)
        return -1;
    else
        return 0;
}

int
ttt_aes_256_cbc_encrypt(const char *src, size_t src_len, char *dest,
        size_t dest_max, const char *secret, size_t secret_len) {
    EVP_CIPHER_CTX *ctx = NULL;
    const EVP_CIPHER *cipher = NULL;
    unsigned char key[32], iv[16];
    unsigned char salt[8];
    unsigned char *dest_ptr;
    char err_buf[256];
    int rc = 0;
    int l;

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        ttt_error(0, 0, "ttt_aes_256_cbc_encrypt: EVP_CIPHER_CTX_new() failed");
        goto fail;
    }

    cipher = EVP_aes_256_cbc();
    if (cipher == NULL) {
        ttt_error(0, 0, "ttt_aes_256_cbc_encrypt: EVP_aws_256_cbc() failed");
        goto fail;
    }

    if (ttt_set_random_bytes(salt, sizeof(salt)) || ttt_set_random_bytes(iv, sizeof(iv))) {
        ttt_error(0, 0, "ttt_aes_256_cbc_encrypt: RAND_bytes() failed");
        goto fail;
    }

    /* Convert our passphrase into a 32-byte key */
    if (ttt_passphrase_to_key(secret, secret_len, salt, sizeof(salt), key, sizeof(key)) < 0) {
        goto fail;
    }

    if (EVP_EncryptInit_ex(ctx, cipher, NULL, key, iv) != 1) {
        ttt_error(0, 0, "ttt_aes_256_cbc_encrypt: EVP_EncryptInit_ex() failed");
        goto fail;
    }

    /* Check we have enough space for the salt, the initialisation vector,
     * and the maximum size the ciphertext could possibly be, which is the
     * plaintext length plus the maximum padding (1x block size = 16 bytes). */
    if (dest_max < sizeof(salt) + sizeof(iv) + src_len + 16) {
        ttt_error(0, 0, "ttt_aes_256_cbc_encrypt(): dest_max (%zd) too small!", dest_max);
        goto fail;
    }

    /* Write the 8-byte salt followed by the 16-byte IV to dest, because the
     * decryption will need these. */
    dest_ptr = (unsigned char *) dest;
    memcpy(dest_ptr, salt, sizeof(salt));
    dest_ptr += sizeof(salt);
    memcpy(dest_ptr, iv, sizeof(iv));
    dest_ptr += sizeof(iv);

    /* Now write the encrypted data after that. */
    if (EVP_EncryptUpdate(ctx, dest_ptr, &l, (const unsigned char *) src, src_len) != 1) {
        ttt_error(0, 0, "ttt_aes_256_cbc_encrypt: EVP_EncryptUpdate() failed");
        goto fail;
    }
    dest_ptr += l;

    if (EVP_EncryptFinal(ctx, dest_ptr, &l) != 1) {
        ttt_error(0, 0, "ttt_aes_256_cbc_encrypt: EVP_EncryptFinal() failed");
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
    ttt_error(0, 0, "openssl: %s", err_buf);
    goto end;
}

int
ttt_secure_randint(int max) {
    union {
	    uint64_t n;
		unsigned char s[8];
    } u;
    max = abs(max);

    if (RAND_bytes(u.s, sizeof(u.n)) != 1) {
        ttt_error(1, 0, "RAND_bytes failed!");
	}
	return (int) (u.n % max);
}


char *
ttt_generate_passphrase(int num_words) {
    int pos = 0;
    char *passphrase = malloc((ttt_wordlist_get_max_word_length() + 1) * num_words);

    if (passphrase == NULL)
        return NULL;

    for (int i = 0; i < num_words; ++i) {
        int n = ttt_secure_randint(ttt_wordlist_length());
        const char *word = ttt_wordlist_get_word(n);
        if (i > 0)
            passphrase[pos++] = ' ';
        strcpy(passphrase + pos, word);
        pos += strlen(word);
    }
    return passphrase;
}

char *
ttt_prompt_passphrase(const char *prompt) {
    int c;
    int buf_size = 80;
    int buf_pos = 0;
    char *buf = malloc(buf_size);
#ifdef UNIX
    struct termios t;
#endif

    fprintf(stderr, "%s", prompt);

#ifdef UNIX
    /* Switch off terminal echo */
    if (tcgetattr(0, &t) < 0) {
        ttt_error(0, errno, "tcgetattr");
        goto fail;
    }
    t.c_lflag &= ~ECHO;
    if (tcsetattr(0, TCSANOW, &t) < 0) {
        ttt_error(0, errno, "tcsetattr");
        goto fail;
    }
#endif

    /* Read a single line */
    while ((c = fgetc(stdin)) != '\n' && c != EOF) {
        if (c != '\r') {
            buf[buf_pos++] = (char) c;
            if (buf_pos >= buf_size) {
                char *new_buf = realloc(buf, buf_size *= 2);
                if (new_buf == NULL) {
                    ttt_error(0, errno, "realloc");
                    goto fail;
                }
                buf = new_buf;
            }
        }
    }
    buf[buf_pos] = '\0';

end:
#ifdef UNIX
    /* Switch terminal echo back on */
    t.c_lflag |= ECHO;
    if (tcsetattr(0, TCSANOW, &t) < 0) {
        ttt_error(0, errno, "tcsetattr");
        goto fail;
    }
#endif

    /* Echo the newline */
    putchar('\n');

    /* Return the newly allocated line */
    return buf;

fail:
    free(buf);
    buf = NULL;
    goto end;
}
