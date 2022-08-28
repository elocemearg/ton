#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <errno.h>
#include <error.h>

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
    if (PKCS5_PBKDF2_HMAC_SHA1(secret, secret_len, salt, 8, 1000, sizeof(key), key) != 1) {
        goto fail;
    }

    if (EVP_DecryptInit_ex(ctx, cipher, NULL, key, iv) != 1) {
        goto fail;
    }

    if (dest_max < ciphertext_len + 16) {
        error(0, 0, "ttt_aes_256_cbc_decrypt(): dest_max too small (%zd)!", dest_max);
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
        error(0, 0, "ttt_aes_256_cbc_encrypt: EVP_CIPHER_CTX_new() failed");
        goto fail;
    }

    cipher = EVP_aes_256_cbc();
    if (cipher == NULL) {
        error(0, 0, "ttt_aes_256_cbc_encrypt: EVP_aws_256_cbc() failed");
        goto fail;
    }

    if (ttt_set_random_bytes(salt, sizeof(salt)) || ttt_set_random_bytes(iv, sizeof(iv))) {
        error(0, 0, "ttt_aes_256_cbc_encrypt: RAND_bytes() failed");
        goto fail;
    }

    /* Convert our passphrase into a 32-byte key */
    if (PKCS5_PBKDF2_HMAC_SHA1(secret, secret_len, salt, sizeof(salt), 1000, sizeof(key), key) != 1) {
        error(0, 0, "ttt_aes_256_cbc_encrypt: PKCS5_PBKDF2_HMAC_SHA1() failed");
        goto fail;
    }

    if (EVP_EncryptInit_ex(ctx, cipher, NULL, key, iv) != 1) {
        error(0, 0, "ttt_aes_256_cbc_encrypt: EVP_EncryptInit_ex() failed");
        goto fail;
    }

    /* Check we have enough space for the salt, the initialisation vector,
     * and the maximum size the ciphertext could possibly be, which is the
     * plaintext length plus the maximum padding (1x block size = 16 bytes). */
    if (dest_max < sizeof(salt) + sizeof(iv) + src_len + 16) {
        error(0, 0, "ttt_aes_256_cbc_encrypt(): dest_max (%zd) too small!", dest_max);
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
        error(0, 0, "ttt_aes_256_cbc_encrypt: EVP_EncryptUpdate() failed");
        goto fail;
    }
    dest_ptr += l;

    if (EVP_EncryptFinal(ctx, dest_ptr, &l) != 1) {
        error(0, 0, "ttt_aes_256_cbc_encrypt: EVP_EncryptFinal() failed");
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
    error(0, 0, "openssl: %s", err_buf);
    goto end;
}
