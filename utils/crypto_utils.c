#include "utils.h"

void process_public_key(char *received_key_str, RSA **client_public_key) {
    BIO *bio = BIO_new_mem_buf(received_key_str, -1);

    *client_public_key = PEM_read_bio_RSAPublicKey(bio, NULL, NULL, NULL);
    BIO_free(bio);

    if (!*client_public_key) {
        fprintf(stderr, "Error reconstructing public key\n");
        exit(EXIT_FAILURE);
    }
}

unsigned char *generate_aes_key(size_t key_size) {
    unsigned char *key = malloc(key_size);
    if (!key || !RAND_bytes(key, key_size)) {
        fprintf(stderr, "Error generating AES key\n");
        exit(EXIT_FAILURE);
    }
    return key;
}

char *bytes_to_base64_encode(const unsigned char *data, size_t len) {
    BIO *b64 = BIO_new(BIO_f_base64());
    BIO *bio = BIO_new(BIO_s_mem());
    b64 = BIO_push(b64, bio);

    BIO_write(b64, data, len);
    BIO_flush(b64);

    BUF_MEM *bptr;
    BIO_get_mem_ptr(b64, &bptr);

    char *b64_encoded = malloc(bptr->length + 1);
    memcpy(b64_encoded, bptr->data, bptr->length);
    b64_encoded[bptr->length] = '\0';

    BIO_free_all(b64);
    return b64_encoded;
}

unsigned char *base64_to_bytes_decode(const char *b64_data, size_t *out_len) {
    char *sanitized_b64 = sanitize_base64(b64_data);
    if (!sanitized_b64) {
        fprintf(stderr, "Sanitization failed\n");
        return NULL;
    }

    BIO *b64 = BIO_new(BIO_f_base64());
    BIO *bio = BIO_new_mem_buf(sanitized_b64, -1);
    b64 = BIO_push(b64, bio);

    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);

    size_t max_decoded_len = strlen(sanitized_b64) * 3 / 4;
    unsigned char *decoded_data = malloc(max_decoded_len);
    if (!decoded_data) {
        fprintf(stderr, "Memory allocation failed\n");
        BIO_free_all(b64);
        free(sanitized_b64);
        return NULL;
    }

    int decoded_len = BIO_read(b64, decoded_data, max_decoded_len);
    if (decoded_len < 0) {
        fprintf(stderr, "Base64 decoding failed\n");
        free(decoded_data);
        BIO_free_all(b64);
        free(sanitized_b64);
        return NULL;
    }

    *out_len = decoded_len;

    BIO_free_all(b64);
    free(sanitized_b64);

    return decoded_data;
}

char *sanitize_base64(const char *input) {
    size_t len = strlen(input);
    char *sanitized = malloc(len + 1);
    if (!sanitized) {
        fprintf(stderr, "Memory allocation failed\n");
        return NULL;
    }
    size_t j = 0;
    for (size_t i = 0; i < len; i++) {
        if (input[i] != '\n' && input[i] != '\r' && input[i] != ' ') {
            sanitized[j++] = input[i];
        }
    }
    sanitized[j] = '\0';
    return sanitized;
}

unsigned char* decrypt_aes_key(RSA* rsa_private_key, const char* encrypted_aes_key_str) {
    if (!rsa_private_key || !encrypted_aes_key_str) {
        fprintf(stderr, "Invalid input to decrypt_aes_key\n");
        return NULL;
    }

    size_t encrypted_len;
    unsigned char* encrypted_aes_key = base64_to_bytes_decode(encrypted_aes_key_str, &encrypted_len);
    if (!encrypted_aes_key) {
        fprintf(stderr, "Failed to decode encrypted AES key from Base64\n");
        return NULL;
    }

    size_t rsa_size = RSA_size(rsa_private_key);
    unsigned char* decrypted_aes_key = malloc(rsa_size);
    if (!decrypted_aes_key) {
        fprintf(stderr, "Failed to allocate memory for decrypted AES key\n");
        free(encrypted_aes_key);
        return NULL;
    }

    int result = RSA_private_decrypt(
        encrypted_len,
        encrypted_aes_key,
        decrypted_aes_key,
        rsa_private_key,
        RSA_PKCS1_OAEP_PADDING
    );

    free(encrypted_aes_key);

    if (result == -1) {
        fprintf(stderr, "Error decrypting AES key: %s\n", ERR_error_string(ERR_get_error(), NULL));
        free(decrypted_aes_key);
        return NULL;
    }

    return decrypted_aes_key;
}

char* encrypt_with_aes(const char* plaintext, const unsigned char* aes_key, const unsigned char* iv) {
    if (!plaintext) {
        fprintf(stderr, "plaintext invalid\n");
        return NULL;
    }
    if (!aes_key) {
        fprintf(stderr, "aes_key invalid\n");
        return NULL;
    }
    if (!iv) {
        fprintf(stderr, "iv invalid\n");
        return NULL;
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        fprintf(stderr, "Error creating encryption context\n");
        return NULL;
    }

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, aes_key, iv) != 1) {
        fprintf(stderr, "Error initializing encryption\n");
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }

    int plaintext_len = strlen(plaintext);
    int ciphertext_len = plaintext_len + AES_BLOCK_SIZE;
    unsigned char* ciphertext = malloc(ciphertext_len);
    if (!ciphertext) {
        fprintf(stderr, "Memory allocation failed for ciphertext\n");
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }

    int len = 0, total_len = 0;
    if (EVP_EncryptUpdate(ctx, ciphertext, &len, (unsigned char*)plaintext, plaintext_len) != 1) {
        fprintf(stderr, "Error encrypting plaintext\n");
        free(ciphertext);
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }
    total_len = len;

    if (EVP_EncryptFinal_ex(ctx, ciphertext + total_len, &len) != 1) {
        fprintf(stderr, "Error finalizing encryption\n");
        free(ciphertext);
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }
    total_len += len;

    BIO* b64 = BIO_new(BIO_f_base64());
    BIO* mem = BIO_new(BIO_s_mem());
    if (!b64 || !mem) {
        fprintf(stderr, "Error creating BIOs\n");
        free(ciphertext);
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }
    b64 = BIO_push(b64, mem);

    if (BIO_write(b64, ciphertext, total_len) <= 0 || BIO_flush(b64) <= 0) {
        fprintf(stderr, "Error during Base64 encoding\n");
        free(ciphertext);
        BIO_free_all(b64);
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }

    BUF_MEM* bptr;
    BIO_get_mem_ptr(b64, &bptr);
    char* encoded_ciphertext = malloc(bptr->length + 1);
    if (!encoded_ciphertext) {
        fprintf(stderr, "Memory allocation failed for encoded ciphertext\n");
        free(ciphertext);
        BIO_free_all(b64);
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }
    memcpy(encoded_ciphertext, bptr->data, bptr->length);
    encoded_ciphertext[bptr->length] = '\0';

    BIO_free_all(b64);
    free(ciphertext);
    EVP_CIPHER_CTX_free(ctx);

    return encoded_ciphertext;
}

char* decrypt_with_aes(const char* encoded_ciphertext, const unsigned char* aes_key, const unsigned char* iv) {
    if (!encoded_ciphertext || !aes_key || !iv) {
        fprintf(stderr, "Invalid input to decrypt_with_aes\n");
        return NULL;
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        fprintf(stderr, "Error creating decryption context\n");
        return NULL;
    }

    BIO* b64 = BIO_new(BIO_f_base64());
    BIO* mem = BIO_new_mem_buf(encoded_ciphertext, -1);
    b64 = BIO_push(b64, mem);

    size_t encoded_len = strlen(encoded_ciphertext);
    unsigned char* ciphertext = malloc(encoded_len);
    if (!ciphertext) {
        fprintf(stderr, "Memory allocation failed for ciphertext\n");
        BIO_free_all(b64);
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }

    int ciphertext_len = BIO_read(b64, ciphertext, encoded_len);
    BIO_free_all(b64);

    if (ciphertext_len <= 0) {
        fprintf(stderr, "Error decoding Base64 ciphertext\n");
        free(ciphertext);
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }

    unsigned char* plaintext = malloc(ciphertext_len + 1);
    if (!plaintext) {
        fprintf(stderr, "Memory allocation failed for plaintext\n");
        free(ciphertext);
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, aes_key, iv) != 1) {
        fprintf(stderr, "Error initializing AES decryption\n");
        free(ciphertext);
        free(plaintext);
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }

    int len = 0, total_len = 0;

    if (EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len) != 1) {
        fprintf(stderr, "Error during AES decryption\n");
        free(ciphertext);
        free(plaintext);
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }
    total_len += len;

    if (EVP_DecryptFinal_ex(ctx, plaintext + total_len, &len) != 1) {
        fprintf(stderr, "Error finalizing AES decryption\n");
        free(ciphertext);
        free(plaintext);
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }
    total_len += len;

    plaintext[total_len] = '\0';

    free(ciphertext);
    EVP_CIPHER_CTX_free(ctx);

    return (char*)plaintext;
}

int aes_encrypt_bytes(const unsigned char *plaintext, size_t plaintext_len,
                      const unsigned char *aes_key, const unsigned char *iv,
                      unsigned char **out_cipher, size_t *out_len) {
    if (!plaintext || !aes_key || !iv || !out_cipher || !out_len) return -1;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    int rc = EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, aes_key, iv);
    if (rc != 1) { EVP_CIPHER_CTX_free(ctx); return -1; }

    int max_len = (int)plaintext_len + AES_BLOCK_SIZE;
    unsigned char *cipher = malloc(max_len);
    if (!cipher) { EVP_CIPHER_CTX_free(ctx); return -1; }

    int len = 0, total = 0;
    rc = EVP_EncryptUpdate(ctx, cipher, &len, plaintext, (int)plaintext_len);
    if (rc != 1) { free(cipher); EVP_CIPHER_CTX_free(ctx); return -1; }
    total = len;

    rc = EVP_EncryptFinal_ex(ctx, cipher + total, &len);
    if (rc != 1) { free(cipher); EVP_CIPHER_CTX_free(ctx); return -1; }
    total += len;

    *out_cipher = cipher;
    *out_len = (size_t)total;
    EVP_CIPHER_CTX_free(ctx);
    return 0;
}

int aes_decrypt_bytes(const unsigned char *cipher, size_t cipher_len,
                      const unsigned char *aes_key, const unsigned char *iv,
                      unsigned char **out_plain, size_t *out_len) {
    if (!cipher || !aes_key || !iv || !out_plain || !out_len) return -1;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    int rc = EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, aes_key, iv);
    if (rc != 1) { EVP_CIPHER_CTX_free(ctx); return -1; }

    unsigned char *plain = malloc(cipher_len + 1);
    if (!plain) { EVP_CIPHER_CTX_free(ctx); return -1; }

    int len = 0, total = 0;
    rc = EVP_DecryptUpdate(ctx, plain, &len, cipher, (int)cipher_len);
    if (rc != 1) { free(plain); EVP_CIPHER_CTX_free(ctx); return -1; }
    total = len;

    rc = EVP_DecryptFinal_ex(ctx, plain + total, &len);
    if (rc != 1) { free(plain); EVP_CIPHER_CTX_free(ctx); return -1; }
    total += len;
    plain[total] = '\0';

    *out_plain = plain;
    *out_len = (size_t)total;
    EVP_CIPHER_CTX_free(ctx);
    return 0;
}
