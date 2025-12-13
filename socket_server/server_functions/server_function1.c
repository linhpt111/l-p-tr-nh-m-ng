#include "server_function1.h"

void manage_encryption_info(SecurityKeys *keys){
    if (!file_exists(RSA_PRI_KEY_PATH) || !file_exists(RSA_PUB_KEY_PATH)){
        write_rsa_keys();
    }

    load_keys(keys);

    if(!keys->private_key || !keys->public_key){
        LOG_ERROR("Error loading [ private / public ] key");
        exit(EXIT_FAILURE);
    }
}

void write_rsa_keys(){
    RSA *rsa = RSA_new();
    BIGNUM *bn = BN_new();

    // Set the public exponent (common value: 65537)
    if (!BN_set_word(bn, RSA_F4)) {
        fprintf(stderr, "Error setting public exponent\n");
        exit(EXIT_FAILURE);
    }

    // Generate RSA key pair (2048-bit)
    if (!RSA_generate_key_ex(rsa, 2048, bn, NULL)) {
        fprintf(stderr, "Error generating RSA keys\n");
        exit(EXIT_FAILURE);
    }

    FILE *private_fp = fopen(RSA_PRI_KEY_PATH, "w");
    if (!private_fp) {
        perror("Failed to open private key file");
        exit(EXIT_FAILURE);
    }
    PEM_write_RSAPrivateKey(private_fp, rsa, NULL, NULL, 0, NULL, NULL);
    fclose(private_fp);

    FILE *public_fp = fopen(RSA_PUB_KEY_PATH, "w");
    if (!public_fp) {
        perror("Failed to open public key file");
        exit(EXIT_FAILURE);
    }
    PEM_write_RSAPublicKey(public_fp, rsa);
    fclose(public_fp);

    printf("RSA keys generated and saved successfully.\n");

    RSA_free(rsa);
    BN_free(bn);
}


void load_keys(SecurityKeys *keys){
    FILE *private_file_ptr;
    FILE *public_file_ptr;
    RSA *public_key;

    private_file_ptr = fopen(RSA_PRI_KEY_PATH, "r");
    public_file_ptr = fopen(RSA_PUB_KEY_PATH, "r");

    if (!private_file_ptr || !public_file_ptr){
        LOG_ERROR("Failed to open private / public file");
        exit(EXIT_FAILURE);
    }

    keys->private_key = PEM_read_RSAPrivateKey(private_file_ptr, NULL, NULL, NULL);
    public_key = PEM_read_RSAPublicKey(public_file_ptr, NULL, NULL, NULL);

    // convert public key from RSA -> string [ for secure transfer over the socket ]
    BIO *bio = BIO_new(BIO_s_mem());
    PEM_write_bio_RSAPublicKey(bio, public_key);

    char *pem_data = NULL;
    size_t pem_len = BIO_get_mem_data(bio, &pem_data);

    // Allocate memory for the string and copy the PEM data
    char *public_key_str = malloc(pem_len + 1);
    memcpy(public_key_str, pem_data, pem_len);
    public_key_str[pem_len] = '\0';

    BIO_free(bio);

    keys->public_key = public_key_str;
}