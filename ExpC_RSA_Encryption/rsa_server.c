#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>

#define PORT 8080

// Helper to decrypt RSA with OAEP and SHA-256
int rsa_decrypt(EVP_PKEY *privkey, const unsigned char *ciphertext, size_t cipher_len, unsigned char **plaintext) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(privkey, NULL);
    EVP_PKEY_decrypt_init(ctx);

    // Set padding to OAEP and hashing to SHA-256
    EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING);
    EVP_PKEY_CTX_set_rsa_oaep_md(ctx, EVP_sha256());
    EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, EVP_sha256());

    size_t outlen;
    EVP_PKEY_decrypt(ctx, NULL, &outlen, ciphertext, cipher_len); // Get required length
    *plaintext = malloc(outlen + 1); // +1 for null terminator
    EVP_PKEY_decrypt(ctx, *plaintext, &outlen, ciphertext, cipher_len); // Actual decryption

    (*plaintext)[outlen] = '\0'; // Null terminate the string
    EVP_PKEY_CTX_free(ctx);
    return outlen;
}

int main() {
    int server_fd, new_socket;
    struct sockaddr_in address;
    int addrlen = sizeof(address);

    // 1. Generate RSA-3072 Keypair
    printf("Generating RSA-3072 Keypair (this might take a second)...\n");
    EVP_PKEY_CTX *kctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    EVP_PKEY_keygen_init(kctx);
    EVP_PKEY_CTX_set_rsa_keygen_bits(kctx, 3072);
    EVP_PKEY *rsa_keypair = NULL;
    EVP_PKEY_keygen(kctx, &rsa_keypair);
    EVP_PKEY_CTX_free(kctx);
    printf("Keypair generated successfully!\n");

    // 2. Setup Socket
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);
    bind(server_fd, (struct sockaddr *)&address, sizeof(address));
    listen(server_fd, 3);

    printf("Waiting for client connection...\n");
    new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen);
    printf("Client connected!\n");

    // 3. Extract and Send Public Key to Client
    unsigned char *server_pub_bytes = NULL;
    int server_pub_len = i2d_PUBKEY(rsa_keypair, &server_pub_bytes);
    send(new_socket, &server_pub_len, sizeof(int), 0);
    send(new_socket, server_pub_bytes, server_pub_len, 0);
    printf("Sent Public Key to Client.\n");

    // 4. Receive Ciphertext from Client
    int cipher_len;
    recv(new_socket, &cipher_len, sizeof(int), 0);
    unsigned char *ciphertext = malloc(cipher_len);
    recv(new_socket, ciphertext, cipher_len, 0);
    printf("Received Encrypted Message (%d bytes).\n", cipher_len);

    // 5. Decrypt the Message
    unsigned char *plaintext = NULL;
    rsa_decrypt(rsa_keypair, ciphertext, cipher_len, &plaintext);

    printf("\n--- DECRYPTED MESSAGE ---\n%s\n-------------------------\n", plaintext);

    // Cleanup
    free(ciphertext); free(plaintext); free(server_pub_bytes);
    EVP_PKEY_free(rsa_keypair);
    close(new_socket); close(server_fd);
    return 0;
}
