#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/x509.h>

#define PORT 8080
#define BUFFER_SIZE 1024

// Helper to decrypt AES-128-CBC
int decrypt_data(unsigned char *ciphertext, int ciphertext_len, unsigned char *key, unsigned char *iv, unsigned char *plaintext) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len, plaintext_len;
    EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv);
    EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len);
    plaintext_len = len;
    EVP_DecryptFinal_ex(ctx, plaintext + len, &len);
    plaintext_len += len;
    EVP_CIPHER_CTX_free(ctx);
    return plaintext_len;
}

int main() {
    int server_fd, new_socket;
    struct sockaddr_in address;
    int addrlen = sizeof(address);

    // 1. Setup Socket
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);
    bind(server_fd, (struct sockaddr *)&address, sizeof(address));
    listen(server_fd, 3);

    printf("Waiting for secure connection...\n");
    new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen);
    printf("Client connected! Initiating Diffie-Hellman Handshake...\n");

    // 2. Diffie-Hellman Setup (ECDH)
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    EVP_PKEY_paramgen_init(pctx);
    EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_X9_62_prime256v1);
    EVP_PKEY *params = NULL;
    EVP_PKEY_paramgen(pctx, &params);

    EVP_PKEY_CTX *kctx = EVP_PKEY_CTX_new(params, NULL);
    EVP_PKEY_keygen_init(kctx);
    EVP_PKEY *server_keypair = NULL;
    EVP_PKEY_keygen(kctx, &server_keypair);

    // 3. Receive Client's Public Key
    int client_pub_len;
    recv(new_socket, &client_pub_len, sizeof(int), 0);
    unsigned char *client_pub_bytes = malloc(client_pub_len);
    recv(new_socket, client_pub_bytes, client_pub_len, 0);

    const unsigned char *p = client_pub_bytes;
    EVP_PKEY *client_pubkey = d2i_PUBKEY(NULL, &p, client_pub_len);

    // 4. Send Server's Public Key
    unsigned char *server_pub_bytes = NULL;
    int server_pub_len = i2d_PUBKEY(server_keypair, &server_pub_bytes);
    send(new_socket, &server_pub_len, sizeof(int), 0);
    send(new_socket, server_pub_bytes, server_pub_len, 0);

    // 5. Derive Shared Secret & AES Key
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(server_keypair, NULL);
    EVP_PKEY_derive_init(ctx);
    EVP_PKEY_derive_set_peer(ctx, client_pubkey);
    size_t secret_len;
    EVP_PKEY_derive(ctx, NULL, &secret_len);
    unsigned char *secret = malloc(secret_len);
    EVP_PKEY_derive(ctx, secret, &secret_len);

    unsigned char aes_key[16]; // 128-bit key
    SHA256(secret, secret_len, aes_key); // Hash secret to exactly 16 bytes
    printf("Symmetric AES Key Established!\n");

    // 6. Receive Encrypted File
    FILE *fp = fopen("received_secure.txt", "wb");
    unsigned char iv[16];
    int cipher_len;
    unsigned char ciphertext[BUFFER_SIZE + 16];
    unsigned char plaintext[BUFFER_SIZE];

    printf("Receiving encrypted file...\n");
    while (recv(new_socket, iv, 16, 0) > 0) { // Receive IV first
        recv(new_socket, &cipher_len, sizeof(int), 0); // Receive length
        recv(new_socket, ciphertext, cipher_len, 0);   // Receive ciphertext

        int plain_len = decrypt_data(ciphertext, cipher_len, aes_key, iv, plaintext);
        fwrite(plaintext, 1, plain_len, fp);
    }

    printf("Secure file transfer complete!\n");

    // Cleanup
    fclose(fp); close(new_socket); close(server_fd);
    return 0;
}
