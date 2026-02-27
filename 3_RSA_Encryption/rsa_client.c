#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>

#define PORT 8080

// Helper to encrypt RSA with OAEP and SHA-256
int rsa_encrypt(EVP_PKEY *pubkey, const unsigned char *plaintext, size_t plain_len, unsigned char **ciphertext) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pubkey, NULL);
    EVP_PKEY_encrypt_init(ctx);

    // Set padding to OAEP and hashing to SHA-256
    EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING);
    EVP_PKEY_CTX_set_rsa_oaep_md(ctx, EVP_sha256());
    EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, EVP_sha256());

    size_t outlen;
    EVP_PKEY_encrypt(ctx, NULL, &outlen, plaintext, plain_len); // Get required length
    *ciphertext = malloc(outlen);
    EVP_PKEY_encrypt(ctx, *ciphertext, &outlen, plaintext, plain_len); // Actual encryption

    EVP_PKEY_CTX_free(ctx);
    return outlen;
}

int main() {
    int sock;
    struct sockaddr_in serv_addr;

    // 1. Setup Socket & Connect
    sock = socket(AF_INET, SOCK_STREAM, 0);
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);
    inet_pton(AF_INET, "10.0.2.4", &serv_addr.sin_addr); // UPDATE THIS!
    connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr));
    printf("Connected to server!\n");

    // 2. Receive Server's Public Key
    int server_pub_len;
    recv(sock, &server_pub_len, sizeof(int), 0);
    unsigned char *server_pub_bytes = malloc(server_pub_len);
    recv(sock, server_pub_bytes, server_pub_len, 0);

    const unsigned char *p = server_pub_bytes;
    EVP_PKEY *server_pubkey = d2i_PUBKEY(NULL, &p, server_pub_len);
    printf("Received Server's RSA-3072 Public Key.\n");

    // 3. Prepare a small message
    const char *secret_msg = "Hello Ubuntu! This is a secret message secured by RSA-3072 and OAEP padding from Kali Linux!";
    size_t msg_len = strlen(secret_msg);

    // 4. Encrypt the Message
    unsigned char *ciphertext = NULL;
    int cipher_len = rsa_encrypt(server_pubkey, (const unsigned char*)secret_msg, msg_len, &ciphertext);
    printf("Message encrypted successfully into %d bytes.\n", cipher_len);

    // 5. Send Ciphertext
    send(sock, &cipher_len, sizeof(int), 0);
    send(sock, ciphertext, cipher_len, 0);
    printf("Encrypted message sent!\n");

    // Cleanup
    free(server_pub_bytes); free(ciphertext);
    EVP_PKEY_free(server_pubkey);
    close(sock);
    return 0;
}
