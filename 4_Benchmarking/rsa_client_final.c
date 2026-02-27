#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>

#define PORT 8080
#define MAX_RSA_PAYLOAD 318 // 384 bytes (RSA-3072) - 66 bytes (OAEP SHA256 overhead)

// Helper to encrypt RSA with OAEP and SHA-256
int rsa_encrypt(EVP_PKEY *pubkey, const unsigned char *plaintext, size_t plain_len, unsigned char **ciphertext) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pubkey, NULL);
    EVP_PKEY_encrypt_init(ctx);

    EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING);
    EVP_PKEY_CTX_set_rsa_oaep_md(ctx, EVP_sha256());
    EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, EVP_sha256());

    size_t outlen;
    EVP_PKEY_encrypt(ctx, NULL, &outlen, plaintext, plain_len);
    *ciphertext = malloc(outlen);
    EVP_PKEY_encrypt(ctx, *ciphertext, &outlen, plaintext, plain_len);

    EVP_PKEY_CTX_free(ctx);
    return outlen;
}

int main() {
    int sock;
    struct sockaddr_in serv_addr;
    struct timeval start, end;

    // 1. Setup Socket & Connect
    sock = socket(AF_INET, SOCK_STREAM, 0);
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);
    inet_pton(AF_INET, "10.0.2.4", &serv_addr.sin_addr); // UPDATE THIS!
    connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr));

    // 2. Receive Public Key
    int server_pub_len;
    recv(sock, &server_pub_len, sizeof(int), 0);
    unsigned char *server_pub_bytes = malloc(server_pub_len);
    recv(sock, server_pub_bytes, server_pub_len, 0);

    const unsigned char *p = server_pub_bytes;
    EVP_PKEY *server_pubkey = d2i_PUBKEY(NULL, &p, server_pub_len);
    printf("Received Server's RSA-3072 Public Key.\n");

    // 3. Open File and Chunk
    FILE *fp = fopen("1kb_file.txt", "rb");
    if (!fp) {
        perror("Could not open 1kb_file.txt. Did you create it?");
        return 1;
    }

    unsigned char buffer[MAX_RSA_PAYLOAD];
    int bytes_read;

    printf("Encrypting and sending file in chunks...\n");
    gettimeofday(&start, NULL); // START BENCHMARK

    while ((bytes_read = fread(buffer, 1, MAX_RSA_PAYLOAD, fp)) > 0) {
        unsigned char *ciphertext = NULL;

        // Encrypt the chunk (max 318 bytes at a time)
        int cipher_len = rsa_encrypt(server_pubkey, buffer, bytes_read, &ciphertext);

        // Send size, then payload
        send(sock, &cipher_len, sizeof(int), 0);
        send(sock, ciphertext, cipher_len, 0);

        free(ciphertext);
    }

    gettimeofday(&end, NULL); // STOP BENCHMARK
    double time_taken = (end.tv_sec - start.tv_sec) * 1e6 + (end.tv_usec - start.tv_usec);

    printf("File sent securely!\n");
    printf("----------------------------------------\n");
    printf("RSA Client Encryption Time: %.0f microseconds\n", time_taken);
    printf("----------------------------------------\n");

    fclose(fp);
    free(server_pub_bytes);
    EVP_PKEY_free(server_pubkey);
    close(sock);
    return 0;
}
