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

// Helper to decrypt RSA with OAEP and SHA-256
int rsa_decrypt(EVP_PKEY *privkey, const unsigned char *ciphertext, size_t cipher_len, unsigned char **plaintext) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(privkey, NULL);
    EVP_PKEY_decrypt_init(ctx);

    EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING);
    EVP_PKEY_CTX_set_rsa_oaep_md(ctx, EVP_sha256());
    EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, EVP_sha256());

    size_t outlen;
    EVP_PKEY_decrypt(ctx, NULL, &outlen, ciphertext, cipher_len);
    *plaintext = malloc(outlen);
    EVP_PKEY_decrypt(ctx, *plaintext, &outlen, ciphertext, cipher_len);

    EVP_PKEY_CTX_free(ctx);
    return outlen;
}

int main() {
    int server_fd, new_socket;
    struct sockaddr_in address;
    int addrlen = sizeof(address);
    struct timeval start, end;

    // 1. Generate RSA-3072 Keypair
    printf("Generating RSA-3072 Keypair...\n");
    EVP_PKEY_CTX *kctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    EVP_PKEY_keygen_init(kctx);
    EVP_PKEY_CTX_set_rsa_keygen_bits(kctx, 3072);
    EVP_PKEY *rsa_keypair = NULL;
    EVP_PKEY_keygen(kctx, &rsa_keypair);
    EVP_PKEY_CTX_free(kctx);

    // 2. Setup Socket
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);
    bind(server_fd, (struct sockaddr *)&address, sizeof(address));
    listen(server_fd, 3);

    printf("Waiting for client connection...\n");
    new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen);

    // 3. Send Public Key
    unsigned char *server_pub_bytes = NULL;
    int server_pub_len = i2d_PUBKEY(rsa_keypair, &server_pub_bytes);
    send(new_socket, &server_pub_len, sizeof(int), 0);
    send(new_socket, server_pub_bytes, server_pub_len, 0);
    printf("Public Key sent.\n");

    // 4. Receive, Decrypt, and Reconstruct File
    FILE *fp = fopen("received_1kb.txt", "wb");
    int cipher_len;

    printf("Receiving and decrypting chunks...\n");
    gettimeofday(&start, NULL); // START BENCHMARK

    while (recv(new_socket, &cipher_len, sizeof(int), 0) > 0) {
        unsigned char *ciphertext = malloc(cipher_len);

        // Ensure we receive the exact full chunk length
        int received = 0;
        while(received < cipher_len) {
            received += recv(new_socket, ciphertext + received, cipher_len - received, 0);
        }

        unsigned char *plaintext = NULL;
        int plain_len = rsa_decrypt(rsa_keypair, ciphertext, cipher_len, &plaintext);

        fwrite(plaintext, 1, plain_len, fp);

        free(ciphertext);
        free(plaintext);
    }

    gettimeofday(&end, NULL); // STOP BENCHMARK
    double time_taken = (end.tv_sec - start.tv_sec) * 1e6 + (end.tv_usec - start.tv_usec);

    printf("File received and saved as 'received_1kb.txt'.\n");
    printf("----------------------------------------\n");
    printf("RSA Server Decryption Time: %.0f microseconds\n", time_taken);
    printf("----------------------------------------\n");

    fclose(fp);
    free(server_pub_bytes);
    EVP_PKEY_free(rsa_keypair);
    close(new_socket); close(server_fd);
    return 0;
}
