#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/x509.h>

#define PORT 8080
#define BUFFER_SIZE 1024

// Helper to encrypt AES-128-CBC
int encrypt_data(unsigned char *plaintext, int plaintext_len, unsigned char *key, unsigned char *iv, unsigned char *ciphertext) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len, ciphertext_len;
    EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv);
    EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len);
    ciphertext_len = len;
    EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);
    ciphertext_len += len;
    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_len;
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

    // 2. Diffie-Hellman Setup (ECDH)
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    EVP_PKEY_paramgen_init(pctx);
    EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_X9_62_prime256v1);
    EVP_PKEY *params = NULL;
    EVP_PKEY_paramgen(pctx, &params);

    EVP_PKEY_CTX *kctx = EVP_PKEY_CTX_new(params, NULL);
    EVP_PKEY_keygen_init(kctx);
    EVP_PKEY *client_keypair = NULL;
    EVP_PKEY_keygen(kctx, &client_keypair);

    // 3. Send Client's Public Key
    unsigned char *client_pub_bytes = NULL;
    int client_pub_len = i2d_PUBKEY(client_keypair, &client_pub_bytes);
    send(sock, &client_pub_len, sizeof(int), 0);
    send(sock, client_pub_bytes, client_pub_len, 0);

    // 4. Receive Server's Public Key
    int server_pub_len;
    recv(sock, &server_pub_len, sizeof(int), 0);
    unsigned char *server_pub_bytes = malloc(server_pub_len);
    recv(sock, server_pub_bytes, server_pub_len, 0);

    const unsigned char *p = server_pub_bytes;
    EVP_PKEY *server_pubkey = d2i_PUBKEY(NULL, &p, server_pub_len);

    // 5. Derive Shared AES Key
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(client_keypair, NULL);
    EVP_PKEY_derive_init(ctx);
    EVP_PKEY_derive_set_peer(ctx, server_pubkey);
    size_t secret_len;
    EVP_PKEY_derive(ctx, NULL, &secret_len);
    unsigned char *secret = malloc(secret_len);
    EVP_PKEY_derive(ctx, secret, &secret_len);

    unsigned char aes_key[16]; // 128-bit key
    SHA256(secret, secret_len, aes_key);
    printf("Symmetric AES Key Established.\n");

    // 6. Benchmark: Encrypt and Send File
    FILE *fp = fopen("1kb_file.txt", "rb");
    if (!fp) {
        perror("Could not open 1kb_file.txt. Did you create it?");
        return 1;
    }

    unsigned char buffer[BUFFER_SIZE];
    unsigned char ciphertext[BUFFER_SIZE + 16];
    unsigned char iv[16];
    int bytes_read;

    printf("Encrypting and sending AES file...\n");
    gettimeofday(&start, NULL); // START BENCHMARK

    while ((bytes_read = fread(buffer, 1, BUFFER_SIZE, fp)) > 0) {
        RAND_bytes(iv, sizeof(iv)); // Generate unique IV per chunk
        int cipher_len = encrypt_data(buffer, bytes_read, aes_key, iv, ciphertext);

        send(sock, iv, 16, 0); // Send IV
        send(sock, &cipher_len, sizeof(int), 0); // Send length
        send(sock, ciphertext, cipher_len, 0); // Send encrypted data
    }

    gettimeofday(&end, NULL); // STOP BENCHMARK
    double time_taken = (end.tv_sec - start.tv_sec) * 1e6 + (end.tv_usec - start.tv_usec);

    printf("File sent securely!\n");
    printf("----------------------------------------\n");
    printf("AES Client Encryption Time: %.0f microseconds\n", time_taken);
    printf("----------------------------------------\n");

    // Cleanup
    fclose(fp); close(sock);
    free(client_pub_bytes); free(server_pub_bytes); free(secret);
    EVP_PKEY_free(client_keypair); EVP_PKEY_free(server_pubkey);
    return 0;
}
