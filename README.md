# Secure File Transfer & Encryption Benchmarking
  
> **Language:** C · **Library:** OpenSSL  
> **Network:** TCP sockets (`AF_INET`, `SOCK_STREAM`) on port **8080**

---

## 📁 Project Structure

```

├── 1_Base_Transfer/          # Plain-text TCP file transfer (no encryption)
│   ├── server.c
│   └── client.c
├── 2_AES_DiffieHellman/      # AES-128-CBC encryption with ECDH key exchange
│   ├── server_secure.c
│   └── client_secure.c
├── 3_RSA_Encryption/         # RSA-3072 asymmetric encryption (OAEP + SHA-256)
│   ├── rsa_server.c
│   └── rsa_client.c
└── 4_Benchmarking/           # Timed AES vs RSA file transfer for performance comparison
    ├── aes_client_final.c
    ├── aes_server_final.c
    ├── rsa_client_final.c
    └── rsa_server_final.c
```

---

## 1️⃣ Base Transfer (`1_Base_Transfer/`)

### Purpose
A baseline **unencrypted** TCP file transfer to demonstrate raw socket communication between two machines.

### Files

| File | Role | Description |
|------|------|-------------|
| `server.c` | **Receiver** | Listens on port 8080, accepts a connection, receives file data in 1024-byte chunks, and writes it to `received_file.txt`. |
| `client.c` | **Sender** | Connects to the server at `10.0.2.4`, reads `file.txt` in 1024-byte chunks, and sends the data over TCP. Closing the socket signals EOF to the server. |

### Key Concepts
- TCP socket lifecycle: `socket()` → `bind()` → `listen()` → `accept()` → `recv()`/`send()` → `close()`
- Binary file I/O with `fread()` / `fwrite()`
- No encryption — data is transmitted in **plaintext**

### How to Run
```bash
# On the server (Ubuntu VM)
gcc server.c -o server && ./server

# On the client (Kali VM) — ensure file.txt exists
gcc client.c -o client && ./client
```

---

## 2️⃣ AES + Diffie-Hellman (`2_AES_DiffieHellman/`)

### Purpose
Secure file transfer using **AES-128-CBC** symmetric encryption, with the shared key established via **Elliptic Curve Diffie-Hellman (ECDH)** key exchange.

### Files

| File | Role | Description |
|------|------|-------------|
| `server_secure.c` | **Receiver / Decryptor** | Generates an ECDH keypair (P-256 curve), exchanges public keys with the client, derives a shared secret, hashes it with SHA-256 to produce a 128-bit AES key, then receives and decrypts the file chunk-by-chunk. |
| `client_secure.c` | **Sender / Encryptor** | Generates its own ECDH keypair, exchanges public keys with the server, derives the same shared AES key, then encrypts and sends the file. Each chunk gets a unique random IV via `RAND_bytes()`. |

### Cryptographic Details
| Component | Algorithm |
|-----------|-----------|
| Key Exchange | **ECDH** using NIST P-256 (`NID_X9_62_prime256v1`) |
| Key Derivation | `SHA-256(shared_secret)` → first 16 bytes used as AES key |
| Encryption | **AES-128-CBC** with per-chunk random IV |
| Wire Format | `[IV (16 bytes)] [cipher_len (4 bytes)] [ciphertext]` per chunk |

### How to Run
```bash
# On the server
gcc server_secure.c -o server_secure -lssl -lcrypto && ./server_secure

# On the client — ensure file.txt exists
gcc client_secure.c -o client_secure -lssl -lcrypto && ./client_secure
```

---

## 3️⃣ RSA Encryption (`3_RSA_Encryption/`)

### Purpose
Demonstrate **asymmetric (RSA-3072)** encryption for sending a short secret message from client to server.

### Files

| File | Role | Description |
|------|------|-------------|
| `rsa_server.c` | **Key Generator / Decryptor** | Generates an RSA-3072 keypair, sends the public key to the client, receives the encrypted message, and decrypts it using the private key. |
| `rsa_client.c` | **Encryptor** | Connects to the server, receives the RSA public key, encrypts a hardcoded secret message, and sends the ciphertext back. |

### Cryptographic Details
| Component | Algorithm |
|-----------|-----------|
| Key Generation | **RSA-3072** |
| Padding | **OAEP** (Optimal Asymmetric Encryption Padding) |
| Hash (OAEP) | **SHA-256** |
| MGF | **MGF1-SHA-256** |
| Max Plaintext Size | ~318 bytes (384 − 66 bytes OAEP overhead) |

### How to Run
```bash
# On the server
gcc rsa_server.c -o rsa_server -lssl -lcrypto && ./rsa_server

# On the client
gcc rsa_client.c -o rsa_client -lssl -lcrypto && ./rsa_client
```

---

## 4️⃣ Benchmarking (`4_Benchmarking/`)

### Purpose
Compare the **encryption/decryption performance** of AES-128-CBC (symmetric) vs RSA-3072 (asymmetric) for transferring a **1 KB file**, with microsecond-precision timing.

### Files

| File | Role | Description |
|------|------|-------------|
| `aes_client_final.c` | AES Sender | Same ECDH + AES-128-CBC flow as Part 2, but wraps the encrypt-and-send loop with `gettimeofday()` to measure **encryption time**. Reads from `1kb_file.txt`. |
| `aes_server_final.c` | AES Receiver | Same ECDH + AES-128-CBC decryption flow, with timing around the receive-and-decrypt loop. Measures **decryption time**. Saves to `received_1kb_aes.txt`. |
| `rsa_client_final.c` | RSA Sender | Encrypts the 1 KB file in 318-byte chunks (max RSA-3072 payload with OAEP). Measures **encryption time**. Reads from `1kb_file.txt`. |
| `rsa_server_final.c` | RSA Receiver | Decrypts each RSA chunk and reconstructs the file. Measures **decryption time**. Saves to `received_1kb.txt`. |

### Benchmark Setup
```bash
# Create a 1 KB test file on the client
dd if=/dev/urandom of=1kb_file.txt bs=1024 count=1
```

### How to Run
```bash
# --- AES Benchmark ---
gcc aes_server_final.c -o aes_server -lssl -lcrypto && ./aes_server
gcc aes_client_final.c -o aes_client -lssl -lcrypto && ./aes_client

# --- RSA Benchmark ---
gcc rsa_server_final.c -o rsa_server -lssl -lcrypto && ./rsa_server
gcc rsa_client_final.c -o rsa_client -lssl -lcrypto && ./rsa_client
```

### Expected Observations
| Metric | AES-128-CBC | RSA-3072 |
|--------|-------------|----------|
| Key Type | Symmetric (128-bit) | Asymmetric (3072-bit) |
| Speed | **Very fast** (hardware-accelerated) | **Much slower** (modular exponentiation) |
| Chunking | 1024 bytes per chunk | 318 bytes per chunk (OAEP overhead) |
| Use Case | Bulk data encryption | Small messages, key exchange |

> ⚡ AES is expected to be **significantly faster** than RSA for file transfer, which is why real-world protocols (TLS, SSH) use RSA/ECDH only for **key exchange** and AES for **data encryption**.

---

## ⚙️ Prerequisites

- **GCC** compiler
- **OpenSSL** development libraries (`libssl-dev`)
- Two networked machines (e.g., Kali Linux + Ubuntu VMs)

```bash
# Install OpenSSL on Debian/Ubuntu
sudo apt install libssl-dev
```

> **Note:** Update the server IP address (`10.0.2.4`) in all client files to match your server VM's actual IP.

---

## 📋 Summary Table

| Part | Encryption | Key Exchange | File Transfer | Benchmarked |
|------|-----------|--------------|---------------|-------------|
| 1 — Base Transfer | ❌ None | N/A | ✅ Full file | ❌ |
| 2 — AES + DH | AES-128-CBC | ECDH (P-256) | ✅ Full file | ❌ |
| 3 — RSA | RSA-3072 OAEP | N/A (direct) | ⚠️ Message only | ❌ |
| 4 — Benchmark | AES-128-CBC & RSA-3072 | ECDH / Direct | ✅ 1 KB file | ✅ (μs timing) |
