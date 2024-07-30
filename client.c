#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "libssl.lib")
#pragma comment(lib, "libcrypto.lib")

#define PORT 8443
#define BUFFER_SIZE 4096

void initialize_winsock() {
    WSADATA wsa_data;
    if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0) {
        perror("WSAStartup failed");
        exit(EXIT_FAILURE);
    }
}

EVP_PKEY* generate_key() {
    EVP_PKEY* pkey = EVP_PKEY_new();
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    EVP_PKEY_keygen_init(ctx);
    EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048);
    EVP_PKEY_keygen(ctx, &pkey);
    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

void send_message(int sock, const char* message, int length) {
    if (send(sock, message, length, 0) == SOCKET_ERROR) {
        perror("Send failed");
        closesocket(sock);
        WSACleanup();
        exit(EXIT_FAILURE);
    }
}

int receive_message(int sock, char* buffer, int length) {
    int bytes_received = recv(sock, buffer, length, 0);
    if (bytes_received == SOCKET_ERROR) {
        perror("Receive failed");
        closesocket(sock);
        WSACleanup();
        exit(EXIT_FAILURE);
    }
    return bytes_received;
}

void perform_ssl_handshake(int sock, EVP_PKEY* pkey) {
    char buffer[BUFFER_SIZE];
    int bytes_received;

    // Step 1: Send ClientHello
    const char* client_hello = "SSL version, preferences, R_A";
    send_message(sock, client_hello, strlen(client_hello));
    printf("ClientHello sent: %s\n", client_hello);

    // Step 2: Receive ServerHello
    bytes_received = receive_message(sock, buffer, BUFFER_SIZE);
    printf("ServerHello received: %.*s\n", bytes_received, buffer);

    // Step 3: Receive Certificate
    bytes_received = receive_message(sock, buffer, BUFFER_SIZE);
    printf("Certificate received\n");
    BIO* bio = BIO_new_mem_buf(buffer, bytes_received);
    X509* cert = PEM_read_bio_X509(bio, NULL, 0, NULL);
    BIO_free(bio);

    // Step 4: Receive ServerHelloDone
    bytes_received = receive_message(sock, buffer, BUFFER_SIZE);
    printf("ServerHelloDone received: %.*s\n", bytes_received, buffer);

    // Step 5: Send ClientKeyExchange
    unsigned char premaster_secret[48];
    RAND_bytes(premaster_secret, sizeof(premaster_secret));
    EVP_PKEY* pubkey = X509_get_pubkey(cert);
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pubkey, NULL);
    EVP_PKEY_encrypt_init(ctx);
    size_t outlen;
    EVP_PKEY_encrypt(ctx, NULL, &outlen, premaster_secret, sizeof(premaster_secret));
    unsigned char* encrypted_premaster_secret = (unsigned char*)malloc(outlen);
    EVP_PKEY_encrypt(ctx, encrypted_premaster_secret, &outlen, premaster_secret, sizeof(premaster_secret));
    send_message(sock, (char*)encrypted_premaster_secret, outlen);
    free(encrypted_premaster_secret);
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pubkey);
    printf("ClientKeyExchange sent\n");

    // Step 6: Send ChangeCipherSpec
    const char* client_change_cipher_spec = "Change cipher spec";
    send_message(sock, client_change_cipher_spec, strlen(client_change_cipher_spec));
    printf("Client ChangeCipherSpec sent: %s\n", client_change_cipher_spec);

    // Step 7: Send Finished
    const char* client_finished = "Client finished";
    send_message(sock, client_finished, strlen(client_finished));
    printf("Client Finished sent: %s\n", client_finished);

    // Step 8: Receive ChangeCipherSpec
    bytes_received = receive_message(sock, buffer, BUFFER_SIZE);
    printf("Server ChangeCipherSpec received: %.*s\n", bytes_received, buffer);

    // Step 9: Receive Finished
    bytes_received = receive_message(sock, buffer, BUFFER_SIZE);
    printf("Server Finished received: %.*s\n", bytes_received, buffer);
}

int main(int argc, char **argv) {
    initialize_winsock();

    // Generate key for the client
    EVP_PKEY* pkey = generate_key();

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == INVALID_SOCKET) {
        perror("Unable to create socket");
        WSACleanup();
        exit(EXIT_FAILURE);
    }

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT);
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");

    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
        perror("Unable to connect");
        closesocket(sock);
        WSACleanup();
        exit(EXIT_FAILURE);
    }

    perform_ssl_handshake(sock, pkey);

    closesocket(sock);
    WSACleanup();

    EVP_PKEY_free(pkey);

    return 0;
}
