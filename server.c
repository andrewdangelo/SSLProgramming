#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
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

X509* generate_certificate(EVP_PKEY* pkey) {
    X509* x509 = X509_new();
    X509_NAME* name = X509_get_subject_name(x509);

    ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);
    X509_gmtime_adj(X509_get_notBefore(x509), 0);
    X509_gmtime_adj(X509_get_notAfter(x509), 31536000L); // Valid for one year

    X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, (const unsigned char*)"US", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, (const unsigned char*)"Example Corp", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (const unsigned char*)"example.com", -1, -1, 0);

    X509_set_issuer_name(x509, name);
    X509_set_pubkey(x509, pkey);

    X509_sign(x509, pkey, EVP_sha256());
    return x509;
}

void send_message(int client, const char* message, int length) {
    if (send(client, message, length, 0) == SOCKET_ERROR) {
        perror("Send failed");
        closesocket(client);
        WSACleanup();
        exit(EXIT_FAILURE);
    }
}

int receive_message(int client, char* buffer, int length) {
    int bytes_received = recv(client, buffer, length, 0);
    if (bytes_received == SOCKET_ERROR) {
        perror("Receive failed");
        closesocket(client);
        WSACleanup();
        exit(EXIT_FAILURE);
    }
    return bytes_received;
}

void perform_ssl_handshake(int client, EVP_PKEY* pkey, X509* cert) {
    char buffer[BUFFER_SIZE];
    int bytes_received;

    // Step 1: Receive ClientHello
    bytes_received = receive_message(client, buffer, BUFFER_SIZE);
    printf("ClientHello received: %.*s\n", bytes_received, buffer);

    // Step 2: Send ServerHello
    const char* server_hello = "SSL version, choices, R_B";
    send_message(client, server_hello, strlen(server_hello));
    printf("ServerHello sent: %s\n", server_hello);

    // Step 3: Send Certificate
    BIO* bio = BIO_new(BIO_s_mem());
    PEM_write_bio_X509(bio, cert);
    int cert_len = BIO_pending(bio);
    char* cert_buffer = (char*)malloc(cert_len);
    BIO_read(bio, cert_buffer, cert_len);
    send_message(client, cert_buffer, cert_len);
    free(cert_buffer);
    BIO_free(bio);
    printf("Certificate sent\n");

    // Step 4: Send ServerHelloDone
    const char* server_done = "Server done";
    send_message(client, server_done, strlen(server_done));
    printf("ServerHelloDone sent: %s\n", server_done);

    // Step 5: Receive ClientKeyExchange
    bytes_received = receive_message(client, buffer, BUFFER_SIZE);
    printf("ClientKeyExchange received\n");

    // Decrypt the premaster secret
    unsigned char premaster_secret[BUFFER_SIZE];
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, NULL);
    EVP_PKEY_decrypt_init(ctx);
    size_t premaster_secret_len = sizeof(premaster_secret);
    EVP_PKEY_decrypt(ctx, premaster_secret, &premaster_secret_len, (unsigned char*)buffer, bytes_received);
    EVP_PKEY_CTX_free(ctx);
    printf("Premaster secret decrypted\n");

    // Step 6: Change Cipher Spec
    bytes_received = receive_message(client, buffer, BUFFER_SIZE);
    printf("Client ChangeCipherSpec received: %.*s\n", bytes_received, buffer);

    // Step 7: Receive Finished
    bytes_received = receive_message(client, buffer, BUFFER_SIZE);
    printf("Client Finished received: %.*s\n", bytes_received, buffer);

    // Step 8: Send ChangeCipherSpec
    const char* server_change_cipher_spec = "Change cipher spec";
    send_message(client, server_change_cipher_spec, strlen(server_change_cipher_spec));
    printf("Server ChangeCipherSpec sent: %s\n", server_change_cipher_spec);

    // Step 9: Send Finished
    const char* server_finished = "Server finished";
    send_message(client, server_finished, strlen(server_finished));
    printf("Server Finished sent: %s\n", server_finished);
}

int main(int argc, char **argv) {
    initialize_winsock();

    // Generate key and certificate
    EVP_PKEY* pkey = generate_key();
    X509* cert = generate_certificate(pkey);

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == INVALID_SOCKET) {
        perror("Unable to create socket");
        WSACleanup();
        exit(EXIT_FAILURE);
    }

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(sock, (struct sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
        perror("Unable to bind");
        closesocket(sock);
        WSACleanup();
        exit(EXIT_FAILURE);
    }

    if (listen(sock, 1) == SOCKET_ERROR) {
        perror("Unable to listen");
        closesocket(sock);
        WSACleanup();
        exit(EXIT_FAILURE);
    }

    printf("Server is listening on port %d...\n", PORT);

    struct sockaddr_in client_addr;
    int len = sizeof(client_addr);
    int client = accept(sock, (struct sockaddr*)&client_addr, &len);
    if (client == INVALID_SOCKET) {
        perror("Unable to accept");
        closesocket(sock);
        WSACleanup();
        exit(EXIT_FAILURE);
    }

    perform_ssl_handshake(client, pkey, cert);

    closesocket(client);
    closesocket(sock);
    WSACleanup();

    EVP_PKEY_free(pkey);
    X509_free(cert);

    return 0;
}
