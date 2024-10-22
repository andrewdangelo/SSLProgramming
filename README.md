# SSL Handshake Example in C

This repository contains an example of a simplified SSL handshake implementation in C using OpenSSL. The example includes both server and client programs that manually perform the SSL handshake steps.

## Prerequisites

- Windows operating system
- MinGW or Microsoft Visual Studio
- OpenSSL library installed

## Clone the Repository

To get started, clone the repository using the following command:

```sh
git clone https://github.com/andrewdangelo/SSLProgramming.git
cd SSLProgramming
```

## Compile the Code

### Using MinGW

1. Open a command prompt and navigate to the directory containing your C scripts.
2. Compile the server script:
    ```sh
    gcc -o server server.c -lws2_32 -lssl -lcrypto
    ```
3. Compile the client script:
    ```sh
    gcc -o client client.c -lws2_32 -lssl -lcrypto
    ```

## Run the Programs

1. Open a command prompt and navigate to the directory containing the compiled server executable.
2. Run the server:
    ```sh
    server.exe
    ```
3. Open another command prompt and navigate to the directory containing the compiled client executable.
4. Run the client:
    ```sh
    client.exe
    ```

## Explanation of the Functions and Steps

### Server Script

#### Functions

- `initialize_winsock()`: Initializes the Winsock library.
- `generate_key()`: Generates an RSA key using `EVP_PKEY`.
- `generate_certificate()`: Generates a self-signed certificate using the generated key.
- `send_message()`: Sends a message to the client.
- `receive_message()`: Receives a message from the client.
- `perform_ssl_handshake()`: Performs the SSL handshake steps with the client.

#### Steps

1. **Receive ClientHello**: The server receives the ClientHello message.
2. **Send ServerHello**: The server sends the ServerHello message.
3. **Send Certificate**: The server sends its certificate to the client.
4. **Send ServerHelloDone**: The server sends the ServerHelloDone message.
5. **Receive ClientKeyExchange**: The server receives the encrypted premaster secret.
6. **Decrypt Premaster Secret**: The server decrypts the premaster secret using its private key.
7. **Receive ChangeCipherSpec**: The server receives the ChangeCipherSpec message from the client.
8. **Receive Finished**: The server receives the Finished message from the client.
9. **Send ChangeCipherSpec**: The server sends the ChangeCipherSpec message to the client.
10. **Send Finished**: The server sends the Finished message to the client.

### Client Script

#### Functions

- `initialize_winsock()`: Initializes the Winsock library.
- `generate_key()`: Generates an RSA key using `EVP_PKEY`.
- `send_message()`: Sends a message to the server.
- `receive_message()`: Receives a message from the server.
- `perform_ssl_handshake()`: Performs the SSL handshake steps with the server.

#### Steps

1. **Send ClientHello**: The client sends the ClientHello message.
2. **Receive ServerHello**: The client receives the ServerHello message.
3. **Receive Certificate**: The client receives the server's certificate.
4. **Receive ServerHelloDone**: The client receives the ServerHelloDone message.
5. **Send ClientKeyExchange**: The client sends the encrypted premaster secret.
6. **Send ChangeCipherSpec**: The client sends the ChangeCipherSpec message.
7. **Send Finished**: The client sends the Finished message.
8. **Receive ChangeCipherSpec**: The client receives the ChangeCipherSpec message from the server.
9. **Receive Finished**: The client receives the Finished message from the server.

## SSL Handshake Diagram

Below is a representation of the SSL handshake process:

![SSL Handshake Diagram](SSL_handshake.png)


## Notes

- The example is for educational purposes and may lack many security features of a real SSL/TLS implementation.
- Make sure you have OpenSSL installed and properly configured on your Windows system.
