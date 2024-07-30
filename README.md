# SSL Handshake Example in C

This repository contains an example of a simplified SSL handshake implementation in C using OpenSSL. The example includes both server and client programs that manually perform the SSL handshake steps.

## Prerequisites

- Windows operating system
- MinGW or Microsoft Visual Studio
- OpenSSL library installed

## Generate Certificates

Before running the programs, you need to generate the server's RSA key and certificate.

1. Open a command prompt and navigate to your working directory.
2. Generate the private key:
    ```sh
    openssl genpkey -algorithm RSA -out server.key -pkeyopt rsa_keygen_bits:2048
    ```
3. Generate a self-signed certificate:
    ```sh
    openssl req -new -x509 -key server.key -out server.crt -days 365
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

### Using Microsoft Visual Studio

1. Open Microsoft Visual Studio.
2. Create a new project and add your C script to the project.
3. Configure the project to link against OpenSSL libraries (`ssl.lib` and `crypto.lib`).
4. Build the project.

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

## Notes

- The example is for educational purposes and may lack many security features of a real SSL/TLS implementation.
- Ensure that you have the `server.crt` and `server.key` files in the same directory as your executable.
- Make sure you have OpenSSL installed and properly configured on your Windows system.
- Use proper error handling in a real-world application.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
