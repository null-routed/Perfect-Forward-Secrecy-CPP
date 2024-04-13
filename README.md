![C++](https://img.shields.io/badge/C++-00599C?style=flat&logo=c%2B%2B&logoColor=white)
![OpenSSL](https://img.shields.io/badge/OpenSSL-721412?style=flat&logo=openssl&logoColor=white)

# Perfect Forward Secrecy App in C++

## Overview 
This repo features a Proof-Of-Concept (PoC) implementation of a cryptographically secure banking application developed C++. The application's handshake protocol between client and server was designed to be compliant with Perfect Forward Secrecy (PFS) standards. Additionally, the app implements an application-level protocol that guarantees integrity, authenticity, confidentiality of the data, as well as offering robust protection against replay attacks.

## Handshake Protocol
![handshake](https://github.com/null-routed/Perfect-Forward-Secrecy-CPP/assets/55241343/95f33f10-058a-40a5-8003-11886169bb05)

1. The server maintains a pair of RSA keys: privK, pubK
2. Upon execution, the client initiates the handshake process by transmitting a `CLIENT_HELLO` message, which includes a random value, R.
3. Upon receiving R, the server generates a pair of ephemeral 2048-bit RSA keys. The server then replies by sending a SERVER_HELLO message, that contains:
   - TpubK, the newly-generated ephemeral public key.
   - `<R||TpubK>privK`, the server’s signature of R and TpubK concatenated together. The signature is based on RSA and uses SHA256 as hashing algorithm.
   - Cert, the server’s certificate.
4. Upon receiving the server’s response, the client performs the following security operations:
   - Verifies the server’s certificate validity using the certification authority’s certificate.
   - Checks that the certificate actually belongs to the server by checking the owner of the certificate.
   - Checks for potential Man-In-The-Middle attacks by verifying the validity of the signature and checking that R is the same one as it sent in the first message.
5. After doing this, the client generates a pair of keys, one for MAC and one for symmetric encryption. The client then builds a `KEY_EXCHANGE` message which contains the keys encrypted with the ephemeral public key TpubK.
6. The server decrypts the message by using TprivK, thus obtaining both keys.
7. For security purposes, both client and server delete the ephemeral RSA key pair.
8. The server concludes the protocol by transmitting a `SERVER_OK` message. This message includes a sessionId encrypted with the AES key, thereby confirming the key to the client. The sessionId is a random stream of 4 bytes, stored as uint32_t and can be used by the client as identifier for the session for future connections.


## Message Structure 
![msg_structure (1)](https://github.com/null-routed/Perfect-Forward-Secrecy-CPP/assets/55241343/7498f6cd-f0d0-41b0-a77e-93b01ca363a8)

## Application-level protocol
![msg_protocol](https://github.com/null-routed/Perfect-Forward-Secrecy-CPP/assets/55241343/a534845d-cea0-4a50-b99b-96f8191c3381)
1. Client creates message that includes command, timestamp, data and HMAC.
2. Message is encrypted using AES-128-CBC and sent with its header.
3. Server receives the message from client and chooses the key pair according to the session ID.
4. Server decrypts the message with appropriate key.
5. Server checks validity of HMAC and correctness of the timestamp (i.e., whether the timestamp
is ahead of the last received message timestamp and within the acceptable window).
6. If the verification procedure is successful, server performs the given operations.
7. The client receives the server’s response, verifies the HMAC, and checks if the timestampmatches that of the client’s original message.

