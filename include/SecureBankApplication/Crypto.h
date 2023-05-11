// Crypto.h
#pragma once

#include <string>

namespace Crypto
{
    // Generate a public/private key pair. Returns the number of bytes in the keys, -1 if generation failed.
    int generateKeyPair(unsigned char *publicKey, unsigned char *privateKey);

    // Encrypt a message with a given key. Returns the number of bytes in the encrypted message, or a negative value if an error occurred.
    int encryptMessage(const unsigned char *key, const std::string &message, unsigned char *encryptedMessage);

    // Decrypt a message with a given key. Returns the number of bytes in the decrypted message, or a negative value if an error occurred.
    int decryptMessage(const unsigned char *key, const unsigned char *encryptedMessage, std::string &decryptedMessage);

    // Generate an HMAC for a given message with a given key. Returns the number of bytes in the HMAC, or a negative value if an error occurred.
    int generateHMAC(const unsigned char *key, const std::string &message, unsigned char *hmac);

    // Verify an HMAC for a given message with a given key. Returns true if the HMAC is valid, false otherwise.
    bool verifyHMAC(const unsigned char *key, const std::string &message, const unsigned char *hmac);

    // Generate a nonce. Returns the nonce as a string using hex encoding.
    std::string generateNonce(int length);

    // Generate a digital signature for a given message with a given private key. Returns the number of bytes in the signature, or a negative value if an error occurred.
    int generateSignature(const unsigned char *privateKey, const std::string &message, unsigned char *signature);

    // Verify a digital signature for a given message with a given public key. Returns true if the signature is valid, false otherwise.
    bool verifySignature(const unsigned char *publicKey, const std::string &message, const unsigned char *signature);
}
