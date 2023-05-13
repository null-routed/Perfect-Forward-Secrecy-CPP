// Crypto.h
#pragma once

#include <string>
#include <vector>

namespace Crypto
{
    /**
     * @brief Generate pair of RSA keys.
     * @param publicKey
     * @param privateKey
     * @return bool
     */
    bool generateKeyPair(std::vector<unsigned char> &publicKey, std::vector<unsigned char> &privateKey);

    /**
     * @brief Encrypts a given message using the AES-128-CBC algorithm with a randomly generated IV.
     * The message string will be overwritten with null bytes to remove any plain text data from memory
     *
     * @param key The key for encryption
     * @param message The string to encrypt
     * @param encryptedMessage The vector that stores the encrypted data
     * @return int, length of the encryptedMessage, or -1 on failure.
     */
    int encryptMessage(const std::vector<unsigned char> &key, std::string &message, std::vector<unsigned char> &encryptedMessage);

    /**
     * @brief Decrypts a given message using the AES-128-CBC algorithm.
     *
     * @param key 
     * @param encryptedMessage 
     * @param decryptedMessage 
     * @return int, length of the decryptedMessage, or -1 on failure.
     */
    int decryptMessage(const std::vector<unsigned char> &key, const std::vector<unsigned char> &encryptedMessage, std::string &decryptedMessage);

    /**
     * @brief Generate an HMAC for a given message with a given key. Returns the number of bytes in the HMAC, or a negative value if an error occurred.
     * @param key
     * @param message
     * @param hmac
     * @return bool
     */
    bool generateHMAC(const std::vector<unsigned char> &key, const std::string &message, std::vector<unsigned char> &hmac);

    /**
     * @brief Verify an HMAC for a given message with a given key. Returns true if the HMAC is valid, false otherwise.
     * @param key
     * @param message
     * @param hmac
     * @return bool
     */
    bool verifyHMAC(const std::vector<unsigned char> &key, const std::string &message, const std::vector<unsigned char> &hmac);

    /**
     * @brief Generates a vector of random bytes of any given length 
     * 
     * @param length 
     * @return std::vector<unsigned char>, a vector of random bytes, empty array on error
     */
    std::vector<unsigned char> generateNonce(int length);

    // Generate a digital signature for a given message with a given private key. Returns the number of bytes in the signature, or a negative value if an error occurred.
    int generateSignature(const std::vector<unsigned char> &privateKey, const std::string &message, std::vector<unsigned char> &signature);

    // Verify a digital signature for a given message with a given public key. Returns true if the signature is valid, false otherwise.
    bool verifySignature(const std::vector<unsigned char> &publicKey, const std::string &message, const std::vector<unsigned char> &signature);

    bool hashWithSalt(const std::string &plaintext, std::vector<unsigned char> &saltedHash);


}
