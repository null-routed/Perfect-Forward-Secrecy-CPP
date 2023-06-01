#ifndef CRYPTO_H
#define CRYPTO_H

#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <vector>
#include <string>

namespace Crypto {

    /**
     * @brief Reads owner from an X509 certificate
     * @param cert
     * @return std::string
     */
    std::string read_owner_from_cert(X509* cert);

    /**
     * @brief Verifies a certificate is valid
     * @param store
     * @param cert
     * @return bool
     */
    bool verify_certificate(X509_STORE *store, X509* cert);

    /**
     * @brief Reads the public key from a certificate
     * @param cert
     * @return std::vector<unsigned char>
     */
    std::vector<unsigned char> read_public_key_from_cert(X509* cert);

    /**
     * @brief Encrypts a string using an RSA public key
     * @param pub_key 
     * @param message 
     * @param encrypted 
     * @return int, size of the ciphertext
     */
    int rsa_encrypt(const std::vector<unsigned char>& pub_key, std::string& message, std::vector<unsigned char>& encrypted);

    /**
     * @brief Decrypts a RSA-encrypted ciphertext
     * @param priv_key 
     * @param encrypted 
     * @param message 
     * @return int, size of the plaintext
     */
    int rsa_decrypt(const std::vector<unsigned char>& priv_key, const std::vector<unsigned char>& encrypted, std::string& message);

    /**
     * @brief Encrypts a string using a symmetric AES key
     * @param key 
     * @param message 
     * @param encryptedMessage 
     * @return int, size of the ciphertext
     */
    int aes_encrypt(const std::vector<unsigned char> &key, std::string &message, std::vector<unsigned char> &encryptedMessage);

    /**
     * @brief Decrypts a AES-encrypted ciphertext
     * @param key 
     * @param encryptedMessage 
     * @param decryptedMessage 
     * @return int, size of plaintext
     */
    int aes_decrypt(const std::vector<unsigned char> &key, const std::vector<unsigned char> &encryptedMessage, std::string &decryptedMessage);

    /**
     * @brief Generates a pair of RSA keys.
     * @param priv_key
     * @param pub_key
     * @return bool, false on failure
     */
    bool generate_key_pair(std::vector<unsigned char> &priv_key, std::vector<unsigned char> &pub_key);

    /**
     * @brief Generates an HMAC for the message
     * @param key 
     * @param message 
     * @param hmac 
     * @return bool, false on failure 
     */
    bool generate_hmac(const std::vector<unsigned char> &key, const std::string &message, std::vector<unsigned char> &hmac);

    /**
     * @brief Verifies if the HMAC is authentic
     * @param key 
     * @param message 
     * @param hmac 
     * @return bool
     */
    bool verify_hmac(const std::vector<unsigned char> &key, const std::string &message, const std::vector<unsigned char> &hmac);

    /**
     * @brief Makes sure the random device is properly seeded and generates a random byte strength of given length
     * @param length 
     * @return std::vector<unsigned char> 
     */
    std::vector<unsigned char> generate_nonce(int length);

    /**
     * @brief Generates a signature on message using a private_key
     * @param priv_key 
     * @param message 
     * @param signature 
     * @return int, length of signature
     */
    int generate_signature(const std::vector<unsigned char> &priv_key, const std::string &message, std::vector<unsigned char> &signature);

    /**
     * @brief Verifies a signature given a message and public key
     * @param message 
     * @param signature 
     * @param pub_key 
     * @return bool
     */
    bool verify_signature(const std::string &message, const std::vector<unsigned char> &signature, const std::vector<unsigned char> &pub_key);

    /**
     * @brief Performs hashing with a 16-byte salt
     * @param plaintext 
     * @param saltedHash 
     * @param salt 
     * @return bool
     */
    bool hash_with_salt(const std::string &plaintext, std::vector<unsigned char> &saltedHash, std::vector<unsigned char> salt);

    /**
     * @brief Verifies that a given plaintex hashes into a given salted hash
     * @param plaintext 
     * @param hash 
     * @return bool
     */
    bool verify_hash(const std::string &plaintext, const std::vector<unsigned char> &hash);

}

#endif
