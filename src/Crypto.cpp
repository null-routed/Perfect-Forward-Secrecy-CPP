#include "../include/SecureBankApplication/Crypto.h"
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <opnessl/rand.h>
#include <vector>
#include <string>
#include <cstring>

using namespace std;

int Crypto::encryptMessage(const vector<unsigned char> &key, string &message, vector<unsigned char> &encryptedMessage)
{

    const EVP_CIPHER *cipher = EVP_aes_128_cbc();
    int iv_length = EVP_CIPHER_iv_length(cipher);
    int block_size = EVP_CIPHER_block_size(cipher);
    unsigned char iv[iv_length];

    // Checking for integer overflow
    if (message.size() + 1 > INT_MAX - block_size)
    {
        return -1;
    }

    // Seeding the OpenSSL PRNG
    if (RAND_poll() == -1)
    {
        return -1;
    }

    // Generating random bytes for the IV
    if (RAND_bytes(iv, iv_length) == -1)
    {
        return -1;
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
    {
        return -1;
    }

    if (EVP_EncryptInit(ctx, cipher, key.data(), iv) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    encryptedMessage.resize(EVP_CIPHER_block_size(cipher) + message.length() + 1 + iv_length);
    memcpy(encryptedMessage.data(), iv, iv_length);

    int outlen;
    if (EVP_EncryptUpdate(ctx, encryptedMessage.data() + iv_length, &outlen, (unsigned char *)message.data(), message.length() + 1) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    int finallen;
    if (EVP_EncryptFinal(ctx, encryptedMessage.data() + iv_length + outlen, &finallen) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    // Resizing the output length in case of the enc buffer being oversized
    encryptedMessage.resize(iv_length + outlen + finallen);

    EVP_CIPHER_CTX_free(ctx);
#pragma optimize("", off)
        fill(&message[0], 0, message.size());
#pragma optimisze("", on)

    return encryptedMessage.size();
}

bool Crypto::generateKeyPair(std::vector<unsigned char> &publicKey, std::vector<unsigned char> privateKey)
{
    // Allocate a new RSA object
    RSA *rsa = RSA_new();

    if (!rsa)
    {
        return false;
    }

    // Generate a new RSA key pair
    BIGNUM *bne = BN_new();

    if (!bne)
    {
        return false;
    }

    BN_set_word(bne, RSA_F4);
    RSA_generate_key_ex(rsa, 2048, bne, nullptr);

    // Convert the private key to DER format and store it in the private key vector
    int privateKeySize = i2d_RSAPrivateKey(rsa, nullptr);
    privateKey.resize(privateKeySize);
    unsigned char *p = privateKey.data();
    i2d_RSAPrivateKey(rsa, &p);

    // Convert the public key to DER format and store it in the public key vector
    int publicKeySize = i2d_RSAPublicKey(rsa, nullptr);
    publicKey.resize(publicKeySize);
    p = publicKey.data();
    i2d_RSAPublicKey(rsa, &p);

    // Free the RSA object and the BIGNUM object
    RSA_free(rsa);
    BN_free(bne);

    return true;
}

bool Crypto::generateHMAC(const std::vector<unsigned char> &key, const std::string &message, std::vector<unsigned char> &hmac)
{   
    // Allocate a new HMAC_CTX object
    HMAC_CTX *hmac_ctx = HMAC_CTX_new();

    if (!hmac_ctx)
    {
        return false;
    }

    // Initialize the HMAC_CTX with the key
    HMAC_Init_ex(hmac_ctx, key.data(), key.size(), EVP_sha256(), nullptr);

    // Update the HMAC_CTX with the message
    HMAC_Update(hmac_ctx, message.data(), data.size());

    // Finalize the HMAC_CTX and store the HMAC in the hmac vector
    unsigned int hmac_size = EVP_MD_size(EVP_sha256());
    hmac.resize(hmac_size);
    HMAC_Final(hmac_ctx, hmac.data(), &hmac_size);

    // Free the HMAC_CTX object
    HMAC_CTX_free(hmac_ctx);

    return true;
}

bool verifyHMAC(const std::vector<unsigned char> &key, const std::string &message, const std::vector<unsigned char> &hmac)
{

}

int Crypto::decryptMessage(const vector<unsigned char> &key, const vector<unsigned char> &encryptedMessage, string &decryptedMessage)
{
    const EVP_CIPHER *cipher = EVP_aes_128_cbc();
    int iv_length = EVP_CIPHER_iv_length(cipher);
    int outlen, totallen;

    vector<unsigned char> iv(encryptedMessage.begin(), encryptedMessage.begin() + iv_length);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
    {
        return -1;
    }

    if (EVP_DecryptionInit(ctx, cipher, key.data(), iv.data()) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    // temp buffer for the plaintext
    vector<unsigned char> plaintext(encryptedMessage.size() - iv_length);

    if (EVP_DecryptUpdate(ctx, plaintext.data(), &outlen, encryptedMessage.data() + iv_length, plaintext.size()) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    totallen = outlen;

    if (EVP_DecryptFinal(ctx, plaintext.data() + outlen, &outlen) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    totallen += outlen;

    decryptedMessage.assign(plaintext.begin(), plaintext.begin() + totallen);
    
    // overwriting the plaintext temp buffer with zeroes
#pragma optimize("", off)
    fill(plaintext.data(), 0, plaintext.size());
#pragma optimisze("", on)

    EVP_CIPHER_CTX_free(ctx);
    return totallensy; 
};
